package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const maxEnvFileBytes = 64 << 10

// LoadEnvSettings reads the DSF block from a deployment-owned dotenv file.
// A missing file, or a file without any DSF_* key, falls through to the normal
// settings store. The credential is held only in memory and never logged.
func LoadEnvSettings(path string) (*Manager, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.New("无法读取模型环境配置文件")
	}
	if len(raw) > maxEnvFileBytes {
		return nil, false, fmt.Errorf("模型环境配置文件超过 %d 字节上限", maxEnvFileBytes)
	}
	values, dsfFound, err := parseDSFEnv(string(raw))
	if err != nil {
		return nil, false, err
	}
	if !dsfFound {
		return nil, false, nil
	}
	apiKey := strings.TrimSpace(values["DSF_API_KEY"])
	baseURL := firstNonEmpty(values, "DSF_BASE_URL", "DSF_API_BASE")
	model := strings.TrimSpace(values["DSF_MODEL"])
	if apiKey == "" {
		return nil, false, errors.New("DSF 环境配置缺少 DSF_API_KEY")
	}
	if baseURL == "" {
		return nil, false, errors.New("DSF 环境配置缺少 DSF_BASE_URL")
	}
	if model == "" {
		return nil, false, errors.New("DSF 环境配置缺少 DSF_MODEL")
	}
	protocol := strings.TrimSpace(values["DSF_PROTOCOL"])
	if protocol == "" {
		protocol = "chat-completions"
	}
	timeout, err := envInt(values, "DSF_TIMEOUT_SECONDS", 120)
	if err != nil {
		return nil, false, err
	}
	maxOutput, err := envInt(values, "DSF_MAX_OUTPUT_TOKENS", 4096)
	if err != nil {
		return nil, false, err
	}
	cfg, err := normalize(Config{
		Enabled: true, Protocol: protocol, BaseURL: baseURL, Model: model,
		APIKey: apiKey, TimeoutSeconds: timeout, MaxOutputTokens: maxOutput,
	})
	if err != nil {
		return nil, false, fmt.Errorf("DSF 环境配置无效: %w", err)
	}
	return &Manager{
		cfg: cfg, version: environmentVersion(cfg), source: "environment", readOnly: true,
	}, true, nil
}

func parseDSFEnv(raw string) (map[string]string, bool, error) {
	dsfValues := map[string]string{}
	genericValues := map[string]string{}
	dsfFound := false
	genericFound := false
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, false, errors.New("模型环境配置文件包含无效行")
		}
		key = strings.TrimSpace(key)
		upperKey := strings.ToUpper(key)
		canonical := ""
		switch strings.ToLower(key) {
		case "api_key":
			canonical = "DSF_API_KEY"
		case "base_url", "api_base", "base":
			canonical = "DSF_BASE_URL"
		case "model":
			canonical = "DSF_MODEL"
		case "protocol":
			canonical = "DSF_PROTOCOL"
		case "timeout_seconds":
			canonical = "DSF_TIMEOUT_SECONDS"
		case "max_output_tokens":
			canonical = "DSF_MAX_OUTPUT_TOKENS"
		default:
			if strings.HasPrefix(upperKey, "DSF_") {
				canonical = upperKey
			}
		}
		if canonical == "" {
			continue
		}
		parsed, err := parseEnvValue(strings.TrimSpace(value))
		if err != nil {
			return nil, false, fmt.Errorf("%s 的值格式无效", key)
		}
		if strings.HasPrefix(upperKey, "DSF_") {
			dsfValues[canonical] = parsed
			dsfFound = true
		} else {
			genericValues[canonical] = parsed
			genericFound = true
		}
	}
	values := genericValues
	for key, value := range dsfValues {
		values[key] = value
	}
	return values, dsfFound || genericFound, nil
}

func parseEnvValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	switch value[0] {
	case '\'':
		if len(value) < 2 || value[len(value)-1] != '\'' {
			return "", errors.New("unterminated quote")
		}
		return value[1 : len(value)-1], nil
	case '"':
		parsed, err := strconv.Unquote(value)
		if err != nil {
			return "", err
		}
		return parsed, nil
	default:
		return value, nil
	}
}

func envInt(values map[string]string, key string, fallback int) (int, error) {
	raw := strings.TrimSpace(values[key])
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s 必须是整数", key)
	}
	return value, nil
}

func firstNonEmpty(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func environmentVersion(cfg Config) string {
	safe := struct {
		Protocol  string
		BaseURL   string
		Model     string
		KeyDigest string
		Timeout   int
		Output    int
	}{
		Protocol: cfg.Protocol, BaseURL: cfg.BaseURL, Model: cfg.Model,
		KeyDigest: credentialDigest(cfg.APIKey), Timeout: cfg.TimeoutSeconds, Output: cfg.MaxOutputTokens,
	}
	raw, _ := json.Marshal(safe)
	sum := sha256.Sum256(raw)
	return "env-" + hex.EncodeToString(sum[:8])
}

func credentialDigest(secret string) string {
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("codexploit/environment-model-key\x00" + secret))
	return hex.EncodeToString(sum[:8])
}
