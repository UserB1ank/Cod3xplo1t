// Package llm provides encrypted, live-reloadable model settings and bounded
// HTTP clients. It never returns credentials through the settings API.
package llm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotConfigured = errors.New("LLM 尚未启用，请先在模型设置中保存配置")
	ErrConflict      = errors.New("模型设置已变更，请刷新后重试")
	// ErrKeyUnavailable reports that the independent installation key was not
	// supplied or cannot be used. Saved ciphertext is never reset or replaced.
	ErrKeyUnavailable = errors.New("模型设置不可用：缺少有效的安装加密密钥")
	// ErrDecrypt reports that the saved ciphertext does not match the supplied
	// installation key, or that its plaintext is invalid.
	ErrDecrypt = errors.New("模型设置不可用：无法使用当前安装密钥解密已保存设置")
	// ErrRepositoryUnavailable reports that the shared settings store cannot be
	// reached.
	ErrRepositoryUnavailable = errors.New("模型设置暂不可用：共享设置存储不可达")
)

// Repository stores encrypted model settings and their effective configuration
// version in a shared database. Implementations must apply expectedVersion as a
// compare-and-swap: saved is false when another writer won.
type Repository interface {
	LoadLLMSettings(ctx context.Context) (ciphertext []byte, version int64, found bool, err error)
	SaveLLMSettings(ctx context.Context, ciphertext []byte, expectedVersion int64) (version int64, saved bool, err error)
}

// Config is server-only. Never include it in logs or API responses.
type Config struct {
	Enabled         bool   `json:"enabled"`
	Protocol        string `json:"protocol"`
	BaseURL         string `json:"base_url"`
	Model           string `json:"model"`
	APIKey          string `json:"api_key"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	MaxOutputTokens int    `json:"max_output_tokens"`
}

type Public struct {
	Enabled          bool   `json:"enabled"`
	Protocol         string `json:"protocol"`
	BaseURL          string `json:"base_url"`
	Model            string `json:"model"`
	APIKeyConfigured bool   `json:"api_key_configured"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	MaxOutputTokens  int    `json:"max_output_tokens"`
	Version          string `json:"version"`
}

// Update distinguishes retaining a secret from replacing or deleting it.
type Update struct {
	Enabled         bool    `json:"enabled"`
	Protocol        string  `json:"protocol"`
	BaseURL         string  `json:"base_url"`
	Model           string  `json:"model"`
	APIKey          *string `json:"api_key,omitempty"`
	ClearAPIKey     bool    `json:"clear_api_key"`
	TimeoutSeconds  int     `json:"timeout_seconds"`
	MaxOutputTokens int     `json:"max_output_tokens"`
}

const settingsAAD = "codexploit/llm/v1"

type Manager struct {
	mu          sync.RWMutex
	file        string
	repo        Repository
	aead        cipher.AEAD
	unavailable error
	cfg         Config
	version     string
}

func defaultConfig() Config {
	return Config{Protocol: "chat-completions", BaseURL: "https://api.openai.com/v1", TimeoutSeconds: 120, MaxOutputTokens: 4096}
}

// Open keeps ciphertext and the installation encryption key in the persistent
// workspace, with owner-only permissions. Missing keys never reset saved data.
func Open(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	keyFile := filepath.Join(dir, "settings.key")
	key, err := os.ReadFile(keyFile)
	if errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Stat(filepath.Join(dir, "llm.enc")); !errors.Is(statErr, os.ErrNotExist) {
			return nil, errors.New("LLM settings encryption key is missing; restore it from the data-volume backup")
		}
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		f, createErr := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return nil, createErr
		}
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	} else if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("invalid settings encryption key")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	m := &Manager{file: filepath.Join(dir, "llm.enc"), aead: aead, version: "initial", cfg: defaultConfig()}
	raw, err := os.ReadFile(m.file)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize() {
		return nil, errors.New("invalid encrypted LLM settings")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(settingsAAD))
	if err != nil {
		return nil, errors.New("cannot decrypt LLM settings; restore the matching data-volume backup")
	}
	if err := json.Unmarshal(plain, &m.cfg); err != nil {
		return nil, errors.New("invalid LLM settings document")
	}
	m.version = versionOf(raw)
	return m, nil
}

// NewRepository builds a manager over a shared settings repository. The
// installation key comes from an independent deployment secret.
func NewRepository(repo Repository, key []byte) (*Manager, error) {
	if repo == nil {
		return nil, errors.New("llm: nil settings repository")
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Manager{repo: repo, aead: aead, version: "0", cfg: defaultConfig()}, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrKeyUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	return cipher.NewGCM(block)
}

// ImportLegacySettings re-encrypts a workspace settings document into a shared
// repository with the independent installation key. It is a one-time upgrade
// path: an existing row is never overwritten and the legacy files are left
// untouched for the operator to archive.
func ImportLegacySettings(ctx context.Context, repo Repository, dir string, key []byte) (bool, error) {
	if repo == nil {
		return false, errors.New("llm: nil settings repository")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	target, err := newAEAD(key)
	if err != nil {
		return false, err
	}
	if _, _, found, err := repo.LoadLLMSettings(ctx); err != nil {
		return false, err
	} else if found {
		return false, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, "llm.enc"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read legacy model settings: %w", err)
	}
	legacyKey, err := os.ReadFile(filepath.Join(dir, "settings.key"))
	if err != nil {
		return false, fmt.Errorf("read legacy settings key: %w", err)
	}
	legacy, err := newAEAD(legacyKey)
	if err != nil {
		return false, errors.New("legacy settings key is invalid")
	}
	if len(raw) < legacy.NonceSize() {
		return false, errors.New("legacy model settings are invalid")
	}
	plain, err := legacy.Open(nil, raw[:legacy.NonceSize()], raw[legacy.NonceSize():], []byte(settingsAAD))
	if err != nil {
		return false, errors.New("cannot decrypt legacy model settings")
	}
	var cfg Config
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return false, errors.New("invalid legacy model settings document")
	}
	document, err := json.Marshal(cfg)
	if err != nil {
		return false, err
	}
	nonce := make([]byte, target.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return false, err
	}
	ciphertext := target.Seal(nonce, nonce, document, []byte(settingsAAD))
	_, saved, err := repo.SaveLLMSettings(ctx, ciphertext, 0)
	if err != nil {
		return false, err
	}
	return saved, nil
}

// NewUnavailableRepository keeps the settings surface honest when the
// installation key is missing or invalid: reads and writes report unavailable
// instead of silently regenerating a key or resetting saved ciphertext.
func NewUnavailableRepository(repo Repository, reason error) *Manager {
	if reason == nil {
		reason = ErrKeyUnavailable
	}
	return &Manager{repo: repo, unavailable: reason, version: "0", cfg: defaultConfig()}
}

// LoadInstallationKey reads a 32-byte key, either raw or as 64 hex characters.
// The file is a deployment secret supplied independently of the database.
func LoadInstallationKey(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: 未提供 --settings-key-file", ErrKeyUnavailable)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法读取安装密钥文件", ErrKeyUnavailable)
	}
	value := strings.TrimSpace(string(raw))
	if len(value) == 64 {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("%w: 安装密钥不是有效的十六进制", ErrKeyUnavailable)
		}
		return decoded, nil
	}
	if len(raw) == 32 {
		return append([]byte(nil), raw...), nil
	}
	return nil, fmt.Errorf("%w: 安装密钥必须为 32 字节或 64 位十六进制", ErrKeyUnavailable)
}

// Unavailable reports why settings cannot be used, or nil when they are usable.
func (m *Manager) Unavailable() error {
	if m == nil {
		return ErrNotConfigured
	}
	return m.unavailable
}

func versionString(version int64) string { return strconv.FormatInt(version, 10) }

func publicOf(c Config, version string) Public {
	return Public{c.Enabled, c.Protocol, c.BaseURL, c.Model, c.APIKey != "", c.TimeoutSeconds, c.MaxOutputTokens, version}
}

// loadRepository returns the stored configuration and its effective version.
// A missing row is the default, unsaved configuration at version zero.
func (m *Manager) loadRepository() (Config, int64, error) {
	if m.repo == nil || m.aead == nil {
		return Config{}, 0, ErrKeyUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ciphertext, version, found, err := m.repo.LoadLLMSettings(ctx)
	cancel()
	if err != nil {
		return Config{}, 0, fmt.Errorf("%w: %v", ErrRepositoryUnavailable, err)
	}
	if !found {
		return defaultConfig(), 0, nil
	}
	if len(ciphertext) < m.aead.NonceSize() {
		return Config{}, 0, ErrDecrypt
	}
	plain, err := m.aead.Open(nil, ciphertext[:m.aead.NonceSize()], ciphertext[m.aead.NonceSize():], []byte(settingsAAD))
	if err != nil {
		return Config{}, 0, ErrDecrypt
	}
	var cfg Config
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return Config{}, 0, ErrDecrypt
	}
	return cfg, version, nil
}

func (m *Manager) Public() (Public, error) {
	if m.unavailable != nil {
		return Public{}, m.unavailable
	}
	if m.repo != nil {
		cfg, version, err := m.loadRepository()
		if err != nil {
			return Public{}, err
		}
		return publicOf(cfg, versionString(version)), nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return publicOf(m.cfg, m.version), nil
}

func (m *Manager) Current() (Config, error) {
	if m.unavailable != nil {
		return Config{}, m.unavailable
	}
	if m.repo != nil {
		cfg, _, err := m.loadRepository()
		if err != nil {
			return Config{}, err
		}
		if !cfg.Enabled || cfg.Model == "" {
			return Config{}, ErrNotConfigured
		}
		return cfg, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.cfg.Enabled || m.cfg.Model == "" {
		return Config{}, ErrNotConfigured
	}
	return m.cfg, nil
}

func normalize(c Config) (Config, error) {
	c.BaseURL, c.Model = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/"), strings.TrimSpace(c.Model)
	if c.Protocol != "chat-completions" && c.Protocol != "responses" {
		return c, errors.New("protocol 必须为 chat-completions 或 responses")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return c, errors.New("服务 Base URL 必须是无凭据和查询参数的 HTTP(S) 地址")
	}
	if len(c.BaseURL) > 2048 || len(c.Model) > 200 || strings.ContainsAny(c.Model, "\r\n") || (c.Enabled && c.Model == "") {
		return c, errors.New("请填写有效的模型名称和服务地址")
	}
	if len(c.APIKey) > 8192 || strings.ContainsAny(c.APIKey, "\r\n") {
		return c, errors.New("API Key 格式无效")
	}
	if c.TimeoutSeconds < 5 || c.TimeoutSeconds > 600 || c.MaxOutputTokens < 256 || c.MaxOutputTokens > 32768 {
		return c, errors.New("超时应为 5–600 秒，输出上限应为 256–32768 tokens")
	}
	return c, nil
}

func (m *Manager) candidateFrom(current Config, u Update) (Config, error) {
	c := Config{Enabled: u.Enabled, Protocol: u.Protocol, BaseURL: u.BaseURL, Model: u.Model, APIKey: current.APIKey, TimeoutSeconds: u.TimeoutSeconds, MaxOutputTokens: u.MaxOutputTokens}
	if u.APIKey != nil && u.ClearAPIKey {
		return c, errors.New("不能同时设置和清除 API Key")
	}
	if u.APIKey != nil {
		c.APIKey = strings.TrimSpace(*u.APIKey)
	}
	if u.ClearAPIKey {
		c.APIKey = ""
	}
	var err error
	c, err = normalize(c)
	if err != nil {
		return c, err
	}
	if current.APIKey != "" && c.BaseURL != current.BaseURL && u.APIKey == nil && !u.ClearAPIKey {
		return c, errors.New("更换服务地址时请重新输入 API Key，或明确清除原 Key")
	}
	return c, nil
}

// Candidate supports testing an unsaved draft, with the same secret-retention
// and version rules as Save. No outbound call is made while holding the lock.
func (m *Manager) Candidate(u Update, version string) (Config, error) {
	if m.unavailable != nil {
		return Config{}, m.unavailable
	}
	if m.repo != nil {
		current, currentVersion, err := m.loadRepository()
		if err != nil {
			return Config{}, err
		}
		if version != versionString(currentVersion) {
			return Config{}, ErrConflict
		}
		return m.candidateFrom(current, u)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if version != m.version {
		return Config{}, ErrConflict
	}
	return m.candidateFrom(m.cfg, u)
}

func (m *Manager) Save(u Update, version string) (Public, error) {
	if m.unavailable != nil {
		return Public{}, m.unavailable
	}
	if m.repo != nil {
		current, currentVersion, err := m.loadRepository()
		if err != nil {
			return Public{}, err
		}
		if version != versionString(currentVersion) {
			return Public{}, ErrConflict
		}
		c, err := m.candidateFrom(current, u)
		if err != nil {
			return Public{}, err
		}
		plain, err := json.Marshal(c)
		if err != nil {
			return Public{}, err
		}
		nonce := make([]byte, m.aead.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			return Public{}, err
		}
		ciphertext := m.aead.Seal(nonce, nonce, plain, []byte(settingsAAD))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		savedVersion, saved, err := m.repo.SaveLLMSettings(ctx, ciphertext, currentVersion)
		cancel()
		if err != nil {
			return Public{}, fmt.Errorf("%w: %v", ErrRepositoryUnavailable, err)
		}
		if !saved {
			return Public{}, ErrConflict
		}
		return publicOf(c, versionString(savedVersion)), nil
	}

	m.mu.Lock()
	if version != m.version {
		m.mu.Unlock()
		return Public{}, ErrConflict
	}
	c, err := m.candidateFrom(m.cfg, u)
	if err != nil {
		m.mu.Unlock()
		return Public{}, err
	}
	plain, err := json.Marshal(c)
	if err != nil {
		m.mu.Unlock()
		return Public{}, err
	}
	nonce := make([]byte, m.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		m.mu.Unlock()
		return Public{}, err
	}
	raw := m.aead.Seal(nonce, nonce, plain, []byte(settingsAAD))
	err = writeAtomic(m.file, raw)
	if err == nil {
		m.cfg, m.version = c, versionOf(raw)
	}
	m.mu.Unlock()
	if err != nil {
		return Public{}, errors.New("无法保存模型配置，请检查数据卷是否可写")
	}
	return publicOf(c, m.version), nil
}

func versionOf(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func writeAtomic(name string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(name), ".settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), name); err != nil {
		return fmt.Errorf("replace settings: %w", err)
	}
	return nil
}

// Snapshot atomically captures a configuration and its public version for one run.
func (m *Manager) Snapshot() (Config, Public, error) {
	if m.unavailable != nil {
		return Config{}, Public{}, m.unavailable
	}
	if m.repo != nil {
		cfg, version, err := m.loadRepository()
		if err != nil {
			return Config{}, Public{}, err
		}
		if !cfg.Enabled || cfg.Model == "" {
			return Config{}, Public{}, ErrNotConfigured
		}
		return cfg, publicOf(cfg, versionString(version)), nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.cfg
	if !c.Enabled || c.Model == "" {
		return Config{}, Public{}, ErrNotConfigured
	}
	return c, publicOf(c, m.version), nil
}
