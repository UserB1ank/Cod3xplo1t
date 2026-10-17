// Package llm provides encrypted, live-reloadable model settings and bounded
// HTTP clients. It never returns credentials through the settings API.
package llm

import (
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
	"strings"
	"sync"
)

var (
	ErrNotConfigured = errors.New("LLM 尚未启用，请先在模型设置中保存配置")
	ErrConflict      = errors.New("模型设置已变更，请刷新后重试")
)

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

type Manager struct {
	mu      sync.RWMutex
	file    string
	aead    cipher.AEAD
	cfg     Config
	version string
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
	m := &Manager{file: filepath.Join(dir, "llm.enc"), aead: aead, version: "initial", cfg: Config{Protocol: "chat-completions", BaseURL: "https://api.openai.com/v1", TimeoutSeconds: 120, MaxOutputTokens: 4096}}
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
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte("codexploit/llm/v1"))
	if err != nil {
		return nil, errors.New("cannot decrypt LLM settings; restore the matching data-volume backup")
	}
	if err := json.Unmarshal(plain, &m.cfg); err != nil {
		return nil, errors.New("invalid LLM settings document")
	}
	m.version = versionOf(raw)
	return m, nil
}

func versionOf(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func (m *Manager) Public() Public {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.cfg
	return Public{c.Enabled, c.Protocol, c.BaseURL, c.Model, c.APIKey != "", c.TimeoutSeconds, c.MaxOutputTokens, m.version}
}

func (m *Manager) Current() (Config, error) {
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

func (m *Manager) candidate(u Update) (Config, error) {
	c := Config{Enabled: u.Enabled, Protocol: u.Protocol, BaseURL: u.BaseURL, Model: u.Model, APIKey: m.cfg.APIKey, TimeoutSeconds: u.TimeoutSeconds, MaxOutputTokens: u.MaxOutputTokens}
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
	if m.cfg.APIKey != "" && c.BaseURL != m.cfg.BaseURL && u.APIKey == nil && !u.ClearAPIKey {
		return c, errors.New("更换服务地址时请重新输入 API Key，或明确清除原 Key")
	}
	return c, nil
}

// Candidate supports testing an unsaved draft, with the same secret-retention
// and version rules as Save. No outbound call is made while holding the lock.
func (m *Manager) Candidate(u Update, version string) (Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if version != m.version {
		return Config{}, ErrConflict
	}
	return m.candidate(u)
}

func (m *Manager) Save(u Update, version string) (Public, error) {
	m.mu.Lock()
	if version != m.version {
		m.mu.Unlock()
		return Public{}, ErrConflict
	}
	c, err := m.candidate(u)
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
	raw := m.aead.Seal(nonce, nonce, plain, []byte("codexploit/llm/v1"))
	err = writeAtomic(m.file, raw)
	if err == nil {
		m.cfg, m.version = c, versionOf(raw)
	}
	m.mu.Unlock()
	if err != nil {
		return Public{}, errors.New("无法保存模型配置，请检查数据卷是否可写")
	}
	return m.Public(), nil
}

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
