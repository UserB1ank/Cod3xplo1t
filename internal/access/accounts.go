// Package access manages a local administrator account and revocable sessions.
package access

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"
)

const SessionLifetime = 12 * time.Hour
const iterations = 600000

var (
	ErrInvalidCredentials = errors.New("账号或密码不正确")
	ErrAlreadyConfigured  = errors.New("管理员账号已创建，请登录")
	ErrRateLimited        = errors.New("登录尝试过于频繁，请稍后重试")
	usernamePattern       = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,64}$`)
)

type account struct {
	Username   string `json:"username"`
	Salt       []byte `json:"salt"`
	Hash       []byte `json:"password_hash"`
	Iterations int    `json:"iterations"`
}

type attempt struct {
	Count int
	Until time.Time
}
type session struct {
	Username string
	Until    time.Time
}

type Manager struct {
	mu       sync.Mutex
	file     string
	account  *account
	sessions map[[32]byte]session
	attempts map[string]attempt
	now      func() time.Time
}

func Open(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	m := &Manager{file: filepath.Join(dir, "account.json"), sessions: map[[32]byte]session{}, attempts: map[string]attempt{}, now: time.Now}
	raw, err := os.ReadFile(m.file)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	var value account
	if json.Unmarshal(raw, &value) != nil || !usernamePattern.MatchString(value.Username) || len(value.Salt) != 32 || len(value.Hash) != 32 || value.Iterations != iterations {
		return nil, errors.New("invalid account database; restore the data-volume backup")
	}
	m.account = &value
	return m, nil
}

func (m *Manager) Configured() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.account != nil }

func (m *Manager) limit(peer string) error {
	now := m.now()
	for key, value := range m.attempts {
		if !now.Before(value.Until) {
			delete(m.attempts, key)
		}
	}
	value, exists := m.attempts[peer]
	if !exists {
		if len(m.attempts) >= 256 {
			return ErrRateLimited
		}
		value.Until = now.Add(time.Minute)
	}
	if value.Count >= 5 {
		return ErrRateLimited
	}
	value.Count++
	m.attempts[peer] = value
	return nil
}

func (m *Manager) Setup(username, password, peer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.account != nil {
		return ErrAlreadyConfigured
	}
	if err := m.limit(peer); err != nil {
		return err
	}
	if !usernamePattern.MatchString(username) {
		return errors.New("账号需为 3–64 个字母、数字、下划线或连字符")
	}
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 || utf8.RuneCountInString(password) > 128 {
		return errors.New("密码长度需为 12–128 个字符")
	}
	value := account{Username: username, Salt: make([]byte, 32), Iterations: iterations}
	if _, err := rand.Read(value.Salt); err != nil {
		return err
	}
	var err error
	value.Hash, err = pbkdf2.Key(sha256.New, password, value.Salt, iterations, 32)
	if err != nil {
		return errors.New("无法生成密码摘要")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// Publish a complete file atomically, and refuse a second setup even from a
	// different process using the same volume.
	f, err := os.CreateTemp(filepath.Dir(m.file), ".account-*")
	if err != nil {
		return errors.New("无法写入账号配置，请检查数据卷")
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("无法保存账号配置")
	}
	if err := os.Link(f.Name(), m.file); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrAlreadyConfigured
		}
		return errors.New("无法保存账号配置")
	}
	m.account = &value
	return nil
}

func (m *Manager) Login(username, password, peer string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.limit(peer); err != nil {
		return "", err
	}
	if m.account == nil || len(password) > 512 {
		return "", ErrInvalidCredentials
	}
	value := m.account
	hash, err := pbkdf2.Key(sha256.New, password, value.Salt, value.Iterations, 32)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	match := subtle.ConstantTimeCompare(hash, value.Hash)
	if username != value.Username || match != 1 {
		return "", ErrInvalidCredentials
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("无法创建登录会话")
	}
	now := m.now()
	for digest, session := range m.sessions {
		if !now.Before(session.Until) {
			delete(m.sessions, digest)
		}
	}
	if len(m.sessions) >= 100 {
		return "", errors.New("登录会话数量已达上限，请先退出其他会话")
	}
	token := hex.EncodeToString(raw)
	m.sessions[sha256.Sum256([]byte(token))] = session{Username: username, Until: now.Add(SessionLifetime)}
	delete(m.attempts, peer)
	return token, nil
}

func (m *Manager) Authenticate(token string) (string, bool) {
	if m == nil || len(token) != 64 {
		return "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	digest := sha256.Sum256([]byte(token))
	session, ok := m.sessions[digest]
	if !ok {
		return "", false
	}
	if !m.now().Before(session.Until) {
		delete(m.sessions, digest)
		return "", false
	}
	return session.Username, true
}

func (m *Manager) Logout(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sha256.Sum256([]byte(token)))
}
