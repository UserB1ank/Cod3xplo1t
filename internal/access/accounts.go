// Package access manages a local administrator account and revocable sessions.
package access

import (
	"context"
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
	// ErrUnavailable reports that the shared identity repository cannot be
	// reached. Callers must fail closed and expose an unavailable state instead
	// of treating the identity as absent or unauthenticated.
	ErrUnavailable  = errors.New("账号与会话存储暂不可用")
	usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,64}$`)
)

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
	repo     Repository
	account  *Account
	sessions map[[32]byte]session
	attempts map[string]attempt
	now      func() time.Time
}

// Open opens the workspace-file identity store used by SQLite and memory
// deployments. It keeps the existing account.json format and in-memory session
// behavior.
func Open(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	m := &Manager{file: filepath.Join(dir, "account.json"), sessions: map[[32]byte]session{}, attempts: map[string]attempt{}, now: time.Now}
	value, found, err := readAccountFile(m.file)
	if err != nil {
		return nil, err
	}
	if found {
		m.account = &value
	}
	return m, nil
}

func readAccountFile(name string) (Account, bool, error) {
	raw, err := os.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return Account{}, false, nil
	}
	if err != nil {
		return Account{}, false, err
	}
	var value Account
	if json.Unmarshal(raw, &value) != nil || !usernamePattern.MatchString(value.Username) || len(value.Salt) != 32 || len(value.Hash) != 32 || value.Iterations != iterations {
		return Account{}, false, errors.New("invalid account database; restore the data-volume backup")
	}
	return value, true, nil
}

// ImportLegacyAccount copies an existing workspace account into a shared
// repository exactly once. It lets a PostgreSQL deployment upgrade without
// silently reopening first-run setup, while a unique constraint keeps two
// instances starting at the same time from importing different accounts.
func ImportLegacyAccount(dir string, repo Repository) (bool, error) {
	if repo == nil {
		return false, errors.New("access: nil identity repository")
	}
	value, found, err := readAccountFile(filepath.Join(dir, "account.json"))
	if err != nil || !found {
		return false, err
	}
	ctx, cancel := identityContext()
	_, exists, err := repo.LoadAccount(ctx)
	cancel()
	if err != nil {
		return false, unavailable(err)
	}
	if exists {
		return false, nil
	}
	ctx, cancel = identityContext()
	defer cancel()
	if err := repo.CreateAccount(ctx, value); err != nil {
		if errors.Is(err, ErrAlreadyConfigured) {
			return false, nil
		}
		return false, unavailable(err)
	}
	return true, nil
}

// OpenRepository builds a manager over a shared identity repository. The
// repository owns the account, sessions, revocations and rate-limit windows, so
// two application instances observe the same login state.
func OpenRepository(repo Repository) (*Manager, error) {
	if repo == nil {
		return nil, errors.New("access: nil identity repository")
	}
	return &Manager{repo: repo, now: time.Now}, nil
}

func (m *Manager) configured() (bool, error) {
	if m.repo == nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.account != nil, nil
	}
	ctx, cancel := identityContext()
	defer cancel()
	_, found, err := m.repo.LoadAccount(ctx)
	if err != nil {
		return false, unavailable(err)
	}
	return found, nil
}

func (m *Manager) Configured() (bool, error) { return m.configured() }

func (m *Manager) nowTime() time.Time {
	if m.now == nil {
		return time.Now()
	}
	return m.now()
}

func (m *Manager) limit(peer string) error {
	now := m.nowTime()
	if m.repo != nil {
		ctx, cancel := identityContext()
		defer cancel()
		allowed, _, err := m.repo.AllowAttempt(ctx, peerDigest(peer), now)
		if err != nil {
			return unavailable(err)
		}
		if !allowed {
			return ErrRateLimited
		}
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
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

func (m *Manager) resetAttempts(peer string) {
	if m.repo == nil {
		m.mu.Lock()
		delete(m.attempts, peer)
		m.mu.Unlock()
		return
	}
	ctx, cancel := identityContext()
	defer cancel()
	_ = m.repo.ResetAttempts(ctx, peerDigest(peer))
}

func (m *Manager) Setup(username, password, peer string) error {
	if m.repo == nil {
		m.mu.Lock()
		configured := m.account != nil
		m.mu.Unlock()
		if configured {
			return ErrAlreadyConfigured
		}
		if err := m.limit(peer); err != nil {
			return err
		}
		value, err := newAccount(username, password)
		if err != nil {
			return err
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.account != nil {
			return ErrAlreadyConfigured
		}
		return m.writeAccount(value)
	}

	ctx, cancel := identityContext()
	_, found, err := m.repo.LoadAccount(ctx)
	cancel()
	if err != nil {
		return unavailable(err)
	}
	if found {
		return ErrAlreadyConfigured
	}
	if err := m.limit(peer); err != nil {
		return err
	}
	value, err := newAccount(username, password)
	if err != nil {
		return err
	}
	ctx, cancel = identityContext()
	defer cancel()
	if err := m.repo.CreateAccount(ctx, value); err != nil {
		if errors.Is(err, ErrAlreadyConfigured) {
			return ErrAlreadyConfigured
		}
		if errors.Is(err, ErrTooManySessions) {
			return err
		}
		return unavailable(err)
	}
	m.resetAttempts(peer)
	return nil
}

func newAccount(username, password string) (Account, error) {
	if !usernamePattern.MatchString(username) {
		return Account{}, errors.New("账号需为 3–64 个字母、数字、下划线或连字符")
	}
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 || utf8.RuneCountInString(password) > 128 {
		return Account{}, errors.New("密码长度需为 12–128 个字符")
	}
	value := Account{Username: username, Salt: make([]byte, 32), Iterations: iterations}
	if _, err := rand.Read(value.Salt); err != nil {
		return Account{}, err
	}
	var err error
	value.Hash, err = pbkdf2.Key(sha256.New, password, value.Salt, iterations, 32)
	if err != nil {
		return Account{}, errors.New("无法生成密码摘要")
	}
	return value, nil
}

func (m *Manager) writeAccount(value Account) error {
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
	if err := m.limit(peer); err != nil {
		return "", err
	}
	var value *Account
	if m.repo != nil {
		ctx, cancel := identityContext()
		loaded, found, err := m.repo.LoadAccount(ctx)
		cancel()
		if err != nil {
			return "", unavailable(err)
		}
		if found {
			value = &loaded
		}
	} else {
		m.mu.Lock()
		if m.account != nil {
			copy := *m.account
			value = &copy
		}
		m.mu.Unlock()
	}
	if value == nil || len(password) > 512 {
		return "", ErrInvalidCredentials
	}
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
	now := m.nowTime()
	token := hex.EncodeToString(raw)
	if m.repo != nil {
		digest := sha256.Sum256([]byte(token))
		ctx, cancel := identityContext()
		err := m.repo.CreateSession(ctx, Session{TokenHash: digest[:], Username: username, CreatedAt: now, ExpiresAt: now.Add(SessionLifetime)})
		cancel()
		if err != nil {
			if errors.Is(err, ErrTooManySessions) {
				return "", err
			}
			return "", unavailable(err)
		}
		m.resetAttempts(peer)
		return token, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for digest, session := range m.sessions {
		if !now.Before(session.Until) {
			delete(m.sessions, digest)
		}
	}
	if len(m.sessions) >= 100 {
		return "", ErrTooManySessions
	}
	m.sessions[sha256.Sum256([]byte(token))] = session{Username: username, Until: now.Add(SessionLifetime)}
	delete(m.attempts, peer)
	return token, nil
}

func (m *Manager) Authenticate(token string) (string, bool, error) {
	if m == nil || len(token) != 64 {
		return "", false, nil
	}
	digest := sha256.Sum256([]byte(token))
	if m.repo != nil {
		ctx, cancel := identityContext()
		session, found, err := m.repo.LoadSession(ctx, digest[:])
		cancel()
		if err != nil {
			return "", false, unavailable(err)
		}
		if !found {
			return "", false, nil
		}
		if !m.nowTime().Before(session.ExpiresAt) {
			ctx, cancel := identityContext()
			_ = m.repo.DeleteSession(ctx, digest[:])
			cancel()
			return "", false, nil
		}
		return session.Username, true, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[digest]
	if !ok {
		return "", false, nil
	}
	if !m.nowTime().Before(session.Until) {
		delete(m.sessions, digest)
		return "", false, nil
	}
	return session.Username, true, nil
}

func (m *Manager) Logout(token string) error {
	if len(token) != 64 {
		return nil
	}
	digest := sha256.Sum256([]byte(token))
	if m.repo != nil {
		ctx, cancel := identityContext()
		defer cancel()
		if err := m.repo.DeleteSession(ctx, digest[:]); err != nil {
			return unavailable(err)
		}
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, digest)
	return nil
}

func peerDigest(peer string) string {
	sum := sha256.Sum256([]byte(peer))
	return hex.EncodeToString(sum[:])
}

func identityContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func unavailable(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return err
	}
	return errors.Join(ErrUnavailable, err)
}
