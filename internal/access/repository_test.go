package access

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeIdentityRepository is an in-memory Repository. It exercises the manager's
// shared-store contract without importing a database adapter, so the access
// package stays independent from storage.
type fakeIdentityRepository struct {
	mu       sync.Mutex
	account  *Account
	sessions map[string]Session
	attempts map[string]fakeAttempt
	now      func() time.Time
	err      error
}

type fakeAttempt struct {
	count   int
	expires time.Time
}

func newFakeIdentityRepository() *fakeIdentityRepository {
	return &fakeIdentityRepository{sessions: map[string]Session{}, attempts: map[string]fakeAttempt{}, now: time.Now}
}

func (f *fakeIdentityRepository) LoadAccount(context.Context) (Account, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return Account{}, false, f.err
	}
	if f.account == nil {
		return Account{}, false, nil
	}
	return *f.account, true, nil
}

func (f *fakeIdentityRepository) CreateAccount(_ context.Context, value Account) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if f.account != nil {
		return ErrAlreadyConfigured
	}
	f.account = &value
	return nil
}

func (f *fakeIdentityRepository) CreateSession(_ context.Context, value Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	now := value.CreatedAt
	for key, session := range f.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(f.sessions, key)
		}
	}
	if len(f.sessions) >= 100 {
		return ErrTooManySessions
	}
	f.sessions[hex.EncodeToString(value.TokenHash)] = value
	return nil
}

func (f *fakeIdentityRepository) LoadSession(_ context.Context, hash []byte) (Session, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return Session{}, false, f.err
	}
	value, ok := f.sessions[hex.EncodeToString(hash)]
	return value, ok, nil
}

func (f *fakeIdentityRepository) DeleteSession(_ context.Context, hash []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	delete(f.sessions, hex.EncodeToString(hash))
	return nil
}

func (f *fakeIdentityRepository) AllowAttempt(_ context.Context, peer string, now time.Time) (bool, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, time.Time{}, f.err
	}
	value := f.attempts[peer]
	if !now.Before(value.expires) {
		value = fakeAttempt{expires: now.Add(time.Minute)}
	}
	value.count++
	f.attempts[peer] = value
	return value.count <= 5, value.expires, nil
}

func (f *fakeIdentityRepository) ResetAttempts(_ context.Context, peer string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	delete(f.attempts, peer)
	return nil
}

func openRepositoryManagers(t *testing.T) (*Manager, *Manager, *fakeIdentityRepository) {
	t.Helper()
	repo := newFakeIdentityRepository()
	first, err := OpenRepository(repo)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenRepository(repo)
	if err != nil {
		t.Fatal(err)
	}
	return first, second, repo
}

func TestRepositoryAccountSessionsRevocationAndExpiryAreShared(t *testing.T) {
	t.Parallel()
	first, second, repo := openRepositoryManagers(t)
	if configured, err := first.Configured(); err != nil || configured {
		t.Fatalf("fresh repository configured=%v err=%v", configured, err)
	}
	if err := first.Setup("fixture-admin", fixturePassword, "setup"); err != nil {
		t.Fatal(err)
	}
	if configured, err := second.Configured(); err != nil || !configured {
		t.Fatalf("second manager did not see the account: configured=%v err=%v", configured, err)
	}
	if err := second.Setup("fixture-admin", fixturePassword, "setup"); !errors.Is(err, ErrAlreadyConfigured) {
		t.Fatalf("second setup: %v", err)
	}
	token, err := second.Login("fixture-admin", fixturePassword, "login-peer")
	if err != nil {
		t.Fatal(err)
	}
	if user, ok, err := first.Authenticate(token); err != nil || !ok || user != "fixture-admin" {
		t.Fatalf("shared session: user=%q ok=%v err=%v", user, ok, err)
	}
	if err := first.Logout(token); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := second.Authenticate(token); err != nil || ok {
		t.Fatalf("logout did not revoke across managers: ok=%v err=%v", ok, err)
	}
	token, err = first.Login("fixture-admin", fixturePassword, "login-peer")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	first.now = func() time.Time { return now.Add(SessionLifetime + time.Second) }
	if _, ok, err := first.Authenticate(token); err != nil || ok {
		t.Fatalf("expired session accepted: ok=%v err=%v", ok, err)
	}
	_ = repo
}

func TestRepositoryRateLimitAndRepositoryErrorsAreShared(t *testing.T) {
	t.Parallel()
	first, second, repo := openRepositoryManagers(t)
	if err := first.Setup("fixture-admin", fixturePassword, "setup"); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		if _, err := first.Login("fixture-admin", "wrong-test-password", "shared-peer"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("first manager attempt %d: %v", attempt, err)
		}
	}
	for attempt := 4; attempt <= 5; attempt++ {
		if _, err := second.Login("fixture-admin", "wrong-test-password", "shared-peer"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("second manager attempt %d: %v", attempt, err)
		}
	}
	if _, err := first.Login("fixture-admin", fixturePassword, "shared-peer"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("shared rate limit: %v", err)
	}
	// A different peer has its own window.
	if _, err := second.Login("fixture-admin", "wrong-test-password", "other-peer"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("independent peer: %v", err)
	}
	// A successful login clears that peer's window.
	if err := repo.ResetAttempts(context.Background(), peerDigest("shared-peer")); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Login("fixture-admin", fixturePassword, "shared-peer"); err != nil {
		t.Fatalf("login after reset: %v", err)
	}

	repo.mu.Lock()
	repo.err = errors.New("database unavailable")
	repo.mu.Unlock()
	if _, err := first.Configured(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("configured error: %v", err)
	}
	if _, err := first.Login("fixture-admin", fixturePassword, "shared-peer"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("login error: %v", err)
	}
	if _, _, err := first.Authenticate("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("authenticate error: %v", err)
	}
	if err := first.Logout("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("logout error: %v", err)
	}
}

func TestLegacyWorkspaceAccountImportsIntoRepositoryOnce(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	legacy, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Setup("fixture-admin", fixturePassword, "setup"); err != nil {
		t.Fatal(err)
	}
	repo := newFakeIdentityRepository()
	imported, err := ImportLegacyAccount(dir, repo)
	if err != nil || !imported {
		t.Fatalf("import: imported=%v err=%v", imported, err)
	}
	if imported, err := ImportLegacyAccount(dir, repo); err != nil || imported {
		t.Fatalf("second import: imported=%v err=%v", imported, err)
	}
	shared, err := OpenRepository(repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shared.Login("fixture-admin", fixturePassword, "login-peer"); err != nil {
		t.Fatalf("imported login: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "account.json"), []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportLegacyAccount(dir, newFakeIdentityRepository()); err == nil {
		t.Fatal("invalid legacy account was imported")
	}
}
