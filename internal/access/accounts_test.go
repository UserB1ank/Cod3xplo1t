package access

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fixturePassword = "test-only-password-for-local-fixture"

func TestAccountPersistenceAndRevocableExpiringSessions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Configured() {
		t.Fatal("new installation unexpectedly configured")
	}
	if err := m.Setup("testadmin", fixturePassword, "fixture"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "account.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(fixturePassword)) {
		t.Fatal("plaintext password persisted")
	}
	if err := m.Setup("otheradmin", fixturePassword, "fixture"); !errors.Is(err, ErrAlreadyConfigured) {
		t.Fatal("setup replaced an existing account", err)
	}
	m, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Login("testadmin", "wrong-test-password", "fixture"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("incorrect password accepted")
	}
	if _, err := m.Login("otheradmin", fixturePassword, "fixture"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("incorrect account accepted")
	}
	token, err := m.Login("testadmin", fixturePassword, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if user, ok := m.Authenticate(token); !ok || user != "testadmin" {
		t.Fatal("session not authenticated")
	}
	m.Logout(token)
	if _, ok := m.Authenticate(token); ok {
		t.Fatal("logout did not revoke session")
	}
	now := time.Now()
	m.now = func() time.Time { return now }
	token, err = m.Login("testadmin", fixturePassword, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(SessionLifetime + time.Second)
	if _, ok := m.Authenticate(token); ok {
		t.Fatal("expired session accepted")
	}
}

func TestSetupIsExclusiveAndLoginIsRateLimited(t *testing.T) {
	t.Parallel()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Setup("testadmin", fixturePassword, "setup"); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrAlreadyConfigured) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("parallel setup created multiple accounts")
	}
	for range 5 {
		_, _ = m.Login("testadmin", "wrong-test-password", "rate-test")
	}
	if _, err := m.Login("testadmin", fixturePassword, "rate-test"); !errors.Is(err, ErrRateLimited) {
		t.Fatal("brute-force limit not enforced", err)
	}
}
