package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/access"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func openIdentitySQL(t *testing.T) (*SQL, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.db")
	s, err := OpenSQL(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.EnsureSchema(context.Background(), migrations.FS); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestSQLIdentityRepositoryPersistsAccountSessionsAndRateLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, path := openIdentitySQL(t)
	repo := newSQLIdentity(s)
	salt, hash := make([]byte, 32), make([]byte, 32)
	for i := range salt {
		salt[i], hash[i] = byte(i), byte(255-i)
	}
	account := access.Account{Username: "fixture-admin", Salt: salt, Hash: hash, Iterations: 600000}
	if err := repo.CreateAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateAccount(ctx, account); !errors.Is(err, access.ErrAlreadyConfigured) {
		t.Fatalf("second account: %v", err)
	}
	loaded, found, err := repo.LoadAccount(ctx)
	if err != nil || !found || loaded.Username != account.Username || string(loaded.Salt) != string(salt) || string(loaded.Hash) != string(hash) || loaded.Iterations != 600000 {
		t.Fatalf("account round trip: %+v found=%v err=%v", loaded, found, err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	tokenHash := sha256.Sum256([]byte("fixture-session-token"))
	session := access.Session{TokenHash: tokenHash[:], Username: account.Username, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := repo.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	second, err := OpenSQL(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	other := newSQLIdentity(second)
	got, found, err := other.LoadSession(ctx, tokenHash[:])
	if err != nil || !found || got.Username != account.Username || !got.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatalf("shared session: %+v found=%v err=%v", got, found, err)
	}
	if err := other.DeleteSession(ctx, tokenHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, found, err := repo.LoadSession(ctx, tokenHash[:]); err != nil || found {
		t.Fatalf("revoked session still found=%v err=%v", found, err)
	}

	const peer = "hashed-peer"
	for attempt := 1; attempt <= 5; attempt++ {
		allowed, _, err := repo.AllowAttempt(ctx, peer, now)
		if err != nil || !allowed {
			t.Fatalf("attempt %d allowed=%v err=%v", attempt, allowed, err)
		}
	}
	allowed, retryAt, err := repo.AllowAttempt(ctx, peer, now)
	if err != nil || allowed || retryAt.Before(now.Add(50*time.Second)) {
		t.Fatalf("rate limit: allowed=%v retry=%v err=%v", allowed, retryAt, err)
	}
	if err := other.ResetAttempts(ctx, peer); err != nil {
		t.Fatal(err)
	}
	if allowed, _, err := repo.AllowAttempt(ctx, peer, now); err != nil || !allowed {
		t.Fatalf("reset attempts: allowed=%v err=%v", allowed, err)
	}
	// A new window starts after the previous one expires.
	if allowed, _, err := other.AllowAttempt(ctx, peer, now.Add(2*time.Minute)); err != nil || !allowed {
		t.Fatalf("expired window: allowed=%v err=%v", allowed, err)
	}
}
