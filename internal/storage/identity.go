package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/access"
)

const (
	loginAttemptLimit  = 5
	loginAttemptWindow = time.Minute
	maxLoginSessions   = 100
)

// IdentityRepository returns the SQL identity store. The deployment profile
// decides whether it is used: PostgreSQL does, while SQLite and memory keep the
// existing workspace-file implementation.
func IdentityRepository(store Store) (access.Repository, bool) {
	s, ok := store.(*SQL)
	if !ok {
		return nil, false
	}
	return newSQLIdentity(s), true
}

type sqlIdentity struct{ s *SQL }

func newSQLIdentity(s *SQL) access.Repository { return sqlIdentity{s: s} }

func (r sqlIdentity) LoadAccount(ctx context.Context) (access.Account, bool, error) {
	var value access.Account
	err := r.s.db.QueryRowContext(ctx, `SELECT username, salt, password_hash, iterations FROM identity_account WHERE singleton = 1`).
		Scan(&value.Username, &value.Salt, &value.Hash, &value.Iterations)
	if errors.Is(err, sql.ErrNoRows) {
		return access.Account{}, false, nil
	}
	if err != nil {
		return access.Account{}, false, mapSQLError(err)
	}
	return value, true, nil
}

func (r sqlIdentity) CreateAccount(ctx context.Context, value access.Account) error {
	_, err := r.s.db.ExecContext(ctx, r.s.rebind(`INSERT INTO identity_account (singleton, username, salt, password_hash, iterations, created_at)
VALUES (1, ?, ?, ?, ?, ?)`),
		value.Username, value.Salt, value.Hash, value.Iterations, time.Now().UTC().UnixMilli())
	if err == nil {
		return nil
	}
	if mapped := mapSQLError(err); errors.Is(mapped, ErrConflict) {
		return access.ErrAlreadyConfigured
	}
	return fmt.Errorf("create identity account: %w", mapSQLError(err))
}

func (r sqlIdentity) CreateSession(ctx context.Context, value access.Session) error {
	tx, err := r.s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	now := value.CreatedAt.UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, r.s.rebind(`DELETE FROM identity_sessions WHERE expires_at <= ?`), now); err != nil {
		return mapSQLError(err)
	}
	var live int
	if err := tx.QueryRowContext(ctx, r.s.rebind(`SELECT COUNT(1) FROM identity_sessions WHERE expires_at > ?`), now).Scan(&live); err != nil {
		return mapSQLError(err)
	}
	if live >= maxLoginSessions {
		return access.ErrTooManySessions
	}
	if _, err := tx.ExecContext(ctx, r.s.rebind(`INSERT INTO identity_sessions (token_hash, username, created_at, expires_at)
VALUES (?, ?, ?, ?)`), value.TokenHash, value.Username, now, value.ExpiresAt.UTC().UnixMilli()); err != nil {
		return mapSQLError(err)
	}
	return mapSQLError(tx.Commit())
}

func (r sqlIdentity) LoadSession(ctx context.Context, tokenHash []byte) (access.Session, bool, error) {
	var value access.Session
	var created, expires int64
	err := r.s.db.QueryRowContext(ctx, r.s.rebind(`SELECT username, created_at, expires_at FROM identity_sessions WHERE token_hash = ?`), tokenHash).
		Scan(&value.Username, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return access.Session{}, false, nil
	}
	if err != nil {
		return access.Session{}, false, mapSQLError(err)
	}
	value.TokenHash = append([]byte(nil), tokenHash...)
	value.CreatedAt, value.ExpiresAt = time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC()
	return value, true, nil
}

func (r sqlIdentity) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := r.s.db.ExecContext(ctx, r.s.rebind(`DELETE FROM identity_sessions WHERE token_hash = ?`), tokenHash)
	return mapSQLError(err)
}

func (r sqlIdentity) AllowAttempt(ctx context.Context, peerHash string, now time.Time) (bool, time.Time, error) {
	now = now.UTC()
	nowMS, windowEnd := now.UnixMilli(), now.Add(loginAttemptWindow).UnixMilli()
	if _, err := r.s.db.ExecContext(ctx, r.s.rebind(`DELETE FROM identity_login_attempts WHERE expires_at <= ?`), nowMS); err != nil {
		return false, time.Time{}, fmt.Errorf("expire login attempts: %w", mapSQLError(err))
	}
	var count, expires int64
	// The upsert is one atomic statement: concurrent instances serialize on the
	// peer row, so the five-attempt ceiling holds across processes without an
	// application mutex. A successful login deletes the row instead.
	err := r.s.db.QueryRowContext(ctx, r.s.rebind(`INSERT INTO identity_login_attempts (peer_hash, count, window_started_at, expires_at)
VALUES (?, 1, ?, ?)
ON CONFLICT (peer_hash) DO UPDATE SET
    count = CASE WHEN identity_login_attempts.expires_at <= ? THEN 1 ELSE identity_login_attempts.count + 1 END,
    window_started_at = CASE WHEN identity_login_attempts.expires_at <= ? THEN ? ELSE identity_login_attempts.window_started_at END,
    expires_at = CASE WHEN identity_login_attempts.expires_at <= ? THEN ? ELSE identity_login_attempts.expires_at END
RETURNING count, expires_at`),
		peerHash, nowMS, windowEnd,
		nowMS, nowMS, nowMS, nowMS, windowEnd).Scan(&count, &expires)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("record login attempt: %w", mapSQLError(err))
	}
	return count <= loginAttemptLimit, time.UnixMilli(expires).UTC(), nil
}

func (r sqlIdentity) ResetAttempts(ctx context.Context, peerHash string) error {
	_, err := r.s.db.ExecContext(ctx, r.s.rebind(`DELETE FROM identity_login_attempts WHERE peer_hash = ?`), peerHash)
	if err != nil {
		return fmt.Errorf("reset login attempts: %w", mapSQLError(err))
	}
	return nil
}
