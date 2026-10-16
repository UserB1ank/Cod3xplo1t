package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// idempotencyTimeLayout is the fixed-width UTC form used for created_at and
// expires_at. time.RFC3339Nano is not usable for these columns because it trims
// trailing zeros from the fraction, so "…:00.12Z" would sort after "…:00.123Z".
// Every value here has the same width, which makes the plain string comparisons
// in the queries below chronological.
const idempotencyTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

func formatIdempotencyTime(t time.Time) string { return t.UTC().Format(idempotencyTimeLayout) }

// rowQueryer is the read surface shared by *sql.DB and *sql.Tx, so the claim
// decision and the conflict re-read run the exact same statement.
type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ClaimIdempotent implements IdempotencyStore.
//
// The read-decide-write sequence runs inside one transaction and starts by
// deleting this key's expired row, so a claim never sees a dead entry and never
// confuses "expired" with "absent". Exactly one caller may receive ClaimNew:
// the writer that commits the INSERT owns the key, and every loser is answered
// from the committed row.
func (s *SQL) ClaimIdempotent(ctx context.Context, rec IdempotencyRecord) (IdempotencyClaim, error) {
	if rec.Scope == "" || rec.Key == "" {
		return IdempotencyClaim{}, fmt.Errorf("%w: scope and key are required", ErrConflict)
	}
	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	if rec.ExpiresAt.IsZero() {
		rec.ExpiresAt = now.Add(24 * time.Hour)
	}
	// rec.Status/rec.Body describe a response, which only CompleteIdempotent
	// may write; a fresh claim always starts empty.
	rec.Status = 0
	rec.Body = nil

	// A unique-key violation is not an error outcome here: it is the database
	// telling us that a concurrent claim committed between our SELECT and our
	// INSERT. Rerunning the transaction re-reads the winner's committed row and
	// reports its state, so the loser can never claim the key a second time. The
	// loop is bounded because a retry only loses to an already committed row; if
	// the row vanished in between it was released or expired, and winning the
	// key again is then the correct answer.
	const maxClaimAttempts = 5
	for attempt := 0; ; attempt++ {
		claim, err := s.claimIdempotentTx(ctx, rec, now)
		if err == nil {
			return claim, nil
		}
		if !errors.Is(err, ErrConflict) || attempt >= maxClaimAttempts-1 {
			return IdempotencyClaim{}, err
		}
	}
}

// claimIdempotentTx is one attempt at the claim decision. The transaction is
// rolled back on every return path except the successful INSERT: a row we found
// alive was not deleted, so there is nothing to persist for a replay.
func (s *SQL) claimIdempotentTx(ctx context.Context, rec IdempotencyRecord, now time.Time) (IdempotencyClaim, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IdempotencyClaim{}, mapSQLError(err)
	}
	defer tx.Rollback()

	// Deleting the expired row before reading means the decision below cannot
	// race a purge into treating an expired claim as live, and it matches the
	// memory store, which drops the expired entry before re-claiming the key.
	if _, err := tx.ExecContext(ctx, s.rebind(
		`DELETE FROM idempotency_keys WHERE scope = ? AND key = ? AND expires_at <= ?`),
		rec.Scope, rec.Key, formatIdempotencyTime(now)); err != nil {
		return IdempotencyClaim{}, mapSQLError(err)
	}

	stored, found, err := s.readIdempotencyRow(ctx, tx, rec.Scope, rec.Key)
	if err != nil {
		return IdempotencyClaim{}, err
	}
	if found {
		return decideClaim(stored, rec), nil
	}

	if _, err := tx.ExecContext(ctx, s.rebind(`
INSERT INTO idempotency_keys (scope, key, request_hash, principal, status, body, created_at, expires_at)
VALUES (?, ?, ?, ?, 0, '', ?, ?)`),
		rec.Scope, rec.Key, rec.RequestHash, rec.Principal,
		formatIdempotencyTime(rec.CreatedAt), formatIdempotencyTime(rec.ExpiresAt)); err != nil {
		return IdempotencyClaim{}, mapSQLError(err)
	}
	if err := tx.Commit(); err != nil {
		return IdempotencyClaim{}, mapSQLError(err)
	}
	return IdempotencyClaim{State: ClaimNew, Record: rec}, nil
}

// readIdempotencyRow loads one claim; found is false when the key is absent.
func (s *SQL) readIdempotencyRow(ctx context.Context, q rowQueryer, scope, key string) (IdempotencyRecord, bool, error) {
	var (
		rec                IdempotencyRecord
		body               string
		created, expiresAt string
	)
	err := q.QueryRowContext(ctx, s.rebind(`
SELECT scope, key, request_hash, principal, status, body, created_at, expires_at
FROM idempotency_keys WHERE scope = ? AND key = ?`), scope, key).
		Scan(&rec.Scope, &rec.Key, &rec.RequestHash, &rec.Principal, &rec.Status, &body, &created, &expiresAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return IdempotencyRecord{}, false, nil
	case err != nil:
		return IdempotencyRecord{}, false, mapSQLError(err)
	}
	rec.Body = []byte(body)
	rec.CreatedAt = parseStoredTime(created)
	rec.ExpiresAt = parseStoredTime(expiresAt)
	return rec, true, nil
}

// decideClaim maps a live stored row onto the claim vocabulary. The order is
// the contract: a key reused with a different payload or by a different
// principal is a mismatch even while the first request still runs, because
// answering it from that row would be worse than a conflict. The mismatch
// result drops the body, so a caller cannot turn it into a response; the
// in-progress and replay results are what the API is allowed to act on.
func decideClaim(stored, rec IdempotencyRecord) IdempotencyClaim {
	switch {
	case stored.RequestHash != rec.RequestHash || stored.Principal != rec.Principal:
		stored.Body = nil
		return IdempotencyClaim{State: ClaimMismatch, Record: stored}
	case stored.InProgress():
		return IdempotencyClaim{State: ClaimInProgress, Record: stored}
	default:
		return IdempotencyClaim{State: ClaimReplay, Record: stored}
	}
}

// CompleteIdempotent implements IdempotencyStore.
func (s *SQL) CompleteIdempotent(ctx context.Context, scope, key string, status int, body []byte) error {
	res, err := s.db.ExecContext(ctx, s.rebind(
		`UPDATE idempotency_keys SET status = ?, body = ? WHERE scope = ? AND key = ?`),
		status, string(body), scope, key)
	if err != nil {
		return mapSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return mapSQLError(err)
	}
	if affected == 0 {
		// A completion without a claim means the claim was released, purged or
		// never made; reporting it as success would hide a lost claim.
		return fmt.Errorf("%w: idempotency key %s/%s", ErrNotFound, scope, key)
	}
	return nil
}

// ReleaseIdempotent implements IdempotencyStore.
//
// Deleting an absent row is a success on purpose: a request that failed before
// it ever claimed the key, or that retried a release, must not fail its
// cleanup. The next claim of the key therefore returns ClaimNew again.
func (s *SQL) ReleaseIdempotent(ctx context.Context, scope, key string) error {
	if _, err := s.db.ExecContext(ctx, s.rebind(
		`DELETE FROM idempotency_keys WHERE scope = ? AND key = ?`), scope, key); err != nil {
		return mapSQLError(err)
	}
	return nil
}

// PurgeExpiredIdempotency implements IdempotencyStore.
func (s *SQL) PurgeExpiredIdempotency(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, s.rebind(
		`DELETE FROM idempotency_keys WHERE expires_at <= ?`), formatIdempotencyTime(now))
	if err != nil {
		return 0, mapSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, mapSQLError(err)
	}
	return int(affected), nil
}
