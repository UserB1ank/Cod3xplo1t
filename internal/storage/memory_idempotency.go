package storage

import (
	"context"
	"fmt"
	"time"
)

// idempotencyKey identifies a claimed key inside one store.
type idempotencyKey struct {
	scope string
	key   string
}

// ClaimIdempotent implements IdempotencyStore.
//
// The whole decision happens under one lock, so exactly one caller can receive
// ClaimNew for a key: concurrent retries see ClaimInProgress instead of running
// the same work twice.
func (m *Memory) ClaimIdempotent(_ context.Context, rec IdempotencyRecord) (IdempotencyClaim, error) {
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

	m.mu.Lock()
	defer m.mu.Unlock()
	id := idempotencyKey{scope: rec.Scope, key: rec.Key}
	if existing, ok := m.idempotency[id]; ok {
		if now.Before(existing.ExpiresAt) {
			switch {
			case existing.RequestHash != rec.RequestHash || existing.Principal != rec.Principal:
				// The stored body must not travel with a mismatch: a caller that
				// reused a key for a different request must never receive the
				// first caller's response.
				existing.Body = nil
				return IdempotencyClaim{State: ClaimMismatch, Record: existing}, nil
			case existing.InProgress():
				return IdempotencyClaim{State: ClaimInProgress, Record: existing}, nil
			default:
				return IdempotencyClaim{State: ClaimReplay, Record: existing}, nil
			}
		}
		delete(m.idempotency, id)
	}
	rec.Status = 0
	rec.Body = nil
	m.idempotency[id] = rec
	return IdempotencyClaim{State: ClaimNew, Record: rec}, nil
}

// CompleteIdempotent implements IdempotencyStore.
func (m *Memory) CompleteIdempotent(_ context.Context, scope, key string, status int, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := idempotencyKey{scope: scope, key: key}
	rec, ok := m.idempotency[id]
	if !ok {
		return fmt.Errorf("%w: idempotency key %s/%s", ErrNotFound, scope, key)
	}
	rec.Status = status
	rec.Body = append([]byte(nil), body...)
	m.idempotency[id] = rec
	return nil
}

// ReleaseIdempotent implements IdempotencyStore.
func (m *Memory) ReleaseIdempotent(_ context.Context, scope, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.idempotency, idempotencyKey{scope: scope, key: key})
	return nil
}

// PurgeExpiredIdempotency implements IdempotencyStore.
func (m *Memory) PurgeExpiredIdempotency(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for id, rec := range m.idempotency {
		if !now.Before(rec.ExpiresAt) {
			delete(m.idempotency, id)
			removed++
		}
	}
	return removed, nil
}
