package storage

import (
	"context"
	"time"
)

// ClaimState is the outcome of trying to claim an idempotency key.
type ClaimState string

const (
	// ClaimNew means the caller owns the key and must execute the request.
	ClaimNew ClaimState = "new"
	// ClaimReplay means a completed response is stored and must be replayed.
	ClaimReplay ClaimState = "replay"
	// ClaimInProgress means another request with the same key is running.
	ClaimInProgress ClaimState = "in_progress"
	// ClaimMismatch means the key was used before with a different request (or a
	// different principal), which must not be answered with the stored result.
	ClaimMismatch ClaimState = "mismatch"
)

// IdempotencyRecord is one claimed key.
type IdempotencyRecord struct {
	// Scope is the operation identity, typically "METHOD /path".
	Scope string
	// Key is the client supplied Idempotency-Key.
	Key string
	// RequestHash fingerprints the request body. Replaying a key with a different
	// body is a client bug and must not silently return the first answer.
	RequestHash string
	// Principal is the authenticated caller. Two callers must not share a stored
	// response, so a different principal is a mismatch.
	Principal string
	// Status is the stored HTTP status; 0 means the claim is still in progress.
	Status int
	// Body is the stored response body.
	Body []byte
	// CreatedAt and ExpiresAt bound the record's life.
	CreatedAt time.Time
	ExpiresAt time.Time
}

// InProgress reports whether the record is a claim without a response yet.
func (r IdempotencyRecord) InProgress() bool { return r.Status == 0 }

// IdempotencyClaim is what a store returns when a key is claimed.
type IdempotencyClaim struct {
	State  ClaimState
	Record IdempotencyRecord
}

// IdempotencyStore makes write idempotency durable, so a client that retries
// after a restart, a crash or a load-balancer hop still gets the first answer
// instead of doing the work twice.
//
// Implementations must be safe under concurrent claims: exactly one caller may
// receive ClaimNew for a (scope, key) pair, and every other caller must receive
// ClaimInProgress, ClaimReplay or ClaimMismatch.
type IdempotencyStore interface {
	// ClaimIdempotent attempts to own a key. rec.Status and rec.Body are ignored:
	// they are filled in by CompleteIdempotent.
	ClaimIdempotent(ctx context.Context, rec IdempotencyRecord) (IdempotencyClaim, error)
	// CompleteIdempotent stores the response of a claimed key.
	CompleteIdempotent(ctx context.Context, scope, key string, status int, body []byte) error
	// ReleaseIdempotent drops a claim whose request failed, so the client can
	// retry the same key instead of being stuck with a permanently in-progress
	// entry.
	ReleaseIdempotent(ctx context.Context, scope, key string) error
	// PurgeExpiredIdempotency removes expired records and reports how many went.
	PurgeExpiredIdempotency(ctx context.Context, now time.Time) (int, error)
}
