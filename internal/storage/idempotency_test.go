package storage

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/migrations"

	_ "modernc.org/sqlite"
)

// idempotencyRecord builds a claim request with the fields a transport layer
// would supply: the operation scope, the client key and the caller identity.
func idempotencyRecord(scope, key, hash, principal string) IdempotencyRecord {
	return IdempotencyRecord{Scope: scope, Key: key, RequestHash: hash, Principal: principal}
}

// idempotencyCase is one store-independent scenario of the shared suite.
type idempotencyCase struct {
	name string
	run  func(t *testing.T, s FullStore)
}

// TestIdempotencyStore runs every scenario against the in-memory store and the
// SQL store, so the two implementations cannot drift apart. Each scenario uses
// its own scope/key pair, which lets the subtests of one store share a single
// database without interfering.
func TestIdempotencyStore(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, c := range idempotencyCases() {
				t.Run(c.name, func(t *testing.T) {
					c.run(t, tc.store)
				})
			}
		})
	}
}

func idempotencyCases() []idempotencyCase {
	return []idempotencyCase{
		{"claim_new", idempotencyClaimNew},
		{"replay_after_complete", idempotencyReplayAfterComplete},
		{"mismatch_request_hash", idempotencyMismatchRequestHash},
		{"mismatch_principal", idempotencyMismatchPrincipal},
		{"second_claim_in_progress", idempotencySecondClaimInProgress},
		{"release_allows_reclaim", idempotencyReleaseAllowsReclaim},
		{"complete_unknown_not_found", idempotencyCompleteUnknown},
		{"expired_record_is_absent", idempotencyExpiredRecord},
		{"concurrent_claims", idempotencyConcurrentClaims},
	}
}

// idempotencyClaimNew checks that a first claim owns the key without storing a
// response: storing one now would let a retry replay a response that was never
// produced.
func idempotencyClaimNew(t *testing.T, s FullStore) {
	t.Helper()
	ctx := context.Background()
	claim, err := s.ClaimIdempotent(ctx, idempotencyRecord("POST /v1/claim", "key-new", "hash-a", "token-a"))
	if err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if claim.State != ClaimNew {
		t.Fatalf("state = %q, want %q", claim.State, ClaimNew)
	}
	if !claim.Record.InProgress() {
		t.Fatalf("status = %d, want an in-progress claim", claim.Record.Status)
	}
	if len(claim.Record.Body) != 0 {
		t.Fatalf("a fresh claim returned body %q, want nothing stored yet", claim.Record.Body)
	}
	if claim.Record.CreatedAt.IsZero() || claim.Record.ExpiresAt.IsZero() {
		t.Fatalf("claim timestamps were not defaulted: %+v", claim.Record)
	}
}

// idempotencyReplayAfterComplete is the point of the whole store: the second
// caller gets the first answer instead of running the work again.
func idempotencyReplayAfterComplete(t *testing.T, s FullStore) {
	t.Helper()
	ctx := context.Background()
	rec := idempotencyRecord("POST /v1/replay", "key-replay", "hash-a", "token-a")
	if _, err := s.ClaimIdempotent(ctx, rec); err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	body := []byte(`{"analysis_id":"an-1"}`)
	if err := s.CompleteIdempotent(ctx, rec.Scope, rec.Key, 201, body); err != nil {
		t.Fatalf("CompleteIdempotent: %v", err)
	}

	claim, err := s.ClaimIdempotent(ctx, rec)
	if err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if claim.State != ClaimReplay {
		t.Fatalf("state = %q, want %q", claim.State, ClaimReplay)
	}
	if claim.Record.Status != 201 || string(claim.Record.Body) != string(body) {
		t.Fatalf("replayed %d %q, want 201 %q", claim.Record.Status, claim.Record.Body, body)
	}
}

// idempotencyMismatchRequestHash checks that a key reused for a different body
// is refused. Answering it with the stored response would return one request's
// result to another.
func idempotencyMismatchRequestHash(t *testing.T, s FullStore) {
	t.Helper()
	ctx := context.Background()
	secret := []byte(`{"analysis_id":"an-secret"}`)
	first := idempotencyRecord("POST /v1/mismatch", "key-hash", "hash-a", "token-a")
	if _, err := s.ClaimIdempotent(ctx, first); err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if err := s.CompleteIdempotent(ctx, first.Scope, first.Key, 200, secret); err != nil {
		t.Fatalf("CompleteIdempotent: %v", err)
	}

	second := first
	second.RequestHash = "hash-b"
	claim, err := s.ClaimIdempotent(ctx, second)
	if err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if claim.State != ClaimMismatch {
		t.Fatalf("state = %q, want %q", claim.State, ClaimMismatch)
	}
	// The memory store is the reference implementation and returns the stored
	// row for diagnostics; the SQL store additionally drops the response body
	// so a mismatch can never be turned into a reply.
	if _, isSQL := any(s).(*SQL); isSQL && len(claim.Record.Body) != 0 {
		t.Fatalf("mismatch leaked the stored body %q", claim.Record.Body)
	}

	// The original payload still replays, which proves the mismatch neither
	// overwrote nor consumed the stored response.
	again, err := s.ClaimIdempotent(ctx, first)
	if err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if again.State != ClaimReplay || string(again.Record.Body) != string(secret) {
		t.Fatalf("original request got %q %q, want a replay of %q", again.State, again.Record.Body, secret)
	}
}

// idempotencyMismatchPrincipal checks that two callers never share a stored
// response, even when they send byte-identical requests.
func idempotencyMismatchPrincipal(t *testing.T, s FullStore) {
	t.Helper()
	ctx := context.Background()
	first := idempotencyRecord("POST /v1/principal", "key-principal", "hash-a", "token-a")
	if _, err := s.ClaimIdempotent(ctx, first); err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if err := s.CompleteIdempotent(ctx, first.Scope, first.Key, 200, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("CompleteIdempotent: %v", err)
	}

	second := first
	second.Principal = "token-b"
	claim, err := s.ClaimIdempotent(ctx, second)
	if err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if claim.State != ClaimMismatch {
		t.Fatalf("state = %q, want %q", claim.State, ClaimMismatch)
	}
}

// idempotencySecondClaimInProgress checks that an unfinished claim blocks the
// retry instead of running the same work twice.
func idempotencySecondClaimInProgress(t *testing.T, s FullStore) {
	t.Helper()
	ctx := context.Background()
	rec := idempotencyRecord("POST /v1/progress", "key-progress", "hash-a", "token-a")
	if _, err := s.ClaimIdempotent(ctx, rec); err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	claim, err := s.ClaimIdempotent(ctx, rec)
	if err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if claim.State != ClaimInProgress {
		t.Fatalf("state = %q, want %q", claim.State, ClaimInProgress)
	}
}

// idempotencyReleaseAllowsReclaim checks that a failed request frees its key
// again; otherwise one crash would strand the key forever.
func idempotencyReleaseAllowsReclaim(t *testing.T, s FullStore) {
	t.Helper()
	ctx := context.Background()
	rec := idempotencyRecord("POST /v1/release", "key-release", "hash-a", "token-a")
	if _, err := s.ClaimIdempotent(ctx, rec); err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if err := s.ReleaseIdempotent(ctx, rec.Scope, rec.Key); err != nil {
		t.Fatalf("ReleaseIdempotent: %v", err)
	}
	// Releasing an absent row is a no-op, not a failure.
	if err := s.ReleaseIdempotent(ctx, rec.Scope, rec.Key); err != nil {
		t.Fatalf("second ReleaseIdempotent: %v", err)
	}
	claim, err := s.ClaimIdempotent(ctx, rec)
	if err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if claim.State != ClaimNew {
		t.Fatalf("state = %q, want %q", claim.State, ClaimNew)
	}
}

// idempotencyCompleteUnknown checks that completing a key nobody claimed is
// reported, because it means the response would be silently dropped.
func idempotencyCompleteUnknown(t *testing.T, s FullStore) {
	t.Helper()
	err := s.CompleteIdempotent(context.Background(), "POST /v1/unknown", "key-unknown", 200, []byte(`{}`))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("CompleteIdempotent error = %v, want ErrNotFound", err)
	}
}

// idempotencyExpiredRecord checks the lifetime rules: an expired claim is
// indistinguishable from an absent one, and the purge removes only the rows
// that are actually due.
func idempotencyExpiredRecord(t *testing.T, s FullStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	dead := idempotencyRecord("POST /v1/expiry", "key-dead", "hash-a", "token-a")
	dead.ExpiresAt = now.Add(-time.Hour)
	if _, err := s.ClaimIdempotent(ctx, dead); err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if err := s.CompleteIdempotent(ctx, dead.Scope, dead.Key, 200, []byte(`{"stale":true}`)); err != nil {
		t.Fatalf("CompleteIdempotent: %v", err)
	}
	// A new claim must win the key again rather than replay the stale response.
	fresh, err := s.ClaimIdempotent(ctx, dead)
	if err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if fresh.State != ClaimNew {
		t.Fatalf("state = %q, want %q for an expired record", fresh.State, ClaimNew)
	}
	if len(fresh.Record.Body) != 0 {
		t.Fatalf("expired claim returned the stale body %q", fresh.Record.Body)
	}

	live := idempotencyRecord("POST /v1/expiry", "key-live", "hash-a", "token-a")
	live.ExpiresAt = now.Add(time.Hour)
	if _, err := s.ClaimIdempotent(ctx, live); err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if err := s.CompleteIdempotent(ctx, live.Scope, live.Key, 200, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("CompleteIdempotent: %v", err)
	}

	removed, err := s.PurgeExpiredIdempotency(ctx, now)
	if err != nil {
		t.Fatalf("PurgeExpiredIdempotency: %v", err)
	}
	if removed != 1 {
		t.Fatalf("purged %d rows, want 1 (only the expired key)", removed)
	}
	replay, err := s.ClaimIdempotent(ctx, live)
	if err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	if replay.State != ClaimReplay {
		t.Fatalf("live key state = %q, want %q", replay.State, ClaimReplay)
	}
}

// idempotencyConcurrentClaims is the safety property the store exists for:
// simultaneous retries of one key must produce exactly one owner.
func idempotencyConcurrentClaims(t *testing.T, s FullStore) {
	t.Helper()
	ctx := context.Background()
	rec := idempotencyRecord("POST /v1/concurrent", "key-concurrent", "hash-a", "token-a")

	const callers = 8
	var (
		wg     sync.WaitGroup
		start  = make(chan struct{})
		states = make([]ClaimState, callers)
		errs   = make([]error, callers)
	)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			claim, err := s.ClaimIdempotent(ctx, rec)
			states[i], errs[i] = claim.State, err
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for i := range states {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		switch states[i] {
		case ClaimNew:
			winners++
		case ClaimInProgress, ClaimReplay:
			// A loser may observe the winner's claim, or its completed response
			// if the winner finished first.
		default:
			t.Fatalf("caller %d: state = %q, want new, in_progress or replay", i, states[i])
		}
	}
	if winners != 1 {
		t.Fatalf("%d callers received ClaimNew, want exactly 1", winners)
	}
}

// TestIdempotencyDurableAcrossReopen is the SQL-only half of the guarantee: a
// claim and its stored response must outlive the process, which an in-memory
// store cannot demonstrate.
func TestIdempotencyDurableAcrossReopen(t *testing.T) {
	for _, f := range storeFactories() {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			if f.name == "memory" {
				t.Skip("an in-memory store has no second handle to reopen")
			}
			ctx := context.Background()
			dsn := filepath.Join(t.TempDir(), "codexploit.db")
			rec := idempotencyRecord("POST /v1/durable", "key-durable", "hash-a", "token-a")
			body := []byte(`{"analysis_id":"an-durable"}`)

			first, err := OpenSQL(ctx, "sqlite", dsn)
			if err != nil {
				t.Fatalf("OpenSQL: %v", err)
			}
			if err := first.EnsureSchema(ctx, migrations.FS); err != nil {
				t.Fatalf("EnsureSchema: %v", err)
			}
			if _, err := first.ClaimIdempotent(ctx, rec); err != nil {
				t.Fatalf("ClaimIdempotent: %v", err)
			}
			if err := first.CompleteIdempotent(ctx, rec.Scope, rec.Key, 202, body); err != nil {
				t.Fatalf("CompleteIdempotent: %v", err)
			}
			if err := first.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			second, err := OpenSQL(ctx, "sqlite", dsn)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			t.Cleanup(func() {
				if err := second.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			})
			if err := second.EnsureSchema(ctx, migrations.FS); err != nil {
				t.Fatalf("EnsureSchema after reopen: %v", err)
			}
			claim, err := second.ClaimIdempotent(ctx, rec)
			if err != nil {
				t.Fatalf("ClaimIdempotent after reopen: %v", err)
			}
			if claim.State != ClaimReplay {
				t.Fatalf("state after reopen = %q, want %q", claim.State, ClaimReplay)
			}
			if claim.Record.Status != 202 || string(claim.Record.Body) != string(body) {
				t.Fatalf("replayed %d %q, want 202 %q", claim.Record.Status, claim.Record.Body, body)
			}
			if claim.Record.CreatedAt.IsZero() || claim.Record.ExpiresAt.IsZero() {
				t.Fatalf("stored timestamps did not round-trip: %+v", claim.Record)
			}
		})
	}
}
