package verify

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testLease(now time.Time) EnvironmentLease {
	return EnvironmentLease{
		ID: "plan-1", PlanID: "plan-1", ProjectID: "proj-1", SnapshotID: "snap-1",
		Owner: "worker-a", Provider: "docker",
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
	}
}

func TestEnvironmentLeaseFencesStaleOwners(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	store := NewMemoryEnvironmentLeases()

	first, err := store.AcquireEnvironmentLease(ctx, testLease(now), now)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if first.Epoch != 1 || first.State != EnvironmentProvisioning || first.Cleanup != CleanupNotStarted {
		t.Fatalf("first lease = %+v", first)
	}
	// The same owner retrying gets the same claim, not a second environment.
	again, err := store.AcquireEnvironmentLease(ctx, testLease(now), now)
	if err != nil || again.Epoch != first.Epoch {
		t.Fatalf("idempotent acquire = %+v, %v", again, err)
	}
	// Another worker cannot take an active lease.
	other := testLease(now)
	other.Owner = "worker-b"
	if _, err := store.AcquireEnvironmentLease(ctx, other, now); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("second owner = %v", err)
	}
	if _, err := store.RenewEnvironmentLease(ctx, "plan-1", "worker-b", first.Epoch, now.Add(time.Minute), now); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("foreign renew = %v", err)
	}
	if _, err := store.RenewEnvironmentLease(ctx, "plan-1", "worker-a", first.Epoch+1, now.Add(time.Minute), now); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale epoch renew = %v", err)
	}
	if _, err := store.BindEnvironmentLease(ctx, "plan-1", "worker-a", first.Epoch, "env-1", "receipt-1", "image-1", now.Add(time.Minute), now); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if _, err := store.ReleaseEnvironmentLease(ctx, "plan-1", "worker-a", first.Epoch, CleanupSucceeded, "", now); err != nil {
		t.Fatalf("release: %v", err)
	}
	// A released lease can be taken over, with a new epoch.
	third, err := store.AcquireEnvironmentLease(ctx, testLease(now), now)
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if third.Epoch != 2 {
		t.Fatalf("takeover epoch = %d, want 2", third.Epoch)
	}
	// The old worker's result is fenced out by the epoch it held.
	if _, err := store.ReleaseEnvironmentLease(ctx, "plan-1", "worker-a", first.Epoch, CleanupSucceeded, "", now); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale release = %v", err)
	}
}

func TestExpiredEnvironmentLeaseIsReclaimedAndCancelsOldWork(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	store := NewMemoryEnvironmentLeases()
	lease, err := store.AcquireEnvironmentLease(ctx, testLease(now), now)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	afterExpiry := now.Add(2 * time.Minute)
	if _, err := store.RenewEnvironmentLease(ctx, lease.ID, lease.Owner, lease.Epoch, afterExpiry.Add(time.Minute), afterExpiry); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("renew after expiry = %v", err)
	}
	expired, err := store.GetEnvironmentLease(ctx, lease.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if expired.Cleanup != CleanupPending || expired.State != EnvironmentFailed {
		t.Fatalf("expired lease = %+v", expired)
	}
	// The reaper can see it and the next execution takes a new epoch.
	leases, err := store.ListEnvironmentLeases(ctx, EnvironmentLeaseQuery{ExpiredOnly: true, Now: afterExpiry})
	if err != nil || len(leases) != 1 {
		t.Fatalf("expired list = %+v, %v", leases, err)
	}
	if _, err := store.ReleaseEnvironmentLease(ctx, expired.ID, expired.Owner, expired.Epoch, CleanupSucceeded, "", afterExpiry); err != nil {
		t.Fatalf("reap: %v", err)
	}
	next, err := store.AcquireEnvironmentLease(ctx, testLease(afterExpiry), afterExpiry.Add(time.Minute))
	if err != nil {
		t.Fatalf("takeover after expiry: %v", err)
	}
	if next.Epoch != 2 {
		t.Fatalf("epoch = %d", next.Epoch)
	}
}

func TestEnvironmentLeaseCleanupFailureIsNotASuccess(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := NewMemoryEnvironmentLeases()
	lease, err := store.AcquireEnvironmentLease(ctx, testLease(now), now)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	released, err := store.ReleaseEnvironmentLease(ctx, lease.ID, lease.Owner, lease.Epoch, CleanupFailed, "docker rm failed", now)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if released.State != EnvironmentFailed || released.Cleanup != CleanupFailed || released.Failure == "" {
		t.Fatalf("failed cleanup = %+v", released)
	}
}
