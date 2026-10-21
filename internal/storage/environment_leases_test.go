package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func leaseStoreFactories() []struct {
	name string
	open func(t *testing.T) verify.EnvironmentLeaseStore
} {
	return []struct {
		name string
		open func(t *testing.T) verify.EnvironmentLeaseStore
	}{
		{name: "memory", open: func(t *testing.T) verify.EnvironmentLeaseStore { return NewMemory() }},
		{name: "sqlite", open: func(t *testing.T) verify.EnvironmentLeaseStore {
			ctx := context.Background()
			s, err := OpenSQL(ctx, "sqlite", filepath.Join(t.TempDir(), "leases.db"))
			if err != nil {
				t.Fatalf("OpenSQL: %v", err)
			}
			if err := s.EnsureSchema(ctx, migrations.FS); err != nil {
				t.Fatalf("EnsureSchema: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		}},
	}
}

func leaseFixture(now time.Time) verify.EnvironmentLease {
	return verify.EnvironmentLease{
		ID: "plan-lease", PlanID: "plan-lease", ProjectID: "proj-1", SnapshotID: "snap-1",
		Owner: "worker-a", Provider: "docker", SourceDigest: "source-1",
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
	}
}

func TestEnvironmentLeaseStoreFencesAndReclaims(t *testing.T) {
	for _, factory := range leaseStoreFactories() {
		t.Run(factory.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
			store := factory.open(t)
			first, err := store.AcquireEnvironmentLease(ctx, leaseFixture(now), now)
			if err != nil {
				t.Fatalf("acquire: %v", err)
			}
			if first.Epoch != 1 || first.Cleanup != verify.CleanupNotStarted {
				t.Fatalf("first = %+v", first)
			}
			if _, err := store.AcquireEnvironmentLease(ctx, leaseFixture(now), now); err != nil {
				t.Fatalf("idempotent acquire: %v", err)
			}
			other := leaseFixture(now)
			other.Owner = "worker-b"
			if _, err := store.AcquireEnvironmentLease(ctx, other, now); !errors.Is(err, verify.ErrLeaseHeld) {
				t.Fatalf("second owner = %v", err)
			}
			if _, err := store.RenewEnvironmentLease(ctx, first.ID, first.Owner, first.Epoch, now.Add(2*time.Minute), now); err != nil {
				t.Fatalf("renew: %v", err)
			}
			if _, err := store.RenewEnvironmentLease(ctx, first.ID, "worker-b", first.Epoch, now.Add(2*time.Minute), now); !errors.Is(err, verify.ErrLeaseLost) {
				t.Fatalf("foreign renew = %v", err)
			}
			if _, err := store.BindEnvironmentLease(ctx, first.ID, first.Owner, first.Epoch, "env-1", "receipt-1", "image-1", now.Add(2*time.Minute), now); err != nil {
				t.Fatalf("bind: %v", err)
			}
			released, err := store.ReleaseEnvironmentLease(ctx, first.ID, first.Owner, first.Epoch, verify.CleanupFailed, "rm failed", now)
			if err != nil {
				t.Fatalf("release: %v", err)
			}
			if released.State != verify.EnvironmentFailed || released.Cleanup != verify.CleanupFailed {
				t.Fatalf("released = %+v", released)
			}
			if _, err := store.AcquireEnvironmentLease(ctx, leaseFixture(now), now); !errors.Is(err, verify.ErrLeaseHeld) {
				t.Fatalf("takeover after failed cleanup = %v", err)
			}
			if _, err := store.ReleaseEnvironmentLease(ctx, first.ID, first.Owner, first.Epoch, verify.CleanupSucceeded, "", now); err != nil {
				t.Fatalf("recovered cleanup: %v", err)
			}
			next, err := store.AcquireEnvironmentLease(ctx, leaseFixture(now), now)
			if err != nil {
				t.Fatalf("takeover: %v", err)
			}
			if next.Epoch != 2 {
				t.Fatalf("takeover epoch = %d", next.Epoch)
			}
			if _, err := store.ReleaseEnvironmentLease(ctx, first.ID, first.Owner, first.Epoch, verify.CleanupSucceeded, "", now); !errors.Is(err, verify.ErrLeaseLost) {
				t.Fatalf("stale release = %v", err)
			}
			expired, err := store.ListEnvironmentLeases(ctx, verify.EnvironmentLeaseQuery{ExpiredOnly: true, Now: now.Add(3 * time.Minute)})
			if err != nil || len(expired) != 1 {
				t.Fatalf("expired list = %+v, %v", expired, err)
			}
		})
	}
}

func TestEnvironmentLeaseSurvivesSQLiteReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "leases.db")
	now := time.Now().UTC()
	first, err := OpenSQL(ctx, "sqlite", path)
	if err != nil {
		t.Fatalf("OpenSQL: %v", err)
	}
	if err := first.EnsureSchema(ctx, migrations.FS); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	lease, err := first.AcquireEnvironmentLease(ctx, leaseFixture(now), now)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	second, err := OpenSQL(ctx, "sqlite", path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()
	stored, err := second.GetEnvironmentLease(ctx, lease.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.Epoch != lease.Epoch || stored.Owner != lease.Owner || stored.ExpiresAt != lease.ExpiresAt {
		t.Fatalf("reopened = %+v, want %+v", stored, lease)
	}
}
