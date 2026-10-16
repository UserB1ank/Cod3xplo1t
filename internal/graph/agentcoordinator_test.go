package graph_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func TestCoordinatorClaimCompleteLeavesNoLease(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	coordinator := graph.NewAgentCoordinator(fixture.audit, "worker-1")
	ctx := context.Background()

	claimed, err := coordinator.ClaimPathForRun(ctx, fixture.auditID, "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("ClaimPathForRun: %v", err)
	}
	if claimed == nil {
		t.Fatal("ClaimPathForRun returned no path although the audit has queued work")
	}
	if claimed.LeaseOwner != "worker-1" {
		t.Fatalf("lease owner = %q, want worker-1", claimed.LeaseOwner)
	}
	if claimed.Status != path.StatusAnalyzing {
		t.Errorf("claimed status = %q, want ANALYZING", claimed.Status)
	}
	if claimed.LeaseUntil == "" {
		t.Error("the claim carries no lease expiry")
	}

	// A second worker gets different work, not the same path.
	second, err := coordinator.ClaimPathForRun(ctx, fixture.auditID, "worker-2", time.Minute)
	if err != nil {
		t.Fatalf("second ClaimPathForRun: %v", err)
	}
	if second.ID == claimed.ID {
		t.Fatalf("two workers hold the same path %s", second.ID)
	}

	// A heartbeat from another owner is refused with the engine's own sentinel.
	if err := coordinator.HeartbeatPath(ctx, claimed.ID, "worker-9", time.Minute); !errors.Is(err, path.ErrLeaseHeld) {
		t.Errorf("heartbeat from a foreign owner = %v, want path.ErrLeaseHeld", err)
	}
	if err := coordinator.HeartbeatPath(ctx, claimed.ID, "worker-1", time.Minute); err != nil {
		t.Fatalf("HeartbeatPath: %v", err)
	}

	if err := coordinator.CompletePath(ctx, claimed.ID, "worker-1", "hypothesis formed"); err != nil {
		t.Fatalf("CompletePath: %v", err)
	}
	completed, _, err := fixture.audit.Path(claimed.ID)
	if err != nil {
		t.Fatalf("Path after CompletePath: %v", err)
	}
	if completed.Status != path.StatusHypothesisFormed {
		t.Errorf("completed status = %q, want HYPOTHESIS_FORMED", completed.Status)
	}
	// The invariant the coordinator exists for: a finished run leaves no lease.
	if completed.LeaseOwner != "" || completed.LeaseUntil != "" || completed.HeartbeatAt != "" {
		t.Errorf("a completed path kept its lease: owner=%q until=%q heartbeat=%q",
			completed.LeaseOwner, completed.LeaseUntil, completed.HeartbeatAt)
	}
	reclaimed, err := fixture.audit.ReclaimExpired(50)
	if err != nil {
		t.Fatalf("ReclaimExpired: %v", err)
	}
	for _, p := range reclaimed {
		if p.ID == claimed.ID {
			t.Errorf("a completed path was handed to ReclaimExpired: %+v", p)
		}
	}
	// A completed path is not claimable either: it left the queue.
	if _, err := coordinator.ClaimPathForRun(ctx, fixture.auditID, "worker-3", time.Minute); err != nil && !errors.Is(err, path.ErrNotFound) {
		t.Fatalf("claiming the rest of the audit: %v", err)
	}

	// Releasing a path puts it back in the queue with its lease cleared.
	if err := coordinator.ReleasePath(ctx, second.ID, "worker-2", "retry later"); err != nil {
		t.Fatalf("ReleasePath: %v", err)
	}
	released, _, err := fixture.audit.Path(second.ID)
	if err != nil {
		t.Fatalf("Path after ReleasePath: %v", err)
	}
	if released.Status != path.StatusQueued || released.LeaseOwner != "" {
		t.Errorf("released path = %+v, want QUEUED without a lease", released)
	}
}

func TestCoordinatorAdvancePathAndOwnerFallback(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	coordinator := graph.NewAgentCoordinator(fixture.audit, "fallback-owner")
	ctx := context.Background()

	// An empty owner falls back to the coordinator's own, so a lease always has an
	// owner to renew and release.
	claimed, err := coordinator.ClaimPathForRun(ctx, fixture.auditID, "", time.Minute)
	if err != nil {
		t.Fatalf("ClaimPathForRun: %v", err)
	}
	if claimed.LeaseOwner != "fallback-owner" {
		t.Errorf("lease owner = %q, want the coordinator's fallback", claimed.LeaseOwner)
	}

	// A spent path is taken out of the queue without pretending it was released.
	if err := coordinator.AdvancePath(ctx, claimed.ID, "fallback-owner", path.StatusFailed, "attempts spent"); err != nil {
		t.Fatalf("AdvancePath: %v", err)
	}
	failed, _, err := fixture.audit.Path(claimed.ID)
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if failed.Status != path.StatusFailed {
		t.Errorf("status = %q, want FAILED", failed.Status)
	}
	if failed.LeaseOwner != "" {
		t.Errorf("a failed path kept its lease: %+v", failed)
	}

	// An illegal transition is the state machine's error, not the coordinator's.
	if err := coordinator.AdvancePath(ctx, claimed.ID, "fallback-owner", path.StatusDiscovered, "backwards"); !errors.Is(err, path.ErrInvalidTransition) {
		t.Errorf("illegal transition = %v, want path.ErrInvalidTransition", err)
	}
}

func TestCoordinatorReportsAnEmptyQueueAsNotFound(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	coordinator := graph.NewAgentCoordinator(fixture.audit, "worker-1")
	ctx := context.Background()

	// RunOnce decides "no work" from "a broken queue" with errors.Is, so the
	// sentinel has to survive the adapter.
	if _, err := coordinator.ClaimPathForRun(ctx, "audit-does-not-exist", "worker-1", time.Minute); !errors.Is(err, path.ErrNotFound) {
		t.Errorf("claiming an unknown audit = %v, want path.ErrNotFound", err)
	}
	if _, err := coordinator.ClaimPathForRun(ctx, "", "worker-1", time.Minute); !errors.Is(err, path.ErrNotFound) {
		t.Errorf("claiming without an audit = %v, want path.ErrNotFound", err)
	}

	// A cancelled context is a cancellation, not an empty queue.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := coordinator.ClaimPathForRun(cancelled, fixture.auditID, "worker-1", time.Minute); !errors.Is(err, context.Canceled) {
		t.Errorf("claiming with a cancelled context = %v, want context.Canceled", err)
	}
}

func TestCoordinatorWithoutAPathServiceIsAWiringBug(t *testing.T) {
	t.Parallel()
	coordinator := graph.NewAgentCoordinator(nil, "worker-1")
	if _, err := coordinator.ClaimPathForRun(context.Background(), "audit-1", "worker-1", time.Minute); err == nil {
		t.Fatal("a coordinator without a path service claimed a path")
	}
	if err := coordinator.HeartbeatPath(context.Background(), "path-1", "worker-1", time.Minute); err == nil {
		t.Fatal("a coordinator without a path service renewed a lease")
	}
	if err := coordinator.CompletePath(context.Background(), "path-1", "worker-1", "done"); err == nil {
		t.Fatal("a coordinator without a path service completed a path")
	}
	if err := coordinator.ReleasePath(context.Background(), "path-1", "worker-1", "retry"); err == nil {
		t.Fatal("a coordinator without a path service released a path")
	}
	if err := coordinator.AdvancePath(context.Background(), "path-1", "worker-1", path.StatusFailed, "spent"); err == nil {
		t.Fatal("a coordinator without a path service advanced a path")
	}
	if _, err := coordinator.ClaimSpecificPath(context.Background(), "path-1", "worker-1", time.Minute); err == nil {
		t.Fatal("a coordinator without a path service claimed a specific path")
	}
}

// TestCoordinatorClaimSpecificPath pins the path-scoped claim a scheduler uses: it
// leases exactly the named path, refuses another owner's lease with the engine's
// sentinel, and treats a repeated claim by the holder as a renewal.
func TestCoordinatorClaimSpecificPath(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	coordinator := graph.NewAgentCoordinator(fixture.audit, "worker-1")
	ctx := context.Background()

	next, err := fixture.audit.Next(fixture.auditID)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	claimed, err := coordinator.ClaimSpecificPath(ctx, next.ID, "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("ClaimSpecificPath: %v", err)
	}
	if claimed.ID != next.ID {
		t.Fatalf("claimed %s, want the named path %s", claimed.ID, next.ID)
	}
	if claimed.Status != path.StatusAnalyzing || claimed.LeaseOwner != "worker-1" {
		t.Errorf("claimed = %s/%s, want ANALYZING leased to worker-1", claimed.Status, claimed.LeaseOwner)
	}

	// Another owner is refused with the engine's own sentinel.
	if _, err := coordinator.ClaimSpecificPath(ctx, next.ID, "worker-2", time.Minute); !errors.Is(err, path.ErrLeaseHeld) {
		t.Errorf("claim by another owner = %v, want path.ErrLeaseHeld", err)
	}
	// The holder claiming again renews: the scheduler claims before dispatching and
	// RunPath then claims for the run.
	again, err := coordinator.ClaimSpecificPath(ctx, next.ID, "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("repeated claim by the holder: %v", err)
	}
	if again.ID != next.ID || again.LeaseOwner != "worker-1" {
		t.Errorf("renewed claim = %+v, want the same path and owner", again)
	}

	// A path that left the queue is not claimable.
	if err := coordinator.CompletePath(ctx, next.ID, "worker-1", "hypothesis formed"); err != nil {
		t.Fatalf("CompletePath: %v", err)
	}
	if _, err := coordinator.ClaimSpecificPath(ctx, next.ID, "worker-3", time.Minute); !errors.Is(err, path.ErrNotClaimable) {
		t.Errorf("claiming a settled path = %v, want path.ErrNotClaimable", err)
	}

	// Wiring and argument errors.
	if _, err := coordinator.ClaimSpecificPath(ctx, "path-does-not-exist", "worker-1", time.Minute); !errors.Is(err, path.ErrNotFound) {
		t.Errorf("claiming an unknown path = %v, want path.ErrNotFound", err)
	}
	if _, err := coordinator.ClaimSpecificPath(ctx, "  ", "worker-1", time.Minute); !errors.Is(err, path.ErrInvalidArgument) {
		t.Errorf("claiming a blank path id = %v, want path.ErrInvalidArgument", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := coordinator.ClaimSpecificPath(cancelled, next.ID, "worker-1", time.Minute); !errors.Is(err, context.Canceled) {
		t.Errorf("claiming with a cancelled context = %v, want context.Canceled", err)
	}
}
