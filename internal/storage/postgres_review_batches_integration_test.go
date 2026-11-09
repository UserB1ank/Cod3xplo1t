package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/reviewbatch"
)

func TestPostgresReviewBatchLeaseFencesThePreviousOwner(t *testing.T) {
	a, b := postgresKnowledgeStores(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	now := time.Now().UTC()
	batch := reviewbatch.Batch{
		ID: "review-batch-lease-fence", ProjectID: "project-review-batch",
		SnapshotID: "snapshot-review-batch", AuditID: "audit-review-batch",
		State: reviewbatch.StateRunning, PathIDs: []string{"path-a"},
		MaxConcurrent: 1, CreatedBy: "operator",
		ExecutionOwner: "owner-a", LeaseEpoch: 1,
		HeartbeatAt: now.Format(time.RFC3339Nano),
		LeaseUntil:  now.Add(100 * time.Millisecond).Format(time.RFC3339Nano),
		CreatedAt:   now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano), Version: 1,
	}
	if _, err := a.CreateReviewBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	claimedAt := now.Add(time.Second)
	claimed, err := b.ClaimReviewBatch(ctx, reviewbatch.ClaimRequest{
		BatchID: batch.ID, Owner: "owner-b", Now: claimedAt.Format(time.RFC3339Nano),
		LeaseUntil: claimedAt.Add(time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ExecutionOwner != "owner-b" || claimed.LeaseEpoch != 2 {
		t.Fatalf("claimed batch = %+v", claimed)
	}
	if _, err := a.RenewReviewBatch(ctx, reviewbatch.RenewRequest{
		BatchID: batch.ID, Owner: "owner-a", Epoch: 1,
		HeartbeatAt: claimedAt.Format(time.RFC3339Nano),
		LeaseUntil:  claimedAt.Add(time.Minute).Format(time.RFC3339Nano),
	}); !errors.Is(err, reviewbatch.ErrConflict) {
		t.Fatalf("stale renew = %v, want conflict", err)
	}
	if _, err := a.FinalizeReviewBatch(ctx, reviewbatch.FinalizeRequest{
		BatchID: batch.ID, ExpectedVersion: claimed.Version, Owner: "owner-a", Epoch: 1,
		State: reviewbatch.StateCompleted, Now: claimedAt.Format(time.RFC3339Nano),
	}); !errors.Is(err, reviewbatch.ErrConflict) {
		t.Fatalf("stale finalize = %v, want conflict", err)
	}
	renewed, err := b.RenewReviewBatch(ctx, reviewbatch.RenewRequest{
		BatchID: batch.ID, Owner: "owner-b", Epoch: 2,
		HeartbeatAt: claimedAt.Add(time.Second).Format(time.RFC3339Nano),
		LeaseUntil:  claimedAt.Add(time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	finalized, err := b.FinalizeReviewBatch(ctx, reviewbatch.FinalizeRequest{
		BatchID: batch.ID, ExpectedVersion: renewed.Version, Owner: "owner-b", Epoch: 2,
		State: reviewbatch.StateCompleted, Now: claimedAt.Add(2 * time.Second).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	if finalized.State != reviewbatch.StateCompleted || finalized.ExecutionOwner != "" || finalized.LeaseUntil != "" {
		t.Fatalf("finalized batch = %+v", finalized)
	}
}
