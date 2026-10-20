package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func TestPlanRepositoryStoresLifecycleWithVersionCAS(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			repo, ok := tc.store.(verify.PlanRepository)
			if !ok {
				t.Fatalf("%s does not implement verify.PlanRepository", tc.name)
			}
			record, err := verify.NewPlanRecord(verify.ExecutionPlan{
				SchemaVersion: verify.ExecutionPlanSchemaVersion, ID: "plan-1", ProjectID: "proj-1",
				HypothesisID: "hyp-1", PathID: "path-1", AuditID: "audit-1", SnapshotID: "snap-1",
				SecurityGoal: "sql_injection", Claim: "claim",
			}, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			created, err := repo.PutPlan(ctx, record, 0)
			if err != nil || created.Version != 1 {
				t.Fatalf("create: %+v %v", created, err)
			}
			if _, err := repo.PutPlan(ctx, record, 0); !errors.Is(err, verify.ErrPlanConflict) {
				t.Fatalf("duplicate create = %v", err)
			}
			updated := created
			updated.State = verify.PlanApproved
			approved, err := repo.PutPlan(ctx, updated, created.Version)
			if err != nil || approved.Version != 2 {
				t.Fatalf("update: %+v %v", approved, err)
			}
			if _, err := repo.PutPlan(ctx, updated, created.Version); !errors.Is(err, verify.ErrPlanConflict) {
				t.Fatalf("stale update = %v", err)
			}
			got, err := repo.GetPlan(ctx, "proj-1", "plan-1")
			if err != nil || got.State != verify.PlanApproved || got.Version != 2 {
				t.Fatalf("get: %+v %v", got, err)
			}
			if _, err := repo.GetPlan(ctx, "proj-2", "plan-1"); !errors.Is(err, verify.ErrPlanNotFound) {
				t.Fatalf("cross project = %v", err)
			}
			rows, total, err := repo.ListPlans(ctx, "proj-1", "", 10, 0)
			if err != nil || total != 1 || len(rows) != 1 {
				t.Fatalf("list: %v %d %v", rows, total, err)
			}
			empty, total, err := repo.ListPlans(ctx, "proj-1", string(verify.PlanPending), 10, 0)
			if err != nil || total != 0 || len(empty) != 0 {
				t.Fatalf("state filter: %v %d %v", empty, total, err)
			}
		})
	}
}
