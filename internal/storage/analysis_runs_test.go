package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func analysisRunFixture(projectID, id string, created time.Time) AnalysisRun {
	return AnalysisRun{
		ID: id, ProjectID: projectID, SnapshotID: "snap-analysis", TaskID: "task-" + id,
		WorkflowRunID: "wrun-" + id, PlanID: "plan-" + id, PlanDigest: "digest",
		WorkflowID: "codexploit.default-analysis", WorkflowVersion: "1.0.0", State: "RUNNING",
		Stages:   []AnalysisRunStage{{Key: "parse", Label: "代码图谱", Status: "SUCCEEDED", NodeID: "parse", PluginID: "builtin.go-parser", PluginVersion: "1.2.0", Outputs: []artifact.Ref{{ID: "artifact-ast", Kind: "code.ast"}}}},
		Coverage: pathCoverage(), Limitations: []string{"call reachability is not taint flow"}, PathCount: 2,
		CreatedAt: created.UTC().Format(time.RFC3339Nano), UpdatedAt: created.UTC().Format(time.RFC3339Nano), Version: 1,
	}
}

func TestAnalysisRunLifecycleAndActiveConflict(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store := tc.store
			project := testProject("proj-analysis-" + tc.name)
			if _, err := store.CreateProject(ctx, project); err != nil {
				t.Fatal(err)
			}
			created := analysisRunFixture(project.ID, "analysis-one-"+tc.name, time.Now())
			first, err := store.CreateAnalysisRun(ctx, created, "key-one")
			if err != nil || first.Version != 1 || len(first.Stages) != 1 {
				t.Fatalf("create = %+v, %v", first, err)
			}
			// The same idempotency key returns the existing run, even while active.
			same, err := store.CreateAnalysisRun(ctx, analysisRunFixture(project.ID, "analysis-other-"+tc.name, time.Now()), "key-one")
			if err != nil || same.ID != first.ID {
				t.Fatalf("idempotent create = %+v, %v", same, err)
			}
			// A different key cannot start a second active run for the project.
			if _, err := store.CreateAnalysisRun(ctx, analysisRunFixture(project.ID, "analysis-two-"+tc.name, time.Now()), "key-two"); !errors.Is(err, ErrConflict) {
				t.Fatalf("active conflict = %v", err)
			}
			active, ok, err := store.ActiveAnalysisRun(ctx, project.ID)
			if err != nil || !ok || active.ID != first.ID {
				t.Fatalf("active = %+v, %v, %v", active, ok, err)
			}
			// Complete the run, then a new history entry is allowed.
			first.State = "SUCCEEDED"
			first.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			updated, err := store.UpdateAnalysisRun(ctx, first)
			if err != nil || updated.Version != 2 {
				t.Fatalf("update = %+v, %v", updated, err)
			}
			if _, err := store.UpdateAnalysisRun(ctx, first); !errors.Is(err, ErrConflict) {
				t.Fatalf("stale update = %v", err)
			}
			if _, ok, _ := store.ActiveAnalysisRun(ctx, project.ID); ok {
				t.Fatal("terminal run still active")
			}
			second, err := store.CreateAnalysisRun(ctx, analysisRunFixture(project.ID, "analysis-two-"+tc.name, time.Now().Add(time.Second)), "")
			if err != nil || second.ID == first.ID {
				t.Fatalf("second history run = %+v, %v", second, err)
			}
			runs, err := store.ListAnalysisRuns(ctx, project.ID, 10)
			if err != nil || len(runs) != 2 || runs[0].ID != second.ID {
				t.Fatalf("history = %+v, %v", runs, err)
			}
			if got, err := store.GetAnalysisRun(ctx, project.ID, first.ID); err != nil || got.State != "SUCCEEDED" {
				t.Fatalf("get = %+v, %v", got, err)
			}
			if _, err := store.GetAnalysisRun(ctx, "another-project", first.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("cross-project get = %v", err)
			}
			if got, err := store.GetAnalysisRunByIdempotency(ctx, project.ID, "key-one"); err != nil || got.ID != first.ID {
				t.Fatalf("idempotency lookup = %+v, %v", got, err)
			}
		})
	}
}

func pathCoverage() path.Coverage {
	return path.Coverage{EntryPointsExamined: 1, ChainsResolved: 1, PathsConsidered: 2, PathsEmitted: 2}
}
