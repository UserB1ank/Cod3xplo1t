package lifecycle_test

import (
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/lifecycle"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestStopStatusWaitsForAnalysisProjection(t *testing.T) {
	store := storage.NewMemory()
	if _, err := store.CreateProject(t.Context(), storage.Project{ID: "project-stop-projection", Name: "Projection fence"}); err != nil {
		t.Fatal(err)
	}
	run, err := store.CreateAnalysisRun(t.Context(), storage.AnalysisRun{ID: "analysis-projection", ProjectID: "project-stop-projection", SnapshotID: "snapshot", TaskID: "task", WorkflowRunID: "workflow", PlanID: "plan", State: "RUNNING"}, "")
	if err != nil {
		t.Fatal(err)
	}
	controls := lifecycle.ProjectPaths{Store: store}
	got, err := controls.Status(t.Context(), run.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "STOPPING" || got.PendingWorkflows != 1 {
		t.Fatalf("declared stopped with active analysis projection: %+v", got)
	}
	run.State = "CANCELLED"
	if _, err := store.UpdateAnalysisRun(t.Context(), run); err != nil {
		t.Fatal(err)
	}
	got, err = controls.Status(t.Context(), run.ProjectID)
	if err != nil || got.State != "STOPPED" {
		t.Fatalf("terminal projection: %+v %v", got, err)
	}
}
