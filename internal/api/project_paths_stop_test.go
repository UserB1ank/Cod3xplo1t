package api

import (
	"context"
	"fmt"
	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
	"net/http"
	"testing"
	"time"
)

func TestProjectStopPathsClosesSchedulingAndAllowsDeletion(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	snapshot := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots", map[string]any{"build_graph": true, "build_asg": true}, nil)
	var snap snapshotResponse
	snapshot.decode(t, &snap)
	task := createAudit(t, env.ts, map[string]any{"snapshot_id": snap.Snapshot.SnapshotID})
	before := auditPaths(t, env.ts, task.Audit.ID, "")
	if len(before.Paths) == 0 {
		t.Fatal("fixture has no queued paths")
	}
	endpoint := "/api/v1/projects/" + project.Project.ID
	blocked := do(t, env.ts, http.MethodDelete, endpoint, nil, nil)
	if blocked.status != http.StatusConflict {
		t.Fatalf("active deletion: %d %s", blocked.status, blocked.body)
	}
	stopped := do(t, env.ts, http.MethodPost, endpoint+"/stop-paths", map[string]any{}, nil)
	if stopped.status != http.StatusOK {
		t.Fatalf("stop paths: %d %s", stopped.status, stopped.body)
	}
	var body struct {
		State     string `json:"state"`
		Cancelled int    `json:"cancelled_paths"`
	}
	stopped.decode(t, &body)
	if body.State != "STOPPED" || body.Cancelled != len(before.Paths) {
		t.Fatalf("stop result: %s", stopped.body)
	}
	audit, err := env.rt.Store.GetAudit(task.Audit.ID)
	if err != nil || !audit.Paused {
		t.Fatalf("scheduling remains open: %+v %v", audit, err)
	}
	for _, p := range auditPaths(t, env.ts, task.Audit.ID, "").Paths {
		if p.Status != path.StatusCancelled {
			t.Fatalf("path not cancelled: %+v", p)
		}
	}
	repeated := do(t, env.ts, http.MethodPost, endpoint+"/stop-paths", map[string]any{}, nil)
	if repeated.status != http.StatusOK {
		t.Fatalf("repeated stop: %d %s", repeated.status, repeated.body)
	}
	reader := doAs(t, env.ts, readerSecret, http.MethodPost, endpoint+"/stop-paths", map[string]any{}, nil)
	if reader.status != http.StatusForbidden {
		t.Fatalf("reader stop: %d", reader.status)
	}
	deleted := do(t, env.ts, http.MethodDelete, endpoint, nil, nil)
	if deleted.status != http.StatusNoContent {
		t.Fatalf("delete after stop: %d %s", deleted.status, deleted.body)
	}
}

func TestProjectStopPathsCancelsAnalysisWithoutLeavingDeletionBlocked(t *testing.T) {
	projectStopPathsCancelsAnalysis(t, newTestEnv(t, false))
}
func projectStopPathsCancelsAnalysis(t *testing.T, env *testEnv) {
	useLegacyAnalysisFixture(env)
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	blocked, release := make(chan string, 8), make(chan struct{}, 8)
	env.rt.WorkflowRunner.Executor = controlExecutor{delegate: workflow.PluginExecutor{Host: env.rt.Plugins, Catalog: env.rt.PluginCatalog}, blocked: blocked, release: release}
	endpoint := "/api/v1/projects/" + project
	started := do(t, env.ts, http.MethodPost, endpoint+"/analysis-runs", map[string]any{"api_version": "codexploit/v1", "idempotency_key": "bulk-stop-analysis"}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start analysis: %d %s", started.status, started.body)
	}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("analysis did not start")
	}
	stopped := do(t, env.ts, http.MethodPost, endpoint+"/stop-paths", map[string]any{}, nil)
	if stopped.status != http.StatusOK {
		t.Fatalf("stop analysis: %d %s", stopped.status, stopped.body)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		status := do(t, env.ts, http.MethodGet, endpoint+"/stop-paths", nil, nil)
		var body struct {
			State string `json:"state"`
		}
		status.decode(t, &body)
		if status.status != http.StatusOK {
			t.Fatalf("stop status: %d %s", status.status, status.body)
		}
		if body.State == "STOPPED" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("analysis remained active: %s", status.body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	deleted := do(t, env.ts, http.MethodDelete, endpoint, nil, nil)
	if deleted.status != http.StatusNoContent {
		t.Fatalf("cancelled analysis blocked deletion: %d %s", deleted.status, deleted.body)
	}
}

func TestProjectStopPathsPagesAllPathsPreservesResultsAndOtherProjects(t *testing.T) {
	projectStopPathsPagesAllPaths(t, newTestEnv(t, false))
}
func projectStopPathsPagesAllPaths(t *testing.T, env *testEnv) {
	project, snapshot := organizationFixture(t, env.ts)
	id := createOrganizedTask(t, env.ts, project, snapshot, "Many paths")
	original := auditPaths(t, env.ts, id, "").Paths[0]
	paths := make([]path.Path, 205)
	for i := range paths {
		paths[i] = original
		paths[i].ID = fmt.Sprintf("path-bulk-%03d", i)
		paths[i].Signature = paths[i].ID
	}
	if err := env.rt.Store.ReplacePaths(id, paths); err != nil {
		t.Fatal(err)
	}
	for _, status := range []path.Status{path.StatusAnalyzing, path.StatusHypothesisFormed, path.StatusConcluded} {
		if _, err := env.rt.Store.Transition(path.TransitionRequest{PathID: paths[0].ID, To: status, Actor: "fixture", Reason: "completed result"}); err != nil {
			t.Fatal(err)
		}
	}
	other, otherSnapshot := organizationFixture(t, env.ts)
	otherID := createOrganizedTask(t, env.ts, other, otherSnapshot, "Other project")
	before := auditPaths(t, env.ts, otherID, "").Paths
	response := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project+"/stop-paths", map[string]any{}, nil)
	var result struct {
		State     string `json:"state"`
		Cancelled int    `json:"cancelled_paths"`
	}
	response.decode(t, &result)
	if response.status != 200 || result.State != "STOPPED" || result.Cancelled != 204 {
		t.Fatalf("bulk stop: %d %s", response.status, response.body)
	}
	completed, err := env.rt.Store.GetPath(paths[0].ID)
	if err != nil || completed.Status != path.StatusConcluded {
		t.Fatalf("completed result changed: %+v %v", completed, err)
	}
	for _, p := range auditPaths(t, env.ts, otherID, "").Paths {
		found := false
		for _, old := range before {
			if old.ID == p.ID {
				found = true
				if p.Status != old.Status || p.Version != old.Version {
					t.Fatalf("other project mutated: %+v", p)
				}
			}
		}
		if !found {
			t.Fatal("unexpected other project path")
		}
	}
	task, err := env.rt.Store.GetAudit(otherID)
	if err != nil || task.Paused {
		t.Fatalf("other project scheduling changed: %+v %v", task, err)
	}
}

func TestProjectStopPathsClosesPausedAttemptsAndKeepsCheckpoint(t *testing.T) {
	projectStopPathsClosesPausedAttempts(t, newTestEnv(t, false))
}
func projectStopPathsClosesPausedAttempts(t *testing.T, env *testEnv) {
	project, snapshot := organizationFixture(t, env.ts)
	id := createOrganizedTask(t, env.ts, project, snapshot, "Paused attempt")
	p := auditPaths(t, env.ts, id, "").Paths[0]
	task, err := env.rt.Agent.Tasks.BuildTask(context.Background(), p, agent.DefaultExplorationPolicy())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	run := agent.Run{ID: "run-project-paused", AuditID: id, PathID: p.ID, SnapshotID: snapshot, Runtime: "scripted", Status: agent.RunPaused, Version: 1, Task: task, CreatedAt: agent.NowString(now), UpdatedAt: agent.NowString(now)}
	if err := env.rt.Store.CreateRun(run); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := agent.BuildCheckpoint(agent.CheckpointInput{Run: run, Task: task, Reason: "budget boundary", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	run.CheckpointID = checkpoint.ID
	if err := env.rt.Store.SaveCheckpointAndPause(run, 1, checkpoint, nil); err != nil {
		t.Fatal(err)
	}
	response := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project+"/stop-paths", map[string]any{}, nil)
	var result struct {
		State string `json:"state"`
	}
	response.decode(t, &result)
	if response.status != 200 || result.State != "STOPPED" {
		t.Fatalf("paused run prevented stop: %d %s", response.status, response.body)
	}
	stopped, err := env.rt.Store.GetRun(run.ID)
	if err != nil || stopped.Status != agent.RunCancelled {
		t.Fatalf("paused attempt not closed: %+v %v", stopped, err)
	}
	if _, err := env.rt.Store.GetCheckpoint(run.ID); err != nil {
		t.Fatalf("checkpoint lost: %v", err)
	}
}
