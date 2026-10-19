package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

// TestCheckpointAPIReadsAndRefusesResume covers the checkpoint boundary: a reader
// can inspect a paused run, only a writer may try to resume, another project
// cannot see it, and an adapter that cannot resume says so explicitly.
func TestCheckpointAPIReadsAndRefusesResume(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	created := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create snapshot: %d %s", created.status, created.body)
	}
	var snapshot snapshotResponse
	created.decode(t, &snapshot)
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": snapshot.Snapshot.SnapshotID})
	pathPage := auditPaths(t, env.ts, audit.Audit.ID, "")
	if len(pathPage.Paths) == 0 {
		t.Fatal("the audit queued no path")
	}
	task, err := env.rt.Agent.Tasks.BuildTask(context.Background(), pathPage.Paths[0], agent.DefaultExplorationPolicy())
	if err != nil {
		t.Fatalf("BuildTask: %v", err)
	}
	run := agent.Run{
		ID: "run-paused-api", PathID: pathPage.Paths[0].ID, AuditID: audit.Audit.ID,
		SnapshotID: snapshot.Snapshot.SnapshotID, Runtime: "scripted", RuntimeVersion: "1",
		Status: agent.RunPaused, StopReason: agent.StopBudgetPaused, Task: task,
		Exploration: agent.DefaultExplorationPolicy(), CreatedAt: time.Now().UTC().Format(time.RFC3339), UpdatedAt: time.Now().UTC().Format(time.RFC3339), Version: 1,
	}
	store := env.rt.Store
	if err := store.CreateRun(run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	checkpoint, err := agent.BuildCheckpoint(agent.CheckpointInput{
		Run: run, Task: task, Reason: "the tool budget is exhausted", Evidence: []string{"ev-1"}, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	run.CheckpointID = checkpoint.ID
	if err := store.SaveCheckpointAndPause(run, 1, checkpoint, nil); err != nil {
		t.Fatalf("SaveCheckpointAndPause: %v", err)
	}
	base := "/api/v1/projects/" + project.Project.ID + "/runs/" + run.ID

	read := doAs(t, env.ts, readerSecret, http.MethodGet, base+"/checkpoint", nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("reader checkpoint: %d %s", read.status, read.body)
	}
	var readCheckpoint agent.Checkpoint
	read.decode(t, &readCheckpoint)
	if readCheckpoint.ID != checkpoint.ID || readCheckpoint.Digest != checkpoint.Digest {
		t.Fatalf("checkpoint response = %+v", readCheckpoint)
	}

	if denied := doAs(t, env.ts, readerSecret, http.MethodPost, base+"/resume", map[string]any{}, nil); denied.status != http.StatusForbidden {
		t.Fatalf("reader resume = %d %s, want 403", denied.status, denied.body)
	}

	// The scripted adapter has no resume capability; the API says so instead of
	// silently starting a fresh attempt.
	unsupported := do(t, env.ts, http.MethodPost, base+"/resume", map[string]any{}, nil)
	if unsupported.status != http.StatusBadRequest || !strings.Contains(string(unsupported.body), "unsupported") {
		t.Fatalf("resume with the scripted adapter = %d %s", unsupported.status, unsupported.body)
	}

	other := createProject(t, env.ts, asgFixtureSource(t))
	crossProject := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+other.Project.ID+"/runs/"+run.ID+"/checkpoint", nil, nil)
	if crossProject.status != http.StatusNotFound {
		t.Fatalf("cross-project checkpoint = %d %s, want 404", crossProject.status, crossProject.body)
	}
}
