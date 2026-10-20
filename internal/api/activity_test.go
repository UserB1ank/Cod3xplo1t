package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

// TestProjectActivityShowsActiveRunsAndStages covers the review surface: the
// project lists the tasks that are executing, each run's stage, and how much path
// work is still queued. A reader may watch it, and another project sees nothing.
func TestProjectActivityShowsActiveRunsAndStages(t *testing.T) {
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
	paths := auditPaths(t, env.ts, audit.Audit.ID, "")
	if len(paths.Paths) < 2 {
		t.Fatalf("fixture produced %d paths, want at least 2", len(paths.Paths))
	}
	now := time.Now().UTC()
	build := func(index int) agent.Task {
		task, err := env.rt.Agent.Tasks.BuildTask(context.Background(), paths.Paths[index], agent.DefaultExplorationPolicy())
		if err != nil {
			t.Fatalf("BuildTask: %v", err)
		}
		return task
	}
	store := env.rt.Store
	running := agent.Run{
		ID: "run-activity-running", PathID: paths.Paths[0].ID, AuditID: audit.Audit.ID,
		SnapshotID: snapshot.Snapshot.SnapshotID, Runtime: "scripted", RuntimeVersion: "1",
		Status: agent.RunRunning, Task: build(0), Exploration: agent.DefaultExplorationPolicy(),
		StartedAt: now.Add(-time.Minute).Format(time.RFC3339), CreatedAt: now.Add(-time.Minute).Format(time.RFC3339),
		UpdatedAt: now.Format(time.RFC3339), Version: 1,
	}
	if err := store.CreateRun(running); err != nil {
		t.Fatalf("CreateRun running: %v", err)
	}
	paused := agent.Run{
		ID: "run-activity-paused", PathID: paths.Paths[1].ID, AuditID: audit.Audit.ID,
		SnapshotID: snapshot.Snapshot.SnapshotID, Runtime: "pi", RuntimeVersion: "1.3.0",
		Status: agent.RunPaused, StopReason: agent.StopBudgetPaused, Task: build(1),
		Exploration: agent.DefaultExplorationPolicy(), StartedAt: now.Add(-2 * time.Minute).Format(time.RFC3339),
		CreatedAt: now.Add(-2 * time.Minute).Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339), Version: 1,
	}
	if err := store.CreateRun(paused); err != nil {
		t.Fatalf("CreateRun paused: %v", err)
	}

	var page struct {
		Active []projectActivityEntry `json:"active"`
		Counts projectActivityCounts  `json:"counts"`
	}
	read := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/projects/"+project.Project.ID+"/activity", nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("reader activity: %d %s", read.status, read.body)
	}
	read.decode(t, &page)
	if page.Counts.Running != 1 || page.Counts.Paused != 1 || page.Counts.Tasks != 1 || page.Counts.Queued == 0 {
		t.Fatalf("counts = %+v", page.Counts)
	}
	stages := map[string]bool{}
	for _, entry := range page.Active {
		if entry.TaskID != audit.Audit.ID || strings.TrimSpace(entry.TaskName) == "" {
			t.Fatalf("entry = %+v", entry)
		}
		if entry.RunID == "" || entry.Queued == 0 {
			t.Fatalf("entry misses run or queued work: %+v", entry)
		}
		stages[entry.Stage] = true
		if entry.Stage == "paused" && entry.Runtime != "pi" {
			t.Fatalf("paused runtime = %q", entry.Runtime)
		}
		if entry.Stage == "analyzing" && entry.ElapsedMS <= 0 {
			t.Fatalf("running entry has no elapsed time: %+v", entry)
		}
	}
	if !stages["analyzing"] || !stages["paused"] {
		t.Fatalf("stages = %v, want analyzing and paused", stages)
	}

	other := createProject(t, env.ts, asgFixtureSource(t))
	empty := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/projects/"+other.Project.ID+"/activity", nil, nil)
	if empty.status != http.StatusOK {
		t.Fatalf("other activity: %d %s", empty.status, empty.body)
	}
	var emptyPage struct {
		Active []projectActivityEntry `json:"active"`
		Counts projectActivityCounts  `json:"counts"`
	}
	empty.decode(t, &emptyPage)
	if len(emptyPage.Active) != 0 || emptyPage.Counts.Tasks != 0 {
		t.Fatalf("another project leaked activity: %+v", emptyPage)
	}
}
