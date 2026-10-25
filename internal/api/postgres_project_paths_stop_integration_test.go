package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/lifecycle"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func TestPostgresProjectPathStopFencesRemoteWorkerAndSurvivesRestart(t *testing.T) {
	cfg := postgresConfig(t)
	a, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	envA := serveTestEnv(t, a, false)
	project, snapshot := organizationFixture(t, envA.ts)
	id := createOrganizedTask(t, envA.ts, project, snapshot, "Stop existing paths")
	paths := auditPaths(t, envA.ts, id, "").Paths
	if len(paths) == 0 {
		t.Fatal("fixture has no paths")
	}
	claimed, err := a.Audit.LeasePath(context.Background(), paths[0].ID, "remote-worker", time.Minute, []path.Status{path.StatusQueued}, "worker")
	if err != nil {
		t.Fatal(err)
	}
	now := path.NowString(time.Now().UTC())
	run := agent.Run{ID: "run-project-stop", AuditID: id, PathID: claimed.ID, SnapshotID: snapshot, Status: agent.RunRunning, Owner: "remote-worker", LeaseEpoch: claimed.LeaseEpoch, Runtime: "fixture", RuntimeVersion: "1", Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := a.Store.CreateRun(run); err != nil {
		t.Fatal(err)
	}
	b, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	envB := serveTestEnv(t, b, false)
	endpoint := "/api/v1/projects/" + project
	stopped := do(t, envB.ts, http.MethodPost, endpoint+"/stop-paths", map[string]any{}, nil)
	if stopped.status != http.StatusOK {
		t.Fatalf("remote stop: %d %s", stopped.status, stopped.body)
	}
	var result lifecycle.PathStopResult
	stopped.decode(t, &result)
	if result.State != "STOPPING" || result.PendingAgentRuns != 1 || result.RemainingPaths != 0 {
		t.Fatalf("premature stop: %s", stopped.body)
	}
	if deleted := do(t, envB.ts, http.MethodDelete, endpoint, nil, nil); deleted.status != http.StatusConflict {
		t.Fatalf("deleted with running worker: %d %s", deleted.status, deleted.body)
	}
	// The old allocation can no longer renew or publish intermediate run state.
	if _, err := a.Audit.HeartbeatEpoch(context.Background(), claimed.ID, "remote-worker", claimed.LeaseEpoch, time.Minute); err == nil {
		t.Fatal("cancelled lease renewed")
	}
	run.Version++
	if err := a.Store.UpdateRun(run, 1); !errors.Is(err, agent.ErrConflict) {
		t.Fatalf("late worker state = %v", err)
	}
	// Only the owning worker acknowledges that its executor has ended.
	run.Status, run.StopReason, run.FinishedAt = agent.RunCancelled, agent.StopCancelled, now
	if err := a.Store.UpdateRun(run, 1); err != nil {
		t.Fatal(err)
	}
	envB.ts.Close()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	envB = serveTestEnv(t, rebuilt, false)
	status := do(t, envB.ts, http.MethodGet, endpoint+"/stop-paths", nil, nil)
	status.decode(t, &result)
	if status.status != http.StatusOK || result.State != "STOPPED" {
		t.Fatalf("restart status: %d %s", status.status, status.body)
	}
	task, err := rebuilt.Store.GetAudit(id)
	if err != nil || !task.Paused {
		t.Fatalf("scheduling reopened after restart: %+v %v", task, err)
	}
	for _, p := range auditPaths(t, envB.ts, id, "").Paths {
		if p.Status != path.StatusCancelled {
			t.Fatalf("cancelled path revived: %+v", p)
		}
	}
}

func TestPostgresProjectPathStopPagesAllPaths(t *testing.T) {
	rt, err := app.Build(context.Background(), postgresConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	projectStopPathsPagesAllPaths(t, serveTestEnv(t, rt, false))
}

func TestPostgresProjectPathStopCancelsAnalysis(t *testing.T) {
	rt, err := app.Build(context.Background(), postgresConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	projectStopPathsCancelsAnalysis(t, serveTestEnv(t, rt, false))
}

func TestPostgresProjectPathStopClosesPausedAttempts(t *testing.T) {
	cfg := postgresConfig(t)
	cfg.Agent = app.AgentConfig{Enabled: true, Runtime: app.AgentRuntimeScripted, ScriptedAnswerJSON: agentTestPlaceholderAnswer(t), MaxToolCalls: 30}
	rt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	projectStopPathsClosesPausedAttempts(t, serveTestEnv(t, rt, false))
}
