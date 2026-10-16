package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/schedule"
)

// newSchedulerTestEnv serves a full runtime with the P7 scheduler wired and the
// deterministic echo adapter answering, so a tick really runs a path instead of
// failing on every dispatch.
func newSchedulerTestEnv(t *testing.T) *testEnv {
	t.Helper()
	rt, err := app.Build(context.Background(), app.Config{
		Workspace: filepath.Join(t.TempDir(), "work"),
		DBPath:    "memory",
		Agent: app.AgentConfig{
			Enabled:            true,
			Runtime:            app.AgentRuntimeScripted,
			ScriptedAnswerJSON: agentTestPlaceholderAnswer(t),
			MaxToolCalls:       30,
		},
		Scheduler: app.SchedulerConfig{
			Enabled:       true,
			Interval:      time.Hour,
			MaxConcurrent: 1,
			LeaseTTL:      time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("app.Build with a scheduler: %v", err)
	}
	if rt.Agent == nil || rt.Scheduler == nil || rt.Metrics == nil {
		t.Fatalf("the configured scheduler was not wired: agent=%v scheduler=%v metrics=%v",
			rt.Agent != nil, rt.Scheduler != nil, rt.Metrics != nil)
	}
	rt.Agent.Runtime = &echoRuntime{Answer: agentTestAnswer}
	return serveTestEnv(t, rt, false)
}

// schedulerStatus fetches the status document.
func schedulerStatus(t *testing.T, ts *httptest.Server) map[string]any {
	t.Helper()
	resp := do(t, ts, http.MethodGet, "/api/scheduler", nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("GET /api/scheduler = %d %s", resp.status, resp.body)
	}
	var doc map[string]any
	resp.decode(t, &doc)
	return doc
}

// TestSchedulerStatusAndTick covers the operator loop: read the state, run one
// pass, and see the pass in the metrics.
func TestSchedulerStatusAndTick(t *testing.T) {
	t.Parallel()
	env := newSchedulerTestEnv(t)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	created := createAudit(t, ts, map[string]any{"snapshot_id": snapID})

	before := schedulerStatus(t, ts)
	if before["running"] != false {
		t.Errorf("running = %v, want false: the resident loop only runs inside the server", before["running"])
	}
	if _, ok := before["metrics"]; !ok {
		t.Fatalf("status has no metrics block: %v", before)
	}
	if config, ok := before["config"].(map[string]any); !ok || config["owner"] == "" || config["owner"] == nil {
		t.Errorf("status config = %v, want the effective configuration", before["config"])
	}

	// One pass dispatches exactly one path: the env bounds concurrency at one.
	tick := do(t, ts, http.MethodPost, "/api/scheduler/tick", map[string]any{"concurrency": 1}, nil)
	if tick.status != http.StatusOK {
		t.Fatalf("POST /api/scheduler/tick = %d %s", tick.status, tick.body)
	}
	var result schedule.TickResult
	tick.decode(t, &result)
	if result.Dispatched != 1 || result.Failed != 0 {
		t.Fatalf("tick = %+v, want one successful dispatch", result)
	}

	// The dispatched path really ran: the echo adapter's answer settles it.
	settled := auditPaths(t, ts, created.Audit.ID, "?status=HYPOTHESIS_FORMED")
	if settled.Total == 0 {
		t.Fatalf("no path reached HYPOTHESIS_FORMED after the tick")
	}

	after := schedulerStatus(t, ts)
	metrics, ok := after["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("status metrics = %v, want an object", after["metrics"])
	}
	if metrics["dispatched_total"] != float64(1) || metrics["succeeded_total"] != float64(1) {
		t.Errorf("metrics = dispatched %v, succeeded %v; want 1/1",
			metrics["dispatched_total"], metrics["succeeded_total"])
	}
	if metrics["ticks"] != float64(1) {
		t.Errorf("ticks = %v, want 1", metrics["ticks"])
	}
}

// TestSchedulerTickIsIdempotent pins the write wrapper: replaying the same key
// must not run a second pass.
func TestSchedulerTickIsIdempotent(t *testing.T) {
	t.Parallel()
	env := newSchedulerTestEnv(t)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	createAudit(t, ts, map[string]any{"snapshot_id": snapID})

	headers := map[string]string{"Idempotency-Key": "scheduler-tick-1"}
	first := do(t, ts, http.MethodPost, "/api/scheduler/tick", map[string]any{"concurrency": 1}, headers)
	second := do(t, ts, http.MethodPost, "/api/scheduler/tick", map[string]any{"concurrency": 1}, headers)
	if first.status != http.StatusOK || second.status != http.StatusOK {
		t.Fatalf("tick statuses = %d and %d, want 200", first.status, second.status)
	}
	if string(first.body) != string(second.body) {
		t.Errorf("idempotent replay differs:\n%s\n%s", first.body, second.body)
	}
	if second.header.Get("Idempotent-Replay") != "true" {
		t.Errorf("replay header = %q, want true", second.header.Get("Idempotent-Replay"))
	}
	metrics, _ := schedulerStatus(t, ts)["metrics"].(map[string]any)
	if metrics["ticks"] != float64(1) {
		t.Errorf("ticks = %v after a replay, want 1", metrics["ticks"])
	}
}

// TestSchedulerRoutesRequireWrite checks the capability rows: a reader may observe
// the scheduler but never move work on its behalf.
func TestSchedulerRoutesRequireWrite(t *testing.T) {
	t.Parallel()
	env := newSchedulerTestEnv(t)
	ts := env.ts

	read := doAs(t, ts, readerSecret, http.MethodGet, "/api/scheduler", nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("reader GET /api/scheduler = %d %s", read.status, read.body)
	}
	for _, route := range []string{"/api/scheduler/tick", "/api/scheduler/reclaim"} {
		resp := doAs(t, ts, readerSecret, http.MethodPost, route, map[string]any{}, nil)
		if resp.status != http.StatusForbidden {
			t.Errorf("reader POST %s = %d, want 403 (%s)", route, resp.status, resp.body)
		}
	}
}

// TestSchedulerRoutesUnavailable checks the unwired server: 501, never an empty
// queue that reads like a healthy idle scheduler.
func TestSchedulerRoutesUnavailable(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	routes := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/scheduler", nil},
		{http.MethodPost, "/api/scheduler/tick", map[string]any{}},
		{http.MethodPost, "/api/scheduler/reclaim", map[string]any{}},
	}
	for _, route := range routes {
		resp := do(t, ts, route.method, route.path, route.body, nil)
		if resp.status != http.StatusNotImplemented {
			t.Errorf("%s %s = %d %s, want 501", route.method, route.path, resp.status, resp.body)
			continue
		}
		if got := responseCode(t, resp); got != "scheduler_unavailable" {
			t.Errorf("%s %s code = %q, want scheduler_unavailable", route.method, route.path, got)
		}
	}
}

// TestSchedulerReclaimRoute is the crash-recovery surface: a lease that expired is
// returned to the queue by the manual sweep.
func TestSchedulerReclaimRoute(t *testing.T) {
	t.Parallel()
	env := newSchedulerTestEnv(t)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	created := createAudit(t, ts, map[string]any{"snapshot_id": snapID})
	pathID := pathIDOf(t, ts, created.Audit.ID)

	// A worker that took the path and then died: its lease already expired.
	expired := path.NowString(time.Now().UTC().Add(-time.Minute))
	if _, err := env.rt.Store.ClaimPath(pathID, "crashed-worker", expired, []path.Status{path.StatusQueued}, "crashed-worker"); err != nil {
		t.Fatalf("ClaimPath with an expired lease: %v", err)
	}

	resp := do(t, ts, http.MethodPost, "/api/scheduler/reclaim", map[string]any{"limit": 10}, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("POST /api/scheduler/reclaim = %d %s", resp.status, resp.body)
	}
	var recovered struct {
		Recovered []path.Path `json:"recovered"`
		Count     int         `json:"count"`
	}
	resp.decode(t, &recovered)
	if recovered.Count != 1 || len(recovered.Recovered) != 1 || recovered.Recovered[0].ID != pathID {
		t.Fatalf("recovered = %+v, want the expired path %s", recovered, pathID)
	}

	// The path is back in the queue and the crashed worker's lease is gone.
	current := do(t, ts, http.MethodGet, "/api/paths/"+pathID, nil, nil)
	if current.status != http.StatusOK {
		t.Fatalf("GET /api/paths/%s = %d %s", pathID, current.status, current.body)
	}
	var detail struct {
		Path path.Path `json:"path"`
	}
	current.decode(t, &detail)
	stored := detail.Path
	if stored.Status != path.StatusQueued || stored.LeaseOwner != "" {
		t.Errorf("path = %s leased by %q, want QUEUED without a lease", stored.Status, stored.LeaseOwner)
	}
}

// TestSchedulerTickRejectsBadOverrides checks the request validation.
func TestSchedulerTickRejectsBadOverrides(t *testing.T) {
	t.Parallel()
	env := newSchedulerTestEnv(t)
	ts := env.ts
	negative := do(t, ts, http.MethodPost, "/api/scheduler/tick", map[string]any{"concurrency": -1}, nil)
	if negative.status != http.StatusBadRequest {
		t.Errorf("negative concurrency = %d, want 400 (%s)", negative.status, negative.body)
	}
	blank := do(t, ts, http.MethodPost, "/api/scheduler/tick", map[string]any{"audits": []string{""}}, nil)
	blankPath := do(t, ts, http.MethodPost, "/api/scheduler/reclaim", map[string]any{"limit": -3}, nil)
	if blank.status != http.StatusBadRequest {
		t.Errorf("blank audit id = %d, want 400 (%s)", blank.status, blank.body)
	}
	if blankPath.status != http.StatusBadRequest {
		t.Errorf("negative reclaim limit = %d, want 400 (%s)", blankPath.status, blankPath.body)
	}
}

// newSchedulerTestEnvWithAnswer serves a scheduler-wired runtime whose adapter
// answers answer(goal), so a test can make a run fail on purpose.
func newSchedulerTestEnvWithAnswer(t *testing.T, answer func(goal string) agent.Answer) *testEnv {
	t.Helper()
	rt, err := app.Build(context.Background(), app.Config{
		Workspace: filepath.Join(t.TempDir(), "work"),
		DBPath:    "memory",
		Agent: app.AgentConfig{
			Enabled:            true,
			Runtime:            app.AgentRuntimeScripted,
			ScriptedAnswerJSON: agentTestPlaceholderAnswer(t),
			MaxToolCalls:       30,
		},
		Scheduler: app.SchedulerConfig{
			Enabled:       true,
			Interval:      time.Hour,
			MaxConcurrent: 1,
			LeaseTTL:      time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("app.Build with a scheduler: %v", err)
	}
	if rt.Agent == nil || rt.Scheduler == nil {
		t.Fatal("the configured scheduler was not wired")
	}
	rt.Agent.Runtime = &echoRuntime{Answer: answer}
	return serveTestEnv(t, rt, false)
}

// TestSchedulerTickDefersAFailedRun pins the bridge from the orchestrator to the
// scheduler: a run that ends without success is a failed dispatch, so the path is
// deferred with a durable next-attempt time instead of being re-dispatched on the
// next tick with no backoff.
func TestSchedulerTickDefersAFailedRun(t *testing.T) {
	t.Parallel()
	env := newSchedulerTestEnvWithAnswer(t, func(goal string) agent.Answer {
		// An answer for a goal the task did not ask about: the protocol rejects it,
		// the run ends INVALID_OUTPUT, and the runner releases the path.
		wrong := agentTestAnswer(goal)
		wrong.SecurityGoal = "not_the_security_goal_of_this_task"
		return wrong
	})
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	// One path is what makes this deterministic: the scheduler dispatches the
	// earliest due path, which need not be the highest-priority one the test would
	// otherwise read back.
	created := createAudit(t, ts, map[string]any{
		"snapshot_id": snapID,
		"limits":      map[string]any{"max_paths": 1},
	})
	if created.PathCount != 1 {
		t.Fatalf("audit with max_paths 1 queued %d path(s)", created.PathCount)
	}
	pathID := pathIDOf(t, ts, created.Audit.ID)

	tick := do(t, ts, http.MethodPost, "/api/scheduler/tick", map[string]any{"concurrency": 1}, nil)
	if tick.status != http.StatusOK {
		t.Fatalf("POST /api/scheduler/tick = %d %s", tick.status, tick.body)
	}
	var result schedule.TickResult
	tick.decode(t, &result)
	if result.Dispatched != 1 || result.Failed != 1 {
		t.Fatalf("tick = %+v, want the failed run reported as a failed dispatch", result)
	}

	current := do(t, ts, http.MethodGet, "/api/paths/"+pathID, nil, nil)
	var detail struct {
		Path path.Path `json:"path"`
	}
	current.decode(t, &detail)
	stored := detail.Path
	if stored.Status != path.StatusQueued {
		t.Fatalf("path status = %s, want QUEUED with attempts left", stored.Status)
	}
	if stored.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", stored.Attempts)
	}
	if stored.NextAttemptAt == "" {
		t.Error("next_attempt_at is empty: a failed run must be deferred, not retried immediately")
	}
	if stored.LeaseOwner != "" {
		t.Errorf("lease owner = %q, want the lease released while the path waits", stored.LeaseOwner)
	}
	metrics, _ := schedulerStatus(t, ts)["metrics"].(map[string]any)
	if metrics["failed_total"] != float64(1) || metrics["retried_total"] != float64(1) {
		t.Errorf("metrics = failed %v, retried %v; want 1/1", metrics["failed_total"], metrics["retried_total"])
	}
}

// responseCode reads the error code from an error body.
func responseCode(t *testing.T, resp response) string {
	t.Helper()
	var body errorResponse
	if err := json.Unmarshal(resp.body, &body); err != nil {
		t.Fatalf("decode error body %s: %v", resp.body, err)
	}
	return body.Code
}
