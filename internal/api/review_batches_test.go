package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func TestReviewBatchCanBeStartedAndReadForAnAudit(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	create := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if create.status != http.StatusCreated {
		t.Fatalf("create snapshot: %d %s", create.status, create.body)
	}
	var createdSnapshot snapshotResponse
	create.decode(t, &createdSnapshot)
	snapshotID := createdSnapshot.Snapshot.SnapshotID
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": snapshotID})

	started := do(t, env.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches",
		map[string]any{
			"api_version":    "codexploit/v1",
			"audit_id":       audit.Audit.ID,
			"max_concurrent": 2,
		}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start review batch = %d, want 201 (%s)", started.status, started.body)
	}
	var created reviewBatchResponse
	started.decode(t, &created)
	if created.APIVersion != "codexploit/v1" || created.Batch.ID == "" {
		t.Fatalf("incomplete review batch: %s", started.body)
	}
	if created.Batch.AuditID != audit.Audit.ID || created.Batch.MaxConcurrent != 2 {
		t.Fatalf("review batch scope = %+v", created.Batch)
	}
	if len(created.Batch.PathIDs) == 0 {
		t.Fatalf("review batch captured no queued paths: %s", started.body)
	}
	if created.Batch.State != "RUNNING" && created.Batch.State != "COMPLETED" {
		t.Fatalf("unexpected initial state %q", created.Batch.State)
	}
	if created.Progress.Total != len(created.Batch.PathIDs) {
		t.Fatalf("progress total = %d, want %d", created.Progress.Total, len(created.Batch.PathIDs))
	}

	read := do(t, env.ts, http.MethodGet,
		"/api/v1/projects/"+project.Project.ID+"/review-batches/"+created.Batch.ID,
		nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("read review batch = %d (%s)", read.status, read.body)
	}
	var loaded reviewBatchResponse
	read.decode(t, &loaded)
	if loaded.Batch.ID != created.Batch.ID || loaded.Batch.AuditID != audit.Audit.ID {
		t.Fatalf("read returned another batch: %s", read.body)
	}
}

type reviewBatchResponse struct {
	APIVersion string `json:"api_version"`
	Batch      struct {
		ID            string   `json:"batch_id"`
		AuditID       string   `json:"audit_id"`
		State         string   `json:"state"`
		MaxConcurrent int      `json:"max_concurrent"`
		PathIDs       []string `json:"path_ids"`
	} `json:"batch"`
	Progress struct {
		Total     int `json:"total"`
		Queued    int `json:"queued"`
		Active    int `json:"active"`
		Reviewed  int `json:"reviewed"`
		Failed    int `json:"failed"`
		Cancelled int `json:"cancelled"`
		Paused    int `json:"paused"`
	} `json:"progress"`
}

func TestReviewBatchRunsItsFixedPathsWithinTheConcurrencyLimit(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	create := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	var createdSnapshot snapshotResponse
	create.decode(t, &createdSnapshot)
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": createdSnapshot.Snapshot.SnapshotID})
	existing, _, err := env.rt.Store.ListPaths(path.PathQuery{AuditID: audit.Audit.ID, Limit: 10})
	if err != nil || len(existing) == 0 {
		t.Fatalf("fixture paths: %v %+v", err, existing)
	}
	seeded := make([]path.Path, 0, 32)
	for i := 0; i < 32; i++ {
		raw, err := json.Marshal(existing[0])
		if err != nil {
			t.Fatal(err)
		}
		var item path.Path
		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatal(err)
		}
		item.ID = fmt.Sprintf("path-review-concurrency-%02d", i)
		item.Signature = fmt.Sprintf("signature-review-concurrency-%02d", i)
		item.Status = path.StatusQueued
		item.LeaseOwner, item.LeaseUntil, item.HeartbeatAt = "", "", ""
		item.LeaseEpoch, item.Version = 0, 1
		seeded = append(seeded, item)
	}
	if err := env.rt.Store.ReplacePaths(audit.Audit.ID, seeded); err != nil {
		t.Fatal(err)
	}
	runtime := &concurrencyRuntime{
		delegate: &echoRuntime{Answer: agentTestAnswer},
		delay:    25 * time.Millisecond,
	}
	env.rt.Agent.Runtime = runtime

	started := do(t, env.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches",
		map[string]any{
			"api_version":    "codexploit/v1",
			"audit_id":       audit.Audit.ID,
			"max_concurrent": 4,
		}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start review batch = %d (%s)", started.status, started.body)
	}
	var created reviewBatchResponse
	started.decode(t, &created)
	total := created.Progress.Total
	if total < 3 {
		t.Fatalf("fixture produced only %d review path(s)", total)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		read := do(t, env.ts, http.MethodGet,
			"/api/v1/projects/"+project.Project.ID+"/review-batches/"+created.Batch.ID,
			nil, nil)
		if read.status != http.StatusOK {
			t.Fatalf("read review batch = %d (%s)", read.status, read.body)
		}
		var current reviewBatchResponse
		read.decode(t, &current)
		if current.Batch.State == "COMPLETED" {
			if current.Progress.Reviewed != total || current.Progress.Queued != 0 || current.Progress.Active != 0 {
				t.Fatalf("completed batch progress = %+v, want %d reviewed", current.Progress, total)
			}
			break
		}
		if current.Batch.State == "FAILED" || current.Batch.State == "CANCELLED" {
			t.Fatalf("review batch ended %s: %s", current.Batch.State, read.body)
		}
		if time.Now().After(deadline) {
			t.Fatalf("review batch did not complete: %s", read.body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := runtime.max.Load(); got > 4 {
		t.Fatalf("observed concurrency %d, want at most 4", got)
	}
	if got := runtime.max.Load(); got < 4 {
		t.Fatalf("observed concurrency %d, want the batch to fill four slots", got)
	}

	runs := do(t, env.ts, http.MethodGet, "/api/runs?audit_id="+audit.Audit.ID+"&limit=100", nil, nil)
	if runs.status != http.StatusOK {
		t.Fatalf("list runs = %d (%s)", runs.status, runs.body)
	}
	var runPage struct {
		Runs  []agent.Run `json:"runs"`
		Total int         `json:"total"`
	}
	runs.decode(t, &runPage)
	if runPage.Total != total {
		t.Fatalf("runs = %d, want one per path (%d)", runPage.Total, total)
	}
	hypotheses := do(t, env.ts, http.MethodGet, "/api/hypotheses?audit_id="+audit.Audit.ID+"&limit=100", nil, nil)
	var hypothesisPage struct {
		Total int `json:"total"`
	}
	hypotheses.decode(t, &hypothesisPage)
	if hypothesisPage.Total != total {
		t.Fatalf("hypotheses = %d, want one per reviewed path (%d)", hypothesisPage.Total, total)
	}
}

type concurrencyRuntime struct {
	delegate agent.Runtime
	delay    time.Duration
	active   atomic.Int32
	max      atomic.Int32
}

func TestReviewBatchPauseStopsNewWorkAndResumeContinues(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	create := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	var createdSnapshot snapshotResponse
	create.decode(t, &createdSnapshot)
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": createdSnapshot.Snapshot.SnapshotID})
	runtime := &blockingRuntime{delegate: &echoRuntime{Answer: agentTestAnswer}, started: make(chan string, 100), release: make(chan struct{})}
	env.rt.Agent.Runtime = runtime

	started := do(t, env.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches",
		map[string]any{"api_version": "codexploit/v1", "audit_id": audit.Audit.ID, "max_concurrent": 1}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start review batch = %d (%s)", started.status, started.body)
	}
	var created reviewBatchResponse
	started.decode(t, &created)
	first := waitStarted(t, runtime.started)
	if first == "" {
		t.Fatal("the review batch did not start its first path")
	}

	paused := do(t, env.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches/"+created.Batch.ID+"/pause",
		map[string]any{"reason": "operator review"},
		map[string]string{"If-Match": currentReviewBatchETag(t, env, project.Project.ID, created.Batch.ID)})
	if paused.status != http.StatusOK {
		t.Fatalf("pause review batch = %d (%s)", paused.status, paused.body)
	}
	runtime.release <- struct{}{}
	waitReviewBatch(t, env, project.Project.ID, created.Batch.ID, func(view reviewBatchResponse) bool {
		return view.Batch.State == "PAUSED" && view.Progress.Active == 0
	})
	select {
	case pathID := <-runtime.started:
		t.Fatalf("paused batch started another path: %s", pathID)
	case <-time.After(150 * time.Millisecond):
	}

	resumed := do(t, env.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches/"+created.Batch.ID+"/resume",
		map[string]any{"reason": "operator resumed"},
		map[string]string{"If-Match": currentReviewBatchETag(t, env, project.Project.ID, created.Batch.ID)})
	if resumed.status != http.StatusOK {
		t.Fatalf("resume review batch = %d (%s)", resumed.status, resumed.body)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		view := readReviewBatch(t, env, project.Project.ID, created.Batch.ID)
		if view.Batch.State == "COMPLETED" {
			if view.Progress.Reviewed != view.Progress.Total {
				t.Fatalf("completed progress = %+v", view.Progress)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resumed batch did not complete: %+v", view)
		}
		select {
		case <-runtime.started:
			runtime.release <- struct{}{}
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestReviewBatchControlsRequireCurrentETag(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	create := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	var createdSnapshot snapshotResponse
	create.decode(t, &createdSnapshot)
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": createdSnapshot.Snapshot.SnapshotID})
	runtime := &blockingRuntime{
		delegate: &echoRuntime{Answer: agentTestAnswer},
		started:  make(chan string, 100), release: make(chan struct{}),
	}
	env.rt.Agent.Runtime = runtime

	started := do(t, env.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches",
		map[string]any{"api_version": "codexploit/v1", "audit_id": audit.Audit.ID, "max_concurrent": 1}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start review batch = %d (%s)", started.status, started.body)
	}
	var created reviewBatchResponse
	started.decode(t, &created)
	waitStarted(t, runtime.started)
	control := "/api/v1/projects/" + project.Project.ID + "/review-batches/" + created.Batch.ID
	read := do(t, env.ts, http.MethodGet, control, nil, nil)
	if read.status != http.StatusOK || read.header.Get("ETag") == "" {
		t.Fatalf("read review batch etag = %d %q (%s)", read.status, read.header.Get("ETag"), read.body)
	}
	etag := read.header.Get("ETag")
	if missing := do(t, env.ts, http.MethodPost, control+"/pause", map[string]any{"reason": "missing precondition"}, nil); missing.status != http.StatusPreconditionRequired {
		t.Fatalf("pause without ETag = %d (%s)", missing.status, missing.body)
	}
	if stale := do(t, env.ts, http.MethodPost, control+"/pause", map[string]any{"reason": "stale"}, map[string]string{"If-Match": `"stale"`}); stale.status != http.StatusPreconditionFailed {
		t.Fatalf("pause with stale ETag = %d (%s)", stale.status, stale.body)
	}
	paused := do(t, env.ts, http.MethodPost, control+"/pause", map[string]any{"reason": "operator pause"}, map[string]string{"If-Match": etag})
	if paused.status != http.StatusOK || paused.header.Get("ETag") == "" || paused.header.Get("ETag") == etag {
		t.Fatalf("pause = %d headers=%v (%s)", paused.status, paused.header, paused.body)
	}
	runtime.release <- struct{}{}
	waitReviewBatch(t, env, project.Project.ID, created.Batch.ID, func(view reviewBatchResponse) bool {
		return view.Batch.State == "PAUSED" && view.Progress.Active == 0
	})
	readyRuntime, readyCatalog := env.rt.Agent.Runtime, env.rt.Agent.Runtimes
	env.rt.Agent.Runtime, env.rt.Agent.Runtimes = nil, nil
	if unavailableResume := do(t, env.ts, http.MethodPost, control+"/resume", map[string]any{"reason": "runtime unavailable"}, map[string]string{"If-Match": paused.header.Get("ETag")}); unavailableResume.status != http.StatusNotImplemented {
		t.Fatalf("resume without runtime = %d (%s)", unavailableResume.status, unavailableResume.body)
	}
	env.rt.Agent.Runtime, env.rt.Agent.Runtimes = readyRuntime, readyCatalog
	if staleResume := do(t, env.ts, http.MethodPost, control+"/resume", map[string]any{"reason": "stale resume"}, map[string]string{"If-Match": etag}); staleResume.status != http.StatusPreconditionFailed {
		t.Fatalf("resume with old ETag = %d (%s)", staleResume.status, staleResume.body)
	}
	resumed := do(t, env.ts, http.MethodPost, control+"/resume", map[string]any{"reason": "operator resume"}, map[string]string{"If-Match": paused.header.Get("ETag")})
	if resumed.status != http.StatusOK || resumed.header.Get("ETag") == "" {
		t.Fatalf("resume = %d (%s)", resumed.status, resumed.body)
	}
	if staleCancel := do(t, env.ts, http.MethodPost, control+"/cancel", map[string]any{"reason": "stale cancel"}, map[string]string{"If-Match": paused.header.Get("ETag")}); staleCancel.status != http.StatusPreconditionFailed {
		t.Fatalf("cancel with old ETag = %d (%s)", staleCancel.status, staleCancel.body)
	}
	cancelled := do(t, env.ts, http.MethodPost, control+"/cancel", map[string]any{"reason": "operator cancel"}, map[string]string{"If-Match": resumed.header.Get("ETag")})
	if cancelled.status != http.StatusOK {
		t.Fatalf("cancel = %d (%s)", cancelled.status, cancelled.body)
	}
}

func TestReviewBatchDoesNotStartWhenAgentIsUnavailable(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	create := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	var createdSnapshot snapshotResponse
	create.decode(t, &createdSnapshot)
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": createdSnapshot.Snapshot.SnapshotID})
	env.rt.Agent.Runtime = nil
	env.rt.Agent.Runtimes = nil
	started := do(t, env.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches",
		map[string]any{"api_version": "codexploit/v1", "audit_id": audit.Audit.ID}, nil)
	if started.status != http.StatusNotImplemented {
		t.Fatalf("unavailable agent start = %d (%s)", started.status, started.body)
	}
	listed := do(t, env.ts, http.MethodGet,
		"/api/v1/projects/"+project.Project.ID+"/review-batches?audit_id="+audit.Audit.ID, nil, nil)
	var page struct {
		Total int `json:"total"`
	}
	listed.decode(t, &page)
	if page.Total != 0 {
		t.Fatalf("unavailable agent created %d batch(es)", page.Total)
	}
}

func TestReviewBatchCancelStopsQueuedAndActivePaths(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	create := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	var createdSnapshot snapshotResponse
	create.decode(t, &createdSnapshot)
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": createdSnapshot.Snapshot.SnapshotID})
	runtime := &blockingRuntime{delegate: &echoRuntime{Answer: agentTestAnswer}, started: make(chan string, 100), release: make(chan struct{})}
	env.rt.Agent.Runtime = runtime

	started := do(t, env.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches",
		map[string]any{"api_version": "codexploit/v1", "audit_id": audit.Audit.ID, "max_concurrent": 1}, nil)
	var created reviewBatchResponse
	started.decode(t, &created)
	waitStarted(t, runtime.started)
	cancelled := do(t, env.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches/"+created.Batch.ID+"/cancel",
		map[string]any{"reason": "operator cancelled"},
		map[string]string{"If-Match": currentReviewBatchETag(t, env, project.Project.ID, created.Batch.ID)})
	if cancelled.status != http.StatusOK {
		t.Fatalf("cancel review batch = %d (%s)", cancelled.status, cancelled.body)
	}
	view := waitReviewBatch(t, env, project.Project.ID, created.Batch.ID, func(view reviewBatchResponse) bool {
		return view.Batch.State == "CANCELLED"
	})
	if view.Progress.Queued != 0 || view.Progress.Active != 0 {
		t.Fatalf("cancelled batch still has work: %+v", view.Progress)
	}
	if view.Progress.Cancelled+view.Progress.Reviewed != view.Progress.Total {
		t.Fatalf("cancelled batch counts = %+v, want every path stopped", view.Progress)
	}
	select {
	case pathID := <-runtime.started:
		t.Fatalf("cancelled batch started another path: %s", pathID)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestReviewBatchEnforcesProjectIsolationAndOneActiveBatch(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	create := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	var createdSnapshot snapshotResponse
	create.decode(t, &createdSnapshot)
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": createdSnapshot.Snapshot.SnapshotID})
	runtime := &blockingRuntime{delegate: &echoRuntime{Answer: agentTestAnswer}, started: make(chan string, 100), release: make(chan struct{})}
	env.rt.Agent.Runtime = runtime
	endpoint := "/api/v1/projects/" + project.Project.ID + "/review-batches"

	started := do(t, env.ts, http.MethodPost, endpoint,
		map[string]any{"api_version": "codexploit/v1", "audit_id": audit.Audit.ID, "max_concurrent": 1}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start review batch = %d (%s)", started.status, started.body)
	}
	var created reviewBatchResponse
	started.decode(t, &created)
	waitStarted(t, runtime.started)

	duplicate := do(t, env.ts, http.MethodPost, endpoint,
		map[string]any{"api_version": "codexploit/v1", "audit_id": audit.Audit.ID, "max_concurrent": 1}, nil)
	if duplicate.status != http.StatusConflict {
		t.Fatalf("second active batch = %d, want 409 (%s)", duplicate.status, duplicate.body)
	}
	reader := doAs(t, env.ts, readerSecret, http.MethodPost, endpoint,
		map[string]any{"api_version": "codexploit/v1", "audit_id": audit.Audit.ID}, nil)
	if reader.status != http.StatusForbidden {
		t.Fatalf("reader started batch = %d (%s)", reader.status, reader.body)
	}
	read := doAs(t, env.ts, readerSecret, http.MethodGet,
		endpoint+"/"+created.Batch.ID, nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("reader read batch = %d (%s)", read.status, read.body)
	}

	other := createProject(t, env.ts, asgFixtureSource(t))
	crossProject := do(t, env.ts, http.MethodGet,
		"/api/v1/projects/"+other.Project.ID+"/review-batches/"+created.Batch.ID, nil, nil)
	if crossProject.status != http.StatusNotFound {
		t.Fatalf("cross-project batch read = %d (%s)", crossProject.status, crossProject.body)
	}

	cancelled := do(t, env.ts, http.MethodPost, endpoint+"/"+created.Batch.ID+"/cancel",
		map[string]any{"reason": "test complete"},
		map[string]string{"If-Match": currentReviewBatchETag(t, env, project.Project.ID, created.Batch.ID)})
	if cancelled.status != http.StatusOK {
		t.Fatalf("cancel review batch = %d (%s)", cancelled.status, cancelled.body)
	}
}

type blockingRuntime struct {
	delegate agent.Runtime
	started  chan string
	release  chan struct{}
}

func (r *blockingRuntime) Capabilities() agent.RuntimeCapabilities {
	return r.delegate.Capabilities()
}

func (r *blockingRuntime) Start(ctx context.Context, task agent.Task) (*agent.Handle, error) {
	select {
	case r.started <- task.PathID:
	case <-ctx.Done():
		return stoppedHandle(), nil
	}
	select {
	case <-r.release:
		return r.delegate.Start(ctx, task)
	case <-ctx.Done():
		return stoppedHandle(), nil
	}
}

func stoppedHandle() *agent.Handle {
	events := make(chan agent.RuntimeEvent)
	done := make(chan agent.RuntimeResult, 1)
	close(events)
	done <- agent.RuntimeResult{Err: context.Canceled}
	close(done)
	return &agent.Handle{Events: events, Done: done, Cancel: func() {}}
}

func waitStarted(t *testing.T, started <-chan string) string {
	t.Helper()
	select {
	case pathID := <-started:
		return pathID
	case <-time.After(5 * time.Second):
		t.Fatal("review batch did not start a path")
		return ""
	}
}

func readReviewBatch(t *testing.T, env *testEnv, projectID, batchID string) reviewBatchResponse {
	t.Helper()
	read := do(t, env.ts, http.MethodGet,
		"/api/v1/projects/"+projectID+"/review-batches/"+batchID, nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("read review batch = %d (%s)", read.status, read.body)
	}
	var view reviewBatchResponse
	read.decode(t, &view)
	return view
}

func currentReviewBatchETag(t *testing.T, env *testEnv, projectID, batchID string) string {
	t.Helper()
	read := do(t, env.ts, http.MethodGet,
		"/api/v1/projects/"+projectID+"/review-batches/"+batchID, nil, nil)
	if read.status != http.StatusOK || read.header.Get("ETag") == "" {
		t.Fatalf("read review batch = %d etag=%q (%s)", read.status, read.header.Get("ETag"), read.body)
	}
	return read.header.Get("ETag")
}

func waitReviewBatch(t *testing.T, env *testEnv, projectID, batchID string, ready func(reviewBatchResponse) bool) reviewBatchResponse {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		view := readReviewBatch(t, env, projectID, batchID)
		if ready(view) {
			return view
		}
		if time.Now().After(deadline) {
			t.Fatalf("review batch did not reach expected state: %+v", view)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *concurrencyRuntime) Capabilities() agent.RuntimeCapabilities {
	return r.delegate.Capabilities()
}

func (r *concurrencyRuntime) Start(ctx context.Context, task agent.Task) (*agent.Handle, error) {
	active := r.active.Add(1)
	for {
		current := r.max.Load()
		if active <= current || r.max.CompareAndSwap(current, active) {
			break
		}
	}
	time.Sleep(r.delay)
	defer r.active.Add(-1)
	return r.delegate.Start(ctx, task)
}
