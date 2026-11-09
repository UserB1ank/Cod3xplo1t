package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
)

func TestPostgresReviewBatchRecoversAfterCoordinatorRestart(t *testing.T) {
	cfg := postgresConfig(t)
	cfg.Agent = app.AgentConfig{
		Enabled: true, Runtime: app.AgentRuntimeScripted,
		ScriptedAnswerJSON: agentTestPlaceholderAnswer(t), MaxToolCalls: 10,
	}
	first, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	envA := serveTestEnv(t, first, false)
	if first.ReviewBatches == nil {
		t.Fatal("review batches were not wired")
	}
	project := createProject(t, envA.ts, asgFixtureSource(t))
	create := do(t, envA.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	var createdSnapshot snapshotResponse
	create.decode(t, &createdSnapshot)
	audit := createAudit(t, envA.ts, map[string]any{"snapshot_id": createdSnapshot.Snapshot.SnapshotID})
	blocked := &blockingRuntime{
		delegate: &echoRuntime{Answer: agentTestAnswer},
		started:  make(chan string, 100), release: make(chan struct{}),
	}
	first.Agent.Runtime = blocked
	first.ReviewBatches.SetLeasePolicy(500*time.Millisecond, 50*time.Millisecond)

	started := do(t, envA.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches",
		map[string]any{
			"api_version": "codexploit/v1", "audit_id": audit.Audit.ID,
			"max_concurrent": 1,
		}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start review batch = %d (%s)", started.status, started.body)
	}
	var created reviewBatchResponse
	started.decode(t, &created)
	waitStarted(t, blocked.started)

	// Simulate a coordinator/process stop. The batch remains RUNNING in PostgreSQL,
	// the interrupted path is fenced by its lease, and a new process must recover it.
	first.ReviewBatches.Close()

	second, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	envB := serveTestEnv(t, second, false)
	second.Agent.Runtime = &echoRuntime{Answer: agentTestAnswer}
	if second.ReviewBatches == nil {
		t.Fatal("recovered runtime has no review batches")
	}

	deadline := time.Now().Add(20 * time.Second)
	for {
		view := readReviewBatch(t, envB, project.Project.ID, created.Batch.ID)
		if view.Batch.State == "COMPLETED" {
			if view.Progress.Reviewed != view.Progress.Total {
				t.Fatalf("recovered progress = %+v", view.Progress)
			}
			break
		}
		if view.Batch.State == "FAILED" {
			t.Fatalf("recovered batch failed: %+v", view)
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovered batch did not complete: %+v", view)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPostgresReviewBatchHotFailoverWithoutRestart(t *testing.T) {
	cfg := postgresConfig(t)
	cfg.Agent = app.AgentConfig{
		Enabled: true, Runtime: app.AgentRuntimeScripted,
		ScriptedAnswerJSON: agentTestPlaceholderAnswer(t), MaxToolCalls: 10,
	}
	first, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	envA := serveTestEnv(t, first, false)
	envB := serveTestEnv(t, second, false)
	if first.ReviewBatches == nil || second.ReviewBatches == nil {
		t.Fatal("review batches were not wired on both instances")
	}
	first.ReviewBatches.SetLeasePolicy(500*time.Millisecond, 50*time.Millisecond)
	second.ReviewBatches.SetLeasePolicy(500*time.Millisecond, 50*time.Millisecond)
	blocked := &blockingRuntime{
		delegate: &echoRuntime{Answer: agentTestAnswer},
		started:  make(chan string, 100), release: make(chan struct{}),
	}
	first.Agent.Runtime = blocked
	second.Agent.Runtime = &echoRuntime{Answer: agentTestAnswer}

	project := createProject(t, envA.ts, asgFixtureSource(t))
	create := do(t, envA.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	var createdSnapshot snapshotResponse
	create.decode(t, &createdSnapshot)
	audit := createAudit(t, envA.ts, map[string]any{"snapshot_id": createdSnapshot.Snapshot.SnapshotID})
	started := do(t, envA.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/review-batches",
		map[string]any{
			"api_version": "codexploit/v1", "audit_id": audit.Audit.ID,
			"max_concurrent": 1,
		}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start review batch = %d (%s)", started.status, started.body)
	}
	var created reviewBatchResponse
	started.decode(t, &created)
	waitStarted(t, blocked.started)

	// Stop only the first coordinator. The second process remains up and must
	// reclaim the batch from PostgreSQL after its lease expires.
	first.ReviewBatches.Close()
	deadline := time.Now().Add(20 * time.Second)
	for {
		view := readReviewBatch(t, envB, project.Project.ID, created.Batch.ID)
		if view.Batch.State == "COMPLETED" {
			if view.Progress.Reviewed != view.Progress.Total {
				t.Fatalf("takeover progress = %+v", view.Progress)
			}
			break
		}
		if view.Batch.State == "FAILED" {
			t.Fatalf("takeover batch failed: %+v", view)
		}
		if time.Now().After(deadline) {
			t.Fatalf("takeover batch did not complete: %+v", view)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
