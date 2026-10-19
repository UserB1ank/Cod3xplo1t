package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func postgresQueue(t *testing.T) (*SQL, *SQL, path.Path) {
	t.Helper()
	a, b := postgresKnowledgeStores(t)
	ctx := context.Background()
	if err := a.PutProject(ctx, testProject("owner")); err != nil {
		t.Fatal(err)
	}
	if err := a.PutSnapshot(ctx, "owner", testSnapshot(auditSnapID)); err != nil {
		t.Fatal(err)
	}
	audit := newAuditFixture(auditMainID, auditSnapID, 1)
	if err := a.CreateAudit(audit); err != nil {
		t.Fatal(err)
	}
	p := newPathFixture("path-pg-lease", audit.ID, audit.SnapshotID, "entry", "sink", .8)
	if err := a.ReplacePaths(audit.ID, []path.Path{p}); err != nil {
		t.Fatal(err)
	}
	return a, b, p
}

func TestPostgresVerificationWorkerOwnsItsStateAndEvidence(t *testing.T) {
	a, b, p := postgresQueue(t)
	run := verificationRunFixture("verify-host-fence", "hyp-host-fence", p.ID, p.AuditID, p.SnapshotID)
	run.Status = verify.VerifyRunning
	if err := a.CreateVerificationRun(run); err != nil {
		t.Fatal(err)
	}
	run.Status = verify.VerifySucceeded
	run.Version++
	if err := b.UpdateVerificationRun(run, 1); !errors.Is(err, verify.ErrConflict) {
		t.Fatalf("foreign worker changed verification: %v", err)
	}
	evidence, err := verify.NewEvidence(verify.EvidenceRuntimeLog, "verification output", verify.EvidenceOptions{Tool: "fixture", SnapshotID: p.SnapshotID, VerificationRunID: run.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AppendEvidence([]verify.Evidence{evidence}); !errors.Is(err, verify.ErrConflict) {
		t.Fatalf("foreign worker published verification evidence: %v", err)
	}
	if err := a.AppendEvidence([]verify.Evidence{evidence}); err != nil {
		t.Fatal(err)
	}
	if err := a.UpdateVerificationRun(run, 1); err != nil {
		t.Fatal(err)
	}
	verdict := verificationFindingFixture(run, "Verified fixture", verify.FindingConfirmed)
	if err := b.UpsertFinding(verdict); !errors.Is(err, verify.ErrConflict) {
		t.Fatalf("foreign worker published verdict: %v", err)
	}
	if err := a.UpsertFinding(verdict); err != nil {
		t.Fatal(err)
	}
	stored, err := b.GetVerificationRun(run.ID)
	if err != nil || stored.Status != verify.VerifySucceeded || len(stored.EvidenceIDs) != 1 {
		t.Fatalf("verification state/evidence: %+v %v", stored, err)
	}
	interrupted := verificationRunFixture("verify-interrupted", "hyp-interrupted", p.ID, p.AuditID, p.SnapshotID)
	interrupted.Status = verify.VerifyRunning
	if err := a.CreateVerificationRun(interrupted); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.RecoverInvocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	failed, err := b.GetVerificationRun(interrupted.ID)
	if err != nil || failed.Status != verify.VerifyFailed || failed.StopReason != "host_restarted" {
		t.Fatalf("verification restart left active work: %+v %v", failed, err)
	}
}

func TestPostgresSerializableConcurrentClaimsKeepContinuousEvents(t *testing.T) {
	a, b, p := postgresQueue(t)
	for _, store := range []*SQL{a, b} {
		store.DB().SetMaxOpenConns(1)
		if _, err := store.DB().ExecContext(context.Background(), `SET default_transaction_isolation TO 'serializable'`); err != nil {
			t.Fatal(err)
		}
	}
	paths := []path.Path{}
	for i := range 4 {
		next := p
		next.ID = fmt.Sprintf("path-concurrent-%d", i)
		next.Signature = next.ID
		paths = append(paths, next)
	}
	if err := a.ReplacePaths(p.AuditID, paths); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 4)
	for i, item := range paths {
		go func() {
			<-start
			store := []*SQL{a, b}[i%2]
			_, err := store.ClaimPathTTL(context.Background(), item.ID, fmt.Sprintf("worker-%d", i), time.Minute, []path.Status{path.StatusQueued}, "worker")
			results <- err
		}()
	}
	close(start)
	for range 4 {
		if err := <-results; err != nil {
			t.Fatalf("serializable claim was not retried: %v", err)
		}
	}
	events, err := a.ListEvents(path.EventQuery{AuditID: p.AuditID, Limit: 100})
	if err != nil || len(events) != 4 {
		t.Fatalf("events: %+v %v", events, err)
	}
	for i, event := range events {
		if event.Seq != int64(i+1) {
			t.Fatalf("event sequence gap: %+v", events)
		}
	}
}

func TestPostgresReclaimedPathRejectsOldAgentStateAndHypotheses(t *testing.T) {
	a, b, p := postgresQueue(t)
	first, err := a.ClaimPathTTL(context.Background(), p.ID, "worker", 500*time.Millisecond, []path.Status{path.StatusQueued}, "worker")
	if err != nil {
		t.Fatal(err)
	}
	run := newAgentRunFixture("agent-old-claim", p.ID, p.AuditID, p.SnapshotID)
	run.Status = agent.RunRunning
	run.Owner = "worker"
	run.LeaseEpoch = first.LeaseEpoch
	if err := a.CreateRun(run); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, err := b.ReclaimExpired("", 10, "reaper")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("claim not reclaimed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := b.ClaimPathTTL(context.Background(), p.ID, "worker", time.Minute, []path.Status{path.StatusQueued}, "worker"); err != nil {
		t.Fatal(err)
	}
	run.Status = agent.RunSucceeded
	if err := a.SaveRunEvents(run, 0, []agent.Event{{Type: agent.EventRunFinished}}); !errors.Is(err, agent.ErrConflict) {
		t.Fatalf("old agent wrote terminal state: %v", err)
	}
	hypothesis := newAgentHypothesisFixture(run, "stale worker claim", agent.HypothesisCandidate, "medium", true)
	if err := a.SaveHypotheses([]agent.Hypothesis{hypothesis}); !errors.Is(err, agent.ErrConflict) {
		t.Fatalf("old agent published hypothesis: %v", err)
	}
}

func TestPostgresSecondHostPreservesLivePluginAndRecoversDepartedHost(t *testing.T) {
	a, b, p := postgresQueue(t)
	ctx := context.Background()
	scope, err := a.ArtifactScope(ctx, "owner", p.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	inv := plugin.Invocation{ID: "inv-live-host", Status: "CREATED", Version: 1, RequestDigest: "fixture", Request: plugin.Request{Scope: scope}}
	if _, _, err := a.CreateInvocation(ctx, inv); err != nil {
		t.Fatal(err)
	}
	inv.Status = "RUNNING"
	inv.Version++
	if err := a.SaveInvocation(ctx, inv, 1); err != nil {
		t.Fatal(err)
	}

	current, err := b.GetInvocation(ctx, scope, inv.ID)
	if err != nil || current.Status != "RUNNING" {
		t.Fatalf("second host interrupted live invocation: %+v %v", current, err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.RecoverInvocations(ctx); err != nil {
		t.Fatal(err)
	}
	current, err = b.GetInvocation(ctx, scope, inv.ID)
	if err != nil || current.Status != "FAILED" || current.ErrorCode != "host_restarted" {
		t.Fatalf("departed host not recovered: %+v %v", current, err)
	}
}

func TestPostgresStaleWorkflowWorkerCannotPublishPluginOutputs(t *testing.T) {
	a, b, p := postgresQueue(t)
	ctx := context.Background()
	scope, err := a.ArtifactScope(ctx, "owner", p.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := workflow.Run{ID: "wrun-output-fence", TaskID: "task-output-fence", PlanID: "plan", Scope: scope, Status: "CREATED", Version: 1, CreatedAt: now, UpdatedAt: now, Nodes: []workflow.NodeRun{{ID: "node", NodeID: "parse", Kind: "plugin", Status: "PENDING"}}, Events: []workflow.RunEvent{{Seq: 1, Type: "run_created", Status: "CREATED", CreatedAt: now}}}
	if err := a.CreateWorkflowRun(ctx, run, workflow.TaskDefinition{}); err != nil {
		t.Fatal(err)
	}
	p.AuditID = run.TaskID
	p.ID = "path-workflow-agent"
	if err := a.ReplacePaths(run.TaskID, []path.Path{p}); err != nil {
		t.Fatal(err)
	}
	_, lease, err := a.AcquireWorkflowLease(ctx, "owner", run.ID, "coordinator-a", 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	run.Status = "RUNNING"
	run.Version++
	run.Nodes[0].Status = "RUNNING"
	run.Nodes[0].InvocationID = "inv-fenced-output"
	run.Events = append(run.Events, workflow.RunEvent{Seq: 2, Type: "node_started", NodeID: "parse", Status: "RUNNING", CreatedAt: now})
	if err := a.SaveWorkflowRun(workflow.WithLease(ctx, lease), run, 1); err != nil {
		t.Fatal(err)
	}
	inv := plugin.Invocation{ID: run.Nodes[0].InvocationID, Status: "CREATED", Version: 1, RequestDigest: "fixture", Request: plugin.Request{Scope: scope}}
	if _, _, err := a.CreateInvocation(ctx, inv); err != nil {
		t.Fatal(err)
	}
	inv.Status = "RUNNING"
	inv.Version++
	if err := a.SaveInvocation(ctx, inv, 1); err != nil {
		t.Fatal(err)
	}
	claimed, err := a.ClaimPathTTL(ctx, p.ID, "workflow-"+run.ID, time.Minute, []path.Status{path.StatusQueued}, "worker")
	if err != nil {
		t.Fatal(err)
	}
	agentRun := newAgentRunFixture("agent-workflow-fence", p.ID, p.AuditID, p.SnapshotID)
	agentRun.Owner, agentRun.LeaseEpoch = claimed.LeaseOwner, claimed.LeaseEpoch
	if err := a.CreateRunEventsContext(workflow.WithLease(ctx, lease), agentRun, []agent.Event{{Type: "run_created"}}); err != nil {
		t.Fatal(err)
	}
	if err := b.RecoverInvocations(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, err := b.AcquireWorkflowLease(ctx, "owner", run.ID, "coordinator-b", time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	reclaimed, err := b.GetPath(p.ID)
	if err != nil || reclaimed.Status != path.StatusQueued || reclaimed.Attempts != 1 {
		t.Fatalf("workflow takeover left old path active: %+v %v", reclaimed, err)
	}
	ref := artifact.Ref{ID: "artifact-stale", Kind: "report.document", Scope: scope, Producer: artifact.Producer{PluginID: "fixture", PluginVersion: "1.0.0", InvocationID: inv.ID, ConfigDigest: strings.Repeat("0", 64)}, SHA256: strings.Repeat("1", 64), Bytes: 1, MediaType: "application/json", SchemaID: "codexploit/builtin-native/v1"}
	agentRun.Status = agent.RunSucceeded
	if err := a.SaveRunEvents(agentRun, agentRun.Version, []agent.Event{{Type: "run_finished"}}); !errors.Is(err, agent.ErrConflict) {
		t.Fatalf("stale workflow agent settled: %v", err)
	}
	if err := a.PublishArtifact(workflow.WithLease(ctx, lease), ref); !errors.Is(err, workflow.ErrConflict) {
		t.Fatalf("stale workflow published effect artifact: %v", err)
	}
	inv.Status = "SUCCEEDED"
	inv.Version++
	inv.Outputs = []artifact.Ref{ref}
	if err := a.SaveInvocation(ctx, inv, 2); !errors.Is(err, plugin.ErrConflict) {
		t.Fatalf("stale workflow published outputs: %v", err)
	}
	if _, err := b.LookupArtifact(ctx, scope, ref.ID); !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("late output is visible: %v", err)
	}
}

func TestPostgresWorkflowLeasePreventsLiveTakeoverAndFencesOldNode(t *testing.T) {
	a, b, p := postgresQueue(t)
	ctx := context.Background()
	scope, err := a.ArtifactScope(ctx, "owner", p.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := workflow.Run{ID: "wrun-leased", TaskID: "task-leased", PlanID: "plan-leased", PlanDigest: "fixed", Scope: scope, Status: "CREATED", Version: 1, CreatedAt: now, UpdatedAt: now, Nodes: []workflow.NodeRun{{ID: "node-leased", NodeID: "parse", Kind: "plugin", Status: "PENDING", Inputs: []artifact.Ref{}, Outputs: []artifact.Ref{}}}, Events: []workflow.RunEvent{{Seq: 1, Type: "run_created", Status: "CREATED", CreatedAt: now}}}
	if err := a.CreateWorkflowRun(ctx, run, workflow.TaskDefinition{}); err != nil {
		t.Fatal(err)
	}
	_, lease, err := a.AcquireWorkflowLease(ctx, "owner", run.ID, "worker-a", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.AcquireWorkflowLease(ctx, "owner", run.ID, "worker-b", time.Second); !errors.Is(err, workflow.ErrConflict) {
		t.Fatalf("live takeover: %v", err)
	}
	run.Status = "RUNNING"
	run.Version++
	run.Nodes[0].Status = "RUNNING"
	run.Nodes[0].LeaseOwner = "worker-a"
	run.Nodes[0].InvocationID = "inv-leased"
	run.Events = append(run.Events, workflow.RunEvent{Seq: 2, Type: "node_started", NodeID: "parse", Status: "RUNNING", CreatedAt: run.UpdatedAt})
	if err := a.SaveWorkflowRun(workflow.WithLease(ctx, lease), run, 1); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var next workflow.Lease
	for {
		_, next, err = b.AcquireWorkflowLease(ctx, "owner", run.ID, "worker-b", time.Second)
		if err == nil {
			break
		}
		if !errors.Is(err, workflow.ErrConflict) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("expired coordinator was not reclaimable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if next.Epoch <= lease.Epoch {
		t.Fatal("lease epoch reused")
	}
	run.Status = "SUCCEEDED"
	run.Version++
	run.Nodes[0].Status = "SUCCEEDED"
	run.Events = append(run.Events, workflow.RunEvent{Seq: 3, Type: "node_finished", NodeID: "parse", Status: "SUCCEEDED", CreatedAt: run.UpdatedAt})
	if err := a.SaveWorkflowRun(workflow.WithLease(ctx, lease), run, 2); !errors.Is(err, workflow.ErrConflict) {
		t.Fatalf("stale node published: %v", err)
	}
	if err := b.RenewWorkflowLease(ctx, next, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveWorkflowRun(workflow.WithLease(ctx, next), run, 2); err != nil {
		t.Fatal(err)
	}
	stored, err := a.GetWorkflowRun(ctx, "owner", run.ID)
	if err != nil || stored.Status != "SUCCEEDED" || len(stored.Events) != 3 {
		t.Fatalf("state/event mismatch: %+v %v", stored, err)
	}
}

func TestPostgresAgentStateAndContinuousEventsCommitTogether(t *testing.T) {
	s, _, p := postgresQueue(t)
	run := newAgentRunFixture("run-atomic", p.ID, p.AuditID, p.SnapshotID)
	if err := s.CreateRunEvents(run, []agent.Event{{RunID: "different-run"}}); err == nil {
		t.Fatal("invalid initial event succeeded")
	}
	if _, err := s.GetRun(run.ID); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("initial state survived event rollback: %v", err)
	}
	event := agent.Event{ID: "event-first", RunID: run.ID, PathID: p.ID, Seq: 1, Type: "run_started"}
	if err := s.CreateRunEvents(run, []agent.Event{event}); err != nil {
		t.Fatal(err)
	}
	run.ToolCalls++
	// The duplicate id forces an actual constraint failure after the state write.
	if err := s.SaveRunEvents(run, run.Version, []agent.Event{{ID: event.ID, RunID: run.ID, PathID: p.ID, Type: "tool_result"}}); err == nil {
		t.Fatal("duplicate event succeeded")
	}
	stored, err := s.GetRun(run.ID)
	if err != nil || stored.ToolCalls != run.ToolCalls-1 || stored.Version != run.Version {
		t.Fatalf("state survived event rollback: %+v %v", stored, err)
	}
	if err := s.SaveRunEvents(run, run.Version, []agent.Event{{RunID: run.ID, PathID: p.ID, Type: "tool_result"}}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListRunEvents(agent.EventQuery{RunID: run.ID, Limit: 100})
	if err != nil || len(rows) != 2 || rows[1].Seq != 2 {
		t.Fatalf("events: %+v %v", rows, err)
	}
	stored, err = s.GetRun(run.ID)
	if err != nil || stored.ToolCalls != run.ToolCalls || stored.Version != run.Version+1 {
		t.Fatalf("state/event split: %+v %v", stored, err)
	}
}

func TestPostgresWorkersUseServerClockAndFenceExpiredClaims(t *testing.T) {
	a, b, p := postgresQueue(t)
	service := path.NewService(a, nil)
	service.Now = func() time.Time { return time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC) }
	start := time.Now()
	first, err := service.Claim(context.Background(), p.AuditID, "worker-a", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	expiry, err := time.Parse(time.RFC3339Nano, first.LeaseUntil)
	if err != nil || expiry.Before(start) || expiry.After(start.Add(3*time.Second)) {
		t.Fatalf("client clock controlled database lease: %s", first.LeaseUntil)
	}
	if first.LeaseEpoch < 1 {
		t.Fatal("claim has no fencing epoch")
	}
	renewed, err := service.Heartbeat(first.ID, "worker-a", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := time.Parse(time.RFC3339Nano, renewed.LeaseUntil)
	if err != nil || renewal.After(start.Add(3*time.Second)) || renewed.LeaseEpoch != first.LeaseEpoch {
		t.Fatalf("renewal trusted client clock or changed epoch: %+v", renewed)
	}
	if _, err := b.ClaimPathTTL(context.Background(), p.ID, "worker-b", time.Second, []path.Status{path.StatusQueued}, "worker-b"); err == nil {
		t.Fatal("second worker stole active claim")
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		rows, err := b.ReclaimExpired("1900-01-01T00:00:00Z", 10, "reaper")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server expiry was not reclaimed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	second, err := b.ClaimPathTTL(context.Background(), p.ID, "worker-a", time.Second, []path.Status{path.StatusQueued}, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if second.LeaseEpoch <= first.LeaseEpoch {
		t.Fatal("reclaim reused fencing epoch")
	}
	_, err = a.Transition(path.TransitionRequest{PathID: p.ID, To: path.StatusHypothesisFormed, Owner: "worker-a", LeaseEpoch: first.LeaseEpoch, ClearLease: true})
	if !errors.Is(err, path.ErrLeaseExpired) {
		t.Fatalf("old worker submitted after same-owner reclaim: %v", err)
	}
	_, err = b.Transition(path.TransitionRequest{PathID: p.ID, To: path.StatusHypothesisFormed, Owner: "worker-a", LeaseEpoch: second.LeaseEpoch, ExpectedVersion: second.Version, ClearLease: true})
	if err != nil {
		t.Fatal(err)
	}
	events, err := a.ListEvents(path.EventQuery{AuditID: p.AuditID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for i, event := range events {
		if event.Seq != int64(i+1) {
			t.Fatalf("event gap: %+v", events)
		}
	}
}

func TestPostgresFutureWorkerClockCannotSkipRetryBackoff(t *testing.T) {
	s, _, p := postgresQueue(t)
	p.NextAttemptAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	if err := s.ReplacePaths(p.AuditID, []path.Path{p}); err != nil {
		t.Fatal(err)
	}
	service := path.NewService(s, nil)
	service.Now = func() time.Time { return time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := service.Claim(context.Background(), p.AuditID, "future-worker", time.Minute); err == nil {
		t.Fatal("worker clock bypassed server backoff")
	}
	stored, err := s.GetPath(p.ID)
	if err != nil || stored.LeaseOwner != "" {
		t.Fatalf("deferred path was claimed: %+v %v", stored, err)
	}
}

func TestPostgresDisconnectRollsBackClaimBeforeAnotherWorkerContinues(t *testing.T) {
	a, b, p := postgresQueue(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.DB().SetMaxOpenConns(1)
	var pid int
	if err := a.DB().QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	blocker, err := b.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.ExecContext(ctx, `SELECT audit_id FROM audits WHERE audit_id=$1 FOR UPDATE`, p.AuditID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := a.ClaimPathTTL(ctx, p.ID, "disconnected", time.Minute, []path.Status{path.StatusQueued}, "worker")
		result <- err
	}()
	for {
		var waiting bool
		if err := b.DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-result:
			t.Fatalf("claim did not wait for lock: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	var terminated bool
	if err := b.DB().QueryRowContext(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&terminated); err != nil || !terminated {
		t.Fatalf("fault injection: %v %v", terminated, err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("disconnected worker claimed work")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	current, err := b.GetPath(p.ID)
	if err != nil || current.LeaseOwner != "" || current.Version != p.Version {
		t.Fatalf("partial claim survived disconnect: %+v %v", current, err)
	}
	claimed, err := b.ClaimPathTTL(ctx, p.ID, "healthy", time.Minute, []path.Status{path.StatusQueued}, "worker")
	if err != nil || claimed.LeaseOwner != "healthy" {
		t.Fatalf("healthy worker could not continue: %+v %v", claimed, err)
	}
	events, err := b.ListEvents(path.EventQuery{AuditID: p.AuditID, Limit: 100})
	if err != nil || len(events) != 1 || events[0].Seq != 1 {
		t.Fatalf("disconnected claim wrote events: %+v %v", events, err)
	}
}
