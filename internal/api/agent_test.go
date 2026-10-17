package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// The agent tests drive a real path queue through a deterministic adapter. They
// deliberately use app.Build with a scripted runtime rather than a hand-wired
// server, because the bug this phase fixes — a successful run leaving its lease
// attached — lives in the wiring, not in the handler.

// agentTestPlaceholderGoal is the security goal compiled into a test fixture
// answer. It is not the goal of any real task; ackRuntime replaces it with the
// goal the facts builder derived before the answer is validated. It is a value no
// objective uses, so a fixture that forgets the replacement fails loudly instead
// of passing for the wrong reason.
const agentTestPlaceholderGoal = "unused-goal-placeholder"

// agentTestStatement is the claim the fixture agent makes. It is deliberately
// distinct so a listing can assert it saw this claim and not another.
const agentTestStatement = "the request name reaches the query without parameterisation"

// agentTestAnswer is a valid structured answer: a candidate claim with one
// supporting citation and a finding-candidate flag, which is what makes it
// visible through the hypothesis listings.
func agentTestAnswer(securityGoal string) agent.Answer {
	return agent.Answer{
		SchemaVersion: agent.SchemaVersion,
		SecurityGoal:  securityGoal,
		Hypothesis: agent.HypothesisDraft{
			Statement:  agentTestStatement,
			Status:     agent.HypothesisCandidate,
			Confidence: "medium",
		},
		SupportingEvidence: []agent.AnswerEvidence{
			{Kind: agent.EvidenceSource, Ref: "ev-1", File: "main.go", Line: 12, Summary: "the slice concatenates the name"},
		},
		NextAction:       "request a deeper dataflow slice",
		FindingCandidate: true,
		SeverityHint:     "high",
	}
}

// agentTestPlaceholderAnswer is the well-formed scripted answer a test
// configuration carries. app.Build validates the configured script, and the env
// constructors then replace the adapter with echoRuntime, so the goal in this
// document is never the goal of a real task; it only has to satisfy the shape
// check. The value is one no objective uses, so a fixture that forgets the
// replacement fails loudly instead of passing for the wrong reason.
func agentTestPlaceholderAnswer(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(agentTestAnswer(agentTestPlaceholderGoal))
	if err != nil {
		t.Fatalf("marshal the placeholder agent answer: %v", err)
	}
	return string(raw)
}

// echoRuntime is a deterministic in-process adapter that answers the task it is
// given.
//
// The plain ScriptedRuntime replays a fixed script, and a fixed script cannot
// know the security goal the facts builder derives from a path. The goal is the
// task's own vocabulary, so this adapter reads it off the task and echoes it. The
// exchange is otherwise identical to a scripted replay, which keeps the API tests
// deterministic without weakening what the orchestrator validates: the answer
// still goes through DecodeAnswer against the real task.
type echoRuntime struct {
	// Note is an optional bounded summary emitted before the answer.
	Note   string
	Answer func(goal string) agent.Answer
}

var _ agent.Runtime = (*echoRuntime)(nil)

func (r *echoRuntime) Capabilities() agent.RuntimeCapabilities {
	return agent.RuntimeCapabilities{
		Name: "scripted", Version: "1",
		ToolCalls: true, Expansions: true, Streaming: true,
		Notes: []string{"in-process test adapter that answers the task it receives"},
	}
}

func (r *echoRuntime) Start(ctx context.Context, task agent.Task) (*agent.Handle, error) {
	if err := agent.ValidateTask(task); err != nil {
		return nil, err
	}
	events := make(chan agent.RuntimeEvent, 4)
	done := make(chan agent.RuntimeResult, 1)
	cancel := make(chan struct{})
	go func() {
		defer close(events)
		defer close(done)
		if strings.TrimSpace(r.Note) != "" {
			events <- agent.RuntimeEvent{Type: "note", Summary: r.Note}
		}
		answer := r.Answer(task.SecurityGoal)
		events <- agent.RuntimeEvent{
			Type:    agent.EventOutputReceived,
			Summary: "structured answer produced",
			Answer:  &answer,
		}
		done <- agent.RuntimeResult{Answer: &answer}
	}()
	return &agent.Handle{
		Events: events,
		Done:   done,
		Cancel: func() { close(cancel) },
	}, nil
}

// newTestEnvWithAgentLimits is newTestEnvWithAgent with explicit configured
// ceilings, so a test can observe that a request is capped rather than trusting a
// default.
func newTestEnvWithAgentLimits(t *testing.T, cfg app.AgentConfig, answer func(goal string) agent.Answer) *testEnv {
	t.Helper()
	cfg.Enabled = true
	cfg.Runtime = app.AgentRuntimeScripted
	if strings.TrimSpace(cfg.ScriptedAnswerJSON) == "" {
		cfg.ScriptedAnswerJSON = agentTestPlaceholderAnswer(t)
	}
	rt, err := app.Build(context.Background(), app.Config{
		Workspace: filepath.Join(t.TempDir(), "work"),
		DBPath:    "memory",
		Agent:     cfg,
	})
	if err != nil {
		t.Fatalf("app.Build with an agent: %v", err)
	}
	if rt.Agent == nil || rt.AgentRegistry == nil {
		t.Fatalf("the configured agent was not wired")
	}
	rt.Agent.Runtime = &echoRuntime{Answer: answer}
	return serveTestEnv(t, rt, false)
}

// newTestEnvWithAgent serves the same runtime as newTestEnv through a deterministic
// adapter configured to answer with answer(task.SecurityGoal).
func newTestEnvWithAgent(t *testing.T, allowNetwork bool, answer func(goal string) agent.Answer) *testEnv {
	t.Helper()
	rt, err := app.Build(context.Background(), app.Config{
		Workspace:    filepath.Join(t.TempDir(), "work"),
		DBPath:       "memory",
		AllowNetwork: allowNetwork,
		Agent: app.AgentConfig{
			Enabled:            true,
			Runtime:            app.AgentRuntimeScripted,
			ScriptedAnswerJSON: agentTestPlaceholderAnswer(t),
			MaxToolCalls:       10,
		},
	})
	if err != nil {
		t.Fatalf("app.Build with an agent: %v", err)
	}
	if rt.Agent == nil || rt.AgentRegistry == nil {
		t.Fatalf("the configured agent was not wired")
	}
	rt.Agent.Runtime = &echoRuntime{Answer: answer}
	return serveTestEnv(t, rt, allowNetwork)
}

// serveTestEnv starts an httptest server for an already-built runtime and returns
// the shared test env, so the two constructors cannot drift.
func serveTestEnv(t *testing.T, rt *app.Runtime, allowNetwork bool) *testEnv {
	t.Helper()
	t.Cleanup(func() {
		ids, err := rt.Manager.List()
		if err != nil {
			t.Errorf("list snapshots for cleanup: %v", err)
		}
		for _, id := range ids {
			if err := rt.Manager.Remove(id); err != nil {
				t.Errorf("remove snapshot %s: %v", id, err)
			}
		}
		if err := rt.Close(); err != nil {
			t.Errorf("runtime close: %v", err)
		}
	})
	srv := NewServer(rt.Store, rt.Manager, rt.Analyzer,
		WithPluginCatalog(rt.PluginCatalog),
		WithPlugins(rt.Plugins),
		WithAllowNetwork(allowNetwork),
		WithGraph(rt.Graph),
		WithBuilder(rt.Builder),
		WithASG(rt.ASG),
		WithASGBuilder(rt.ASGBuilder),
		WithAudit(rt.Audit),
		WithAgent(rt.Agent),
		WithVerifier(rt.Verifier),
		WithVerifyPlanner(rt.VerifyPlanner),
		// A runtime without a scheduler leaves this nil, which is what keeps the
		// scheduler routes at 501 for the tests that do not wire one.
		WithScheduler(rt.Scheduler),
		WithAuth(testAuthenticator(t)),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{ts: ts, rt: rt, source: newTestSource(t), workspace: rt.Workspace}
}

// startRun posts a run request and returns the raw response.
func startRun(t *testing.T, ts *httptest.Server, route string, body any, headers map[string]string) response {
	t.Helper()
	return do(t, ts, http.MethodPost, route, body, headers)
}

// runBatch is the wire shape of POST .../runs.
type runBatch struct {
	Runs       []agent.Run `json:"runs"`
	Count      int         `json:"count"`
	StopReason string      `json:"stop_reason"`
}

func TestAgentRunsPathAndRecordsHypothesis(t *testing.T) {
	t.Parallel()
	env := newTestEnvWithAgent(t, false, agentTestAnswer)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})

	resp := startRun(t, ts, "/api/audits/"+audit.Audit.ID+"/runs",
		map[string]any{"max_runs": 1, "policy": map[string]any{
			"max_hops": 2, "max_branches": 4, "max_tool_calls": 5,
			"max_expansions": 1, "timeout_seconds": 60, "token_budget": 0,
		}}, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("start run = %d, want 200 (%s)", resp.status, resp.body)
	}
	var batch runBatch
	resp.decode(t, &batch)
	if batch.Count != 1 || len(batch.Runs) != 1 {
		t.Fatalf("run batch = %+v", batch)
	}
	run := batch.Runs[0]
	if run.Status != agent.RunSucceeded {
		t.Fatalf("run status = %s, want SUCCEEDED (%s)", run.Status, resp.body)
	}
	if run.StopReason == "" {
		t.Errorf("run carries no stop reason: %s", resp.body)
	}
	if batch.StopReason != run.StopReason {
		t.Errorf("batch stop reason %q disagrees with the run's %q", batch.StopReason, run.StopReason)
	}
	// The task and the answer are both in the document: a run is the question and
	// the answer, not just the answer.
	if run.Task.SecurityGoal == "" || run.Task.PathID == "" || len(run.Task.EvidenceRefs) == 0 {
		t.Errorf("run lost its task: %s", resp.body)
	}
	if run.Answer == nil || run.Answer.Hypothesis.Statement != agentTestStatement {
		t.Errorf("run lost its answer: %s", resp.body)
	}
	if run.AuditID != audit.Audit.ID {
		t.Errorf("run audit = %q, want %q", run.AuditID, audit.Audit.ID)
	}

	// The path ends HYPOTHESIS_FORMED and holds no lease. This is the P5 fix that
	// makes the loop terminate: an active status with a live lease would keep the
	// audit's ceiling spent on finished work and hand the same path back.
	detail := do(t, ts, http.MethodGet, "/api/paths/"+run.PathID, nil, nil)
	if detail.status != http.StatusOK {
		t.Fatalf("get path: %d %s", detail.status, detail.body)
	}
	var pathDetail pathDetailResponse
	detail.decode(t, &pathDetail)
	if pathDetail.Path.Status != path.StatusHypothesisFormed {
		t.Errorf("path status = %s, want HYPOTHESIS_FORMED", pathDetail.Path.Status)
	}
	if pathDetail.Path.LeaseOwner != "" {
		t.Errorf("the finished path still holds a lease for %q", pathDetail.Path.LeaseOwner)
	}

	// The claim is visible through both listings, with the citation and the
	// finding-candidate flag an operator schedules verification from.
	byPath := do(t, ts, http.MethodGet, "/api/paths/"+run.PathID+"/hypotheses", nil, nil)
	if byPath.status != http.StatusOK {
		t.Fatalf("path hypotheses: %d %s", byPath.status, byPath.body)
	}
	var page struct {
		Hypotheses []agent.Hypothesis `json:"hypotheses"`
		Total      int                `json:"total"`
	}
	byPath.decode(t, &page)
	if page.Total != 1 || len(page.Hypotheses) != 1 {
		t.Fatalf("path hypotheses = %s", byPath.body)
	}
	hypothesis := page.Hypotheses[0]
	if hypothesis.Statement != agentTestStatement || !hypothesis.FindingCandidate {
		t.Errorf("hypothesis = %+v", hypothesis)
	}
	if hypothesis.Status != agent.HypothesisCandidate {
		t.Errorf("hypothesis status = %q, want candidate", hypothesis.Status)
	}
	if len(hypothesis.Supporting) == 0 || hypothesis.Supporting[0].ID != "ev-1" {
		t.Errorf("hypothesis lost its evidence refs: %+v", hypothesis.Supporting)
	}
	if hypothesis.RunID != run.ID {
		t.Errorf("hypothesis run = %q, want %q", hypothesis.RunID, run.ID)
	}

	all := do(t, ts, http.MethodGet, "/api/hypotheses?audit_id="+audit.Audit.ID, nil, nil)
	if all.status != http.StatusOK {
		t.Fatalf("hypotheses: %d %s", all.status, all.body)
	}
	var allPage struct {
		Hypotheses []agent.Hypothesis `json:"hypotheses"`
	}
	all.decode(t, &allPage)
	if len(allPage.Hypotheses) != 1 || allPage.Hypotheses[0].ID != hypothesis.ID {
		t.Errorf("global hypotheses disagree with the path listing: %s", all.body)
	}
	// A finding-candidate filter must keep the claim, and the show route must
	// return the same document.
	candidates := do(t, ts, http.MethodGet, "/api/hypotheses?finding_candidates=true", nil, nil)
	if candidates.status != http.StatusOK {
		t.Fatalf("finding candidates: %d %s", candidates.status, candidates.body)
	}
	shown := do(t, ts, http.MethodGet, "/api/hypotheses/"+hypothesis.ID, nil, nil)
	if shown.status != http.StatusOK {
		t.Fatalf("show hypothesis: %d %s", shown.status, shown.body)
	}
	var one agent.Hypothesis
	shown.decode(t, &one)
	if one.ID != hypothesis.ID || one.Statement != agentTestStatement {
		t.Errorf("show hypothesis = %+v", one)
	}

	// A second request leases the next path, not the one that just finished.
	second := startRun(t, ts, "/api/audits/"+audit.Audit.ID+"/runs", map[string]any{}, nil)
	if second.status != http.StatusOK {
		t.Fatalf("second run = %d (%s)", second.status, second.body)
	}
	var secondBatch runBatch
	second.decode(t, &secondBatch)
	if len(secondBatch.Runs) != 1 {
		t.Fatalf("second batch = %s", second.body)
	}
	if secondBatch.Runs[0].PathID == run.PathID {
		t.Errorf("the second run re-ran path %s", run.PathID)
	}
}

func TestAgentRunEventsAreOrderedAndFilterable(t *testing.T) {
	t.Parallel()
	env := newTestEnvWithAgent(t, false, agentTestAnswer)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})

	resp := startRun(t, ts, "/api/audits/"+audit.Audit.ID+"/runs", map[string]any{}, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("start run = %d (%s)", resp.status, resp.body)
	}
	var batch runBatch
	resp.decode(t, &batch)
	runID := batch.Runs[0].ID

	events := do(t, ts, http.MethodGet, "/api/runs/"+runID+"/events", nil, nil)
	if events.status != http.StatusOK {
		t.Fatalf("run events: %d %s", events.status, events.body)
	}
	var page runEventPage
	events.decode(t, &page)
	if page.Total == 0 || page.NextAfterSeq == 0 {
		t.Fatalf("event page carries no events or no cursor: %s", events.body)
	}
	// The exchange is the protocol's story, in order: the run existed, started,
	// received the task, produced output, recorded the claim, and finished.
	wantOrder := []string{
		agent.EventRunCreated, agent.EventRunStarted, agent.EventTaskDelivered,
		agent.EventOutputReceived, agent.EventHypothesis, agent.EventRunFinished,
	}
	got := make([]string, 0, len(page.Events))
	for _, event := range page.Events {
		got = append(got, event.Type)
	}
	if !isSubsequence(wantOrder, got) {
		t.Errorf("run events = %v, want %v in that order", got, wantOrder)
	}
	for i := 1; i < len(page.Events); i++ {
		if page.Events[i].Seq <= page.Events[i-1].Seq {
			t.Errorf("event sequences are not increasing: %d then %d", page.Events[i-1].Seq, page.Events[i].Seq)
		}
	}

	// The type filter is the audit trail of the expansion decision the runner
	// makes inline; an unknown type is an empty page, not an error.
	filtered := do(t, ts, http.MethodGet, "/api/runs/"+runID+"/events?type="+agent.EventRunCreated, nil, nil)
	if filtered.status != http.StatusOK {
		t.Fatalf("filtered events: %d %s", filtered.status, filtered.body)
	}
	var filteredPage runEventPage
	filtered.decode(t, &filteredPage)
	if filteredPage.Total != 1 || filteredPage.Events[0].Type != agent.EventRunCreated {
		t.Errorf("type filter = %s", filtered.body)
	}

	// after_seq is a resumable cursor: everything up to and including the first
	// page's last sequence is behind us.
	cursor := page.Events[0].Seq
	resumed := do(t, ts, http.MethodGet,
		"/api/runs/"+runID+"/events?after_seq="+strconvFormat(cursor), nil, nil)
	if resumed.status != http.StatusOK {
		t.Fatalf("resumed events: %d %s", resumed.status, resumed.body)
	}
	var resumedPage runEventPage
	resumed.decode(t, &resumedPage)
	if resumedPage.Total != len(page.Events)-1 {
		t.Errorf("after_seq=%d returned %d events, want %d", cursor, resumedPage.Total, len(page.Events)-1)
	}
	for _, event := range resumedPage.Events {
		if event.Seq <= cursor {
			t.Errorf("after_seq returned sequence %d", event.Seq)
		}
	}
	if bad := do(t, ts, http.MethodGet, "/api/runs/"+runID+"/events?after_seq=x", nil, nil); bad.status != http.StatusBadRequest {
		t.Errorf("bad after_seq = %d, want 400 (%s)", bad.status, bad.body)
	}

	// The run document is readable on its own and carries the task.
	show := do(t, ts, http.MethodGet, "/api/runs/"+runID, nil, nil)
	if show.status != http.StatusOK {
		t.Fatalf("show run: %d %s", show.status, show.body)
	}
	var run agent.Run
	show.decode(t, &run)
	if run.ID != runID || run.Task.SecurityGoal == "" {
		t.Errorf("run document = %+v", run)
	}

	// The run is listable by path, audit, snapshot and status.
	for _, query := range []string{
		"?path_id=" + run.PathID, "?audit_id=" + audit.Audit.ID,
		"?snapshot_id=" + run.SnapshotID, "?status=SUCCEEDED",
	} {
		list := do(t, ts, http.MethodGet, "/api/runs"+query, nil, nil)
		if list.status != http.StatusOK {
			t.Fatalf("runs%s: %d %s", query, list.status, list.body)
		}
		var listed struct {
			Runs  []agent.Run `json:"runs"`
			Total int         `json:"total"`
		}
		list.decode(t, &listed)
		if listed.Total == 0 {
			t.Errorf("runs%s listed nothing: %s", query, list.body)
		}
	}
	if bad := do(t, ts, http.MethodGet, "/api/runs?status=NOPE", nil, nil); bad.status != http.StatusBadRequest {
		t.Errorf("unknown status = %d, want 400 (%s)", bad.status, bad.body)
	}
}

func TestAgentRunPolicyIsBounded(t *testing.T) {
	t.Parallel()
	env := newTestEnvWithAgent(t, false, agentTestAnswer)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})
	route := "/api/audits/" + audit.Audit.ID + "/runs"

	// max_runs is bounded: a batch is a request bound, and a value beyond the cap
	// is refused instead of silently clamped, because the caller asked for
	// something the server will not do.
	over := startRun(t, ts, route, map[string]any{"max_runs": 11}, nil)
	if over.status != http.StatusBadRequest {
		t.Fatalf("max_runs=11 = %d, want 400 (%s)", over.status, over.body)
	}
	var errBody errorResponse
	over.decode(t, &errBody)
	if errBody.Code != "invalid_request" || !strings.Contains(errBody.Error, "11") {
		t.Errorf("max_runs error = %+v", errBody)
	}

	// max_runs bounds the batch: two paths run, and each run is over a distinct
	// path because a successful run releases the one it finished.
	batchOf := startRun(t, ts, route, map[string]any{"max_runs": 2}, nil)
	if batchOf.status != http.StatusOK {
		t.Fatalf("max_runs=2 = %d (%s)", batchOf.status, batchOf.body)
	}
	var two runBatch
	batchOf.decode(t, &two)
	if two.Count != 2 || len(two.Runs) != 2 {
		t.Fatalf("max_runs=2 ran %d path(s): %s", two.Count, batchOf.body)
	}
	if two.Runs[0].PathID == two.Runs[1].PathID {
		t.Errorf("the batch ran the same path twice: %s", two.Runs[0].PathID)
	}

	// An unknown tool is refused and named: advertising a tool the gate would
	// refuse teaches the agent to waste its budget on refusals.
	unknown := startRun(t, ts, route,
		map[string]any{"policy": map[string]any{"allowed_tools": []string{"torch.eval"}}}, nil)
	if unknown.status != http.StatusBadRequest {
		t.Fatalf("unknown tool = %d, want 400 (%s)", unknown.status, unknown.body)
	}
	var unknownBody errorResponse
	unknown.decode(t, &unknownBody)
	if unknownBody.Code != "invalid_request" || !strings.Contains(unknownBody.Error, "torch.eval") {
		t.Errorf("unknown tool error = %+v", unknownBody)
	}

	// Unknown field and bad JSON are refused by the shared decoder.
	if bad := startRun(t, ts, route, `{"max_runs":1,"nope":true}`, nil); bad.status != http.StatusBadRequest {
		t.Errorf("unknown field = %d, want 400 (%s)", bad.status, bad.body)
	}
	if bad := startRun(t, ts, route, "{not json", nil); bad.status != http.StatusBadRequest {
		t.Errorf("bad json = %d, want 400 (%s)", bad.status, bad.body)
	}
}

// TestAgentRunPolicyNeverWidensConfiguredLimits pins the rule that a request may
// spend less of the agent's budget but never more. The API is a second caller of
// the same policy, so it must not be the place where a limit is raised.
func TestAgentRunPolicyNeverWidensConfiguredLimits(t *testing.T) {
	t.Parallel()
	// Every ceiling is configured explicitly and non-zero, because zero means "use
	// the policy default" and a default could not show whether the request or the
	// configuration decided the value.
	env := newTestEnvWithAgentLimits(t, app.AgentConfig{
		MaxHops: 2, MaxBranches: 4, MaxToolCalls: 6,
		MaxExpansions: 1, TimeoutSeconds: 60, TokenBudget: 1000,
	}, agentTestAnswer)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})
	route := "/api/audits/" + audit.Audit.ID + "/runs"

	// The request asks for room the configuration does not have. The run is
	// accepted, but the policy recorded on it is the intersection.
	resp := startRun(t, ts, route, map[string]any{"policy": map[string]any{
		"max_hops": 99, "max_branches": 99, "max_tool_calls": 99,
		"max_expansions": 99, "timeout_seconds": 9999, "token_budget": 999999,
	}}, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("run = %d (%s)", resp.status, resp.body)
	}
	var batch runBatch
	resp.decode(t, &batch)
	got := batch.Runs[0].Exploration
	base := env.rt.Agent.Policy
	if got.MaxHops > base.MaxHops || got.MaxBranches > base.MaxBranches ||
		got.MaxToolCalls > base.MaxToolCalls || got.MaxExpansions > base.MaxExpansions ||
		got.TimeoutSeconds > base.TimeoutSeconds || got.TokenBudget > base.TokenBudget {
		t.Errorf("request widened the configured policy:\ngot  %+v\nbase %+v", got, base)
	}
	// Capped, not dropped: the request's own values are still the effective ones
	// where they are smaller.
	if got.MaxHops != base.MaxHops || got.TokenBudget != base.TokenBudget {
		t.Errorf("a requested limit was dropped instead of capped: %+v", got)
	}

	// A request that asks for less is honoured, which is the other half of the
	// same rule.
	narrow := startRun(t, ts, route, map[string]any{"policy": map[string]any{"max_tool_calls": 1}}, nil)
	if narrow.status != http.StatusOK {
		t.Fatalf("narrow run = %d (%s)", narrow.status, narrow.body)
	}
	var narrowBatch runBatch
	narrow.decode(t, &narrowBatch)
	if narrow := narrowBatch.Runs[0].Exploration.MaxToolCalls; narrow != 1 {
		t.Errorf("narrow request was not honoured: max_tool_calls = %d, want 1", narrow)
	}
}

func TestAgentRunThroughPathRouteAndEmptyQueue(t *testing.T) {
	t.Parallel()
	env := newTestEnvWithAgent(t, false, agentTestAnswer)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})
	pathID := pathIDOf(t, ts, audit.Audit.ID)

	// The path-scoped route resolves the path's audit and runs its next pick, so
	// the path in the URL only identifies the queue.
	resp := startRun(t, ts, "/api/paths/"+pathID+"/runs", map[string]any{}, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("path route run = %d (%s)", resp.status, resp.body)
	}
	var batch runBatch
	resp.decode(t, &batch)
	if batch.Count != 1 || batch.Runs[0].AuditID != audit.Audit.ID {
		t.Errorf("path route batch = %+v", batch)
	}

	// Draining the queue makes the next request a 404, not an empty 200: the
	// caller asked for work and there was none.
	for i := 0; i < 60; i++ {
		next := startRun(t, ts, "/api/audits/"+audit.Audit.ID+"/runs", map[string]any{"max_runs": 10}, nil)
		if next.status == http.StatusNotFound {
			var errBody errorResponse
			next.decode(t, &errBody)
			if errBody.Code != "not_found" {
				t.Errorf("empty queue code = %q, want not_found", errBody.Code)
			}
			return
		}
		if next.status != http.StatusOK {
			t.Fatalf("draining run %d = %d (%s)", i, next.status, next.body)
		}
	}
	t.Fatal("the queue never drained")
}

func TestAgentRunBudgetExceededWhenLeaseCeilingReached(t *testing.T) {
	t.Parallel()
	env := newTestEnvWithAgent(t, false, agentTestAnswer)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{
		"snapshot_id": snapID,
		"limits":      map[string]any{"max_active_leases": 1},
	})

	// One worker already holds the audit's only lease, so the agent cannot claim.
	pathID := pathIDOf(t, ts, audit.Audit.ID)
	claim := do(t, ts, http.MethodPost, "/api/paths/"+pathID+"/claim", map[string]any{"owner": "worker-a"}, nil)
	if claim.status != http.StatusOK {
		t.Fatalf("claim: %d %s", claim.status, claim.body)
	}
	resp := startRun(t, ts, "/api/audits/"+audit.Audit.ID+"/runs", map[string]any{}, nil)
	if resp.status != http.StatusConflict {
		t.Fatalf("run over the lease ceiling = %d, want 409 (%s)", resp.status, resp.body)
	}
	var errBody errorResponse
	resp.decode(t, &errBody)
	if errBody.Code != "budget_exceeded" {
		t.Errorf("code = %q, want budget_exceeded", errBody.Code)
	}
}

func TestAgentErrorsAndAuthentication(t *testing.T) {
	t.Parallel()
	env := newTestEnvWithAgent(t, false, agentTestAnswer)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})
	runResp := startRun(t, ts, "/api/audits/"+audit.Audit.ID+"/runs", map[string]any{}, nil)
	var batch runBatch
	runResp.decode(t, &batch)
	runID := batch.Runs[0].ID

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
		code   string
	}{
		{"unknown audit run", http.MethodPost, "/api/audits/audit-00000000000000000000000000000000/runs",
			map[string]any{}, http.StatusNotFound, "not_found"},
		{"unknown path run", http.MethodPost, "/api/paths/path-00000000000000000000000000000000/runs",
			map[string]any{}, http.StatusNotFound, "not_found"},
		{"unknown run", http.MethodGet, "/api/runs/run-00000000000000000000000000000000", nil, http.StatusNotFound, "not_found"},
		{"unknown run events", http.MethodGet, "/api/runs/run-00000000000000000000000000000000/events", nil, http.StatusNotFound, "not_found"},
		{"unknown hypothesis", http.MethodGet, "/api/hypotheses/hyp-00000000000000000000000000000000", nil, http.StatusNotFound, "not_found"},
		{"bad hypothesis status", http.MethodGet, "/api/hypotheses?status=nope", nil, http.StatusBadRequest, "invalid_request"},
		{"bad finding flag", http.MethodGet, "/api/hypotheses?finding_candidates=ture", nil, http.StatusBadRequest, "invalid_request"},
		{"negative offset", http.MethodGet, "/api/hypotheses?offset=-1", nil, http.StatusBadRequest, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(t, ts, tc.method, tc.path, tc.body, nil)
			if resp.status != tc.want {
				t.Fatalf("status = %d, want %d (%s)", resp.status, tc.want, resp.body)
			}
			var errBody errorResponse
			resp.decode(t, &errBody)
			if errBody.Code != tc.code {
				t.Errorf("code = %q, want %q (%s)", errBody.Code, tc.code, resp.body)
			}
		})
	}

	// Authentication and capability gates, both directions: starting a run spends
	// the audit's budget, so a reader may not do it.
	noToken := doAs(t, ts, "", http.MethodPost, "/api/audits/"+audit.Audit.ID+"/runs", map[string]any{}, nil)
	if noToken.status != http.StatusUnauthorized {
		t.Errorf("unauthenticated run = %d, want 401 (%s)", noToken.status, noToken.body)
	}
	readerPost := doAs(t, ts, readerSecret, http.MethodPost, "/api/audits/"+audit.Audit.ID+"/runs", map[string]any{}, nil)
	if readerPost.status != http.StatusForbidden {
		t.Errorf("reader run = %d, want 403 (%s)", readerPost.status, readerPost.body)
	}
	readerGet := doAs(t, ts, readerSecret, http.MethodGet, "/api/runs", nil, nil)
	if readerGet.status != http.StatusOK {
		t.Errorf("reader runs list = %d, want 200 (%s)", readerGet.status, readerGet.body)
	}
	readerShow := doAs(t, ts, readerSecret, http.MethodGet, "/api/runs/"+runID, nil, nil)
	if readerShow.status != http.StatusOK {
		t.Errorf("reader run show = %d, want 200 (%s)", readerShow.status, readerShow.body)
	}

	// A server without the orchestrator says so instead of answering "gone".
	bare := NewServer(env.rt.Store, env.rt.Manager, env.rt.Analyzer,
		WithAuth(testAuthenticator(t)),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	bareTS := httptest.NewServer(bare.Handler())
	defer bareTS.Close()
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/api/audits/" + audit.Audit.ID + "/runs", map[string]any{}},
		{http.MethodPost, "/api/paths/" + pathIDOf(t, ts, audit.Audit.ID) + "/runs", map[string]any{}},
		{http.MethodGet, "/api/runs", nil},
		{http.MethodGet, "/api/hypotheses", nil},
	} {
		resp := do(t, bareTS, tc.method, tc.path, tc.body, nil)
		if resp.status != http.StatusNotImplemented {
			t.Fatalf("%s %s = %d, want 501 (%s)", tc.method, tc.path, resp.status, resp.body)
		}
		var errBody errorResponse
		resp.decode(t, &errBody)
		if errBody.Code != "agent_unavailable" {
			t.Errorf("code = %q, want agent_unavailable", errBody.Code)
		}
		if !strings.Contains(errBody.Error, "--agent-runtime") {
			t.Errorf("agent_unavailable is not actionable: %q", errBody.Error)
		}
	}
}

// isSubsequence reports whether want appears in got in order. The log may hold
// additional events (a heartbeat, a note); the protocol's own steps must be there
// and in order.
func isSubsequence(want, got []string) bool {
	i := 0
	for _, value := range got {
		if i < len(want) && value == want[i] {
			i++
		}
	}
	return i == len(want)
}

// strconvFormat renders a sequence number for a URL.
func strconvFormat(value int64) string {
	return strconv.FormatInt(value, 10)
}
