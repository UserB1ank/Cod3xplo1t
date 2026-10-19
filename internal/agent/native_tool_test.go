package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// recordingTool captures what the host actually executed: the resolved native
// arguments and the trusted scope. It is the observation point for scope
// injection and alias resolution.
type recordingTool struct {
	mu     sync.Mutex
	calls  int
	args   []map[string]any
	scopes []ToolScope
}

func (t *recordingTool) Name() string     { return "graph.query" }
func (t *recordingTool) Describe() string { return "records native calls" }
func (t *recordingTool) Descriptor() ToolDescriptor {
	return ToolDescriptor{
		Name: t.Name(), Description: t.Describe(), Version: "1",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"symbol_id":{"type":"string"},"max_depth":{"type":"integer"}},"additionalProperties":false}`),
	}
}

func (t *recordingTool) Call(ctx context.Context, raw json.RawMessage) (ToolResult, error) {
	var args map[string]any
	_ = json.Unmarshal(raw, &args)
	t.mu.Lock()
	t.calls++
	t.args = append(t.args, args)
	t.scopes = append(t.scopes, ToolScopeFrom(ctx))
	t.mu.Unlock()
	return ToolResult{OK: true, Result: `{"edge":"sink"}`, Refs: []string{"sym-1"}}, nil
}

func runNativeToolScenario(t *testing.T, request func(ctx context.Context) *ToolRequest, budget int) (*Run, *recordingTool, string) {
	t.Helper()
	fixture := aliasFixtureTask()
	fixture.Exploration.TokenBudget = budget
	fixture.Budget.TokenBudget = budget
	answer, err := json.Marshal(Answer{
		SchemaVersion: SchemaVersionObligations,
		SecurityGoal:  fixture.SecurityGoal,
		Hypothesis:    HypothesisDraft{Statement: "scope and receipt test", Status: HypothesisInconclusive, Confidence: "low"},
		Obligations: []ObligationVerdict{
			{Kind: ObligationSource, Verdict: VerdictUnknown, Blocker: BlockerBudget, Reason: "test"},
			{Kind: ObligationFlow, Verdict: VerdictUnknown, Blocker: BlockerBudget, Reason: "test"},
			{Kind: ObligationControl, Verdict: VerdictUnknown, Blocker: BlockerBudget, Reason: "test"},
			{Kind: ObligationSink, Verdict: VerdictUnknown, Blocker: BlockerBudget, Reason: "test"},
		},
		NextAction: "stop",
	})
	if err != nil {
		t.Fatal(err)
	}
	tool := &recordingTool{}
	modelResult := ""
	runtime := &turnTestRuntime{name: "native-test", script: func(ctx context.Context, _ Task, events chan<- RuntimeEvent, done chan<- RuntimeResult) {
		permitReply := make(chan PermitDecision, 1)
		events <- RuntimeEvent{Type: EventModelPermitRequested, Permit: &PermitRequest{
			RequestID: "req-1", Generation: RunGeneration(ctx), InputTokensEstimate: 10, MaxOutputTokens: 10,
		}, PermitReply: permitReply}
		if decision := <-permitReply; decision.Decision != DecisionContinue {
			done <- RuntimeResult{ExitCode: 1, Err: ErrTurnDenied}
			return
		}
		toolReply := make(chan ToolResult, 1)
		events <- RuntimeEvent{Type: EventToolRequested, Tool: request(ctx), ToolReply: toolReply}
		modelResult = (<-toolReply).Result
		answerReply := make(chan AnswerDecision, 1)
		events <- RuntimeEvent{Type: EventAnswerProposed, Proposal: &AnswerProposal{RequestID: "req-1", Raw: answer}, ProposalReply: answerReply}
		if decision := <-answerReply; decision.Decision == DecisionAccepted {
			done <- RuntimeResult{ExitCode: 0}
			return
		}
		done <- RuntimeResult{ExitCode: 1, Err: ErrTurnDenied}
	}}
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	registry := NewRegistry()
	registry.Register(tool)
	run, err := runnerTestRunner(store, paths, &aliasTaskBuilder{task: fixture}, runtime, registry, fixture.Exploration).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return run, tool, modelResult
}

func TestNativeToolInjectsScopeAndReportsBudget(t *testing.T) {
	run, tool, result := runNativeToolScenario(t, func(context.Context) *ToolRequest {
		return &ToolRequest{CallID: "model-0", Tool: "graph.query", Args: json.RawMessage(`{"symbol_id":"S1"}`)}
	}, 1000)
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s (%q)", run.Status, run.Error)
	}
	if tool.calls != 1 {
		t.Fatalf("tool calls = %d, want 1", tool.calls)
	}
	if got := tool.args[0]["symbol_id"]; got != "entry-1" {
		t.Errorf("symbol_id = %v, want the canonical alias target", got)
	}
	scope := tool.scopes[0]
	if scope.SnapshotID != "snap-1" || scope.PathID != "path-1" || scope.AuditID != "audit-1" || scope.RunID == "" {
		t.Errorf("scope = %+v, want the task's trusted scope", scope)
	}
	var envelope ToolResultEnvelope
	if err := json.Unmarshal([]byte(result), &envelope); err != nil {
		t.Fatalf("model result is not the host envelope: %v (%s)", err, result)
	}
	if !envelope.OK || !strings.Contains(envelope.Result, "edge") {
		t.Fatalf("envelope payload = %+v", envelope)
	}
	budget := envelope.Budget
	if budget == nil {
		t.Fatal("the tool result carries no budget receipt")
	}
	if budget.CallsLeft != 29 || budget.RepairsLeft != 2 || budget.ObligationsTotal != 4 || budget.ObligationsClosed != 0 {
		t.Errorf("receipt = %+v", budget)
	}
	if !budget.BudgetEnforced || budget.UsageSource != MetricsSourceReported {
		t.Errorf("receipt mode = %+v, want enforced and reported", budget)
	}
	// 1000 budget, 20 reserved by the permit, nothing spent: the model must see
	// what it can still spend, not the unreserved total.
	if budget.TokensLeft == nil || *budget.TokensLeft != 980 {
		t.Errorf("tokens_left = %v, want 980", budget.TokensLeft)
	}
}

func TestNativeToolRejectsClientScope(t *testing.T) {
	run, tool, result := runNativeToolScenario(t, func(context.Context) *ToolRequest {
		return &ToolRequest{CallID: "model-0", Tool: "graph.query", Args: json.RawMessage(`{"symbol_id":"S1","snapshot_id":"snap-evil"}`)}
	}, 0)
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s (%q)", run.Status, run.Error)
	}
	if tool.calls != 0 {
		t.Fatalf("tool calls = %d, want 0: a client-supplied scope field must never reach a tool", tool.calls)
	}
	if run.Metrics == nil || run.Metrics.InvalidCalls != 1 {
		t.Fatalf("invalid calls = %+v, want 1", run.Metrics)
	}
	if !strings.Contains(result, "unknown argument") {
		t.Fatalf("the model did not receive the schema rejection: %s", result)
	}
}

func TestNativeToolConvertsLegacyArguments(t *testing.T) {
	run, tool, _ := runNativeToolScenario(t, func(context.Context) *ToolRequest {
		return &ToolRequest{CallID: "model-0", Tool: "graph.query", LegacyArgs: map[string]string{"symbol_id": "S1", "max_depth": "2"}}
	}, 0)
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s (%q)", run.Status, run.Error)
	}
	if tool.calls != 1 {
		t.Fatalf("tool calls = %d, want 1", tool.calls)
	}
	if tool.args[0]["symbol_id"] != "entry-1" || tool.args[0]["max_depth"] != float64(2) {
		t.Fatalf("converted args = %+v, want canonical symbol and integer depth", tool.args[0])
	}
}
