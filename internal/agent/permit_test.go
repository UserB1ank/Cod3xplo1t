package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
)

// Turn control is the host's single authority over provider requests, answer
// acceptance and corrections. These tests pin the contract the Pi worker will
// consume in #58: nothing reaches the provider without a permit, nothing becomes
// the run's answer without host acceptance, and the counters say which of the two
// worlds produced them.

func runTurnScenario(t *testing.T, policy ExplorationPolicy, responses ...string) (*Run, *repairProvider, *runnerTestStore) {
	t.Helper()
	provider, server := newRepairProvider(t, responses...)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	update := llm.Update{
		Enabled: true, Protocol: "chat-completions", BaseURL: server.URL,
		Model: "test-model", TimeoutSeconds: 5, MaxOutputTokens: 1024,
	}
	if _, err := settings.Save(update, agentPublicVersion(t, settings)); err != nil {
		t.Fatal(err)
	}
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	registry := NewRegistry()
	registry.Register(&runnerTestTool{name: "graph.query", result: "edge-list"})
	runtime := &ModelRuntime{Settings: settings, Tools: []ToolDescriptor{testToolDescriptor("graph.query")}}
	run, err := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, registry, policy).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return run, provider, store
}

func TestTurnControlCountsRealRoundsAndRepairs(t *testing.T) {
	run, provider, store := runTurnScenario(t, runnerTestPolicy(),
		chatAnswerRaw(`{"schema_version":1,"unexpected":true}`),
		chatAnswer(runnerTestAnswer()),
	)
	if run.Status != RunSucceeded || run.StopReason != StopCompleted {
		t.Fatalf("run = %s/%s, want SUCCEEDED/completed (%q)", run.Status, run.StopReason, run.Error)
	}
	if provider.count() != 2 {
		t.Fatalf("provider requests = %d, want 2 (one corrected answer)", provider.count())
	}
	metrics := run.Metrics
	if metrics == nil || metrics.Source != MetricsSourceReported {
		t.Fatalf("metrics source = %+v, want reported", metrics)
	}
	if metrics.ModelRequests != 2 || metrics.Rounds != 2 {
		t.Errorf("model requests/rounds = %d/%d, want 2/2", metrics.ModelRequests, metrics.Rounds)
	}
	if metrics.Repairs != 1 {
		t.Errorf("repairs = %d, want 1", metrics.Repairs)
	}
	events, err := store.ListRunEvents(EventQuery{RunID: run.ID, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var repaired, accepted bool
	for _, event := range events {
		switch event.Type {
		case EventAnswerRepairAsked:
			repaired = true
		case EventAnswerAccepted:
			accepted = true
		}
	}
	if !repaired || !accepted {
		t.Fatalf("events = %v, want a repair request and an acceptance", eventTypes(events))
	}
}

func TestTurnControlStopsBeforeAnOversizedRequest(t *testing.T) {
	policy := runnerTestPolicy()
	policy.TokenBudget = 100 // smaller than the estimate plus the output limit
	run, provider, _ := runTurnScenario(t, policy, chatAnswer(runnerTestAnswer()))
	if provider.count() != 0 {
		t.Fatalf("provider requests = %d, want 0: the permit must be refused before the request", provider.count())
	}
	if run.Status != RunPaused || run.StopReason != StopBudgetPaused {
		t.Fatalf("run = %s/%s, want PAUSED/budget_paused", run.Status, run.StopReason)
	}
	if run.Metrics == nil || run.Metrics.Source != MetricsSourceReported {
		t.Fatalf("metrics = %+v, want a reported source even when the request was refused", run.Metrics)
	}
	if run.Metrics.ModelRequests != 0 {
		t.Errorf("model requests = %d, want 0", run.Metrics.ModelRequests)
	}
}

func TestTurnControlStopsAfterTheRepairBudget(t *testing.T) {
	invalid := chatAnswerRaw(`{"schema_version":1,"unexpected":true}`)
	run, provider, _ := runTurnScenario(t, runnerTestPolicy(), invalid, invalid, invalid)
	if provider.count() != 3 {
		t.Fatalf("provider requests = %d, want 3 (1 attempt + 2 repairs)", provider.count())
	}
	if run.Status != RunInvalidOutput || run.StopReason != StopInvalidOutput {
		t.Fatalf("run = %s/%s, want INVALID_OUTPUT/invalid_output", run.Status, run.StopReason)
	}
	if run.Metrics == nil || run.Metrics.Repairs != 2 || run.Metrics.ModelRequests != 3 {
		t.Fatalf("metrics = %+v, want repairs 2 and model requests 3", run.Metrics)
	}
}

// turnTestRuntime emits one permit and lets the test decide what follows. It is
// the smallest adapter that speaks turn control, which is what makes the counters
// and the fencing testable without a provider.
type turnTestRuntime struct {
	name   string
	script func(ctx context.Context, task Task, events chan<- RuntimeEvent, done chan<- RuntimeResult)
}

func (rt *turnTestRuntime) Capabilities() RuntimeCapabilities {
	return RuntimeCapabilities{Name: rt.name, Version: "1", ToolCalls: true, TurnControl: true, TokenUsage: true}
}

func (rt *turnTestRuntime) Start(ctx context.Context, task Task) (*Handle, error) {
	events := make(chan RuntimeEvent, 8)
	done := make(chan RuntimeResult, 1)
	go func() {
		defer close(events)
		defer close(done)
		rt.script(ctx, task, events, done)
	}()
	return &Handle{Events: events, Done: done, Cancel: func() {}}, nil
}

func TestTurnControlIgnoresDuplicateUsage(t *testing.T) {
	answer, _ := json.Marshal(runnerTestAnswer())
	runtime := &turnTestRuntime{name: "turn-test", script: func(ctx context.Context, _ Task, events chan<- RuntimeEvent, done chan<- RuntimeResult) {
		permitReply := make(chan PermitDecision, 1)
		events <- RuntimeEvent{Type: EventModelPermitRequested, Permit: &PermitRequest{
			RequestID: "req-1", Generation: RunGeneration(ctx), InputTokensEstimate: 10, MaxOutputTokens: 10,
		}, PermitReply: permitReply}
		if decision := <-permitReply; decision.Decision != DecisionContinue {
			done <- RuntimeResult{ExitCode: 1, Err: ErrTurnDenied}
			return
		}
		// The same request reports usage twice; the second report is a duplicate,
		// not a second bill.
		events <- RuntimeEvent{Type: runtimeEventNote, RequestID: "req-1", InputTokens: 100, OutputTokens: 50}
		events <- RuntimeEvent{Type: runtimeEventNote, RequestID: "req-1", InputTokens: 100, OutputTokens: 50}
		answerReply := make(chan AnswerDecision, 1)
		events <- RuntimeEvent{Type: EventAnswerProposed, Proposal: &AnswerProposal{RequestID: "req-1", Raw: answer}, ProposalReply: answerReply}
		if decision := <-answerReply; decision.Decision == DecisionAccepted {
			done <- RuntimeResult{ExitCode: 0}
			return
		}
		done <- RuntimeResult{ExitCode: 1, Err: ErrTurnDenied}
	}}
	run := runTurnRuntime(t, runtime)
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s, want SUCCEEDED (%q)", run.Status, run.Error)
	}
	if run.InputTokens != 100 || run.OutputTokens != 50 {
		t.Fatalf("tokens = %d/%d, want 100/50: duplicate usage must not be billed twice", run.InputTokens, run.OutputTokens)
	}
}

func TestTurnControlRejectsStaleGeneration(t *testing.T) {
	runtime := &turnTestRuntime{name: "stale", script: func(ctx context.Context, _ Task, events chan<- RuntimeEvent, done chan<- RuntimeResult) {
		permitReply := make(chan PermitDecision, 1)
		events <- RuntimeEvent{Type: EventModelPermitRequested, Permit: &PermitRequest{
			RequestID: "req-1", Generation: RunGeneration(ctx) + 1, InputTokensEstimate: 10, MaxOutputTokens: 10,
		}, PermitReply: permitReply}
		decision := <-permitReply
		if decision.Decision == DecisionContinue {
			t.Error("a stale generation was permitted")
		}
		done <- RuntimeResult{ExitCode: 1, Err: ErrTurnDenied}
	}}
	run := runTurnRuntime(t, runtime)
	if run.Status != RunInvalidOutput {
		t.Fatalf("run = %s, want INVALID_OUTPUT for a stale generation (%q)", run.Status, run.Error)
	}
}

func runTurnRuntime(t *testing.T, runtime *turnTestRuntime) *Run {
	t.Helper()
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	run, err := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), runnerTestPolicy()).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return run
}

func eventTypes(events []Event) []string {
	out := make([]string, 0, len(events))
	for _, event := range events {
		out = append(out, event.Type)
	}
	return out
}
