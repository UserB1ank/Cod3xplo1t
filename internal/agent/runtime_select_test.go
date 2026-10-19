package agent

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
)

// selectionRuntime answers immediately; it exists to prove which adapter the
// runner selected, not to exercise the loop.
func selectionRuntime(t *testing.T, name string, used *atomic.Int32) *turnTestRuntime {
	t.Helper()
	fixture := aliasFixtureTask()
	answer, err := json.Marshal(Answer{
		SchemaVersion: SchemaVersionObligations,
		SecurityGoal:  fixture.SecurityGoal,
		Hypothesis:    HypothesisDraft{Statement: "selection test", Status: HypothesisInconclusive, Confidence: "low"},
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
	return &turnTestRuntime{name: name, script: func(ctx context.Context, _ Task, events chan<- RuntimeEvent, done chan<- RuntimeResult) {
		used.Add(1)
		permitReply := make(chan PermitDecision, 1)
		events <- RuntimeEvent{Type: EventModelPermitRequested, Permit: &PermitRequest{
			RequestID: "req-1", Generation: RunGeneration(ctx), InputTokensEstimate: 10, MaxOutputTokens: 10,
		}, PermitReply: permitReply}
		if decision := <-permitReply; decision.Decision != DecisionContinue {
			done <- RuntimeResult{ExitCode: 1, Err: ErrTurnDenied}
			return
		}
		answerReply := make(chan AnswerDecision, 1)
		events <- RuntimeEvent{Type: EventAnswerProposed, Proposal: &AnswerProposal{RequestID: "req-1", Raw: answer}, ProposalReply: answerReply}
		if decision := <-answerReply; decision.Decision == DecisionAccepted {
			done <- RuntimeResult{ExitCode: 0}
			return
		}
		done <- RuntimeResult{ExitCode: 1, Err: ErrTurnDenied}
	}}
}

func TestRunnerSelectsTheTaskRuntimeAndPinsIt(t *testing.T) {
	fixture := aliasFixtureTask()
	fixture.Exploration.AllowedTools = []string{"graph.query"}
	var alphaUsed, betaUsed atomic.Int32
	alpha := selectionRuntime(t, "alpha", &alphaUsed)
	beta := selectionRuntime(t, "beta", &betaUsed)
	registry := NewRegistry()
	registry.Register(&runnerTestTool{name: "graph.query", result: `{"ok":true}`})
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	runner := runnerTestRunner(store, paths, &aliasTaskBuilder{task: fixture}, alpha, registry, fixture.Exploration)
	runner.Runtimes = map[string]Runtime{"alpha": alpha, "beta": beta}
	runner.DefaultRuntime = "alpha"
	runner.RuntimeFor = func(string) string { return "beta" }

	run, err := runner.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s (%q)", run.Status, run.Error)
	}
	if betaUsed.Load() != 1 || alphaUsed.Load() != 0 {
		t.Fatalf("runtime use = alpha %d / beta %d, want the task's beta only", alphaUsed.Load(), betaUsed.Load())
	}
	if run.Runtime != "beta" {
		t.Errorf("run runtime = %q, want beta", run.Runtime)
	}
	if run.Pin == nil || run.Pin.Runtime != "beta" || run.Pin.PromptVersion != PromptVersion {
		t.Fatalf("run pin = %+v", run.Pin)
	}
	if run.Pin.ToolSchemaDigest == "" {
		t.Error("the run pin has no tool schema digest")
	}
}

func TestRunnerRejectsAnUnknownSelectedRuntime(t *testing.T) {
	fixture := aliasFixtureTask()
	var used atomic.Int32
	alpha := selectionRuntime(t, "alpha", &used)
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	runner := runnerTestRunner(store, paths, &aliasTaskBuilder{task: fixture}, alpha, NewRegistry(), fixture.Exploration)
	runner.Runtimes = map[string]Runtime{"alpha": alpha}
	runner.DefaultRuntime = "alpha"
	runner.RuntimeFor = func(string) string { return "pi" }

	_, err := runner.RunOnce(context.Background(), "audit-1")
	if err == nil {
		t.Fatal("an unknown runtime was selected")
	}
	if used.Load() != 0 {
		t.Fatal("the default runtime ran despite an unknown selection")
	}
}
