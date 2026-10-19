package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// aliasTaskBuilder delivers the fixture task for path-1, which is what makes the
// alias expectations below stable.
type aliasTaskBuilder struct{ task Task }

func (b *aliasTaskBuilder) BuildTask(_ context.Context, _ path.Path, _ ExplorationPolicy) (Task, error) {
	return b.task, nil
}

func TestRunnerResolvesAliasesAndProjectsResults(t *testing.T) {
	fixture := aliasFixtureTask()
	answer, err := json.Marshal(Answer{
		SchemaVersion: SchemaVersionObligations,
		SecurityGoal:  fixture.SecurityGoal,
		Hypothesis: HypothesisDraft{
			Statement: "the id parameter reaches the query unvalidated",
			Status:    HypothesisInconclusive, Confidence: "low",
		},
		Obligations: []ObligationVerdict{
			{Kind: ObligationSource, Verdict: VerdictUnknown, Blocker: BlockerBudget, Reason: "no budget left"},
			{Kind: ObligationFlow, Verdict: VerdictUnknown, Blocker: BlockerBudget, Reason: "no budget left"},
			{Kind: ObligationControl, Verdict: VerdictUnknown, Blocker: BlockerBudget, Reason: "no budget left"},
			{Kind: ObligationSink, Verdict: VerdictUnknown, Blocker: BlockerBudget, Reason: "no budget left"},
		},
		SupportingEvidence:    []AnswerEvidence{{Kind: "call_site", Ref: "E1", Summary: "the input reaches the query"}},
		ContradictingEvidence: []AnswerEvidence{},
		NextAction:            "stop",
	})
	if err != nil {
		t.Fatal(err)
	}

	var modelToolResult string
	runtime := &turnTestRuntime{name: "alias-test", script: func(ctx context.Context, _ Task, events chan<- RuntimeEvent, done chan<- RuntimeResult) {
		permitReply := make(chan PermitDecision, 1)
		events <- RuntimeEvent{Type: EventModelPermitRequested, Permit: &PermitRequest{
			RequestID: "req-1", Generation: RunGeneration(ctx), InputTokensEstimate: 10, MaxOutputTokens: 10,
		}, PermitReply: permitReply}
		if decision := <-permitReply; decision.Decision != DecisionContinue {
			done <- RuntimeResult{ExitCode: 1, Err: ErrTurnDenied}
			return
		}
		toolReply := make(chan ToolResult, 1)
		events <- RuntimeEvent{Type: EventToolRequested, Tool: &ToolRequest{
			CallID: "model-0", Tool: "graph.query", Args: map[string]string{"symbol_id": "S1", "query": "S1"},
		}, ToolReply: toolReply}
		result := <-toolReply
		modelToolResult = result.Result
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
	tool := &runnerTestTool{name: "graph.query", result: `{"id":"entry-1","refs":["entry-1","fact-1"],"summary":"entry-1 is the entry"}`}
	registry := NewRegistry()
	registry.Register(tool)
	run, err := runnerTestRunner(store, paths, &aliasTaskBuilder{task: fixture}, runtime, registry, runnerTestPolicy()).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s, want SUCCEEDED (%q)", run.Status, run.Error)
	}

	// The tool received canonical ids; free text was not rewritten.
	if len(tool.args) != 1 {
		events, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Limit: 50})
		for _, event := range events {
			t.Logf("event %s %s %v", event.Type, event.Summary, event.Detail)
		}
		t.Fatalf("tool calls = %d, want 1", len(tool.args))
	}
	if got := tool.args[0]["symbol_id"]; got != "entry-1" {
		t.Errorf("tool symbol_id = %q, want canonical entry-1", got)
	}
	if got := tool.args[0]["query"]; got != "S1" {
		t.Errorf("free-text query = %q, want S1 untouched", got)
	}

	// The model sees aliases, including in the tool result.
	if !strings.Contains(modelToolResult, `"id":"S1"`) || !strings.Contains(modelToolResult, `"refs":["S1","E1"]`) {
		t.Fatalf("tool result was not projected: %s", modelToolResult)
	}
	if !strings.Contains(modelToolResult, `"summary":"entry-1 is the entry"`) {
		t.Fatalf("free text in the tool result was rewritten: %s", modelToolResult)
	}

	// The stored answer carries the canonical evidence id, not the alias.
	if run.Answer == nil || len(run.Answer.SupportingEvidence) != 1 {
		t.Fatalf("answer = %+v", run.Answer)
	}
	if got := run.Answer.SupportingEvidence[0].Ref; got != "fact-1" {
		t.Errorf("stored evidence ref = %q, want canonical fact-1", got)
	}
	if run.Aliases == nil || run.Aliases.Version != AliasTableVersion {
		t.Fatalf("run has no persisted alias table: %+v", run.Aliases)
	}
}
