package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// schemaTwoTaskBuilder delivers the obligation fixture so the falsifier rules run
// against a real schema 2 task with input evidence.
type schemaTwoTaskBuilder struct{ task Task }

func (b schemaTwoTaskBuilder) BuildTask(_ context.Context, p path.Path, policy ExplorationPolicy) (Task, error) {
	task := b.task
	task.SnapshotID, task.PathID, task.AuditID = p.SnapshotID, p.ID, p.AuditID
	task.Exploration = policy
	return task, nil
}

func runFalsifierScenario(t *testing.T, responses ...string) (*Run, *repairProvider) {
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
	task := aliasFixtureTask()
	task.Exploration = runnerTestPolicy()
	task.Exploration.AllowedTools = []string{"graph.query"}
	run, err := runnerTestRunner(store, paths, schemaTwoTaskBuilder{task: task}, runtime, registry, runnerTestPolicy()).RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return run, provider
}

func falsifierAnswer(how []string, checked bool) Answer {
	answer := checklistAnswer()
	answer.SecurityGoal = aliasFixtureTask().SecurityGoal
	answer.Hypothesis.Statement = "the id parameter reaches the query"
	answer.Falsifier = &Falsifier{Claim: "the value is validated before the query", Checked: checked, How: how}
	return answer
}

func TestFalsifierNeedsTheNewFieldForSchemaTwoConclusions(t *testing.T) {
	task := aliasFixtureTask()
	answer := checklistAnswer()
	answer.Falsifier = nil
	raw, _ := json.Marshal(answer)
	if _, err := DecodeAnswer(raw, task); !errors.Is(err, ErrInvalidAnswer) || !strings.Contains(err.Error(), "falsifier") {
		t.Fatalf("candidate without a falsifier: %v, want invalid answer naming falsifier", err)
	}

	refuted := checklistAnswer()
	refuted.Hypothesis.Status = HypothesisRefuted
	refuted.Falsifier = nil
	raw, _ = json.Marshal(refuted)
	if _, err := DecodeAnswer(raw, task); err == nil {
		t.Fatal("refuted answer without a falsifier was accepted")
	}

	checked := checklistAnswer()
	checked.Falsifier = &Falsifier{Claim: "a parameterised call", Checked: true}
	raw, _ = json.Marshal(checked)
	if _, err := DecodeAnswer(raw, task); err == nil || !strings.Contains(err.Error(), "how") {
		t.Fatalf("checked=true without how: %v, want a how requirement", err)
	}

	inconclusive := checklistAnswer()
	inconclusive.SecurityGoal = task.SecurityGoal
	inconclusive.Hypothesis.Status = HypothesisInconclusive
	verdicts := closedVerdicts()
	for index := range verdicts {
		verdicts[index].Verdict = VerdictUnknown
		verdicts[index].Blocker = BlockerExternalDependency
	}
	inconclusive.Obligations = verdicts
	inconclusive.Falsifier = nil
	raw, _ = json.Marshal(inconclusive)
	if _, err := DecodeAnswer(raw, task); err != nil {
		t.Fatalf("inconclusive answer without a falsifier: %v", err)
	}
}

func TestFalsifierResolvesInputEvidenceAndAliases(t *testing.T) {
	run, provider := runFalsifierScenario(t, chatAnswer(falsifierAnswer([]string{"fact-1"}, true)))
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s (%q)", run.Status, run.Error)
	}
	if provider.count() != 1 {
		t.Fatalf("provider requests = %d, want 1", provider.count())
	}
	if run.Answer == nil || run.Answer.Falsifier == nil || !run.Answer.Falsifier.Checked {
		t.Fatalf("stored answer = %+v, want the checked falsifier", run.Answer)
	}

	// The model speaks in aliases; the host stores the canonical evidence id.
	run, _ = runFalsifierScenario(t, chatAnswer(falsifierAnswer([]string{"E1"}, true)))
	if run.Status != RunSucceeded {
		t.Fatalf("alias answer run = %s (%q)", run.Status, run.Error)
	}
	if run.Answer.Falsifier.How[0] != "fact-1" {
		t.Fatalf("stored how = %v, want fact-1", run.Answer.Falsifier.How)
	}
}

func TestFalsifierWithAnUnprovableReferenceGetsRepaired(t *testing.T) {
	run, provider := runFalsifierScenario(t,
		chatAnswer(falsifierAnswer([]string{"call-from-another-run"}, true)),
		chatAnswer(falsifierAnswer([]string{"fact-1"}, true)),
	)
	if run.Status != RunSucceeded || run.StopReason != StopCompleted {
		t.Fatalf("run = %s/%s (%q)", run.Status, run.StopReason, run.Error)
	}
	if provider.count() != 2 {
		t.Fatalf("provider requests = %d, want 2 (one repair)", provider.count())
	}
	if run.Metrics == nil || run.Metrics.Repairs != 1 {
		t.Fatalf("repairs = %+v, want 1", run.Metrics)
	}
}

func TestFalsifierRepairExhaustionInvalidOutput(t *testing.T) {
	responses := []string{
		chatAnswer(falsifierAnswer([]string{"call-missing"}, true)),
		chatAnswer(falsifierAnswer([]string{"call-missing"}, true)),
		chatAnswer(falsifierAnswer([]string{"call-missing"}, true)),
	}
	run, provider := runFalsifierScenario(t, responses...)
	if run.Status != RunInvalidOutput || run.StopReason != StopInvalidOutput {
		t.Fatalf("run = %s/%s (%q), want INVALID_OUTPUT", run.Status, run.StopReason, run.Error)
	}
	if provider.count() != 3 {
		t.Fatalf("provider requests = %d, want 3 (two repairs and a rejection)", provider.count())
	}
}

func TestFalsifierRejectsFailedAndDeniedCallReferences(t *testing.T) {
	session := &runnerSession{
		task:         Task{EvidenceRefs: []EvidenceRef{{ID: "fact-1"}}},
		batchResults: map[string]batchCallRecord{},
	}
	session.batchResults["call-ok"] = batchCallRecord{Result: ToolResult{OK: true}}
	session.batchResults["call-failed"] = batchCallRecord{Result: ToolResult{OK: false, Error: "tool returned no result"}}
	session.batchResults["call-denied"] = batchCallRecord{Result: ToolResult{OK: false, Error: "denied"}}

	answer := func(how string) *Answer {
		return &Answer{Falsifier: &Falsifier{Checked: true, How: []string{how}}}
	}
	if err := session.checkFalsifier(answer("call-ok")); err != nil {
		t.Fatalf("successful call rejected: %v", err)
	}
	if err := session.checkFalsifier(answer("fact-1")); err != nil {
		t.Fatalf("input evidence rejected: %v", err)
	}
	for _, ref := range []string{"call-failed", "call-denied", "call-from-another-run"} {
		if err := session.checkFalsifier(answer(ref)); err == nil {
			t.Errorf("falsifier.how %q was accepted, want a rejection", ref)
		}
	}
}
