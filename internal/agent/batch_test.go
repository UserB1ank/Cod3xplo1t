package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
)

// delayedTool answers after a per-symbol delay, so a two-call batch can prove that
// calls run concurrently while their results still pair in source order.
type delayedTool struct {
	name   string
	delays map[string]time.Duration
	mu     sync.Mutex
	order  []string
}

func (t *delayedTool) Name() string     { return t.name }
func (t *delayedTool) Describe() string { return "delayed test tool" }
func (t *delayedTool) Descriptor() ToolDescriptor {
	return ToolDescriptor{
		Name: t.name, Description: t.Describe(), Version: "1",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"symbol":{"type":"string"}},"additionalProperties":false}`),
	}
}

func (t *delayedTool) Call(_ context.Context, raw json.RawMessage) (ToolResult, error) {
	var args map[string]string
	_ = json.Unmarshal(raw, &args)
	symbol := args["symbol"]
	time.Sleep(t.delays[symbol])
	t.mu.Lock()
	t.order = append(t.order, symbol)
	t.mu.Unlock()
	return ToolResult{OK: true, Result: fmt.Sprintf(`{"symbol":%q}`, symbol)}, nil
}

func runBatchScenario(t *testing.T, policy ExplorationPolicy, tool ToolExecutor, responses ...string) (*Run, *repairProvider, *runnerTestStore) {
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
	registry := NewRegistry()
	registry.Register(tool)
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	runtime := &ModelRuntime{Settings: settings, Tools: []ToolDescriptor{tool.Descriptor()}}
	run, err := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, registry, policy).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return run, provider, store
}

func batchCall(id, symbol string) map[string]any {
	return map[string]any{
		"id": id, "type": "function",
		"function": map[string]string{"name": "graph.query", "arguments": fmt.Sprintf(`{"symbol":%q}`, symbol)},
	}
}

func TestBatchReservesBudgetInSourceOrder(t *testing.T) {
	policy := runnerTestPolicy()
	policy.MaxToolCalls = 2
	run, provider, store := runBatchScenario(t, policy, &runnerTestTool{name: "graph.query", result: "edge-list"},
		chatToolCalls(batchCall("call-a", "a"), batchCall("call-b", "b"), batchCall("call-c", "c")),
		chatAnswer(runnerTestAnswer()),
	)
	if run.Status != RunBudgetExceeded || run.StopReason != StopToolBudget {
		t.Fatalf("run = %s/%s, want BUDGET_EXCEEDED/%s", run.Status, run.StopReason, StopToolBudget)
	}
	if run.ToolCalls != 2 {
		t.Fatalf("tool calls = %d, want 2", run.ToolCalls)
	}
	if provider.count() != 1 {
		t.Fatalf("provider requests = %d, want 1: the run must stop before the next request", provider.count())
	}
	events, err := store.ListRunEvents(EventQuery{RunID: run.ID, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	denied := 0
	for _, event := range events {
		if event.Type == EventToolDenied && event.CallID == "call-c" {
			denied++
			if !strings.Contains(event.Summary, "budget") {
				t.Errorf("denial reason = %q, want budget", event.Summary)
			}
		}
	}
	if denied != 1 {
		t.Fatalf("call-c denials = %d, want 1", denied)
	}
}

func TestBatchOverTheTurnLimitDeniesEveryCall(t *testing.T) {
	policy := runnerTestPolicy()
	policy.MaxCallsPerTurn = 2
	run, provider, store := runBatchScenario(t, policy, &runnerTestTool{name: "graph.query", result: "edge-list"},
		chatToolCalls(batchCall("call-a", "a"), batchCall("call-b", "b"), batchCall("call-c", "c")),
		chatAnswer(runnerTestAnswer()),
	)
	if run.Status != RunSucceeded || run.ToolCalls != 0 {
		t.Fatalf("run = %s calls=%d, want SUCCEEDED with no executed call", run.Status, run.ToolCalls)
	}
	if provider.count() != 2 {
		t.Fatalf("provider requests = %d, want 2 (the model gets paired denials)", provider.count())
	}
	events, err := store.ListRunEvents(EventQuery{RunID: run.ID, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, callID := range []string{"call-a", "call-b", "call-c"} {
		found := false
		for _, event := range events {
			if event.Type == EventToolDenied && event.CallID == callID && strings.Contains(event.Summary, "at most 2") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s did not receive a paired turn-limit denial", callID)
		}
	}
}

func TestBatchRejectsDuplicateCallIDs(t *testing.T) {
	run, _, _ := runBatchScenario(t, runnerTestPolicy(), &runnerTestTool{name: "graph.query", result: "edge-list"},
		chatToolCalls(batchCall("call-a", "a"), batchCall("call-a", "b")),
		chatAnswer(runnerTestAnswer()),
	)
	// The first occurrence executes; the duplicate is denied rather than run twice.
	if run.Status != RunSucceeded || run.ToolCalls != 1 {
		t.Fatalf("run = %s calls=%d, want SUCCEEDED with one execution", run.Status, run.ToolCalls)
	}
	if run.Metrics == nil || run.Metrics.InvalidCalls != 1 {
		t.Fatalf("invalid calls = %+v, want 1", run.Metrics)
	}
}

func TestBatchRunsConcurrentlyButPairsResultsInSourceOrder(t *testing.T) {
	policy := runnerTestPolicy()
	policy.ToolConcurrency = 2
	tool := &delayedTool{name: "graph.query", delays: map[string]time.Duration{
		"slow": 300 * time.Millisecond, "fast": 10 * time.Millisecond,
	}}
	run, provider, store := runBatchScenario(t, policy, tool,
		chatToolCalls(batchCall("call-slow", "slow"), batchCall("call-fast", "fast")),
		chatAnswer(runnerTestAnswer()),
	)
	if run.Status != RunSucceeded || run.ToolCalls != 2 {
		t.Fatalf("run = %s calls=%d (%q)", run.Status, run.ToolCalls, run.Error)
	}
	messages := provider.lastRequest()
	var order []string
	for _, message := range messages {
		if message.Role == "tool" {
			order = append(order, message.ToolCallID)
		}
	}
	if len(order) != 2 || order[0] != "call-slow" || order[1] != "call-fast" {
		t.Fatalf("provider tool order = %v, want source order", order)
	}
	events, err := store.ListRunEvents(EventQuery{RunID: run.ID, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var completion []string
	for _, event := range events {
		if event.Type == EventToolResult {
			completion = append(completion, event.CallID)
		}
	}
	if len(completion) != 2 || completion[0] != "call-fast" || completion[1] != "call-slow" {
		t.Fatalf("completion order = %v, want the fast call first", completion)
	}
}

func TestBatchDeniesInvalidAndDisallowedCalls(t *testing.T) {
	invalid := map[string]any{
		"id": "call-bad", "type": "function",
		"function": map[string]string{"name": "graph.query", "arguments": `{"nope":"x"}`},
	}
	disallowed := map[string]any{
		"id": "call-shell", "type": "function",
		"function": map[string]string{"name": "shell.exec", "arguments": `{"cmd":"id"}`},
	}
	run, provider, store := runBatchScenario(t, runnerTestPolicy(), &runnerTestTool{name: "graph.query", result: "edge-list"},
		chatToolCalls(invalid, disallowed),
		chatAnswer(runnerTestAnswer()),
	)
	if run.Status != RunSucceeded || run.ToolCalls != 0 {
		t.Fatalf("run = %s calls=%d, want SUCCEEDED with no executed call", run.Status, run.ToolCalls)
	}
	if provider.count() != 2 {
		t.Fatalf("provider requests = %d, want 2: both calls get paired denials", provider.count())
	}
	events, err := store.ListRunEvents(EventQuery{RunID: run.ID, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	denied := map[string]bool{}
	for _, event := range events {
		if event.Type == EventToolDenied {
			denied[event.CallID] = true
		}
	}
	if !denied["call-bad"] || !denied["call-shell"] {
		t.Fatalf("denied = %v, want both calls", denied)
	}
}

func TestBatchPolicyIsPersistedWithTheRun(t *testing.T) {
	policy := runnerTestPolicy()
	policy.MaxCallsPerTurn = 3
	policy.ToolConcurrency = 2
	run, _, _ := runBatchScenario(t, policy, &runnerTestTool{name: "graph.query", result: "edge-list"},
		chatAnswer(runnerTestAnswer()),
	)
	if run.Exploration.MaxCallsPerTurn != 3 || run.Exploration.ToolConcurrency != 2 {
		t.Fatalf("persisted policy = %+v, want 3 calls and concurrency 2", run.Exploration)
	}
}

// refTool returns one evidence ref per call, so a round's novelty is the size of
// the union of the refs its calls produced.
type refTool struct{}

func (t *refTool) Name() string     { return "graph.query" }
func (t *refTool) Describe() string { return "ref test tool" }
func (t *refTool) Descriptor() ToolDescriptor {
	return ToolDescriptor{
		Name: t.Name(), Description: t.Describe(), Version: "1",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"symbol":{"type":"string"}},"additionalProperties":false}`),
	}
}
func (t *refTool) Call(_ context.Context, raw json.RawMessage) (ToolResult, error) {
	var args map[string]string
	_ = json.Unmarshal(raw, &args)
	return ToolResult{OK: true, Result: `{"ok":true}`, Refs: []string{args["symbol"]}}, nil
}

func TestNoveltyCountsTheWholeRoundAndDoesNotStopEarly(t *testing.T) {
	run, provider, _ := runBatchScenario(t, runnerTestPolicy(), &refTool{},
		chatToolCalls(batchCall("call-1", "A"), batchCall("call-2", "A"), batchCall("call-3", "B")),
		chatAnswer(runnerTestAnswer()),
	)
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s (%q)", run.Status, run.Error)
	}
	if provider.count() != 2 {
		t.Fatalf("provider requests = %d, want 2", provider.count())
	}
	if run.Metrics == nil || len(run.Metrics.Novelty) != 1 || run.Metrics.Novelty[0] != 2 {
		t.Fatalf("novelty = %+v, want one round with two new refs", run.Metrics)
	}
}

func TestThreeRoundsWithoutNewEvidenceStopTheRun(t *testing.T) {
	var responses []string
	for round := 0; round < 4; round++ {
		responses = append(responses, chatToolCalls(batchCall(fmt.Sprintf("call-%d", round), "A")))
	}
	responses = append(responses, chatAnswer(runnerTestAnswer()))
	run, provider, store := runBatchScenario(t, runnerTestPolicy(), &refTool{}, responses...)
	if run.Status != RunFailed || run.StopReason != StopNoNewEvidence {
		t.Fatalf("run = %s/%s, want FAILED/%s", run.Status, run.StopReason, StopNoNewEvidence)
	}
	if provider.count() != 4 {
		t.Fatalf("provider requests = %d, want 4: the fifth is denied before the request", provider.count())
	}
	if run.Metrics == nil || len(run.Metrics.Novelty) != 4 {
		t.Fatalf("novelty = %+v, want four rounds", run.Metrics)
	}
	want := []int{1, 0, 0, 0}
	for index, value := range want {
		if run.Metrics.Novelty[index] != value {
			t.Fatalf("novelty = %v, want %v", run.Metrics.Novelty, want)
		}
	}
	events, err := store.ListRunEvents(EventQuery{RunID: run.ID, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Type == EventRunFinished && strings.Contains(event.Summary, StopNoNewEvidence) {
			found = true
		}
	}
	if !found {
		t.Fatal("the run-finished event does not name the converged stop")
	}
}

func TestRepairTurnsDoNotCountAsExplorationRounds(t *testing.T) {
	run, provider, _ := runBatchScenario(t, runnerTestPolicy(), &refTool{},
		chatToolCalls(batchCall("call-1", "A")),
		chatAnswerRaw(`{"schema_version":1,"unexpected":true}`),
		chatAnswer(runnerTestAnswer()),
	)
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s (%q)", run.Status, run.Error)
	}
	if provider.count() != 3 {
		t.Fatalf("provider requests = %d, want 3 (tool, rejected answer, repaired answer)", provider.count())
	}
	if run.Metrics == nil || len(run.Metrics.Novelty) != 1 || run.Metrics.Novelty[0] != 1 {
		t.Fatalf("novelty = %+v, want only the exploration round", run.Metrics)
	}
}

func TestDirectAnswerAddsNoNoveltySample(t *testing.T) {
	run, _, _ := runBatchScenario(t, runnerTestPolicy(), &refTool{}, chatAnswer(runnerTestAnswer()))
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s (%q)", run.Status, run.Error)
	}
	if run.Metrics == nil || len(run.Metrics.Novelty) != 0 {
		t.Fatalf("novelty = %+v, want no sample for a direct answer", run.Metrics)
	}
}
