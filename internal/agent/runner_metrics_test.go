package agent

import (
	"context"
	"strings"
	"testing"
)

// failingTool answers every call with a policy-free failure, which is what the
// orchestrator counts as an invalid call: the model asked correctly and the tool
// could not answer.
type failingTool struct{ name string }

var _ ToolExecutor = (*failingTool)(nil)

func (t *failingTool) Name() string     { return t.name }
func (t *failingTool) Describe() string { return "always fails" }
func (t *failingTool) Call(context.Context, map[string]string) (ToolResult, error) {
	return ToolResult{Tool: t.name, OK: false, Error: "symbol not found"}, nil
}

func TestRunnerRecordsRunMetrics(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	tasks := &runnerTestTasks{}
	registry := NewRegistry()
	registry.Register(&goldenTool{name: "graph.query", result: "first", refs: []string{"sym-1", "sym-2"}})
	registry.Register(&goldenTool{name: "graph.neighbors", result: "second", refs: []string{"sym-2", "sym-3"}})

	runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{
		ScriptTool(ToolRequest{CallID: "call-1", Tool: "graph.query"}),
		ScriptTool(ToolRequest{CallID: "call-2", Tool: "graph.neighbors"}),
		ScriptAnswer(runnerTestAnswer()),
	})
	policy := runnerTestPolicy()
	policy.AllowedTools = []string{"graph.query", "graph.neighbors"}

	run, err := runnerTestRunner(store, paths, tasks, runtime, registry, policy).RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Metrics == nil {
		t.Fatalf("run has no metrics: %+v", run)
	}
	if run.Metrics.Exchanges != 2 {
		t.Errorf("exchanges = %d, want 2", run.Metrics.Exchanges)
	}
	// One tool per turn plus the turn that answered.
	if run.Metrics.Rounds != 3 {
		t.Errorf("rounds = %d, want 3", run.Metrics.Rounds)
	}
	if run.Metrics.InvalidCalls != 0 || run.Metrics.Truncations != 0 {
		t.Errorf("invalid/truncated = %d/%d, want 0/0", run.Metrics.InvalidCalls, run.Metrics.Truncations)
	}
	// The second exchange repeats sym-2, so it only contributes one new ref.
	if want := []int{2, 1}; !equalInts(run.Metrics.Novelty, want) {
		t.Errorf("novelty = %v, want %v", run.Metrics.Novelty, want)
	}
}

func TestRunnerCountsInvalidCalls(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	registry := NewRegistry()
	registry.Register(&failingTool{name: "graph.query"})

	runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{
		ScriptTool(ToolRequest{CallID: "call-1", Tool: "graph.query"}),
		ScriptAnswer(runnerTestAnswer()),
	})
	policy := runnerTestPolicy()
	policy.AllowedTools = []string{"graph.query"}

	run, err := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, registry, policy).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Metrics == nil || run.Metrics.InvalidCalls != 1 {
		t.Fatalf("invalid calls = %+v, want 1", run.Metrics)
	}
	if run.Metrics.Novelty == nil || len(run.Metrics.Novelty) != 1 || run.Metrics.Novelty[0] != 0 {
		t.Errorf("novelty = %v, want [0] for a failed call", run.Metrics.Novelty)
	}
}

func TestRunnerCountsTruncations(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	registry := NewRegistry()
	registry.Register(&goldenTool{name: "graph.query", result: strings.Repeat("x", MaxToolResultChars+1)})

	runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{
		ScriptTool(ToolRequest{CallID: "call-1", Tool: "graph.query"}),
		ScriptAnswer(runnerTestAnswer()),
	})
	policy := runnerTestPolicy()
	policy.AllowedTools = []string{"graph.query"}

	run, err := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, registry, policy).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Metrics == nil || run.Metrics.Truncations != 1 {
		t.Fatalf("truncations = %+v, want 1", run.Metrics)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
