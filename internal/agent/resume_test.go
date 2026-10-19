package agent

import (
	"context"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
)

// TestRunnerPausesOnBudgetAndResumesFromTheCheckpoint is the pause/resume
// boundary: a spent tool budget ends the attempt as PAUSED with a real
// checkpoint, and a resume starts a new attempt from the recorded evidence and
// usage instead of a fresh task.
func TestRunnerPausesOnBudgetAndResumesFromTheCheckpoint(t *testing.T) {
	policy := runnerTestPolicy()
	policy.MaxToolCalls = 1
	provider, server := newRepairProvider(t,
		chatToolCalls(batchCall("call-1", "a"), batchCall("call-2", "b")),
		chatAnswer(runnerTestAnswer()),
	)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	update := llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: server.URL, Model: "test-model", TimeoutSeconds: 5, MaxOutputTokens: 1024}
	if _, err := settings.Save(update, agentPublicVersion(t, settings)); err != nil {
		t.Fatal(err)
	}
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	registry := NewRegistry()
	registry.Register(&runnerTestTool{name: "graph.query", result: "edge-list"})
	runtime := &ModelRuntime{Settings: settings, Tools: []ToolDescriptor{testToolDescriptor("graph.query")}}
	runner := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, registry, policy)

	run, err := runner.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunPaused || run.StopReason != StopBudgetPaused {
		t.Fatalf("run = %s/%s (%q), want PAUSED/%s", run.Status, run.StopReason, run.Error, StopBudgetPaused)
	}
	if run.CheckpointID == "" {
		t.Fatal("a paused run must carry its checkpoint id")
	}
	if run.Answer != nil {
		t.Fatal("a pause must not synthesize an answer")
	}
	checkpoint, err := store.GetCheckpoint(run.ID)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if checkpoint.RunID != run.ID || len(checkpoint.Frontier) == 0 {
		t.Fatalf("checkpoint = %+v", checkpoint)
	}
	if checkpoint.Usage.ToolCalls != 1 || checkpoint.Usage.InputTokens <= 0 {
		t.Fatalf("usage = %+v, want the executed call and the reported tokens recorded", checkpoint.Usage)
	}

	resumed, err := runner.Resume(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if resumed.Status != RunSucceeded || resumed.StopReason != StopCompleted {
		t.Fatalf("resumed = %s/%s (%q)", resumed.Status, resumed.StopReason, resumed.Error)
	}
	if resumed.ResumeOf != run.ID {
		t.Fatalf("resume_of = %q, want %q", resumed.ResumeOf, run.ID)
	}
	if resumed.ToolCalls != 1 {
		t.Fatalf("resumed tool calls = %d, want the checkpoint usage carried forward", resumed.ToolCalls)
	}
	if resumed.CheckpointID != "" {
		t.Fatalf("a running resume must not keep the old checkpoint id: %q", resumed.CheckpointID)
	}
	if provider.count() != 2 {
		t.Fatalf("provider requests = %d, want the first attempt and the resume", provider.count())
	}

	// A second resume of the same paused run is refused: its attempt is over and
	// exactly one continuation was created.
	if _, err := runner.Resume(context.Background(), run.ID); err == nil {
		t.Fatal("resuming a run twice must be refused")
	}
}
