package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPiWorkerResumesAfterTheWorkerIsDestroyed is the #61 boundary: a Pi attempt
// pauses on budget, its worker process and runtime are discarded, and a fresh
// worker resumes from the checkpoint with the rendered frontier.
func TestPiWorkerResumesAfterTheWorkerIsDestroyed(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	worker, err := filepath.Abs("../../runtime/pi-worker/dist/main.js")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(worker); err != nil {
		t.Skip("runtime/pi-worker/dist/main.js is not built; run `make pi-worker`")
	}

	fixture := aliasFixtureTask()
	fixture.Exploration.AllowedTools = []string{"get_code_slice"}
	fixture.Exploration.MaxToolCalls = 1
	answer := map[string]any{
		"schema_version": 2, "security_goal": fixture.SecurityGoal,
		"hypothesis":          map[string]any{"statement": "resumed worker reached the slice", "status": "inconclusive", "confidence": "low"},
		"supporting_evidence": []any{}, "contradicting_evidence": []any{},
		"next_action": "stop", "finding_candidate": false,
		"obligations": []any{
			map[string]any{"kind": ObligationSource, "verdict": "unknown", "blocker": "budget", "reason": "test"},
			map[string]any{"kind": ObligationFlow, "verdict": "unknown", "blocker": "budget", "reason": "test"},
			map[string]any{"kind": ObligationControl, "verdict": "unknown", "blocker": "budget", "reason": "test"},
			map[string]any{"kind": ObligationSink, "verdict": "unknown", "blocker": "budget", "reason": "test"},
		},
	}
	answerJSON, _ := json.Marshal(answer)

	resumeSawTask := false
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resumed := bytes.Contains(body, []byte("RESUMED FROM"))
		if resumed {
			resumeSawTask = true
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		write := func(value any) {
			encoded, _ := json.Marshal(value)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", encoded)
			if flusher != nil {
				flusher.Flush()
			}
		}
		chunk := func(choices []any, usage any) map[string]any {
			value := map[string]any{"id": "chunk", "object": "chat.completion.chunk", "created": 0, "model": "test-model", "choices": choices}
			if usage != nil {
				value["usage"] = usage
			}
			return value
		}
		if resumed {
			write(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "content": string(answerJSON)}}}, nil))
			write(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
				map[string]any{"prompt_tokens": 60, "completion_tokens": 20, "total_tokens": 80}))
		} else {
			// Two calls in one turn: the host's tool budget of one executes the
			// first, denies the second and pauses the attempt.
			calls := []any{
				map[string]any{"index": 0, "id": "call-1", "type": "function", "function": map[string]any{"name": "get_code_slice", "arguments": `{"symbol_id":"S1"}`}},
				map[string]any{"index": 1, "id": "call-2", "type": "function", "function": map[string]any{"name": "get_code_slice", "arguments": `{"symbol_id":"S1"}`}},
			}
			write(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "tool_calls": calls}, "finish_reason": nil}}, nil))
			write(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "tool_calls"}}, nil))
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer provider.Close()

	initConfig, _ := json.Marshal(map[string]any{
		"protocol": "chat-completions", "base_url": provider.URL + "/v1", "model": "test-model",
		"api_key": "synthetic", "timeout_seconds": 20, "max_output_tokens": 1024,
	})
	newRuntime := func() *PiRuntime {
		runtime, err := NewPiRuntime(PiConfig{
			Name: "pi", Command: []string{node, worker}, Init: initConfig,
			Tools: []ToolDescriptor{{Name: "get_code_slice", Version: "1",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"symbol_id":{"type":"string"}},"additionalProperties":false}`)}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return runtime
	}
	tool := &runnerTestTool{name: "get_code_slice", result: `{"slice":"func showUser() {}"}`}
	registry := NewRegistry()
	registry.Register(tool)
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))

	first := newRuntime()
	run, err := runnerTestRunner(store, paths, &aliasTaskBuilder{task: fixture}, first, registry, fixture.Exploration).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunPaused || run.StopReason != StopBudgetPaused {
		t.Fatalf("first attempt = %s/%s (%q), want PAUSED", run.Status, run.StopReason, run.Error)
	}
	if run.CheckpointID == "" {
		t.Fatal("the paused attempt has no checkpoint")
	}
	// The app and its worker are gone: close the runtime and build a fresh one.
	if closer, ok := any(first).(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	second := newRuntime()
	resumed, err := runnerTestRunner(store, paths, &aliasTaskBuilder{task: fixture}, second, registry, fixture.Exploration).
		Resume(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if resumed.Status != RunSucceeded {
		t.Fatalf("resumed = %s (%q)", resumed.Status, resumed.Error)
	}
	if resumed.ResumeOf != run.ID {
		t.Fatalf("resume_of = %q, want %q", resumed.ResumeOf, run.ID)
	}
	if !resumeSawTask {
		t.Fatal("the fresh worker did not receive the rendered resume task")
	}
	if resumed.ToolCalls != 1 {
		t.Fatalf("resumed tool calls = %d, want the checkpoint usage carried forward", resumed.ToolCalls)
	}
}
