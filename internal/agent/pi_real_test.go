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

// TestPiWorkerRunsARealAgentLoop is the integration boundary of #58: the real
// worker, the real Agent Core, a provider fixture that first asks for a tool and
// only then answers, and the host executing that tool against the task.
//
// It is skipped unless Node and a built worker exist; `make pi-worker` builds
// them, and CI runs that target before the Go tests.
func TestPiWorkerRunsARealAgentLoop(t *testing.T) {
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
	answer := map[string]any{
		"schema_version": 2, "security_goal": fixture.SecurityGoal,
		"hypothesis":          map[string]any{"statement": "the worker loop reached the slice", "status": "inconclusive", "confidence": "low"},
		"supporting_evidence": []any{}, "contradicting_evidence": []any{},
		"next_action": "stop", "finding_candidate": false,
		"obligations": []any{
			map[string]any{"kind": ObligationSource, "verdict": "unknown", "blocker": "budget", "reason": "test"},
			map[string]any{"kind": ObligationFlow, "verdict": "unknown", "blocker": "budget", "reason": "test"},
			map[string]any{"kind": ObligationControl, "verdict": "unknown", "blocker": "budget", "reason": "test"},
			map[string]any{"kind": ObligationSink, "verdict": "unknown", "blocker": "budget", "reason": "test"},
		},
	}
	answerJSON, err := json.Marshal(answer)
	if err != nil {
		t.Fatal(err)
	}

	var providerRequests int
	var secondRequest []byte
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		providerRequests++
		var request struct {
			Messages []struct {
				Role string `json:"role"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &request)
		sawTool := false
		for _, message := range request.Messages {
			if message.Role == "tool" {
				sawTool = true
			}
		}
		if sawTool {
			secondRequest = body
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
		if !sawTool {
			write(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{
				"role": "assistant",
				"tool_calls": []any{map[string]any{"index": 0, "id": "call-1", "type": "function",
					"function": map[string]any{"name": "get_code_slice", "arguments": `{"symbol_id":"S1"}`}}},
			}, "finish_reason": nil}}, nil))
			write(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "tool_calls"}}, nil))
		} else {
			write(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "content": string(answerJSON)}}}, nil))
			write(chunk([]any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
				map[string]any{"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}))
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer provider.Close()

	init, _ := json.Marshal(map[string]any{
		"protocol": "chat-completions", "base_url": provider.URL + "/v1", "model": "test-model",
		"api_key": "synthetic", "timeout_seconds": 20, "max_output_tokens": 1024,
	})
	runtime, err := NewPiRuntime(PiConfig{
		Name: "pi", Command: []string{node, worker}, Init: init,
		Tools: []ToolDescriptor{{Name: "get_code_slice", Version: "1",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"symbol_id":{"type":"string"}},"additionalProperties":false}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	tool := &runnerTestTool{name: "get_code_slice", result: `{"slice":"func showUser() {}"}`}
	registry := NewRegistry()
	registry.Register(tool)
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	run, err := runnerTestRunner(store, paths, &aliasTaskBuilder{task: fixture}, runtime, registry, fixture.Exploration).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s: %s", run.Status, run.Error)
	}
	if tool.calls != 1 {
		t.Fatalf("tool calls = %d, want 1", tool.calls)
	}
	if got := tool.args[0]["symbol_id"]; got != "entry-1" {
		t.Errorf("the worker's alias was not resolved by the host: %q", got)
	}
	if providerRequests != 2 {
		t.Errorf("provider requests = %d, want 2 (tool turn and answer turn)", providerRequests)
	}
	if !json.Valid(secondRequest) || !bytes.Contains(secondRequest, []byte("func showUser")) {
		t.Errorf("the second provider request does not carry the host tool result: %s", secondRequest)
	}
	if run.Metrics == nil || run.Metrics.ModelRequests != 2 || run.Metrics.Source != MetricsSourceReported {
		t.Errorf("metrics = %+v, want two reported model requests", run.Metrics)
	}
}
