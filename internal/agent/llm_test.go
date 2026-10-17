package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
)

func TestModelRuntimeUsesOrchestratorFeedbackAndLiveSettings(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []llm.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"model-call-1","type":"function","function":{"name":"graph_query","arguments":"{\"tool\":\"graph.query\",\"args\":{}}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
			return
		}
		last := body.Messages[len(body.Messages)-1]
		if last.Role != "tool" || last.ToolCallID != "model-call-1" || !strings.Contains(last.Content, "edge-list") {
			t.Error("model did not receive the actual orchestrator result")
		}
		answer, _ := json.Marshal(runnerTestAnswer())
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": string(answer)}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 15, "completion_tokens": 10}})
	}))
	defer provider.Close()
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	tool := &runnerTestTool{name: "graph.query", result: "edge-list"}
	registry := NewRegistry()
	registry.Register(tool)
	runtime := &ModelRuntime{Settings: settings}
	runner := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, registry, runnerTestPolicy())
	if _, err := runner.RunOnce(context.Background(), "audit-1"); err == nil || len(paths.claimIDs()) != 0 {
		t.Fatal("unconfigured model consumed queued work")
	}
	update := llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "test-model", TimeoutSeconds: 5, MaxOutputTokens: 1024}
	if _, err := settings.Save(update, settings.Public().Version); err != nil {
		t.Fatal(err)
	}
	run, err := runner.RunOnce(context.Background(), "audit-1")
	if err != nil || run == nil || run.Status != RunSucceeded || run.ToolCalls != 1 || run.InputTokens != 25 || tool.callCount() != 1 {
		t.Fatalf("model run failed: %+v %v", run, err)
	}
	update.Enabled = false
	if _, err := settings.Save(update, settings.Public().Version); err != nil {
		t.Fatal(err)
	}
	if runner.Ready() == nil {
		t.Fatal("disabled settings did not apply live")
	}
}
