package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
)

// A repair is a protocol correction: the model produced something the protocol
// rejects, and the adapter tells it why instead of ending the run. These tests
// pin the three shapes a repair must handle and the one it must refuse to loop on.

// repairProvider replays a fixed list of responses and keeps the last request it
// received, which is where the correction messages show up.
type repairProvider struct {
	mu        sync.Mutex
	requests  int
	last      []llm.Message
	all       [][]llm.Message
	responses []string
	index     int
}

func newRepairProvider(t *testing.T, responses ...string) (*repairProvider, *httptest.Server) {
	t.Helper()
	provider := &repairProvider{responses: responses}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []llm.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		provider.mu.Lock()
		provider.requests++
		provider.last = body.Messages
		provider.all = append(provider.all, append([]llm.Message(nil), body.Messages...))
		response := provider.responses[len(provider.responses)-1]
		if provider.index < len(provider.responses) {
			response = provider.responses[provider.index]
			provider.index++
		}
		provider.mu.Unlock()
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)
	return provider, server
}

func (p *repairProvider) lastRequest() []llm.Message {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]llm.Message(nil), p.last...)
}

func (p *repairProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests
}

func chatToolCall(id, arguments string) string {
	return chatToolCalls(map[string]any{
		"id": id, "type": "function",
		"function": map[string]string{"name": "graph.query", "arguments": arguments},
	})
}

func chatToolCalls(calls ...map[string]any) string {
	message := map[string]any{"role": "assistant", "content": nil, "tool_calls": calls}
	return encodeChat([]any{map[string]any{"message": message, "finish_reason": "tool_calls"}})
}

func chatAnswerRaw(content string) string {
	return encodeChat([]any{map[string]any{
		"message": map[string]string{"role": "assistant", "content": content}, "finish_reason": "stop",
	}})
}

func chatAnswer(answer Answer) string {
	encoded, _ := json.Marshal(answer)
	return chatAnswerRaw(string(encoded))
}

func encodeChat(choices []any) string {
	body := map[string]any{
		"choices": choices,
		"usage":   map[string]int{"prompt_tokens": 10, "completion_tokens": 5},
	}
	encoded, _ := json.Marshal(body)
	return string(encoded)
}

// runRepairScenario configures a model runtime against a scripted provider and
// returns the finished run.
func runRepairScenario(t *testing.T, responses ...string) (*Run, *repairProvider) {
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
	run, err := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, registry, runnerTestPolicy()).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return run, provider
}

// TestModelRepairsInvalidToolArguments is the exact failure the baseline exposed:
// a numeric argument used to end the run and discard every token already spent.
func TestModelRepairsInvalidToolArguments(t *testing.T) {
	d := testToolDescriptor("graph.query")
	_ = d
	run, provider := runRepairScenario(t,
		chatToolCall("model-call-1", `{"max_depth":"2"}`),
		chatToolCall("model-call-2", `{"max_depth":2}`),
		chatAnswer(runnerTestAnswer()),
	)
	if run.Status != RunSucceeded || run.ToolCalls != 1 {
		t.Fatalf("run = %s calls=%d requests=%d err=%q metrics=%+v, want SUCCEEDED with 1 call", run.Status, run.ToolCalls, provider.count(), run.Error, run.Metrics)
	}
	if !repairMessageSeen(provider.lastRequest(), "model-call-1", "must be an integer") {
		t.Fatal("the rejected call did not receive the host's schema error")
	}
}

// TestModelRepairsMultipleToolCalls covers a model that batches two requests in a
// turn the protocol accepts only one of.
func TestModelRepairsMultipleToolCalls(t *testing.T) {
	first := map[string]any{
		"id": "call-a", "type": "function",
		"function": map[string]string{"name": "graph_query", "arguments": `{}`},
	}
	second := map[string]any{
		"id": "call-b", "type": "function",
		"function": map[string]string{"name": "graph_query", "arguments": `{}`},
	}
	run, provider := runRepairScenario(t,
		chatToolCalls(first, second),
		chatToolCall("model-call-3", `{}`),
		chatAnswer(runnerTestAnswer()),
	)
	if run.Status != RunSucceeded || run.ToolCalls != 1 {
		t.Fatalf("run = %s calls=%d requests=%d err=%q metrics=%+v, want SUCCEEDED with 1 call", run.Status, run.ToolCalls, provider.count(), run.Error, run.Metrics)
	}
	messages := provider.lastRequest()
	if !repairMessageSeen(messages, "call-a", "one_tool_call_per_turn") || !repairMessageSeen(messages, "call-b", "one_tool_call_per_turn") {
		t.Fatal("both rejected calls must receive a paired repair message")
	}
}

// TestModelRepairsRejectedAnswer covers structural validation: the protocol names
// the offending field and the model gets one chance to fix it.
func TestModelRepairsRejectedAnswer(t *testing.T) {
	run, provider := runRepairScenario(t,
		chatAnswerRaw(`{"schema_version":1,"unexpected":true}`),
		chatAnswer(runnerTestAnswer()),
	)
	if run.Status != RunSucceeded || run.Answer == nil {
		t.Fatalf("run = %s answer=%v, want SUCCEEDED with an answer", run.Status, run.Answer)
	}
	last := lastUserMessage(provider.lastRequest())
	if !strings.Contains(last, "unexpected") {
		t.Fatalf("repair did not name the rejected field: %q", last)
	}
	if len(last) > 300 {
		t.Fatalf("repair message is %d bytes, want at most 300", len(last))
	}
}

// TestModelStopsAfterRepairBudget covers the refusal to loop: two corrections, then
// the run is invalid output rather than an endless retry.
func TestModelStopsAfterRepairBudget(t *testing.T) {
	run, provider := runRepairScenario(t,
		chatAnswerRaw(`{"schema_version":1,"unexpected":true}`),
		chatAnswerRaw(`{"schema_version":1,"unexpected":true}`),
		chatAnswerRaw(`{"schema_version":1,"unexpected":true}`),
	)
	if run.Status != RunInvalidOutput || run.StopReason != StopInvalidOutput {
		t.Fatalf("run = %s/%s, want INVALID_OUTPUT/invalid_output", run.Status, run.StopReason)
	}
	// One original attempt plus two repairs; the third correction is refused.
	if got := provider.count(); got != 3 {
		t.Fatalf("provider saw %d requests, want 3 (1 attempt + 2 repairs)", got)
	}
}

func repairMessageSeen(messages []llm.Message, callID, want string) bool {
	for _, message := range messages {
		if message.Role == "tool" && message.ToolCallID == callID && strings.Contains(message.Content, want) {
			return true
		}
	}
	return false
}

func lastUserMessage(messages []llm.Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	return ""
}

// TestModelToolResultOmitsBookkeeping keeps the orchestrator's metadata out of the
// model's context: the payload already names every fact, and refs, call ids and
// timings are a second copy paid for on every turn.
func TestModelToolResultOmitsBookkeeping(t *testing.T) {
	_, provider := runRepairScenario(t,
		chatToolCall("model-call-1", `{}`),
		chatAnswer(runnerTestAnswer()),
	)
	var content string
	for _, message := range provider.lastRequest() {
		if message.Role == "tool" && message.ToolCallID == "model-call-1" {
			content = message.Content
		}
	}
	if content == "" {
		t.Fatal("the tool result never reached the model")
	}
	for _, unwanted := range []string{"call_id", "refs", "elapsed_ms"} {
		if strings.Contains(content, unwanted) {
			t.Fatalf("tool result carries orchestrator bookkeeping %q: %s", unwanted, content)
		}
	}
	if !strings.Contains(content, `"ok":true`) {
		t.Fatalf("tool result lost its outcome: %s", content)
	}
}
