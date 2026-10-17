package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClientProtocolsAndToolFeedback(t *testing.T) {
	t.Parallel()
	for _, protocol := range []string{"chat-completions", "responses"} {
		t.Run(protocol, func(t *testing.T) {
			var calls atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-only-key" {
					t.Error("missing authorization")
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				second := calls.Add(1) == 2
				w.Header().Set("Content-Type", "application/json")
				if protocol == "responses" {
					if r.URL.Path != "/v1/responses" || string(body["store"]) != "false" {
						t.Error("wrong Responses endpoint or storage policy")
					}
					if second && (!strings.Contains(string(body["input"]), "function_call_output") || !strings.Contains(string(body["input"]), "encrypted_content")) {
						t.Error("lost function feedback or reasoning state")
					}
					if second {
						_, _ = w.Write([]byte(`{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":5,"output_tokens":1}}`))
						return
					}
					_, _ = w.Write([]byte(`{"status":"completed","output":[{"type":"reasoning","encrypted_content":"test-encrypted-state"},{"type":"function_call","call_id":"call-1","name":"connection_check","arguments":"{}"}],"usage":{"input_tokens":4,"output_tokens":2}}`))
				} else {
					if r.URL.Path != "/v1/chat/completions" {
						t.Error("wrong Chat endpoint")
					}
					if second && !strings.Contains(string(body["messages"]), `"tool_call_id":"call-1"`) {
						t.Error("lost tool result")
					}
					if second {
						_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1}}`))
						return
					}
					_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"connection_check","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":4,"completion_tokens":2}}`))
				}
			}))
			defer ts.Close()
			cfg := Config{Protocol: protocol, BaseURL: ts.URL + "/v1", Model: "test-model", APIKey: "test-only-key", TimeoutSeconds: 5, MaxOutputTokens: 1024}
			messages := []Message{{Role: "user", Content: "test"}}
			result, err := Complete(context.Background(), cfg, messages, nil, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Message.Calls) != 1 || !result.UsageReported || result.InputTokens != 4 {
				t.Fatal("missing calls or usage")
			}
			messages = append(messages, result.Message, Message{Role: "tool", ToolCallID: "call-1", Content: "test-result"})
			result, err = Complete(context.Background(), cfg, messages, nil, "")
			if err != nil || result.Message.Content != "ok" {
				t.Fatal("feedback roundtrip failed", err)
			}
		})
	}
}

func TestClientErrorsNeverExposeProviderBodyAndRefuseRedirects(t *testing.T) {
	t.Parallel()
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer target.Close()
	for _, status := range []int{401, 307} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", target.URL)
			w.WriteHeader(status)
			_, _ = w.Write([]byte("echoed-test-secret"))
		}))
		cfg := Config{Protocol: "chat-completions", BaseURL: ts.URL, Model: "test", APIKey: "echoed-test-secret", TimeoutSeconds: 5, MaxOutputTokens: 1024}
		_, err := Complete(context.Background(), cfg, []Message{{Role: "user", Content: "test"}}, nil, "")
		ts.Close()
		if err == nil || strings.Contains(err.Error(), cfg.APIKey) || strings.Contains(err.Error(), ts.URL) {
			t.Fatal("unsafe error", err)
		}
	}
	if leaked.Load() {
		t.Fatal("followed redirect with credentials")
	}
}
