package supervisor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestSupervisorContextBudgetKeepsCompleteTurnsAndDropsBrokenToolPairs(t *testing.T) {
	session := storage.SupervisorSession{}
	for i := 0; i < 140; i++ {
		userID := fmt.Sprintf("user-%d", i)
		callID := fmt.Sprintf("call-%d", i)
		session.Messages = append(session.Messages,
			storage.SupervisorMessage{ID: userID, Role: "user", Content: strings.Repeat("u", 4096)},
			storage.SupervisorMessage{ID: "assistant-" + fmt.Sprint(i), Role: "assistant", Content: strings.Repeat("a", 2048), Calls: []storage.SupervisorCall{{ID: callID, Name: "graph_summary", Arguments: `{"query":"entry"}`}}},
			storage.SupervisorMessage{ID: "tool-" + fmt.Sprint(i), Role: "tool", ToolCallID: callID, Content: strings.Repeat("t", 4096)},
		)
	}
	session.Messages = append(session.Messages,
		storage.SupervisorMessage{ID: "broken-user", Role: "user", Content: "broken"},
		storage.SupervisorMessage{ID: "broken-assistant", Role: "assistant", Calls: []storage.SupervisorCall{{ID: "missing-tool", Name: "graph_summary", Arguments: "{}"}}},
	)
	current := storage.SupervisorMessage{ID: "current-user", Role: "user", Content: "current question"}
	tools := []llm.Tool{{
		Name: "graph_summary", Description: "summary",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}}},
	}}
	messages, omitted := history(session, current, tools)
	if omitted == 0 {
		t.Fatal("oversized history was not trimmed")
	}
	if messages[len(messages)-1].Content != current.Content {
		t.Fatalf("current question missing: %+v", messages)
	}
	if messages[0].Role != "system" {
		t.Fatalf("system prompt no longer leads the model view: %+v", messages[0])
	}
	if supervisorContextSize(messages, tools) > 256<<10 || estimateSupervisorTokens(messages, tools) > 30000 {
		t.Fatalf("context exceeds hard budget: bytes=%d tokens=%d", supervisorContextSize(messages, tools), estimateSupervisorTokens(messages, tools))
	}
	pending := map[string]bool{}
	for _, message := range messages {
		for _, call := range message.Calls {
			pending[call.ID] = true
		}
		if message.Role == "tool" {
			if !pending[message.ToolCallID] {
				t.Fatalf("orphan tool result survived trimming: %+v", message)
			}
			delete(pending, message.ToolCallID)
		}
	}
	if len(pending) != 0 {
		t.Fatalf("assistant tool calls without results survived: %v", pending)
	}
}

func TestSupervisorTokenBudgetRejectsBeforeProviderRequestAndSurvivesContinue(t *testing.T) {
	var providerCalls atomic.Int32
	provider := testProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		providerCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"should not be called"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`))
	})
	service, project, _ := supervisorFixture(t)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider, Model: "budget", TimeoutSeconds: 10, MaxOutputTokens: 256}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings
	session, err := service.CreateSession(context.Background(), project.ID, "snap-fixed", "budget")
	if err != nil {
		t.Fatal(err)
	}
	budgetStore := service.Store.(agent.Store)
	if _, err := budgetStore.ReserveAuditTokens(session.AuditID, agent.DefaultAuditTokenBudget-10); err != nil {
		t.Fatal(err)
	}
	_, first, err := service.Send(context.Background(), project.ID, session.ID, "do work", "budget-source")
	if err != nil {
		t.Fatal(err)
	}
	first = waitSupervisor(t, service, project.ID, session.ID, first.ID)
	if first.Status != RunPaused || first.StopReason != StopGlobalBudget || first.Checkpoint == nil || first.VisibleMessageID == "" {
		t.Fatalf("pre-request budget pause = %+v", first)
	}
	if providerCalls.Load() != 0 {
		t.Fatalf("provider was called %d time(s) after budget refusal", providerCalls.Load())
	}
	continued, err := service.Continue(context.Background(), project.ID, session.ID, first.ID, "continue after grant")
	if err != nil {
		t.Fatal(err)
	}
	continued = waitSupervisor(t, service, project.ID, session.ID, continued.ID)
	if continued.Status != RunPaused || continued.StopReason != StopGlobalBudget || providerCalls.Load() != 0 {
		t.Fatalf("continue reset the audit budget: run=%+v provider_calls=%d", continued, providerCalls.Load())
	}
	budget, err := budgetStore.GetAuditBudget(session.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if budget.UsedTokens != 0 || budget.ReservedTokens != agent.DefaultAuditTokenBudget-10 {
		t.Fatalf("budget ledger changed on refused requests: %+v", budget)
	}
}

func testProvider(t *testing.T, handler func(http.ResponseWriter, *http.Request)) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	return server.URL
}
