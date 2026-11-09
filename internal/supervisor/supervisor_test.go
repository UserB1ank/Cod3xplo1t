package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/open-mcp-ai/Codexploit/internal/claim"
	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestSupervisorOldConversationKeepsToolResultPairsWhenHistoryIsBounded(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []llm.Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		pending := map[string]bool{}
		for _, m := range request.Messages {
			if m.Role == "tool" {
				if !pending[m.ToolCallID] {
					http.Error(w, "orphan tool result", 400)
					return
				}
				delete(pending, m.ToolCallID)
			} else {
				if len(pending) > 0 {
					http.Error(w, "missing tool result", 400)
					return
				}
				for _, call := range m.Calls {
					pending[call.ID] = true
				}
			}
		}
		if len(pending) > 0 {
			http.Error(w, "missing tool result", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"已重新查询当前能力。"},"finish_reason":"stop"}]}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "strict-history", TimeoutSeconds: 10, MaxOutputTokens: 512}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings
	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "old")
	if err != nil {
		t.Fatal(err)
	}
	session.Messages = []storage.SupervisorMessage{
		{ID: "m0", Role: "user", Content: "旧查询"},
		{ID: "m1", Role: "assistant", Calls: []storage.SupervisorCall{{ID: "c1", Name: "graph_summary", Arguments: "{}"}, {ID: "c2", Name: "graph_summary", Arguments: "{}"}}},
		{ID: "m2", Role: "tool", ToolCallID: "c1", Content: `{"error":"old graph unavailable"}`},
		{ID: "m3", Role: "tool", ToolCallID: "c2", Content: `{"error":"old graph unavailable"}`},
	}
	for i := 4; i < 22; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		session.Messages = append(session.Messages, storage.SupervisorMessage{ID: fmt.Sprint("m", i), Role: role, Content: "旧消息"})
	}
	for i := range session.Messages {
		session.Messages[i].Seq = int64(i + 1)
	}
	if _, err := service.Store.SaveSupervisorSession(context.Background(), session, session.Version); err != nil {
		t.Fatal(err)
	}
	_, run, err := service.Send(context.Background(), project.ID, session.ID, "请重新查询", "current-turn")
	if err != nil {
		t.Fatal(err)
	}
	finished := waitSupervisor(t, service, project.ID, session.ID, run.ID)
	if finished.Status != RunSucceeded {
		t.Fatalf("old conversation lost protocol pairing: %+v", finished)
	}
}

func TestSupervisorConcurrentBootstrapReusesOneSession(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	const clients = 8
	start := make(chan struct{})
	results := make(chan storage.SupervisorSession, clients)
	errors := make(chan error, clients)
	var workers sync.WaitGroup
	for range clients {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
			if err != nil {
				errors <- err
				return
			}
			results <- session
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	unique := map[string]bool{}
	for session := range results {
		unique[session.ID] = true
	}
	if len(unique) != 1 {
		t.Fatalf("concurrent bootstrap created %d sessions: %v", len(unique), unique)
	}
	sessions, err := service.List(context.Background(), project.ID, 20)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("stored sessions = %d, %v", len(sessions), err)
	}
}

func TestSupervisorRoundLimitWritesVisiblePauseMessage(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	service.MaxRounds = 2
	service.MaxToolCalls = 10
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call-loop","type":"function","function":{"name":"graph_summary","arguments":"{\"q\":\"entry\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "loop", TimeoutSeconds: 10, MaxOutputTokens: 256}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings

	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := service.Send(context.Background(), project.ID, session.ID, "loop until the limit", "round-limit")
	if err != nil {
		t.Fatal(err)
	}
	finished := waitSupervisor(t, service, project.ID, session.ID, run.ID)
	if finished.Status != "PAUSED" {
		t.Fatalf("round-limit status = %s, want PAUSED", finished.Status)
	}
	if finished.StopReason != StopRoundLimit || finished.ModelTurns != 2 || finished.ToolCalls != 2 {
		t.Fatalf("round-limit facts = %+v", finished)
	}
	if finished.FinalizerSource != "template" {
		t.Fatalf("finalizer source = %q, want template", finished.FinalizerSource)
	}
	session, err = service.Get(context.Background(), project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	var terminal string
	var terminalKind string
	for i := len(session.Messages) - 1; i >= 0; i-- {
		message := session.Messages[i]
		if message.RunID == run.ID && message.Role == "assistant" && strings.TrimSpace(message.Content) != "" {
			terminal = message.Content
			terminalKind = message.MessageKind
			break
		}
	}
	if terminal == "" {
		t.Fatal("round-limit run has no visible assistant terminal message")
	}
	if !strings.Contains(terminal, "90") && !strings.Contains(terminal, "2/2") && !strings.Contains(terminal, "轮次") {
		t.Fatalf("terminal message does not explain the round limit: %q", terminal)
	}
	if !strings.Contains(terminal, "继续") {
		t.Fatalf("terminal message does not explain how to continue: %q", terminal)
	}
	if terminalKind != "paused" || finished.VisibleMessageID == "" {
		t.Fatalf("terminal message metadata = kind %q id %q", terminalKind, finished.VisibleMessageID)
	}
}

func TestSupervisorDefaultsToNinetyRounds(t *testing.T) {
	service, _, _ := supervisorFixture(t)
	if service.MaxRounds != 90 {
		t.Fatalf("default rounds = %d, want 90", service.MaxRounds)
	}
	if service.MaxToolCalls != 150 {
		t.Fatalf("default tool calls = %d, want 150", service.MaxToolCalls)
	}
	if service.RunTimeout != 600*time.Second {
		t.Fatalf("default run timeout = %s, want 10m", service.RunTimeout)
	}
	if service.FinalizerTimeout != 30*time.Second {
		t.Fatalf("default finalizer timeout = %s, want 30s", service.FinalizerTimeout)
	}
	if service.LeaseTTL != 12*time.Minute {
		t.Fatalf("default lease ttl = %s, want 12m", service.LeaseTTL)
	}
	if PromptVersion != "supervisor/v5" {
		t.Fatalf("prompt version = %q, want supervisor/v5", PromptVersion)
	}
}

func TestSupervisorFinalizerUsesModelTextWithoutTools(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	service.MaxRounds = 2
	service.MaxToolCalls = 10
	finalizerStarted := make(chan struct{}, 1)
	finalizerCanContinue := make(chan bool, 1)
	releaseFinalizer := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseFinalizer) }) })
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Tools    []llm.Tool    `json:"tools"`
			Messages []llm.Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		w.Header().Set("Content-Type", "application/json")
		if len(request.Tools) > 0 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call-loop","type":"function","function":{"name":"graph_summary","arguments":"{\"q\":\"entry\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
			return
		}
		var facts map[string]any
		_ = json.Unmarshal([]byte(request.Messages[len(request.Messages)-1].Content), &facts)
		canContinue, _ := facts["can_continue"].(bool)
		finalizerCanContinue <- canContinue
		finalizerStarted <- struct{}{}
		<-releaseFinalizer
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"模型收尾：轮次 2/2，已暂停并保留当前结果。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":7}}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "finalizer", TimeoutSeconds: 10, MaxOutputTokens: 256}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings
	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := service.Send(context.Background(), project.ID, session.ID, "loop then summarize", "model-finalizer")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-finalizerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("finalizer did not start")
	}
	select {
	case canContinue := <-finalizerCanContinue:
		if !canContinue {
			t.Error("finalizer was told the paused run cannot continue")
		}
	case <-time.After(5 * time.Second):
		t.Error("finalizer did not receive its facts")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		session, err = service.Get(context.Background(), project.ID, session.ID)
		if err != nil {
			t.Fatal(err)
		}
		var finalizing bool
		for _, stored := range session.Runs {
			if stored.ID == run.ID && stored.Status == RunFinalizing {
				finalizing = true
			}
		}
		if finalizing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run never entered FINALIZING: %+v", session.Runs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	releaseOnce.Do(func() { close(releaseFinalizer) })
	finished := waitSupervisor(t, service, project.ID, session.ID, run.ID)
	if finished.Status != RunPaused || finished.FinalizerSource != "model" {
		t.Fatalf("model finalizer run = %+v", finished)
	}
	session, err = service.Get(context.Background(), project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, message := range session.Messages {
		if message.ID == finished.VisibleMessageID && message.RunID == run.ID &&
			message.MessageKind == "paused" && strings.Contains(message.Content, "模型收尾") {
			found = true
		}
	}
	if !found {
		t.Fatalf("model finalizer message missing from session: %+v", session.Messages)
	}
}

func TestSupervisorFinalizerTimeoutUsesTemplate(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	service.MaxRounds = 1
	service.MaxToolCalls = 10
	service.FinalizerTimeout = 20 * time.Millisecond
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Tools []llm.Tool `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		w.Header().Set("Content-Type", "application/json")
		if len(request.Tools) > 0 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call-loop","type":"function","function":{"name":"graph_summary","arguments":"{\"q\":\"entry\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
			return
		}
		time.Sleep(120 * time.Millisecond)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"late finalizer"},"finish_reason":"stop"}]}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "slow-finalizer", TimeoutSeconds: 10, MaxOutputTokens: 256}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings
	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := service.Send(context.Background(), project.ID, session.ID, "finalizer timeout", "finalizer-timeout")
	if err != nil {
		t.Fatal(err)
	}
	finished := waitSupervisor(t, service, project.ID, session.ID, run.ID)
	if finished.Status != RunPaused || finished.FinalizerSource != "template" {
		t.Fatalf("finalizer timeout run = %+v", finished)
	}
}

func TestSupervisorToolLimitPausesInsteadOfSpinning(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	service.MaxRounds = 5
	service.MaxToolCalls = 1
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Tools []llm.Tool `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		w.Header().Set("Content-Type", "application/json")
		if len(request.Tools) > 0 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call-loop","type":"function","function":{"name":"graph_summary","arguments":"{\"q\":\"entry\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"模型收尾：工具预算已耗尽，已暂停。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":7}}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "tool-limit", TimeoutSeconds: 10, MaxOutputTokens: 256}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings
	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := service.Send(context.Background(), project.ID, session.ID, "loop tools", "tool-limit")
	if err != nil {
		t.Fatal(err)
	}
	finished := waitSupervisor(t, service, project.ID, session.ID, run.ID)
	if finished.Status != RunPaused || finished.StopReason != StopToolLimit || finished.ToolCalls != 1 {
		t.Fatalf("tool-limit run = %+v", finished)
	}
	if finished.ModelTurns != 2 {
		t.Fatalf("tool-limit model turns = %d, want the round that requested over-budget work", finished.ModelTurns)
	}
}

func TestSupervisorBreaksRepeatedInvalidToolCalls(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	service.MaxRounds = 6
	service.MaxToolCalls = 20
	var executions atomic.Int32
	service.MCPClient = func(ctx context.Context) (*sdk.ClientSession, error) {
		server := sdk.NewServer(&sdk.Implementation{Name: "failing", Version: "1"}, nil)
		sdk.AddTool(server, &sdk.Tool{Name: "graph_summary", Description: "failing graph summary"}, func(_ context.Context, _ *sdk.CallToolRequest, _ fakeToolInput) (*sdk.CallToolResult, fakeToolOutput, error) {
			executions.Add(1)
			return nil, fakeToolOutput{}, errors.New("missing required field: q")
		})
		serverTransport, clientTransport := sdk.NewInMemoryTransports()
		go func() { _, _ = server.Connect(ctx, serverTransport, nil) }()
		client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil)
		return client.Connect(ctx, clientTransport, nil)
	}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Tools []llm.Tool `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		w.Header().Set("Content-Type", "application/json")
		if len(request.Tools) > 0 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call-loop","type":"function","function":{"name":"graph_summary","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"重复工具错误已熔断，运行暂停。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":7}}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "breaker", TimeoutSeconds: 10, MaxOutputTokens: 256}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings
	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := service.Send(context.Background(), project.ID, session.ID, "repeat invalid call", "breaker")
	if err != nil {
		t.Fatal(err)
	}
	finished := waitSupervisor(t, service, project.ID, session.ID, run.ID)
	if finished.Status != RunPaused || finished.StopReason != StopStuck {
		t.Fatalf("breaker run = %+v", finished)
	}
	if finished.ToolErrors != 2 || finished.BlockedToolCalls != 1 {
		t.Fatalf("breaker counters = errors %d blocked %d", finished.ToolErrors, finished.BlockedToolCalls)
	}
	if got := executions.Load(); got != 2 {
		t.Fatalf("tool executions = %d, want two before the third was blocked", got)
	}
	if finished.Checkpoint == nil ||
		!strings.Contains(finished.Checkpoint.LastToolError, "REPEATED_CALL") {
		t.Fatalf("paused checkpoint did not persist the current tool failure: %+v", finished.Checkpoint)
	}
	session, err = service.Get(context.Background(), project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, message := range session.Messages {
		if message.RunID == run.ID && message.Role == "tool" &&
			strings.Contains(message.Content, "REPEATED_CALL") &&
			strings.Contains(message.Content, "inspect_tool_schema") {
			found = true
		}
	}
	if !found {
		t.Fatalf("structured repeated-call denial missing: %+v", session.Messages)
	}
}

func TestSupervisorInjectsBudgetSoftThresholdsOnce(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	service.MaxRounds = 5
	service.MaxToolCalls = 20
	var warned atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []llm.Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		for _, message := range request.Messages {
			if strings.Contains(message.Content, "预算提示") {
				warned.Store(true)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if warned.Load() {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"已根据预算提示收尾。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call-soft","type":"function","function":{"name":"graph_summary","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "soft-budget", TimeoutSeconds: 10, MaxOutputTokens: 256}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings
	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := service.Send(context.Background(), project.ID, session.ID, "use the soft budget", "soft-budget")
	if err != nil {
		t.Fatal(err)
	}
	finished := waitSupervisor(t, service, project.ID, session.ID, run.ID)
	if finished.Status != RunSucceeded || finished.ModelTurns != 5 {
		t.Fatalf("soft-budget run = %+v", finished)
	}
	session, err = service.Get(context.Background(), project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	var notices []string
	for _, event := range session.Events {
		if event.RunID == run.ID && event.Type == "budget_threshold" {
			notices = append(notices, event.Detail["percent"])
		}
	}
	if len(notices) != 1 || notices[0] != "80" {
		t.Fatalf("budget notices = %v, want one 80%% notice", notices)
	}
}

func TestSupervisorContinuesPausedRunFromCheckpoint(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	service.MaxRounds = 1
	service.MaxToolCalls = 10
	var normalCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Tools []llm.Tool `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		w.Header().Set("Content-Type", "application/json")
		if len(request.Tools) == 0 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"第一段已暂停。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
			return
		}
		if normalCalls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call-first","type":"function","function":{"name":"graph_summary","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"续跑完成。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":3}}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "continue", TimeoutSeconds: 10, MaxOutputTokens: 256}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings
	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	if err != nil {
		t.Fatal(err)
	}
	userMessage, firstRun, err := service.Send(context.Background(), project.ID, session.ID, "continue this audit", "continue-source")
	if err != nil {
		t.Fatal(err)
	}
	paused := waitSupervisor(t, service, project.ID, session.ID, firstRun.ID)
	if paused.Status != RunPaused || paused.Checkpoint == nil ||
		paused.UserMessageID != userMessage.ID || paused.RootRunID != firstRun.ID {
		t.Fatalf("paused checkpoint run = %+v", paused)
	}
	continued, err := service.Continue(context.Background(), project.ID, session.ID, firstRun.ID, "operator continue")
	if err != nil {
		t.Fatal(err)
	}
	if continued.Status != RunRunning || continued.ResumeOf != firstRun.ID ||
		continued.RootRunID != firstRun.ID || continued.UserMessageID != userMessage.ID ||
		continued.ExecutionOwner == "" || continued.LeaseEpoch <= 0 ||
		continued.ID == firstRun.ID {
		t.Fatalf("continued run lineage = %+v", continued)
	}
	if err := service.updateRun(context.Background(), project.ID, session.ID, firstRun, func(value *storage.SupervisorRun) {
		value.Checkpoint = nil
	}); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("old paused segment accepted a late write: %v", err)
	}
	finished := waitSupervisor(t, service, project.ID, session.ID, continued.ID)
	if finished.Status != RunSucceeded || finished.StopReason != StopNormal {
		t.Fatalf("continued completion = %+v", finished)
	}
	session, err = service.Get(context.Background(), project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	userMessages := 0
	continuedEvent := false
	for _, message := range session.Messages {
		if message.Role == "user" {
			userMessages++
		}
	}
	for _, event := range session.Events {
		if event.RunID == continued.ID && event.Type == "turn_continued" &&
			event.Detail["resume_of"] == firstRun.ID {
			continuedEvent = true
		}
	}
	if userMessages != 1 || !continuedEvent {
		t.Fatalf("continue duplicated user message or lost lineage: users=%d event=%t", userMessages, continuedEvent)
	}
}

func TestSupervisorRecoversExpiredRunningSegmentOnRead(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	user := storage.SupervisorMessage{
		ID: "sm-recovery-user", SessionID: session.ID, ProjectID: project.ID,
		Role: "user", Content: "recover this run", Status: "complete",
		Seq: nextMessageSeq(session), CreatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
	}
	run := storage.SupervisorRun{
		ID: "srun-recovery", SessionID: session.ID, ProjectID: project.ID,
		Status: RunRunning, Runtime: "llm", Model: "fixture",
		ConfigVersion: "1", PromptVersion: PromptVersion, ToolDigest: "digest",
		RoundLimit: 90, ToolCallLimit: 150, UserMessageID: user.ID,
		RootRunID: "srun-recovery", ExecutionOwner: "dead-owner",
		LeaseUntil:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		HeartbeatAt: now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		StartedAt:   now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		CreatedAt:   now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		UpdatedAt:   now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		Version:     1,
	}
	user.RunID = run.ID
	session.Messages = append(session.Messages, user)
	session.Runs = append(session.Runs, run)
	if _, err := service.Store.SaveSupervisorSession(context.Background(), session, session.Version); err != nil {
		t.Fatal(err)
	}
	recovered, err := service.Get(context.Background(), project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored := recovered.Runs[len(recovered.Runs)-1]
	if stored.Status != RunPaused || stored.StopReason != StopRecovery || stored.VisibleMessageID == "" {
		t.Fatalf("recovered run = %+v", stored)
	}
	found := false
	for _, message := range recovered.Messages {
		if message.ID == stored.VisibleMessageID && message.MessageKind == "paused" &&
			strings.Contains(message.Content, "宿主") {
			found = true
		}
	}
	if !found {
		t.Fatalf("recovery terminal message missing: %+v", recovered.Messages)
	}
}

func TestSupervisorRecoveryFencesEveryOldOwnerWrite(t *testing.T) {
	store := storage.NewMemory()
	project := storage.Project{ID: "proj-fenced-recovery", Name: "fixture", Source: "/srv/fixture"}
	if _, err := store.CreateProject(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	oldService := New(store, nil, nil)
	oldService.executionOwner = "owner-old"
	newService := New(store, nil, nil)
	newService.executionOwner = "owner-new"
	session, err := oldService.CreateSession(context.Background(), project.ID, "snap-fixed", "fenced")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	user := storage.SupervisorMessage{
		ID: "sm-fenced-user", SessionID: session.ID, ProjectID: project.ID,
		Role: "user", Content: "recover", Status: "complete",
		Seq: 1, RunID: "srun-fenced", CreatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
	}
	oldRun := storage.SupervisorRun{
		ID: "srun-fenced", SessionID: session.ID, ProjectID: project.ID,
		Status: RunRunning, Runtime: "llm", Model: "fixture",
		ConfigVersion: "1", PromptVersion: PromptVersion, ToolDigest: "digest",
		RoundLimit: 10, ToolCallLimit: 10, UserMessageID: user.ID, RootRunID: "srun-fenced",
		ExecutionOwner: "owner-old", LeaseEpoch: 3,
		HeartbeatAt: now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		LeaseUntil:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		StartedAt:   now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		CreatedAt:   now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		UpdatedAt:   now.Add(-2 * time.Minute).Format(time.RFC3339Nano), Version: 1,
	}
	session.Messages = append(session.Messages, user)
	session.Runs = append(session.Runs, oldRun)
	if _, err := store.SaveSupervisorSession(context.Background(), session, session.Version); err != nil {
		t.Fatal(err)
	}
	recovered, err := newService.Get(context.Background(), project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	current := recovered.Runs[0]
	if current.Status != RunPaused || current.ExecutionOwner != "owner-new" || current.LeaseEpoch != 4 {
		t.Fatalf("recovered run = %+v", current)
	}
	messageCount, eventCount := len(recovered.Messages), len(recovered.Events)
	ctx := context.Background()
	if err := oldService.appendMessage(ctx, project.ID, session.ID, oldRun, storage.SupervisorMessage{
		ID: "sm-late", SessionID: session.ID, ProjectID: project.ID,
		Role: "assistant", Content: "late", RunID: oldRun.ID, Status: "complete",
		CreatedAt: now.Format(time.RFC3339Nano),
	}); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("late message = %v, want conflict", err)
	}
	if err := oldService.appendToolResult(ctx, project.ID, session.ID, oldRun, "call-late", "graph_summary", `{"late":true}`, false); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("late tool result = %v, want conflict", err)
	}
	if err := oldService.appendEvent(ctx, project.ID, session.ID, oldRun, "late_event", "late", nil); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("late event = %v, want conflict", err)
	}
	if err := oldService.updateRun(ctx, project.ID, session.ID, oldRun, func(value *storage.SupervisorRun) {
		value.Checkpoint = &storage.SupervisorCheckpoint{SchemaVersion: 1, UserMessageID: user.ID, StopReason: StopRecovery, NextAction: "late", CreatedAt: now.Format(time.RFC3339Nano)}
	}); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("late checkpoint = %v, want conflict", err)
	}
	oldService.finishRun(finishOptions{
		projectID: project.ID, sessionID: session.ID, runID: oldRun.ID,
		owner: oldRun.ExecutionOwner, epoch: oldRun.LeaseEpoch,
		status: RunSucceeded, stopReason: StopNormal,
		terminalText: "late final", messageKind: "final", finalizerSource: "template",
	})
	originCtx := claim.WithOrigin(ctx, claim.Origin{
		SessionID: session.ID, RunID: oldRun.ID, Owner: oldRun.ExecutionOwner, Epoch: oldRun.LeaseEpoch,
	})
	if _, err := oldService.Cancel(originCtx, project.ID, session.ID, oldRun.ID, "late cancel"); !errors.Is(err, ErrConflict) {
		t.Fatalf("late cancel = %v, want conflict", err)
	}
	after, err := newService.Get(ctx, project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Messages) != messageCount || len(after.Events) != eventCount {
		t.Fatalf("late writes entered history: before messages=%d events=%d after=%d/%d", messageCount, eventCount, len(after.Messages), len(after.Events))
	}
	if after.Runs[0].Status != RunPaused || after.Runs[0].ExecutionOwner != "owner-new" || after.Runs[0].LeaseEpoch != 4 {
		t.Fatalf("late finalize changed run = %+v", after.Runs[0])
	}
}

func TestSupervisorTimeLimitPausesWithVisibleMessage(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	service.MaxRounds = 5
	service.MaxToolCalls = 10
	service.RunTimeout = 40 * time.Millisecond
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Tools []llm.Tool `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		w.Header().Set("Content-Type", "application/json")
		if len(request.Tools) > 0 {
			time.Sleep(150 * time.Millisecond)
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"late"},"finish_reason":"stop"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"模型收尾：时间预算已耗尽，已暂停。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":7}}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "time-limit", TimeoutSeconds: 10, MaxOutputTokens: 256}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings
	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := service.Send(context.Background(), project.ID, session.ID, "time out", "time-limit")
	if err != nil {
		t.Fatal(err)
	}
	finished := waitSupervisor(t, service, project.ID, session.ID, run.ID)
	if finished.Status != RunPaused || finished.StopReason != StopTimeLimit {
		t.Fatalf("time-limit run = %+v", finished)
	}
	session, err = service.Get(context.Background(), project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, message := range session.Messages {
		if message.ID == finished.VisibleMessageID && message.MessageKind == "paused" && strings.Contains(message.Content, "时间预算") {
			found = true
		}
	}
	if !found {
		t.Fatalf("time-limit terminal message missing: %+v", session.Messages)
	}
}

type fakeToolInput struct {
	SnapshotID string `json:"snapshot_id" jsonschema:"the snapshot id"`
	Query      string `json:"q,omitempty" jsonschema:"query"`
}

type fakeToolOutput struct {
	Summary string `json:"summary"`
}

func fakeMCPFactory(t *testing.T, calls *[]map[string]any) func(context.Context) (*sdk.ClientSession, error) {
	t.Helper()
	return func(ctx context.Context) (*sdk.ClientSession, error) {
		server := sdk.NewServer(&sdk.Implementation{Name: "fake", Version: "1"}, nil)
		sdk.AddTool(server, &sdk.Tool{Name: "graph_summary", Description: "summarize the graph"}, func(_ context.Context, _ *sdk.CallToolRequest, in fakeToolInput) (*sdk.CallToolResult, fakeToolOutput, error) {
			*calls = append(*calls, map[string]any{"snapshot_id": in.SnapshotID, "q": in.Query})
			return nil, fakeToolOutput{Summary: "real tool result"}, nil
		})
		serverTransport, clientTransport := sdk.NewInMemoryTransports()
		go func() { _, _ = server.Connect(ctx, serverTransport, nil) }()
		client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil)
		return client.Connect(ctx, clientTransport, nil)
	}
}

func fakeProvider(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		last := ""
		if len(body.Messages) > 0 {
			last = body.Messages[len(body.Messages)-1].Content
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(last, "summarize") && !strings.Contains(last, "tool result") {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call-1","type":"function","function":{"name":"graph_summary","arguments":"{\"q\":\"entry\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":4}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"这是直接回答，未调用工具。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":5}}`))
	}))
}

func supervisorFixture(t *testing.T) (*Service, storage.Project, *[]map[string]any) {
	t.Helper()
	store := storage.NewMemory()
	project := storage.Project{ID: "proj-supervisor", Name: "fixture", Source: "/srv/fixture"}
	if _, err := store.CreateProject(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	provider := fakeProvider(t)
	t.Cleanup(provider.Close)
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "test-model", TimeoutSeconds: 10, MaxOutputTokens: 512}, "initial"); err != nil {
		t.Fatal(err)
	}
	calls := []map[string]any{}
	service := New(store, settings, fakeMCPFactory(t, &calls))
	return service, project, &calls
}

func waitSupervisor(t *testing.T, service *Service, projectID, sessionID, runID string) storage.SupervisorRun {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		session, err := service.Get(context.Background(), projectID, sessionID)
		if err != nil {
			t.Fatal(err)
		}
		for _, run := range session.Runs {
			if run.ID == runID && terminal(run.Status) {
				return run
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("run did not finish: %+v", session.Runs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSupervisorAnswersWithoutToolsAndQueriesRealMCPWithBoundScope(t *testing.T) {
	service, project, calls := supervisorFixture(t)
	session, err := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := service.Send(context.Background(), project.ID, session.ID, "请直接回答这个问题", "client-1")
	if err != nil {
		t.Fatal(err)
	}
	finished := waitSupervisor(t, service, project.ID, session.ID, run.ID)
	if finished.Status != RunSucceeded || len(*calls) != 0 {
		t.Fatalf("pure answer used a tool: %+v calls=%+v", finished, *calls)
	}
	_, run, err = service.Send(context.Background(), project.ID, session.ID, "请 summarize 这个项目的图谱", "client-2")
	if err != nil {
		t.Fatal(err)
	}
	finished = waitSupervisor(t, service, project.ID, session.ID, run.ID)
	if finished.Status != RunSucceeded || len(*calls) != 1 || (*calls)[0]["snapshot_id"] != "snap-fixed" || (*calls)[0]["q"] != "entry" {
		t.Fatalf("tool loop = %+v calls=%+v", finished, *calls)
	}
	if finished.StopReason != StopNormal || finished.ModelTurns != 2 || finished.ToolCalls != 1 ||
		finished.RoundLimit != 90 || finished.ToolCallLimit != 150 {
		t.Fatalf("successful run budget facts = %+v, want normal 2 turns / 1 tool", finished)
	}
	session, err = service.Get(context.Background(), project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	var assistant, tool bool
	for _, message := range session.Messages {
		if message.Role == "assistant" && strings.Contains(message.Content, "直接回答") {
			assistant = true
		}
		if message.Role == "tool" && strings.Contains(message.Content, "real tool result") {
			tool = true
		}
	}
	if !assistant || !tool {
		t.Fatalf("message ledger missing assistant/tool pair: %+v", session.Messages)
	}
	if finished.ToolDigest == "" || finished.Model != "test-model" || finished.ConfigVersion == "" || finished.PromptVersion != PromptVersion {
		t.Fatalf("run pin missing: %+v", finished)
	}
}

func TestSupervisorMessageIdempotencyAndActiveTurnConflict(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	session, _ := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	first, run, err := service.Send(context.Background(), project.ID, session.ID, "hello", "same-key")
	if err != nil {
		t.Fatal(err)
	}
	again, replay, err := service.Send(context.Background(), project.ID, session.ID, "different body", "same-key")
	if err != nil || again.ID != first.ID || replay.ID != run.ID {
		t.Fatalf("idempotent send = %+v %+v %v", again, replay, err)
	}
	waitSupervisor(t, service, project.ID, session.ID, run.ID)
	session, _ = service.Get(context.Background(), project.ID, session.ID)
	count := 0
	for _, message := range session.Messages {
		if message.Role == "user" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate user messages: %+v", session.Messages)
	}
}

func TestSupervisorCancellationIsReadable(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	// Make the provider slow so cancellation can happen before completion.
	block := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"late"},"finish_reason":"stop"}]}`))
	}))
	defer slow.Close()
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: slow.URL, Model: "slow", TimeoutSeconds: 10, MaxOutputTokens: 256}, "initial"); err != nil {
		t.Fatal(err)
	}
	service.Settings = settings
	session, _ := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	_, run, err := service.Send(context.Background(), project.ID, session.ID, "block", "cancel-key")
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := service.Cancel(context.Background(), project.ID, session.ID, run.ID, "operator stop")
	close(block)
	if err != nil || cancelled.Status != RunCancelled {
		t.Fatalf("cancel = %+v %v", cancelled, err)
	}
	time.Sleep(100 * time.Millisecond)
	session, _ = service.Get(context.Background(), project.ID, session.ID)
	var visibleCancellation bool
	for _, stored := range session.Runs {
		if stored.ID == run.ID && stored.Status != RunCancelled {
			t.Fatalf("late model output overwrote cancellation: %+v", stored)
		}
	}
	for _, message := range session.Messages {
		if message.RunID == run.ID && message.Role == "assistant" &&
			message.MessageKind == "cancelled" && strings.TrimSpace(message.Content) != "" {
			visibleCancellation = true
		}
	}
	if !visibleCancellation {
		t.Fatal("cancelled run has no visible terminal message")
	}
}

func TestSupervisorRejectsUnknownProjectAndUnavailableModel(t *testing.T) {
	service, project, _ := supervisorFixture(t)
	if _, err := service.EnsureSession(context.Background(), "missing-project", "snap", ""); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown project = %v", err)
	}
	service.Settings = nil
	session, _ := service.EnsureSession(context.Background(), project.ID, "snap-fixed", "default")
	_, _, err := service.Send(context.Background(), project.ID, session.ID, "hello", "no-model")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable model = %v", err)
	}
}
