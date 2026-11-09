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
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

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
	for _, stored := range session.Runs {
		if stored.ID == run.ID && stored.Status != RunCancelled {
			t.Fatalf("late model output overwrote cancellation: %+v", stored)
		}
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
