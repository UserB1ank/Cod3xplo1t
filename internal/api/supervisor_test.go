package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/supervisor"
)

func configureSupervisorProvider(t *testing.T, env *testEnv) {
	t.Helper()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		last := ""
		if len(body.Messages) > 0 {
			last = body.Messages[len(body.Messages)-1].Content
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(last, "tool") {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"graph_summary","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"这是项目助手的回答。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4}}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "supervisor-test", TimeoutSeconds: 10, MaxOutputTokens: 512}, "initial"); err != nil {
		t.Fatal(err)
	}
	if env.rt.Supervisor == nil {
		t.Fatal("supervisor was not wired")
	}
	env.rt.Supervisor.Settings = settings
}

func waitSupervisorAPI(t *testing.T, env *testEnv, projectID, sessionID, runID string) (storage.SupervisorSession, storage.SupervisorRun) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		response := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+projectID+"/agent-sessions/"+sessionID, nil, nil)
		var page struct {
			Session storage.SupervisorSession `json:"session"`
		}
		response.decode(t, &page)
		for _, run := range page.Session.Runs {
			if run.ID == runID && (run.Status == supervisor.RunSucceeded || run.Status == supervisor.RunFailed || run.Status == supervisor.RunCancelled) {
				return page.Session, run
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("supervisor run timeout: %s", response.body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestProjectSupervisorSessionAndConversation(t *testing.T) {
	env := newTestEnv(t, false)
	configureSupervisorProvider(t, env)
	projectID := createAnalysisProject(t, env, asgFixtureSource(t))
	base := "/api/v1/projects/" + projectID + "/agent-sessions"
	listed := do(t, env.ts, http.MethodGet, base, nil, nil)
	var page struct {
		Sessions  []storage.SupervisorSession `json:"sessions"`
		Available bool                        `json:"available"`
	}
	listed.decode(t, &page)
	if listed.status != http.StatusOK || !page.Available || len(page.Sessions) != 0 {
		t.Fatalf("initial sessions = %d %s", listed.status, listed.body)
	}
	created := do(t, env.ts, http.MethodPost, base, map[string]any{"api_version": "codexploit/v1", "title": "默认会话"}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create session: %d %s", created.status, created.body)
	}
	var sessionPage struct {
		Session storage.SupervisorSession `json:"session"`
	}
	created.decode(t, &sessionPage)
	sessionID := sessionPage.Session.ID
	if sessionID == "" || sessionPage.Session.SnapshotID == "" {
		t.Fatalf("session = %+v", sessionPage.Session)
	}
	sent := do(t, env.ts, http.MethodPost, base+"/"+sessionID+"/messages", map[string]any{
		"api_version": "codexploit/v1", "content": "你好，直接回答即可", "client_message_id": "api-1",
	}, nil)
	if sent.status != http.StatusAccepted {
		t.Fatalf("send: %d %s", sent.status, sent.body)
	}
	var receipt struct {
		Message storage.SupervisorMessage `json:"message"`
		Run     storage.SupervisorRun     `json:"run"`
	}
	sent.decode(t, &receipt)
	session, run := waitSupervisorAPI(t, env, projectID, sessionID, receipt.Run.ID)
	if run.Status != supervisor.RunSucceeded {
		t.Fatalf("run = %+v", run)
	}
	var assistant bool
	for _, message := range session.Messages {
		if message.Role == "assistant" && strings.Contains(message.Content, "项目助手") {
			assistant = true
		}
	}
	if !assistant {
		t.Fatalf("assistant answer missing: %+v", session.Messages)
	}
	// Repeating the same client message is idempotent.
	replay := do(t, env.ts, http.MethodPost, base+"/"+sessionID+"/messages", map[string]any{
		"api_version": "codexploit/v1", "content": "你好，直接回答即可", "client_message_id": "api-1",
	}, nil)
	var replayPage struct {
		Run storage.SupervisorRun `json:"run"`
	}
	replay.decode(t, &replayPage)
	if replay.status != http.StatusAccepted || replayPage.Run.ID != receipt.Run.ID {
		t.Fatalf("replay = %d %+v", replay.status, replayPage)
	}
	if reader := doAs(t, env.ts, readerSecret, http.MethodPost, base+"/"+sessionID+"/messages", map[string]any{
		"api_version": "codexploit/v1", "content": "reader", "client_message_id": "reader-1",
	}, nil); reader.status != http.StatusForbidden {
		t.Fatalf("reader send = %d %s", reader.status, reader.body)
	}
	other := do(t, env.ts, http.MethodPost, "/api/v1/projects", map[string]any{"api_version": "codexploit/v1", "name": "Other"}, nil)
	var otherPage projectResponse
	other.decode(t, &otherPage)
	if cross := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+otherPage.Project.ID+"/agent-sessions/"+sessionID, nil, nil); cross.status != http.StatusNotFound {
		t.Fatalf("cross-project session = %d %s", cross.status, cross.body)
	}
}

func TestProjectSupervisorReportsUnavailableModel(t *testing.T) {
	env := newTestEnv(t, false)
	projectID := createAnalysisProject(t, env, asgFixtureSource(t))
	env.rt.Supervisor.Settings = nil
	base := "/api/v1/projects/" + projectID + "/agent-sessions"
	created := do(t, env.ts, http.MethodPost, base, map[string]any{"api_version": "codexploit/v1"}, nil)
	if created.status != http.StatusConflict || !strings.Contains(string(created.body), "agent_unavailable") {
		t.Fatalf("unavailable session = %d %s", created.status, created.body)
	}
}
