package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
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
			if run.ID == runID && (run.Status == supervisor.RunSucceeded ||
				run.Status == supervisor.RunFailed || run.Status == supervisor.RunCancelled ||
				run.Status == supervisor.RunPaused || run.Status == supervisor.RunPartial) {
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
	if run.StopReason != supervisor.StopNormal || run.ModelTurns != 1 ||
		run.ToolCalls != 0 || run.RoundLimit != 90 || run.ToolCallLimit != 150 ||
		run.VisibleMessageID == "" || run.ExecutionOwner == "" || run.LeaseEpoch <= 0 {
		t.Fatalf("successful run facts = %+v", run)
	}
	budget, err := env.rt.Store.GetAuditBudget(session.AuditID)
	if err != nil || budget.UsedTokens != run.InputTokens+run.OutputTokens || budget.ReservedTokens != 0 {
		t.Fatalf("settled supervisor budget = %+v err=%v", budget, err)
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

func TestProjectSupervisorBudgetUsesWriterAndLedgerVersion(t *testing.T) {
	env := newTestEnv(t, false)
	configureSupervisorProvider(t, env)
	projectID := createAnalysisProject(t, env, asgFixtureSource(t))
	base := "/api/v1/projects/" + projectID + "/agent-sessions"
	created := do(t, env.ts, http.MethodPost, base, map[string]any{"api_version": "codexploit/v1"}, nil)
	var page struct {
		Session storage.SupervisorSession `json:"session"`
	}
	created.decode(t, &page)
	budgetURL := base + "/" + page.Session.ID + "/budget"
	read := doAs(t, env.ts, readerSecret, http.MethodGet, budgetURL, nil, nil)
	var current struct {
		Budget agent.AuditBudget `json:"budget"`
	}
	read.decode(t, &current)
	if read.status != http.StatusOK || current.Budget.LimitTokens != agent.DefaultAuditTokenBudget || current.Budget.Version == 0 {
		t.Fatalf("read supervisor budget = %d %s", read.status, read.body)
	}
	grantBody := map[string]any{
		"tokens": 5000, "reason": "continue investigation",
		"decision": agent.GrantApproved, "expected_version": current.Budget.Version,
	}
	if denied := doAs(t, env.ts, readerSecret, http.MethodPost, budgetURL+"/grants", grantBody, nil); denied.status != http.StatusForbidden {
		t.Fatalf("reader budget grant = %d (%s)", denied.status, denied.body)
	}
	granted := do(t, env.ts, http.MethodPost, budgetURL+"/grants", grantBody, nil)
	var updated struct {
		Budget agent.AuditBudget `json:"budget"`
	}
	granted.decode(t, &updated)
	if granted.status != http.StatusCreated || updated.Budget.LimitTokens != current.Budget.LimitTokens+5000 {
		t.Fatalf("grant supervisor budget = %d %s", granted.status, granted.body)
	}
	stale := do(t, env.ts, http.MethodPost, budgetURL+"/grants", grantBody, nil)
	if stale.status != http.StatusPreconditionFailed {
		t.Fatalf("stale supervisor grant = %d (%s)", stale.status, stale.body)
	}
	rejectedBody := map[string]any{
		"tokens": 1000, "reason": "budget request rejected",
		"decision": agent.GrantRejected, "expected_version": updated.Budget.Version,
	}
	rejected := do(t, env.ts, http.MethodPost, budgetURL+"/grants", rejectedBody, nil)
	var final struct {
		Budget agent.AuditBudget `json:"budget"`
	}
	rejected.decode(t, &final)
	if rejected.status != http.StatusCreated || final.Budget.LimitTokens != updated.Budget.LimitTokens {
		t.Fatalf("rejected supervisor grant = %d %s", rejected.status, rejected.body)
	}
}

func TestProjectSupervisorPausesAtRoundLimitWithVisibleMessage(t *testing.T) {
	env := newTestEnv(t, false)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tools []llm.Tool `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		if len(body.Tools) > 0 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"graph_summary","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"本轮达到轮次上限，已暂停。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4}}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "round-limit", TimeoutSeconds: 10, MaxOutputTokens: 512}, "initial"); err != nil {
		t.Fatal(err)
	}
	env.rt.Supervisor.Settings = settings
	env.rt.Supervisor.MaxRounds = 2
	env.rt.Supervisor.MaxToolCalls = 10
	projectID := createAnalysisProject(t, env, asgFixtureSource(t))
	base := "/api/v1/projects/" + projectID + "/agent-sessions"
	created := do(t, env.ts, http.MethodPost, base, map[string]any{"api_version": "codexploit/v1"}, nil)
	var sessionPage struct {
		Session storage.SupervisorSession `json:"session"`
	}
	created.decode(t, &sessionPage)
	sent := do(t, env.ts, http.MethodPost, base+"/"+sessionPage.Session.ID+"/messages", map[string]any{
		"api_version": "codexploit/v1", "content": "loop", "client_message_id": "api-round-limit",
	}, nil)
	var receipt struct {
		Run storage.SupervisorRun `json:"run"`
	}
	sent.decode(t, &receipt)
	session, run := waitSupervisorAPI(t, env, projectID, sessionPage.Session.ID, receipt.Run.ID)
	if run.Status != supervisor.RunPaused || run.StopReason != supervisor.StopRoundLimit ||
		run.ModelTurns != 2 || run.ToolCalls != 2 || run.VisibleMessageID == "" {
		t.Fatalf("round-limit API run = %+v", run)
	}
	found := false
	for _, message := range session.Messages {
		if message.ID == run.VisibleMessageID && message.MessageKind == "paused" &&
			strings.TrimSpace(message.Content) != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("visible terminal message missing: %+v", session.Messages)
	}
}

func TestProjectSupervisorContinuesPausedRun(t *testing.T) {
	env := newTestEnv(t, false)
	var normalCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tools []llm.Tool `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		if len(body.Tools) == 0 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"第一段暂停。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
			return
		}
		if normalCalls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"graph_summary","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"续跑完成。"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4}}`))
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "continue-api", TimeoutSeconds: 10, MaxOutputTokens: 512}, "initial"); err != nil {
		t.Fatal(err)
	}
	env.rt.Supervisor.Settings = settings
	env.rt.Supervisor.MaxRounds = 1
	env.rt.Supervisor.MaxToolCalls = 10
	projectID := createAnalysisProject(t, env, asgFixtureSource(t))
	base := "/api/v1/projects/" + projectID + "/agent-sessions"
	created := do(t, env.ts, http.MethodPost, base, map[string]any{"api_version": "codexploit/v1"}, nil)
	var sessionPage struct {
		Session storage.SupervisorSession `json:"session"`
	}
	created.decode(t, &sessionPage)
	sent := do(t, env.ts, http.MethodPost, base+"/"+sessionPage.Session.ID+"/messages", map[string]any{
		"api_version": "codexploit/v1", "content": "continue", "client_message_id": "api-continue-source",
	}, nil)
	var first struct {
		Run storage.SupervisorRun `json:"run"`
	}
	sent.decode(t, &first)
	_, paused := waitSupervisorAPI(t, env, projectID, sessionPage.Session.ID, first.Run.ID)
	if paused.Status != supervisor.RunPaused || paused.Checkpoint == nil {
		t.Fatalf("paused run = %+v", paused)
	}
	if denied := doAs(t, env.ts, readerSecret, http.MethodPost,
		base+"/"+sessionPage.Session.ID+"/runs/"+paused.ID+"/continue",
		map[string]any{"reason": "reader"}, map[string]string{"Idempotency-Key": "reader-continue"}); denied.status != http.StatusForbidden {
		t.Fatalf("reader continue = %d (%s)", denied.status, denied.body)
	}
	continued := do(t, env.ts, http.MethodPost,
		base+"/"+sessionPage.Session.ID+"/runs/"+paused.ID+"/continue",
		map[string]any{"reason": "operator continue"},
		map[string]string{"Idempotency-Key": "continue-api-key"})
	if continued.status != http.StatusAccepted {
		t.Fatalf("continue = %d (%s)", continued.status, continued.body)
	}
	var receipt struct {
		Run storage.SupervisorRun `json:"run"`
	}
	continued.decode(t, &receipt)
	replayed := do(t, env.ts, http.MethodPost,
		base+"/"+sessionPage.Session.ID+"/runs/"+paused.ID+"/continue",
		map[string]any{"reason": "operator continue"},
		map[string]string{"Idempotency-Key": "continue-api-key"})
	var replayReceipt struct {
		Run storage.SupervisorRun `json:"run"`
	}
	replayed.decode(t, &replayReceipt)
	if replayed.status != http.StatusAccepted || replayReceipt.Run.ID != receipt.Run.ID {
		t.Fatalf("continue replay = %d %+v", replayed.status, replayReceipt.Run)
	}
	session, finished := waitSupervisorAPI(t, env, projectID, sessionPage.Session.ID, receipt.Run.ID)
	if finished.Status != supervisor.RunSucceeded || finished.ResumeOf != paused.ID ||
		finished.RootRunID != paused.RootRunID {
		t.Fatalf("continued run = %+v", finished)
	}
	users := 0
	for _, message := range session.Messages {
		if message.Role == "user" {
			users++
		}
	}
	if users != 1 {
		t.Fatalf("continue duplicated user message: %d", users)
	}
}

func TestProjectSupervisorCreatesIsolatedSessionsOnEveryRequest(t *testing.T) {
	env := newTestEnv(t, false)
	configureSupervisorProvider(t, env)
	firstProject := createAnalysisProject(t, env, asgFixtureSource(t))
	secondProject := createAnalysisProject(t, env, asgFixtureSource(t))

	create := func(projectID, title string) storage.SupervisorSession {
		t.Helper()
		response := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projectID+"/agent-sessions", map[string]any{
			"api_version": "codexploit/v1",
			"title":       title,
		}, nil)
		if response.status != http.StatusCreated {
			t.Fatalf("create session: %d %s", response.status, response.body)
		}
		var page struct {
			Session storage.SupervisorSession `json:"session"`
		}
		response.decode(t, &page)
		if page.Session.ProjectID != projectID {
			t.Fatalf("session project = %q, want %q", page.Session.ProjectID, projectID)
		}
		return page.Session
	}

	first := create(firstProject, "First")
	ensure := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+firstProject+"/agent-sessions", map[string]any{
		"api_version":    "codexploit/v1",
		"title":          "Ignored after bootstrap",
		"reuse_existing": true,
	}, nil)
	var ensured struct {
		Session storage.SupervisorSession `json:"session"`
	}
	ensure.decode(t, &ensured)
	if ensure.status != http.StatusCreated || ensured.Session.ID != first.ID {
		t.Fatalf("ensure existing session = %d %s", ensure.status, ensure.body)
	}
	second := create(firstProject, "Second")
	if first.ID == second.ID {
		t.Fatalf("manual session creation reused %s", first.ID)
	}
	other := create(secondProject, "Other project")

	list := func(projectID string) []storage.SupervisorSession {
		t.Helper()
		response := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+projectID+"/agent-sessions", nil, nil)
		if response.status != http.StatusOK {
			t.Fatalf("list sessions: %d %s", response.status, response.body)
		}
		var page struct {
			Sessions []storage.SupervisorSession `json:"sessions"`
		}
		response.decode(t, &page)
		return page.Sessions
	}

	firstSessions := list(firstProject)
	if len(firstSessions) != 2 {
		t.Fatalf("first project sessions = %d, want 2", len(firstSessions))
	}
	for _, session := range firstSessions {
		if session.ProjectID != firstProject || session.ID == other.ID {
			t.Fatalf("first project leaked session: %+v", session)
		}
	}
	otherSessions := list(secondProject)
	if len(otherSessions) != 1 || otherSessions[0].ID != other.ID || otherSessions[0].ProjectID != secondProject {
		t.Fatalf("second project sessions = %+v", otherSessions)
	}
	cross := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+secondProject+"/agent-sessions/"+first.ID, nil, nil)
	if cross.status != http.StatusNotFound {
		t.Fatalf("cross-project session read = %d %s", cross.status, cross.body)
	}
}
