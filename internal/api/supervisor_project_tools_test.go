package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/supervisor"
)

type supervisorCatalogFault struct {
	storage.FullStore
	unavailable atomic.Bool
}

func (s *supervisorCatalogFault) GetProject(ctx context.Context, id string) (storage.Project, error) {
	if s.unavailable.Load() {
		return storage.Project{}, errors.New("catalog disconnected")
	}
	return s.FullStore.GetProject(ctx, id)
}

func TestSupervisorDistinguishesCatalogFailureFromMissingProject(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	input, _ := env.rt.Store.GetProjectInput(context.Background(), project)
	fault := &supervisorCatalogFault{FullStore: env.rt.Store}
	_ = NewServer(fault, env.rt.Manager, env.rt.Analyzer, WithGraph(env.rt.Graph), WithSupervisor(env.rt.Supervisor))
	ctx := withPrincipal(context.Background(), Principal{Name: "operator", Capabilities: CapAdmin})
	client, err := env.rt.Supervisor.ProjectMCPClient(ctx, project, input.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	fault.unavailable.Store(true)
	result, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "project_api", Arguments: map[string]any{"operation": "GET /api/projects/{id}"}})
	raw, _ := json.Marshal(result)
	if err != nil || !result.IsError || !strings.Contains(string(raw), "storage_unavailable") {
		t.Fatalf("catalog failure misclassified: %v %s", err, raw)
	}
}

func TestSupervisorProjectToolsDiscoverCurrentGraph(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	input, err := env.rt.Store.GetProjectInput(context.Background(), project)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withPrincipal(context.Background(), Principal{Name: "operator", Capabilities: CapAdmin})
	client, err := env.rt.Supervisor.ProjectMCPClient(ctx, project, input.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "list_project_operations", Arguments: map[string]any{"search": "snapshots"}})
	if err != nil || result.IsError {
		t.Fatalf("project operation directory unavailable: %v %+v", err, result)
	}
	result, err = client.CallTool(ctx, &sdk.CallToolParams{Name: "project_api", Arguments: map[string]any{"operation": "GET /api/snapshots"}})
	if err != nil || result.IsError {
		t.Fatalf("project snapshots unavailable: %v %+v", err, result)
	}
	raw, _ := json.Marshal(result.StructuredContent)
	if !strings.Contains(string(raw), input.SnapshotID) {
		t.Fatalf("bound source absent: %s", raw)
	}
}

func TestSupervisorReadsVerifiedArtifactInStableWindows(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	input, _ := env.rt.Store.GetProjectInput(context.Background(), project)
	index := env.rt.Store.(artifact.Index)
	scope, err := index.ArtifactScope(context.Background(), project, input.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := artifact.NewLocal(filepath.Join(env.rt.Manager.Root, "artifacts"), index)
	if err != nil {
		t.Fatal(err)
	}
	content := "x" + strings.Repeat("这是固定报告的真实正文。\n", 900)
	ref := artifact.Ref{ID: "artifact-window-report", Kind: "report.document", Scope: scope, SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(content))), Bytes: int64(len(content)), MediaType: "text/plain", SchemaID: "codexploit/example/v1", Producer: artifact.Producer{PluginID: "builtin.reporter", PluginVersion: "1.0.0", InvocationID: "report-window", ConfigDigest: strings.Repeat("0", 64)}}
	if _, err := objects.Put(context.Background(), ref, strings.NewReader(content), ref.Bytes); err != nil {
		t.Fatal(err)
	}
	ctx := withPrincipal(context.Background(), Principal{Name: "operator", Capabilities: CapAdmin})
	client, err := env.rt.Supervisor.ProjectMCPClient(ctx, project, input.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	args := map[string]any{"operation": "GET /api/v1/projects/{projectID}/snapshots/{snapshotID}/artifacts/{artifactID}/content", "params": map[string]string{"snapshotID": input.SnapshotID, "artifactID": ref.ID}}
	var got strings.Builder
	for page := 0; page < 30; page++ {
		result, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "project_api", Arguments: args})
		if err != nil || result.IsError {
			t.Fatalf("report read: %v %+v", err, result)
		}
		raw, _ := json.Marshal(result.StructuredContent)
		var window struct {
			Content   string `json:"content"`
			Next      int    `json:"next_offset"`
			Truncated bool   `json:"truncated"`
			SHA       string `json:"sha256"`
		}
		if err := json.Unmarshal(raw, &window); err != nil {
			t.Fatal(err)
		}
		if window.SHA != ref.SHA256 {
			t.Fatalf("wrong fixed report digest: %s", raw)
		}
		got.WriteString(window.Content)
		if !window.Truncated {
			break
		}
		args["response_offset"] = window.Next
		args["expected_sha256"] = window.SHA
	}
	if got.String() != content {
		t.Fatalf("report content incomplete: %d != %d", got.Len(), len(content))
	}
	if err := os.WriteFile(filepath.Join(env.rt.Manager.Root, "artifacts", "objects", ref.SHA256), []byte(strings.Repeat("x", len(content))), 0600); err != nil {
		t.Fatal(err)
	}
	delete(args, "expected_sha256")
	delete(args, "response_offset")
	result, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "project_api", Arguments: args})
	if err != nil || !result.IsError {
		t.Fatalf("corrupt content must be a failed tool result: %v %+v", err, result)
	}
}

func TestSupervisorCanSelectAnotherGraphWithinTheProject(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	input, _ := env.rt.Store.GetProjectInput(context.Background(), project)
	second := "snap-123456789abcdef0123456789abcdef0"
	if err := env.rt.Store.PutSnapshot(context.Background(), project, &repository.Snapshot{SnapshotID: second}); err != nil {
		t.Fatal(err)
	}
	if err := env.rt.Store.ReplaceGraph(context.Background(), second, &scg.Graph{SchemaVersion: scg.SchemaVersion, SnapshotID: second, GraphVersion: "graph-second"}); err != nil {
		t.Fatal(err)
	}
	ctx := withPrincipal(context.Background(), Principal{Name: "operator", Capabilities: CapAdmin})
	client, err := env.rt.Supervisor.ProjectMCPClient(ctx, project, input.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "graph_summary", Arguments: map[string]any{"snapshot_id": second}})
	if err != nil || result.IsError {
		t.Fatalf("own graph cannot be selected: %v %+v", err, result)
	}
	raw, _ := json.Marshal(result.StructuredContent)
	if !strings.Contains(string(raw), "graph-second") {
		t.Fatalf("wrong graph returned: %s", raw)
	}
}

func TestSupervisorProjectOperationsKeepObjectOwnership(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	other := "other-project"
	if _, err := env.rt.Store.CreateProject(context.Background(), storage.Project{ID: other, Name: "Other"}); err != nil {
		t.Fatal(err)
	}
	input, _ := env.rt.Store.GetProjectInput(context.Background(), project)
	foreign := repository.Snapshot{SnapshotID: "snap-abcdef0123456789abcdef0123456789"}
	if err := env.rt.Store.PutSnapshot(context.Background(), other, &foreign); err != nil {
		t.Fatal(err)
	}
	for _, a := range []path.Audit{{ID: "own-task", SnapshotID: input.SnapshotID, Status: "PAUSED", Paused: true}, {ID: "foreign-task", SnapshotID: foreign.SnapshotID, Status: "PAUSED", Paused: true}} {
		if err := env.rt.Store.CreateAudit(a); err != nil {
			t.Fatal(err)
		}
	}
	ctx := withPrincipal(context.Background(), Principal{Name: "operator", Capabilities: CapAdmin})
	client, err := env.rt.Supervisor.ProjectMCPClient(ctx, project, input.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	invoke := func(args map[string]any) (*sdk.CallToolResult, error) {
		return client.CallTool(ctx, &sdk.CallToolParams{Name: "project_api", Arguments: args})
	}
	result, err := invoke(map[string]any{"operation": "GET /api/tasks/{id}", "params": map[string]string{"id": "own-task"}})
	if err != nil || result.IsError {
		t.Fatalf("own task detail unavailable: %v %+v", err, result)
	}
	for _, args := range []map[string]any{
		{"operation": "GET /api/tasks/{id}", "params": map[string]string{"id": "foreign-task"}},
		{"operation": "POST /api/tasks/{id}/resume", "params": map[string]string{"id": "foreign-task"}},
		{"operation": "POST /api/projects/{id}/tasks", "body": map[string]any{"snapshot_id": foreign.SnapshotID, "name": "foreign write"}},
		{"operation": "GET /api/snapshots/{id}/graph", "params": map[string]string{"id": foreign.SnapshotID}},
		{"operation": "GET /api/runs", "query": map[string]string{"snapshot_id": foreign.SnapshotID}},
		{"operation": "PUT /api/settings/llm", "body": map[string]any{}},
	} {
		result, err := invoke(args)
		if err == nil && !result.IsError {
			t.Fatalf("out-of-project operation accepted: %+v %+v", args, result)
		}
	}
	foreignTask, err := env.rt.Store.GetAudit("foreign-task")
	if err != nil || !foreignTask.Paused {
		t.Fatalf("foreign task changed: %+v %v", foreignTask, err)
	}
}

func TestSupervisorProjectToolsRespectOperatorRoleAndCAS(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	input, _ := env.rt.Store.GetProjectInput(context.Background(), project)
	for _, role := range []Capability{CapRead, CapAdmin} {
		ctx := withPrincipal(context.Background(), Principal{Name: "operator", Capabilities: role})
		client, err := env.rt.Supervisor.ProjectMCPClient(ctx, project, input.SnapshotID)
		if err != nil {
			t.Fatal(err)
		}
		result, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "project_api", Arguments: map[string]any{"operation": "GET /api/projects/{id}"}})
		if err != nil || result.IsError {
			t.Fatalf("project read: %v %+v", err, result)
		}
		result, err = client.CallTool(ctx, &sdk.CallToolParams{Name: "project_api", Arguments: map[string]any{"operation": "PATCH /api/projects/{id}", "if_match": "\"stale\"", "body": map[string]any{"description": "must not apply"}}})
		if err != nil || !result.IsError {
			t.Fatalf("role/CAS gate bypassed: %v %+v", err, result)
		}
		_ = client.Close()
	}
	updated, _ := env.rt.Store.GetProject(context.Background(), project)
	if updated.Description != "one source" {
		t.Fatalf("rejected write changed project: %+v", updated)
	}
}

func TestSupervisorConversationCanOperateOnItsProject(t *testing.T) {
	env := newTestEnv(t, false)
	exerciseSupervisorProjectOperation(t, env)
}

func exerciseSupervisorProjectOperation(t *testing.T, env *testEnv) (string, string) {
	t.Helper()
	project := createAnalysisProject(t, env, asgFixtureSource(t))
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []llm.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		last := request.Messages[len(request.Messages)-1]
		message := map[string]any{"role": "assistant"}
		arguments := map[string]any{"operation": "GET /api/projects/{id}"}
		callID := "read-project"
		if last.Role == "tool" {
			var result struct {
				ETag string `json:"etag"`
				OK   bool   `json:"ok"`
			}
			_ = json.Unmarshal([]byte(last.Content), &result)
			if !result.OK {
				message["content"] = "项目操作失败：" + last.Content
			} else if last.ToolCallID == "read-project" {
				arguments = map[string]any{"operation": "PATCH /api/projects/{id}", "if_match": result.ETag, "body": map[string]any{"description": "项目助手已更新"}}
				callID = "edit-project"
			} else {
				message["content"] = "已更新当前项目说明。"
			}
		}
		if message["content"] == nil {
			raw, _ := json.Marshal(arguments)
			message["tool_calls"] = []any{map[string]any{"id": callID, "type": "function", "function": map[string]any{"name": "project_api", "arguments": string(raw)}}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": message, "finish_reason": "stop"}}})
	}))
	t.Cleanup(provider.Close)
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = settings.Save(llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: provider.URL, Model: "project-operator", TimeoutSeconds: 10, MaxOutputTokens: 512}, "initial"); err != nil {
		t.Fatal(err)
	}
	env.rt.Supervisor.Settings = settings
	base := "/api/v1/projects/" + project + "/agent-sessions"
	created := do(t, env.ts, http.MethodPost, base, map[string]any{"api_version": "codexploit/v1"}, nil)
	var session struct {
		Session storage.SupervisorSession `json:"session"`
	}
	created.decode(t, &session)
	sent := do(t, env.ts, http.MethodPost, base+"/"+session.Session.ID+"/messages", map[string]any{"api_version": "codexploit/v1", "content": "把当前项目说明改成项目助手已更新", "client_message_id": "operate-project"}, nil)
	var receipt struct {
		Run storage.SupervisorRun `json:"run"`
	}
	sent.decode(t, &receipt)
	ledger, run := waitSupervisorAPI(t, env, project, session.Session.ID, receipt.Run.ID)
	updated, err := env.rt.Store.GetProject(context.Background(), project)
	if err != nil || run.Status != supervisor.RunSucceeded || updated.Description != "项目助手已更新" {
		t.Fatalf("project operation did not apply: %+v %+v %v messages=%+v", run, updated, err, ledger.Messages)
	}
	return project, session.Session.ID
}

func TestPostgresSupervisorProjectAccessSurvivesRestart(t *testing.T) {
	cfg := postgresConfig(t)
	runtime, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, runtime, false)
	project, sessionID := exerciseSupervisorProjectOperation(t, env)
	env.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted := serveTestEnv(t, rebuilt, false)
	session, err := rebuilt.Supervisor.Get(context.Background(), project, sessionID)
	if err != nil || len(session.Runs) != 1 || session.Runs[0].Status != supervisor.RunSucceeded {
		t.Fatalf("persisted turn missing: %+v %v", session, err)
	}
	ctx := withPrincipal(context.Background(), Principal{Name: "operator", Capabilities: CapAdmin})
	client, err := rebuilt.Supervisor.ProjectMCPClient(ctx, project, session.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "project_api", Arguments: map[string]any{"operation": "GET /api/projects/{id}"}})
	raw, _ := json.Marshal(result)
	if err != nil || result.IsError || !strings.Contains(string(raw), "项目助手已更新") {
		t.Fatalf("rebuilt project access: %v %s", err, raw)
	}
	response := do(t, restarted.ts, http.MethodGet, "/api/v1/projects/"+project+"/agent-sessions/"+sessionID, nil, nil)
	if response.status != 200 || !strings.Contains(string(response.body), "edit-project") {
		t.Fatalf("tool ledger not restored: %s", response.body)
	}
}
