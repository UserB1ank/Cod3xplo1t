package api

import (
	"context"
	"encoding/json"
	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

func TestTaskStartsFixedWorkflowAndExposesRealNodeArtifacts(t *testing.T) {
	env := newTestEnv(t, false)
	source := t.TempDir()
	writeFile(t, source, "main.go", "package main\nfunc main() {}\n")
	project := createProject(t, env.ts, source).Project
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	prefix := "/api/v1/projects/" + project.ID
	registered := do(t, env.ts, http.MethodPost, prefix+"/snapshots/"+snapshot.Snapshot.SnapshotID+"/artifacts", nil, nil)
	var page struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	registered.decode(t, &page)
	var input artifact.Ref
	for _, ref := range page.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref
		}
	}
	saved := do(t, env.ts, http.MethodPost, prefix+"/workflows", map[string]any{"api_version": "codexploit/v1", "spec": workflowSpecFixture()}, nil)
	if saved.status != 201 {
		t.Fatal(string(saved.body))
	}
	compiled := do(t, env.ts, http.MethodPost, prefix+"/workflows/workflow-discovery/versions/1.0.0/compile", map[string]any{"api_version": "codexploit/v1", "snapshot_id": input.Scope.SnapshotID, "inputs": []string{input.ID}, "language": "Go"}, nil)
	var plan struct {
		Plan struct {
			ID     string `json:"plan_id"`
			Digest string `json:"digest"`
		} `json:"plan"`
	}
	compiled.decode(t, &plan)
	listed := doAs(t, env.ts, readerSecret, http.MethodGet, prefix+"/workflow-plans?snapshot_id="+snapshot.Snapshot.SnapshotID, nil, nil)
	if listed.status != 200 || !strings.Contains(string(listed.body), plan.Plan.ID) {
		t.Fatalf("plan directory: %d %s", listed.status, listed.body)
	}

	created := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/tasks", map[string]any{"name": "Workflow task", "objective": "Syntax discovery", "snapshot_id": input.Scope.SnapshotID, "workflow_plan_id": plan.Plan.ID, "analyze_candidates": false}, nil)
	if created.status != 201 {
		t.Fatalf("create task with plan: %d %s", created.status, created.body)
	}
	var receipt struct {
		Task struct {
			ID string `json:"audit_id"`
		} `json:"task"`
		Run struct {
			ID string `json:"workflow_run_id"`
		} `json:"workflow_run"`
	}
	created.decode(t, &receipt)
	if receipt.Task.ID == "" || receipt.Run.ID == "" {
		t.Fatalf("missing separate task/run IDs: %s", created.body)
	}
	endpoint := prefix + "/workflow-runs/" + receipt.Run.ID
	var result struct {
		Run struct {
			ID         string `json:"workflow_run_id"`
			TaskID     string `json:"task_id"`
			PlanDigest string `json:"plan_digest"`
			Status     string `json:"status"`
			Nodes      []struct {
				ID           string         `json:"node_run_id"`
				InvocationID string         `json:"invocation_id"`
				Outputs      []artifact.Ref `json:"outputs"`
				Status       string         `json:"status"`
			} `json:"nodes"`
		} `json:"run"`
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		r := doAs(t, env.ts, readerSecret, http.MethodGet, endpoint, nil, nil)
		if r.status != 200 {
			t.Fatalf("run status: %d %s", r.status, r.body)
		}
		r.decode(t, &result)
		if result.Run.Status != "CREATED" && result.Run.Status != "RUNNING" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("workflow did not settle")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if result.Run.Status != "SUCCEEDED" || result.Run.TaskID != receipt.Task.ID || result.Run.PlanDigest != plan.Plan.Digest || len(result.Run.Nodes) < 1 || result.Run.Nodes[0].Status != "SUCCEEDED" || result.Run.Nodes[0].InvocationID == "" || len(result.Run.Nodes[0].Outputs) != 2 {
		t.Fatalf("not a real parser run: %+v", result)
	}
	for _, ref := range result.Run.Nodes[0].Outputs {
		if result.Run.Nodes[0].ID == result.Run.Nodes[0].InvocationID || ref.Producer.InvocationID != result.Run.Nodes[0].InvocationID {
			t.Fatalf("node run and plugin invocation must have distinct traceable IDs: %+v", result.Run.Nodes[0])
		}
		r := doAs(t, env.ts, readerSecret, http.MethodGet, prefix+"/snapshots/"+input.Scope.SnapshotID+"/artifacts/"+ref.ID+"/content", nil, nil)
		if r.status != 200 {
			t.Fatalf("node output: %d %s", r.status, r.body)
		}
	}
	events := doAs(t, env.ts, readerSecret, http.MethodGet, endpoint+"/events?after_seq=0&limit=100", nil, nil)
	if events.status != 200 {
		t.Fatalf("events: %d %s", events.status, events.body)
	}
}

func TestWorkflowPublishesSharedKnowledgeAndRunsConfiguredCandidateRuntime(t *testing.T) {
	env := newSchedulerTestEnv(t)
	p := createProject(t, env.ts, asgFixtureSource(t)).Project
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+p.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	prefix := "/api/v1/projects/" + p.ID
	registered := do(t, env.ts, http.MethodPost, prefix+"/snapshots/"+snapshot.Snapshot.SnapshotID+"/artifacts", nil, nil)
	var page struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	registered.decode(t, &page)
	root := ""
	for _, ref := range page.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			root = ref.ID
		}
	}
	spec := workflowSpecFixture()
	nodes := spec["nodes"].([]any)
	nodes = append(nodes, map[string]any{"id": "semantic", "plugin_id": plugin.SemanticID, "plugin_version": "1.1.0", "needs": []string{"parse"}, "config": map[string]any{}, "timeout_seconds": 60}, map[string]any{"id": "paths", "plugin_id": "builtin.discovery-paths", "plugin_version": "1.1.0", "needs": []string{"semantic"}, "config": map[string]any{}, "timeout_seconds": 60})
	nodes = append(nodes, map[string]any{"id": "zsemantic", "plugin_id": plugin.SemanticID, "plugin_version": "1.1.0", "needs": []string{"parse"}, "config": map[string]any{}, "timeout_seconds": 60})
	nodes = append(nodes, map[string]any{"id": "zpaths", "plugin_id": "builtin.discovery-paths", "plugin_version": "1.1.0", "needs": []string{"semantic"}, "config": map[string]any{"max_paths": 1}, "timeout_seconds": 60})
	spec["nodes"] = nodes
	saved := do(t, env.ts, http.MethodPost, prefix+"/workflows", map[string]any{"api_version": "codexploit/v1", "spec": spec}, nil)
	if saved.status != 201 {
		t.Fatal(string(saved.body))
	}
	compiled := do(t, env.ts, http.MethodPost, prefix+"/workflows/workflow-discovery/versions/1.0.0/compile", map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshot.Snapshot.SnapshotID, "inputs": []string{root}, "language": "Go"}, nil)
	var plan struct {
		Plan workflow.Plan `json:"plan"`
	}
	compiled.decode(t, &plan)
	created := do(t, env.ts, http.MethodPost, "/api/projects/"+p.ID+"/tasks", map[string]any{"name": "End to end workflow", "objective": "Collect bounded vulnerability candidates", "snapshot_id": snapshot.Snapshot.SnapshotID, "workflow_plan_id": plan.Plan.ID, "analyze_candidates": true, "accept_partial_nodes": []string{"zpaths"}}, nil)
	if created.status != 201 {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	var receipt struct {
		Run workflow.Run `json:"workflow_run"`
	}
	created.decode(t, &receipt)
	deadline := time.Now().Add(20 * time.Second)
	var run workflow.Run
	for {
		response := doAs(t, env.ts, readerSecret, http.MethodGet, prefix+"/workflow-runs/"+receipt.Run.ID, nil, nil)
		var value struct {
			Run workflow.Run `json:"run"`
		}
		response.decode(t, &value)
		run = value.Run
		if workflow.RunTerminal(run.Status) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("workflow timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if run.Status != "PARTIAL" || len(run.Nodes) != 7 {
		t.Fatalf("full discovery chain: %+v", run)
	}
	publish, analyze := run.Nodes[5], run.Nodes[6]
	if publish.Kind != "knowledge_publish" || len(publish.Knowledge) != 4 || analyze.Kind != "candidate_analysis" || len(analyze.AgentRunIDs) == 0 || run.Model.Runtime == "" {
		t.Fatalf("missing graph/model trace: %+v", run)
	}
	revisions := doAs(t, env.ts, readerSecret, http.MethodGet, prefix+"/knowledge/revisions?snapshot_id="+snapshot.Snapshot.SnapshotID, nil, nil)
	if revisions.status != 200 || !strings.Contains(string(revisions.body), `"rev-2"`) {
		t.Fatalf("knowledge not published: %d %s", revisions.status, revisions.body)
	}
	task := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/tasks/"+run.TaskID, nil, nil)
	var view struct {
		PathCount int    `json:"path_count"`
		Status    string `json:"status"`
	}
	task.decode(t, &view)
	if task.status != 200 || view.PathCount < 2 || view.Status != "READY" {
		t.Fatalf("task paths not materialized: %d %s", task.status, task.body)
	}
	findings := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/findings?audit_id="+run.TaskID, nil, nil)
	if strings.Contains(string(findings.body), `"confirmed"`) {
		t.Fatalf("discovery manufactured confirmation: %s", findings.body)
	}
	staticCreated := do(t, env.ts, http.MethodPost, "/api/projects/"+p.ID+"/tasks", map[string]any{"name": "Static only workflow", "objective": "Collect candidates without model calls", "snapshot_id": snapshot.Snapshot.SnapshotID, "workflow_plan_id": plan.Plan.ID, "analyze_candidates": false, "accept_partial_nodes": []string{"zpaths"}}, nil)
	var staticReceipt struct {
		Run workflow.Run `json:"workflow_run"`
	}
	staticCreated.decode(t, &staticReceipt)
	deadline = time.Now().Add(20 * time.Second)
	for {
		response := do(t, env.ts, http.MethodGet, prefix+"/workflow-runs/"+staticReceipt.Run.ID, nil, nil)
		var value struct {
			Run workflow.Run `json:"run"`
		}
		response.decode(t, &value)
		if workflow.RunTerminal(value.Run.Status) {
			if value.Run.Status != "PARTIAL" {
				t.Fatalf("static workflow: %+v", value.Run)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("static workflow timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	small := do(t, env.ts, http.MethodPost, "/api/projects/"+p.ID+"/tasks", map[string]any{"name": "Bounded task", "objective": "Only one candidate path", "snapshot_id": snapshot.Snapshot.SnapshotID, "workflow_plan_id": plan.Plan.ID, "limits": map[string]any{"max_paths": 1}, "accept_partial_nodes": []string{"zpaths"}}, nil)
	var bounded struct {
		Run workflow.Run `json:"workflow_run"`
	}
	small.decode(t, &bounded)
	deadline = time.Now().Add(20 * time.Second)
	for {
		read := do(t, env.ts, http.MethodGet, prefix+"/workflow-runs/"+bounded.Run.ID, nil, nil)
		if read.status != 200 {
			t.Fatalf("bounded run read: %d %s", read.status, read.body)
		}
		var value struct {
			Run workflow.Run `json:"run"`
		}
		read.decode(t, &value)
		bounded.Run = value.Run
		if workflow.RunTerminal(bounded.Run.Status) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bounded task timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if bounded.Run.Status != "FAILED" || bounded.Run.Nodes[len(bounded.Run.Nodes)-2].Status != "PARTIAL" {
		summary := []string{}
		for _, n := range bounded.Run.Nodes {
			summary = append(summary, n.NodeID+"="+n.Status+"/"+n.ErrorCode)
		}
		t.Fatalf("task path truncation was not explicit: status %s nodes %v", bounded.Run.Status, summary)
	}
	tick := do(t, env.ts, http.MethodPost, "/api/scheduler/tick", map[string]any{"concurrency": 1}, nil)
	var scheduled struct {
		Dispatched int `json:"dispatched"`
	}
	tick.decode(t, &scheduled)
	if tick.status != 200 || scheduled.Dispatched != 0 {
		t.Fatalf("legacy scheduler took workflow-owned candidates: %d %s", tick.status, tick.body)
	}

}

type workflowGate struct {
	entered  chan struct{}
	release  chan struct{}
	delegate workflow.NodeExecutor
}

func (g workflowGate) Execute(ctx context.Context, node workflow.CompiledNode, scope artifact.Scope, inputs []artifact.Ref, id string) (workflow.NodeResult, error) {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return workflow.NodeResult{}, ctx.Err()
	case <-g.release:
	}
	return g.delegate.Execute(ctx, node, scope, inputs, id)
}
func TestWorkflowRunPersistsAndFencesTaskAndSnapshotLifecycle(t *testing.T) {
	dir := t.TempDir()
	cfg := app.Config{Workspace: dir, DBPath: filepath.Join(dir, "state.db")}
	rt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}, 1), make(chan struct{})
	rt.WorkflowRunner.Executor = workflowGate{entered, release, workflow.PluginExecutor{Host: rt.Plugins, Catalog: rt.PluginCatalog}}
	env := serveTestEnv(t, rt, false)
	source := t.TempDir()
	writeFile(t, source, "main.go", "package main\nfunc main(){}\n")
	p := createProject(t, env.ts, source).Project
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+p.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snap snapshotResponse
	captured.decode(t, &snap)
	prefix := "/api/v1/projects/" + p.ID
	registered := do(t, env.ts, http.MethodPost, prefix+"/snapshots/"+snap.Snapshot.SnapshotID+"/artifacts", nil, nil)
	var page struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	registered.decode(t, &page)
	root := ""
	for _, ref := range page.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			root = ref.ID
		}
	}
	do(t, env.ts, http.MethodPost, prefix+"/workflows", map[string]any{"api_version": "codexploit/v1", "spec": workflowSpecFixture()}, nil)
	compiled := do(t, env.ts, http.MethodPost, prefix+"/workflows/workflow-discovery/versions/1.0.0/compile", map[string]any{"api_version": "codexploit/v1", "snapshot_id": snap.Snapshot.SnapshotID, "inputs": []string{root}, "language": "Go"}, nil)
	var plan struct {
		Plan workflow.Plan `json:"plan"`
	}
	compiled.decode(t, &plan)
	body := map[string]any{"name": "Durable workflow", "objective": "Inspect syntax", "snapshot_id": snap.Snapshot.SnapshotID, "workflow_plan_id": plan.Plan.ID}
	headers := map[string]string{"Idempotency-Key": "workflow-task-fixture"}
	created := do(t, env.ts, http.MethodPost, "/api/projects/"+p.ID+"/tasks", body, headers)
	if created.status != 201 {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	var receipt struct {
		Run workflow.Run `json:"workflow_run"`
	}
	created.decode(t, &receipt)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("node did not enter")
	}
	running := do(t, env.ts, http.MethodGet, "/api/projects/"+p.ID+"/tasks?state=RUNNING", nil, nil)
	if running.status != 200 || !strings.Contains(string(running.body), receipt.Run.TaskID) {
		t.Fatalf("workflow running state missing from task filter: %d %s", running.status, running.body)
	}
	task := do(t, env.ts, http.MethodGet, "/api/tasks/"+receipt.Run.TaskID, nil, nil)
	if response := do(t, env.ts, http.MethodPost, "/api/tasks/"+receipt.Run.TaskID+"/pause", map[string]any{}, map[string]string{"If-Match": task.header.Get("ETag")}); response.status != 409 {
		t.Fatalf("legacy pause must not simulate workflow pause: %d %s", response.status, response.body)
	}
	if response := do(t, env.ts, http.MethodDelete, "/api/snapshots/"+snap.Snapshot.SnapshotID, nil, nil); response.status != 409 {
		t.Fatalf("active workflow snapshot deleted: %d %s", response.status, response.body)
	}
	denied := doAs(t, env.ts, readerSecret, http.MethodPost, "/api/projects/"+p.ID+"/tasks", body, nil)
	if denied.status != 403 {
		t.Fatalf("reader started workflow: %d", denied.status)
	}
	endpoint := prefix + "/workflow-runs/" + receipt.Run.ID
	if response := do(t, env.ts, http.MethodGet, strings.Replace(endpoint, p.ID, "another-project", 1), nil, nil); response.status != 404 {
		t.Fatalf("cross project run: %d", response.status)
	}
	replay := do(t, env.ts, http.MethodPost, "/api/projects/"+p.ID+"/tasks", body, headers)
	if replay.status != 201 || string(replay.body) != string(created.body) {
		t.Fatalf("task replay created different workflow: %d %s", replay.status, replay.body)
	}
	close(release)
	deadline := time.Now().Add(10 * time.Second)
	var before struct {
		Run workflow.Run `json:"run"`
	}
	for {
		response := do(t, env.ts, http.MethodGet, endpoint, nil, nil)
		var current struct {
			Run workflow.Run `json:"run"`
		}
		response.decode(t, &current)
		before = current
		if workflow.RunTerminal(before.Run.Status) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("run did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if before.Run.Status != "SUCCEEDED" {
		t.Fatalf("run failed: %+v", before.Run)
	}
	env.ts.Close()
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	rt, err = app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	env = serveTestEnv(t, rt, false)
	response := doAs(t, env.ts, readerSecret, http.MethodGet, endpoint, nil, nil)
	var after struct {
		Run workflow.Run `json:"run"`
	}
	response.decode(t, &after)
	if response.status != 200 || !reflect.DeepEqual(after.Run, before.Run) {
		t.Fatalf("restart changed workflow trace: %d %s", response.status, response.body)
	}
}

func TestWorkflowKeepsCapturedModelAfterApplicationSettingsChange(t *testing.T) {
	type observedRequest struct{ model, authorization string }
	observed := make(chan observedRequest, 32)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model    string        `json:"model"`
			Messages []llm.Message `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		var task agent.Task
		for _, message := range body.Messages {
			if message.Role == "user" {
				_ = json.Unmarshal([]byte(message.Content), &task)
			}
		}
		observed <- observedRequest{body.Model, r.Header.Get("Authorization")}
		answer, _ := json.Marshal(agentTestAnswer(task.SecurityGoal))
		writeJSON(w, 200, map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": string(answer)}, "finish_reason": "stop"}}, "usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}})
	}))
	defer provider.Close()
	dir := t.TempDir()
	settings, err := llm.Open(filepath.Join(dir, "settings"))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := app.Build(context.Background(), app.Config{Workspace: filepath.Join(dir, "workspace"), DBPath: filepath.Join(dir, "state.db"), Agent: app.AgentConfig{Enabled: true, Runtime: app.AgentRuntimeLLM, ModelSettings: settings, MaxToolCalls: 10}})
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}, 1), make(chan struct{})
	rt.WorkflowRunner.Executor = workflowGate{entered, release, workflow.PluginExecutor{Host: rt.Plugins, Catalog: rt.PluginCatalog}}
	env := serveTestEnv(t, rt, false)
	saveModel := func(model, key string) llm.Public {
		current := doAs(t, env.ts, adminSecret, http.MethodGet, "/api/settings/llm", nil, nil)
		saved := doAs(t, env.ts, adminSecret, http.MethodPut, "/api/settings/llm", map[string]any{"enabled": true, "protocol": "chat-completions", "base_url": provider.URL + "/v1", "model": model, "api_key": key, "timeout_seconds": 30, "max_output_tokens": 1024}, map[string]string{"If-Match": current.header.Get("ETag")})
		if saved.status != 200 {
			t.Fatalf("settings: %d %s", saved.status, saved.body)
		}
		var metadata llm.Public
		saved.decode(t, &metadata)
		return metadata
	}
	old := saveModel("fixture-old-model", "synthetic-old-key")
	p := createProject(t, env.ts, asgFixtureSource(t)).Project
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+p.ID+"/snapshots", map[string]any{"build_graph": true}, nil)
	var snap snapshotResponse
	captured.decode(t, &snap)
	prefix := "/api/v1/projects/" + p.ID
	registered := do(t, env.ts, http.MethodPost, prefix+"/snapshots/"+snap.Snapshot.SnapshotID+"/artifacts", nil, nil)
	var directory struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	registered.decode(t, &directory)
	input := ""
	for _, ref := range directory.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref.ID
		}
	}
	spec := workflowSpecFixture()
	spec["nodes"] = append(spec["nodes"].([]any), map[string]any{"id": "semantic", "plugin_id": plugin.SemanticID, "plugin_version": "1.1.0", "needs": []string{"parse"}, "config": map[string]any{}, "timeout_seconds": 60}, map[string]any{"id": "paths", "plugin_id": "builtin.discovery-paths", "plugin_version": "1.1.0", "needs": []string{"semantic"}, "config": map[string]any{}, "timeout_seconds": 60})
	do(t, env.ts, http.MethodPost, prefix+"/workflows", map[string]any{"api_version": "codexploit/v1", "spec": spec}, nil)
	compiled := do(t, env.ts, http.MethodPost, prefix+"/workflows/workflow-discovery/versions/1.0.0/compile", map[string]any{"api_version": "codexploit/v1", "snapshot_id": snap.Snapshot.SnapshotID, "inputs": []string{input}, "language": "Go"}, nil)
	var plan struct {
		Plan workflow.Plan `json:"plan"`
	}
	compiled.decode(t, &plan)
	created := do(t, env.ts, http.MethodPost, "/api/projects/"+p.ID+"/tasks", map[string]any{"name": "Pinned model workflow", "objective": "Collect candidates", "snapshot_id": snap.Snapshot.SnapshotID, "workflow_plan_id": plan.Plan.ID, "analyze_candidates": true}, nil)
	var receipt struct {
		Run workflow.Run `json:"workflow_run"`
	}
	created.decode(t, &receipt)
	if created.status != 201 {
		t.Fatalf("start: %d %s", created.status, created.body)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("node did not enter")
	}
	latest := saveModel("fixture-new-model", "synthetic-new-key")
	if latest.Version == old.Version {
		t.Fatal("settings did not change")
	}
	close(release)
	deadline := time.Now().Add(20 * time.Second)
	var run workflow.Run
	for {
		response := do(t, env.ts, http.MethodGet, prefix+"/workflow-runs/"+receipt.Run.ID, nil, nil)
		if strings.Contains(string(response.body), "synthetic-old-key") || strings.Contains(string(response.body), "synthetic-new-key") {
			t.Fatal("model credentials leaked into workflow response")
		}
		var value struct {
			Run workflow.Run `json:"run"`
		}
		response.decode(t, &value)
		run = value.Run
		if workflow.RunTerminal(run.Status) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("workflow did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if run.Status != "SUCCEEDED" {
		response := do(t, env.ts, http.MethodGet, "/api/runs?audit_id="+run.TaskID, nil, nil)
		var diagnostics struct {
			Runs []struct {
				Status string `json:"status"`
				Reason string `json:"stop_reason"`
				Error  string `json:"error"`
			} `json:"runs"`
		}
		response.decode(t, &diagnostics)
		t.Fatalf("model phase failed: %+v", diagnostics)
	}
	if run.Status != "SUCCEEDED" || run.Model.ConfigVersion != old.Version || run.Model.Model != "fixture-old-model" {
		t.Fatalf("model pin changed: %+v", run)
	}
	surface := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/snapshots/"+snap.Snapshot.SnapshotID+"/asg", nil, nil)
	if surface.status != 200 {
		t.Fatalf("workflow did not populate missing ASG beside existing SCG: %d %s", surface.status, surface.body)
	}
	count := 0
	for {
		select {
		case request := <-observed:
			count++
			if request.model != "fixture-old-model" || request.authorization != "Bearer synthetic-old-key" {
				t.Fatal("workflow used updated model configuration")
			}
		default:
			if count == 0 {
				t.Fatal("no real model request")
			}
			return
		}
	}
}
