package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func createAnalysisProject(t *testing.T, env *testEnv, fixture string) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"go.mod", "main.go"} {
		raw, err := os.ReadFile(filepath.Join(fixture, name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, root, "service/"+name, string(raw))
	}
	ts := localSourceServer(t, env, root)
	created := do(t, ts, http.MethodPost, "/api/v1/projects", map[string]any{
		"api_version": "codexploit/v1", "name": "Default analysis", "description": "one source",
	}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create project: %d %s", created.status, created.body)
	}
	var project projectResponse
	created.decode(t, &project)
	if added := addLocalSource(t, ts, project.Project.ID, "src-analysis", "/repos/service"); added.status != http.StatusCreated {
		t.Fatalf("add source: %d %s", added.status, added.body)
	}
	captured := do(t, ts, http.MethodPost, "/api/v1/sources/src-analysis/snapshots", map[string]any{
		"project_id": project.Project.ID, "source_version": 1, "skip_analysis": true,
	}, nil)
	if captured.status != http.StatusCreated {
		t.Fatalf("capture: %d %s", captured.status, captured.body)
	}
	input := readAuditInput(t, ts, project.Project.ID)
	if input.State != storage.ProjectInputReady {
		t.Fatalf("input not ready: %+v", input)
	}
	return project.Project.ID
}

func waitAnalysisRun(t *testing.T, env *testEnv, projectID, analysisRunID string) storage.AnalysisRun {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		response := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+projectID+"/analysis-runs/"+analysisRunID, nil, nil)
		if response.status != http.StatusOK {
			t.Fatalf("get analysis run: %d %s", response.status, response.body)
		}
		var result struct {
			Run storage.AnalysisRun `json:"analysis_run"`
		}
		response.decode(t, &result)
		if analysisTerminal(result.Run.State) {
			return result.Run
		}
		if time.Now().After(deadline) {
			t.Fatalf("analysis run timed out: %+v", result.Run)
		}
		time.Sleep(40 * time.Millisecond)
	}
}

func TestProjectOneClickAnalysisRunRunsFourStagesWithoutAModel(t *testing.T) {
	env := newTestEnv(t, false)
	projectID := createAnalysisProject(t, env, asgFixtureSource(t))
	started := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projectID+"/analysis-runs", map[string]any{
		"api_version": "codexploit/v1", "idempotency_key": "one-click-1",
	}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start analysis: %d %s", started.status, started.body)
	}
	var receipt struct {
		Run    storage.AnalysisRun `json:"analysis_run"`
		Reused bool                `json:"reused"`
	}
	started.decode(t, &receipt)
	if receipt.Reused || receipt.Run.AgentAssisted || receipt.Run.State == "SUCCEEDED" {
		t.Fatalf("start receipt = %+v", receipt)
	}
	run := waitAnalysisRun(t, env, projectID, receipt.Run.ID)
	if run.State != "SUCCEEDED" {
		t.Fatalf("analysis state = %s (%+v)", run.State, run)
	}
	if len(run.Stages) != 5 || run.Stages[0].Key != "parse" || run.Stages[3].Key != "enhance" || run.Stages[4].Key != "publish" {
		t.Fatalf("stage projection = %+v", run.Stages)
	}
	for _, stage := range run.Stages {
		if stage.Status != "SUCCEEDED" {
			t.Fatalf("stage %s = %s (%+v)", stage.Key, stage.Status, stage)
		}
	}
	if run.PlanID == "" || run.PlanDigest == "" || run.Stages[3].PluginID != "builtin.path-enhancer" || run.Stages[3].InvocationID == "" {
		t.Fatalf("fixed lineage missing: %+v", run)
	}
	if run.PathCount == 0 || len(run.Knowledge) == 0 || run.Coverage.EntryPointsExamined == 0 {
		t.Fatalf("analysis outputs missing: %+v", run)
	}
	// The same key is idempotent after completion and returns the existing run.
	again := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projectID+"/analysis-runs", map[string]any{
		"api_version": "codexploit/v1", "idempotency_key": "one-click-1",
	}, nil)
	var replay struct {
		Run    storage.AnalysisRun `json:"analysis_run"`
		Reused bool                `json:"reused"`
	}
	again.decode(t, &replay)
	if again.status != http.StatusOK || !replay.Reused || replay.Run.ID != run.ID {
		t.Fatalf("idempotent replay = %d %+v", again.status, replay)
	}
	// An explicit new key starts a new history entry only after the first is terminal.
	second := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projectID+"/analysis-runs", map[string]any{
		"api_version": "codexploit/v1", "idempotency_key": "one-click-2",
	}, nil)
	if second.status != http.StatusCreated {
		t.Fatalf("second analysis: %d %s", second.status, second.body)
	}
	var secondReceipt struct {
		Run storage.AnalysisRun `json:"analysis_run"`
	}
	second.decode(t, &secondReceipt)
	if secondReceipt.Run.ID == run.ID {
		t.Fatalf("history reused terminal run: %+v", secondReceipt.Run)
	}
	waitAnalysisRun(t, env, projectID, secondReceipt.Run.ID)
	list := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+projectID+"/analysis-runs?limit=10", nil, nil)
	if list.status != http.StatusOK || !strings.Contains(string(list.body), run.ID) || !strings.Contains(string(list.body), secondReceipt.Run.ID) {
		t.Fatalf("history list = %d %s", list.status, list.body)
	}
	// Cross-project access is rejected without revealing the run.
	otherProject := createProject(t, env.ts, env.source)
	cross := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+otherProject.Project.ID+"/analysis-runs/"+run.ID, nil, nil)
	if cross.status != http.StatusNotFound {
		t.Fatalf("cross-project get = %d %s", cross.status, cross.body)
	}
}

func TestProjectDeleteRejectsAnActiveAnalysisRun(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := env.rt.Store.CreateAnalysisRun(t.Context(), storage.AnalysisRun{
		ID: "analysis-active-delete", ProjectID: project.ID, SnapshotID: "snap-not-used",
		TaskID: "task-active", WorkflowRunID: "wrun-active", PlanID: "plan-active", PlanDigest: "digest",
		WorkflowID: "codexploit.default-analysis", WorkflowVersion: "1.0.0", State: "RUNNING",
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}, ""); err != nil {
		t.Fatal(err)
	}
	deleted := doAs(t, env.ts, writerSecret, http.MethodDelete, "/api/v1/projects/"+project.ID, nil, nil)
	if deleted.status != http.StatusConflict {
		t.Fatalf("delete active analysis = %d %s", deleted.status, deleted.body)
	}
}

func TestAnalysisRunSurvivesRestartWithItsFixedStageLineage(t *testing.T) {
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	runtime, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, runtime, false)
	projectID := createAnalysisProject(t, env, asgFixtureSource(t))
	started := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projectID+"/analysis-runs", map[string]any{
		"api_version": "codexploit/v1", "idempotency_key": "restart-run",
	}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start: %d %s", started.status, started.body)
	}
	var receipt struct {
		Run storage.AnalysisRun `json:"analysis_run"`
	}
	started.decode(t, &receipt)
	before := waitAnalysisRun(t, env, projectID, receipt.Run.ID)
	env.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	afterEnv := serveTestEnv(t, reopened, false)
	response := do(t, afterEnv.ts, http.MethodGet, "/api/v1/projects/"+projectID+"/analysis-runs/"+before.ID, nil, nil)
	if response.status != http.StatusOK {
		t.Fatalf("get after restart: %d %s", response.status, response.body)
	}
	var after struct {
		Run storage.AnalysisRun `json:"analysis_run"`
	}
	response.decode(t, &after)
	if after.Run.State != before.State || after.Run.PlanID != before.PlanID || after.Run.PlanDigest != before.PlanDigest || len(after.Run.Stages) != len(before.Stages) || len(after.Run.Knowledge) != len(before.Knowledge) {
		t.Fatalf("lineage changed after restart: before=%+v after=%+v", before, after.Run)
	}
	for i := range before.Stages {
		if before.Stages[i].Key != after.Run.Stages[i].Key || before.Stages[i].Status != after.Run.Stages[i].Status || before.Stages[i].InvocationID != after.Run.Stages[i].InvocationID {
			t.Fatalf("stage %d changed: %+v / %+v", i, before.Stages[i], after.Run.Stages[i])
		}
	}
}

func TestAnalysisRunAgentAssistanceRequiresARealConfiguredRuntime(t *testing.T) {
	workspace := t.TempDir()
	runtime, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, runtime, false)
	projectID := createAnalysisProject(t, env, asgFixtureSource(t))
	assisted := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projectID+"/analysis-runs", map[string]any{
		"api_version": "codexploit/v1", "agent_assisted": true,
	}, nil)
	if assisted.status != http.StatusConflict || !strings.Contains(string(assisted.body), "agent_unavailable") {
		t.Fatalf("agent-assisted without a runtime = %d %s", assisted.status, assisted.body)
	}
	defaultRun := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projectID+"/analysis-runs", map[string]any{
		"api_version": "codexploit/v1",
	}, nil)
	if defaultRun.status != http.StatusCreated {
		t.Fatalf("default analysis still requires a model: %d %s", defaultRun.status, defaultRun.body)
	}
}

func TestAnalysisStageProjectionKeepsFailureAndSkipReasons(t *testing.T) {
	run := workflow.Run{Status: "FAILED", Nodes: []workflow.NodeRun{
		{NodeID: "parse", Status: "SUCCEEDED", InvocationID: "winv-parse"},
		{NodeID: "semantic", Status: "FAILED", ErrorCode: "plugin_failed", Note: "semantic rules rejected the input"},
		{NodeID: "$publish", Status: "SKIPPED", ErrorCode: "upstream_failed", Note: "upstream node failed"},
	}}
	stages := analysisStages(run)
	if len(stages) != 5 || stages[0].Status != "SUCCEEDED" || stages[1].Status != "FAILED" || stages[1].ErrorCode != "plugin_failed" || stages[4].Status != "SKIPPED" {
		t.Fatalf("failure projection = %+v", stages)
	}
	if analysisRunState("FAILED") != "FAILED" || analysisRunState("PARTIAL") != "PARTIAL" || analysisRunState("PAUSED") != "PAUSED" || analysisRunState("CREATED") != "QUEUED" {
		t.Fatal("analysis state mapping changed")
	}
	if analysisTerminal("RUNNING") || !analysisTerminal("PARTIAL") {
		t.Fatal("terminal classification changed")
	}
}
