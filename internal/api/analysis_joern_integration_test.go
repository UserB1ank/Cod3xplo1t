package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestRealJoernDefaultAnalysisFeedsGraphAndAgent(t *testing.T) {
	realJoernDefaultAnalysis(t, app.Config{Workspace: t.TempDir(), DBPath: "memory"})
}
func TestPostgresRealJoernDefaultAnalysisFeedsGraphAndAgent(t *testing.T) {
	if os.Getenv("JOERN_TEST_PACKAGE") == "" {
		t.Skip("set JOERN_TEST_PACKAGE to a sealed real package")
	}
	realJoernDefaultAnalysis(t, postgresConfig(t))
}
func realJoernDefaultAnalysis(t *testing.T, cfg app.Config) {
	t.Helper()
	pkg := os.Getenv("JOERN_TEST_PACKAGE")
	if pkg == "" {
		t.Skip("set JOERN_TEST_PACKAGE to a sealed real package")
	}
	// Hard links preserve the sealed content without copying three GiB for each
	// test. Jobs themselves still verify and copy the full package privately.
	cfg.PluginPackages = t.TempDir()
	target := filepath.Join(cfg.PluginPackages, "codexploit.joern@2.3.0")
	if err := filepath.WalkDir(pkg, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(pkg, name)
		if err != nil {
			return err
		}
		dest := filepath.Join(target, rel)
		if entry.IsDir() {
			return os.MkdirAll(dest, 0700)
		}
		return os.Link(name, dest)
	}); err != nil {
		t.Fatal(err)
	}
	cfg.Agent = app.AgentConfig{Enabled: true, Runtime: app.AgentRuntimeScripted, ScriptedAnswerJSON: agentTestPlaceholderAnswer(t), MaxToolCalls: 30}
	rt, err := app.Build(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	// This runtime validates the real task boundary and returns unknown controls;
	// it is not a model-quality or vulnerability-verdict test.
	rt.Agent.Runtime = &echoRuntime{Answer: func(goal string) agent.Answer {
		a := agentTestAnswer(goal)
		a.Hypothesis.Statement = "Static trace requires source-trust and control review"
		a.Hypothesis.Status = agent.HypothesisInconclusive
		a.FindingCandidate = false
		a.SupportingEvidence = nil
		for i := range a.Obligations {
			if a.Obligations[i].Kind == agent.ObligationControl {
				a.Obligations[i].Verdict = agent.VerdictUnknown
				a.Obligations[i].Blocker = "control_unassessed"
			}
		}
		return a
	}}
	env := serveTestEnv(t, rt, false)
	source := t.TempDir()
	writeFile(t, source, "service/example.c", "int system(const char *command);\nvoid entry(char *input) { system(input); system(\"constant\"); }\n")
	writeFile(t, source, "service/example.js", "const cp = require('child_process');\nfunction entry(input) { cp.execSync(input); cp.execSync('constant'); }\n")
	writeFile(t, source, "service/example.py", "import os\ndef entry(value):\n    os.system(value)\n    os.system('constant')\n")
	ts := localSourceServer(t, env, source)
	created := do(t, ts, http.MethodPost, "/api/v1/projects", map[string]any{"api_version": "codexploit/v1", "name": "Real Joern boundary"}, nil)
	var project projectResponse
	created.decode(t, &project)
	if added := addLocalSource(t, ts, project.Project.ID, "src-joern-real", "/repos/service"); added.status != 201 {
		t.Fatalf("source: %d %s", added.status, added.body)
	}
	captured := do(t, ts, http.MethodPost, "/api/v1/sources/src-joern-real/snapshots", map[string]any{"project_id": project.Project.ID, "source_version": 1, "skip_analysis": true}, nil)
	if captured.status != 201 {
		t.Fatalf("capture: %d %s", captured.status, captured.body)
	}
	// An existing immutable v1 definition must not block adoption of the new head.
	raw, _ := json.Marshal((legacyAnalysisFixture{}).Workflow())
	if _, err := rt.Workflows.Save(t.Context(), project.Project.ID, raw, ""); err != nil {
		t.Fatal(err)
	}
	started := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.Project.ID+"/analysis-runs", map[string]any{"api_version": "codexploit/v1", "agent_assisted": true}, nil)
	if started.status != 201 {
		t.Fatalf("start: %d %s", started.status, started.body)
	}
	var receipt struct {
		Run storage.AnalysisRun `json:"analysis_run"`
	}
	started.decode(t, &receipt)
	deadline := time.Now().Add(8 * time.Minute)
	var run storage.AnalysisRun
	for time.Now().Before(deadline) {
		r := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+project.Project.ID+"/analysis-runs/"+receipt.Run.ID, nil, nil)
		var doc struct {
			Run storage.AnalysisRun `json:"analysis_run"`
		}
		r.decode(t, &doc)
		run = doc.Run
		if analysisTerminal(run.State) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if run.State != "PARTIAL" || run.PathCount < 3 || run.Engine == nil || run.Engine.ID != "joern" || len(run.Stages) != 6 {
		t.Fatalf("real chain: %+v", run)
	}
	for i, s := range run.Stages {
		if i < 4 && (s.PluginID != "codexploit.joern" || s.OperationID == "") {
			t.Fatalf("mixed stage: %+v", s)
		}
		if s.Status != "PARTIAL" && s.Status != "SUCCEEDED" {
			t.Fatalf("stage: %+v", s)
		}
	}
	paths, _, err := rt.Store.ListPaths(path.PathQuery{AuditID: run.TaskID, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Stages[5].AgentRunIDs) != len(paths) {
		t.Fatal("Agent did not consume the real task paths")
	}
	for _, p := range paths {
		if p.PathKind != "data_flow" || p.Selection == nil || len(p.SCGRefs) == 0 {
			t.Fatalf("lost canonical evidence: %+v", p)
		}
		task, err := rt.Agent.Tasks.BuildTask(context.Background(), p, rt.Agent.Policy)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(task.MinimalCodeSlice)
		if len(task.Obligations) != 4 || !strings.Contains(string(raw), "system") && !strings.Contains(string(raw), "execSync") {
			t.Fatalf("Agent lacks source: %s", raw)
		}
	}
	// Reopening PostgreSQL and a fresh runtime preserves pinned engines and stages.
	if cfg.StorageDriver == "postgres" {
		env.ts.Close()
		_ = rt.Close()
		reopened, err := app.Build(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		got, err := reopened.Store.GetAnalysisRun(t.Context(), project.Project.ID, run.ID)
		if err != nil || got.Engine == nil || *got.Engine != *run.Engine || got.PlanDigest != run.PlanDigest {
			t.Fatal("engine pin lost on restart")
		}
	}
}
