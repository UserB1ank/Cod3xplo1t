package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func TestAnalysisFrontendSelectionRewritesOnlyTheParseConfig(t *testing.T) {
	base := workflow.DefaultAnalysisSpec()
	semanticConfig := string(base.Nodes[1].Config)

	selected, err := analysisWorkflowForFrontend(base, "C#")
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(selected.Nodes[0].Config, &config); err != nil {
		t.Fatal(err)
	}
	if config["frontend"] != "CSHARPSRC" || config["heap_mib"] != float64(4096) {
		t.Fatalf("parse config = %+v", config)
	}
	if string(selected.Nodes[1].Config) != semanticConfig {
		t.Fatalf("frontend selection rewrote downstream config: %s", selected.Nodes[1].Config)
	}
	var original map[string]any
	if err := json.Unmarshal(base.Nodes[0].Config, &original); err != nil {
		t.Fatal(err)
	}
	if original["frontend"] != "AUTO" {
		t.Fatalf("frontend selection mutated the provider workflow: %+v", original)
	}

	for input, want := range map[string]string{
		"Java":          "JAVASRC",
		"Java bytecode": "JAVA",
		"go":            "GOLANG",
		"Python":        "PYTHONSRC",
	} {
		got, err := normalizeAnalysisFrontend(input)
		if err != nil || got != want {
			t.Fatalf("normalize %q = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := normalizeAnalysisFrontend("COBOL"); err == nil {
		t.Fatal("unsupported frontend was accepted")
	}
}

func TestAnalysisStartRejectsAnUnsupportedFrontendBeforeEngineWork(t *testing.T) {
	env := newTestEnv(t, false)
	projectID := createAnalysisProject(t, env, asgFixtureSource(t))
	result := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projectID+"/analysis-runs", map[string]any{
		"api_version": "codexploit/v1",
		"frontend":    "COBOL",
	}, nil)
	if result.status != http.StatusBadRequest ||
		!strings.Contains(string(result.body), `"invalid_frontend"`) {
		t.Fatalf("unsupported frontend = %d %s", result.status, result.body)
	}
	runs, err := env.rt.Store.ListAnalysisRuns(t.Context(), projectID, 20)
	if err != nil || len(runs) != 0 {
		t.Fatalf("invalid frontend created work: %+v %v", runs, err)
	}
}
