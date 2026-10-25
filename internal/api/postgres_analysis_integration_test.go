package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestPostgresLegacyAnalysisRunRestartAndLineage(t *testing.T) {
	cfg := postgresConfig(t)
	runtime, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, runtime, false)
	useLegacyAnalysisFixture(env)
	projectID := createAnalysisProject(t, env, asgFixtureSource(t))
	started := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projectID+"/analysis-runs", map[string]any{
		"api_version": "codexploit/v1", "idempotency_key": "pg-one-click",
	}, nil)
	if started.status != http.StatusCreated {
		t.Fatalf("start: %d %s", started.status, started.body)
	}
	var receipt struct {
		Run storage.AnalysisRun `json:"analysis_run"`
	}
	started.decode(t, &receipt)
	before := waitAnalysisRun(t, env, projectID, receipt.Run.ID)
	if before.State != "SUCCEEDED" || before.PathCount == 0 || len(before.Stages) != 5 || len(before.Knowledge) == 0 {
		t.Fatalf("PostgreSQL analysis did not complete: %+v", before)
	}
	if before.Stages[3].PluginID != "builtin.path-enhancer" || before.Stages[4].Status != "SUCCEEDED" {
		t.Fatalf("PostgreSQL fixed lineage = %+v", before.Stages)
	}
	env.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	env = serveTestEnv(t, rebuilt, false)
	response := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+projectID+"/analysis-runs/"+before.ID, nil, nil)
	if response.status != http.StatusOK {
		t.Fatalf("get after restart: %d %s", response.status, response.body)
	}
	var after struct {
		Run storage.AnalysisRun `json:"analysis_run"`
	}
	response.decode(t, &after)
	if after.Run.State != before.State || after.Run.PlanDigest != before.PlanDigest || after.Run.PathCount != before.PathCount || len(after.Run.Stages) != 5 || len(after.Run.Knowledge) != len(before.Knowledge) {
		t.Fatalf("PostgreSQL lineage changed: before=%+v after=%+v", before, after.Run)
	}
	for i := range before.Stages {
		if before.Stages[i].InvocationID != after.Run.Stages[i].InvocationID || before.Stages[i].Status != after.Run.Stages[i].Status {
			t.Fatalf("stage %d changed: %+v / %+v", i, before.Stages[i], after.Run.Stages[i])
		}
	}
}
