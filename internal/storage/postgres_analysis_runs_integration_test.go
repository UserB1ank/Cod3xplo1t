package storage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/testpostgres"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func TestPostgresAnalysisRunSurvivesRestartAndRejectsASecondActiveRun(t *testing.T) {
	file := testpostgres.DSNFile(t)
	dsn, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := OpenSQL(ctx, "pgx", string(dsn))
	if err != nil {
		t.Fatal("open PostgreSQL")
	}
	if err := store.EnsureSchema(ctx, migrations.Postgres); err != nil {
		t.Fatal(err)
	}
	project := testProject("proj-pg-analysis")
	if _, err := store.CreateProject(ctx, project); err != nil {
		t.Fatal(err)
	}
	run := analysisRunFixture(project.ID, "analysis-pg", time.Now())
	run.Engine = &AnalysisEnginePin{ID: "joern", ProfileVersion: "2.0.0", PluginID: "codexploit.joern", PluginVersion: "2.1.0", PackageDigest: "package", ManifestDigest: "manifest"}
	run.Knowledge = []AnalysisKnowledge{{Revision: "rev-3", Digest: "digest-3"}}
	created, err := store.CreateAnalysisRun(ctx, run, "pg-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAnalysisRun(ctx, analysisRunFixture(project.ID, "analysis-pg-second", time.Now()), "pg-key-2"); err == nil {
		t.Fatal("second active run was accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQL(ctx, "pgx", string(dsn))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	stored, err := reopened.GetAnalysisRun(ctx, project.ID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Engine == nil || *stored.Engine != *run.Engine || stored.State != "RUNNING" || len(stored.Stages) != 1 || len(stored.Knowledge) != 1 || stored.Knowledge[0].Revision != "rev-3" {
		t.Fatalf("analysis run after restart = %+v", stored)
	}
	if active, ok, err := reopened.ActiveAnalysisRun(ctx, project.ID); err != nil || !ok || active.ID != created.ID {
		t.Fatalf("active after restart = %+v %v %v", active, ok, err)
	}
	stored.State = "SUCCEEDED"
	stored.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := reopened.UpdateAnalysisRun(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := reopened.ActiveAnalysisRun(ctx, project.ID); err != nil || ok {
		t.Fatalf("terminal run still active: %v %v", ok, err)
	}
}
