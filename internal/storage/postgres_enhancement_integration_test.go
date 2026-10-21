package storage

import (
	"context"
	"os"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/testpostgres"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func TestPostgresPathEnhancementLineageSurvivesRestart(t *testing.T) {
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
	summary := &path.EnhancementSummary{
		SchemaVersion: "codexploit/path-enhancement-summary/v1", ProducerID: "builtin.path-enhancer",
		ProducerVersion: "1.0.0", InvocationID: "inv-pg-enhance", ScoreVersion: path.ScoreVersion,
		WeightsDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Selected:      []path.EnhancementPath{{PathID: "path-pg-enhanced", Selection: path.PathSelection{SchemaVersion: "codexploit/path-selection/v1", Selection: "selected", Reason: "retained", ScoreVersion: path.ScoreVersion, WeightsDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SourcePathID: "path-pg-enhanced"}}},
		Filtered:      []path.EnhancementPath{{PathID: "path-pg-filtered", Selection: path.PathSelection{SchemaVersion: "codexploit/path-selection/v1", Selection: "filtered", Reason: "filtered by threshold", FilterCode: "below_priority_threshold", ScoreVersion: path.ScoreVersion, WeightsDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SourcePathID: "path-pg-filtered"}}},
		Limitations:   []string{"filtering is not proof of safety"},
	}
	audit := newAuditFixture(auditMainID, auditSnapID, 1)
	audit.Enhancement = summary
	selected := newPathFixture("path-pg-enhanced", auditMainID, auditSnapID, "entry", "sink", 0.9)
	selected.Selection = &path.PathSelection{SchemaVersion: "codexploit/path-selection/v1", Selection: "selected", Reason: "retained", ScoreVersion: path.ScoreVersion, WeightsDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SourcePathID: selected.ID}
	seedAudit(t, store, audit, selected)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQL(ctx, "pgx", string(dsn))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	stored, err := reopened.GetAudit(auditMainID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Enhancement == nil || len(stored.Enhancement.Selected) != 1 || len(stored.Enhancement.Filtered) != 1 || stored.Enhancement.Filtered[0].Selection.FilterCode != "below_priority_threshold" {
		t.Fatalf("enhancement lineage = %+v", stored.Enhancement)
	}
	paths, _, err := reopened.ListPaths(path.PathQuery{AuditID: auditMainID, Limit: 10})
	if err != nil || len(paths) != 1 || paths[0].Selection == nil || paths[0].Selection.Selection != "selected" || paths[0].Selection.SourcePathID != "path-pg-enhanced" {
		t.Fatalf("path selection = %+v, %v", paths, err)
	}
}
