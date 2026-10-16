package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestBuildRejectsEmptyWorkspace(t *testing.T) {
	t.Parallel()
	if _, err := Build(context.Background(), Config{}); err == nil {
		t.Fatal("Build accepted an empty workspace")
	}
}

func TestBuildDefaultsToInMemoryStore(t *testing.T) {
	t.Parallel()
	workspace := filepath.Join(t.TempDir(), "work")
	rt, err := Build(context.Background(), Config{Workspace: workspace})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer rt.Close()
	if _, ok := rt.Store.(*storage.Memory); !ok {
		t.Fatalf("store type = %T, want *storage.Memory", rt.Store)
	}
	if rt.Analyzer == nil || rt.Manager == nil {
		t.Fatal("runtime is not fully wired")
	}
	if _, err := os.Stat(filepath.Join(workspace, "snapshots")); err != nil {
		t.Fatalf("snapshots directory missing: %v", err)
	}
	if !rt.Manager.AllowNetwork {
		if rt.Manager.Freeze != true {
			t.Error("snapshot freezing should be on by default")
		}
	}
}

func TestBuildWithSQLiteMigratesAndPersists(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	workspace := filepath.Join(t.TempDir(), "work")
	dbPath := filepath.Join(t.TempDir(), "nested", "codexploit.db")

	rt, err := Build(ctx, Config{Workspace: workspace, DBPath: dbPath})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := rt.Store.(*storage.SQL); !ok {
		t.Fatalf("store type = %T, want *storage.SQL", rt.Store)
	}
	project := storage.Project{ID: "proj-1", Name: "fixture", Source: "/srv/fixture", IdentityKind: "dir", Identity: "/srv/fixture"}
	if err := rt.Store.PutProject(ctx, project); err != nil {
		t.Fatalf("PutProject: %v", err)
	}
	snap := &repository.Snapshot{
		SchemaVersion: repository.SchemaVersion,
		SnapshotID:    "snap-0123456789abcdef0123456789abcdef",
		Identity:      repository.Identity{Kind: "dir", Name: "/srv/fixture"},
		VCS:           "none",
		Commit:        "content:deadbeef",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if err := rt.Store.PutSnapshot(ctx, project.ID, snap); err != nil {
		t.Fatalf("PutSnapshot: %v", err)
	}
	manifest := &analysis.Manifest{
		SchemaVersion: analysis.SchemaVersion,
		SnapshotID:    snap.SnapshotID,
		AnalysisID:    "analysis-1",
		Engine:        analysis.DefaultEngine,
	}
	if err := rt.Store.PutManifest(ctx, snap.SnapshotID, manifest); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopening the same database must see the same records: migrations are
	// already applied and nothing is recreated from scratch.
	reopened, err := Build(ctx, Config{Workspace: workspace, DBPath: dbPath})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	gotProject, err := reopened.Store.GetProject(ctx, project.ID)
	if err != nil {
		t.Fatalf("GetProject after reopen: %v", err)
	}
	if gotProject.Name != project.Name {
		t.Errorf("project = %+v, want %+v", gotProject, project)
	}
	gotManifest, err := reopened.Store.GetManifest(ctx, snap.SnapshotID)
	if err != nil {
		t.Fatalf("GetManifest after reopen: %v", err)
	}
	if gotManifest.AnalysisID != "analysis-1" {
		t.Errorf("manifest analysis id = %q", gotManifest.AnalysisID)
	}
}

func TestBuildFailsWhenDatabasePathIsADirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rt, err := Build(context.Background(), Config{Workspace: filepath.Join(t.TempDir(), "work"), DBPath: dir})
	if err == nil {
		rt.Close()
		t.Fatal("Build accepted a directory as database path")
	}
	if !errors.Is(err, os.ErrExist) && !errors.Is(err, context.DeadlineExceeded) {
		// The driver reports this as a plain error; accept any failure, but make
		// sure we did not silently fall back to memory.
		t.Logf("open error: %v", err)
	}
}
