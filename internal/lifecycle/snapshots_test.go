package lifecycle_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/lifecycle"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func lifecycleRuntime(t *testing.T, backend string) (*app.Runtime, string) {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "work")
	db := "memory"
	if backend == "sqlite" {
		db = filepath.Join(workspace, "store.db")
	}
	rt, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ids, err := rt.Manager.List()
		if err != nil {
			t.Error(err)
		}
		for _, id := range ids {
			if err := rt.Manager.Remove(id); err != nil {
				t.Error(err)
			}
		}
		if err := rt.Close(); err != nil {
			t.Error(err)
		}
	})
	return rt, db
}

func indexedSnapshot(t *testing.T, rt *app.Runtime) (*repository.Snapshot, *scg.Graph, string) {
	t.Helper()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "go.mod"), []byte("module example.invalid/lifecycle\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	snap, err := rt.Manager.Create(ctx, repository.Source{Raw: source})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Snapshots.Register(ctx, snap, source); err != nil {
		t.Fatal(err)
	}
	manifest, err := rt.Analyzer.Analyze(ctx, snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Snapshots.PutManifest(ctx, snap, manifest); err != nil {
		t.Fatal(err)
	}
	g, err := rt.Builder.Build(ctx, snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Store.ReplaceGraph(ctx, snap.SnapshotID, g); err != nil {
		t.Fatal(err)
	}
	return snap, g, source
}

func TestDeletionBlocksLateWritesAndAllowsExplicitRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()
			rt, _ := lifecycleRuntime(t, backend)
			snap, g, source := indexedSnapshot(t, rt)
			ctx := context.Background()
			if err := rt.Store.BeginSnapshotDeletion(ctx, snap.SnapshotID); err != nil {
				t.Fatal(err)
			}
			if err := rt.Store.ReplaceGraph(ctx, snap.SnapshotID, g); !errors.Is(err, storage.ErrConflict) {
				t.Fatalf("write during deletion: %v", err)
			}
			if _, err := rt.Snapshots.Register(ctx, snap, source); !errors.Is(err, storage.ErrConflict) {
				t.Fatalf("register during deletion: %v", err)
			}
			if err := rt.Snapshots.Remove(ctx, snap.SnapshotID); err != nil {
				t.Fatal(err)
			}
			if err := snap.WriteManifest([]byte("{}\n")); err == nil {
				t.Fatal("a late manifest write recreated the deleted directory")
			}
			if _, err := os.Stat(snap.Dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("late write left a snapshot directory: %v", err)
			}
			if err := rt.Store.ReplaceGraph(ctx, snap.SnapshotID, g); !errors.Is(err, storage.ErrConflict) {
				t.Fatalf("late write after deletion: %v", err)
			}
			if _, err := rt.Snapshots.Register(ctx, snap, source); !errors.Is(err, storage.ErrConflict) {
				t.Fatalf("stale registration without a tree: %v", err)
			}
			recreated, err := rt.Manager.Create(ctx, repository.Source{Raw: source})
			if err != nil {
				t.Fatal(err)
			}
			if recreated.SnapshotID != snap.SnapshotID {
				t.Fatal("recreation changed snapshot identity")
			}
			if _, err := rt.Snapshots.Register(ctx, recreated, source); err != nil {
				t.Fatalf("explicit recreation: %v", err)
			}
			if err := rt.Store.ReplaceGraph(ctx, snap.SnapshotID, g); err != nil {
				t.Fatalf("write after recreation: %v", err)
			}
		})
	}
}

type failingSnapshotDelete struct{ storage.FullStore }

func (s failingSnapshotDelete) DeleteSnapshot(context.Context, string) error {
	return errors.New("injected database cleanup failure")
}

func TestDeletionResumesAfterDatabaseFailureAndRestart(t *testing.T) {
	rt, db := lifecycleRuntime(t, "sqlite")
	snap, _, _ := indexedSnapshot(t, rt)
	ctx := context.Background()
	faulty := lifecycle.Snapshots{Store: failingSnapshotDelete{rt.Store}, Manager: rt.Manager}
	if err := faulty.Remove(ctx, snap.SnapshotID); err == nil {
		t.Fatal("database failure was ignored")
	}
	if _, err := rt.Manager.Load(snap.SnapshotID); !errors.Is(err, repository.ErrSnapshotNotFound) {
		t.Fatalf("tree not removed: %v", err)
	}
	if _, err := rt.Store.GetSnapshot(ctx, snap.SnapshotID); err != nil {
		t.Fatalf("registry lost before cleanup: %v", err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := app.Build(ctx, app.Config{Workspace: rt.Workspace, DBPath: db})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := restarted.Close(); err != nil {
			t.Error(err)
		}
	})
	pending, err := restarted.Store.SnapshotDeletionPending(ctx, snap.SnapshotID)
	if err != nil || !pending {
		t.Fatalf("deletion was not durable: pending=%v err=%v", pending, err)
	}
	if err := restarted.Snapshots.Remove(ctx, snap.SnapshotID); err != nil {
		t.Fatalf("retry after restart: %v", err)
	}
	if _, err := restarted.Store.GetSnapshot(ctx, snap.SnapshotID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("registry after retry: %v", err)
	}
	if _, err := restarted.Store.GraphSummary(ctx, snap.SnapshotID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("graph after retry: %v", err)
	}
	pending, err = restarted.Store.SnapshotDeletionPending(ctx, snap.SnapshotID)
	if err != nil || pending {
		t.Fatalf("deletion not completed: %v %v", pending, err)
	}
}
