package storage

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/open-mcp-ai/Codexploit/internal/testpostgres"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func TestPostgresConcurrentMigrationsAndFailedMigrationRollback(t *testing.T) {
	file := testpostgres.DSNFile(t)
	dsn, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var stores []*SQL
	for range 4 {
		s, err := OpenSQL(ctx, "pgx", string(dsn))
		if err != nil {
			t.Fatal("open PostgreSQL")
		}
		t.Cleanup(func() { s.Close() })
		stores = append(stores, s)
	}
	start := make(chan struct{})
	errors := make(chan error, len(stores))
	var wg sync.WaitGroup
	for _, s := range stores {
		wg.Go(func() { <-start; errors <- s.EnsureSchema(ctx, migrations.Postgres) })
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent migration: %v", err)
		}
	}
	bad := fstest.MapFS{"9999_rollback.sql": {Data: []byte("CREATE TABLE rollback_probe (id TEXT PRIMARY KEY);\nINSERT INTO missing_probe VALUES ('fail');")}}
	if err := stores[0].Migrate(ctx, bad); err == nil {
		t.Fatal("broken migration succeeded")
	}
	// The same version may be retried, and CREATE TABLE must succeed because
	// both the DDL and migration bookkeeping of the failed attempt rolled back.
	good := fstest.MapFS{"9999_rollback.sql": {Data: []byte("CREATE TABLE rollback_probe (id TEXT PRIMARY KEY);\nINSERT INTO rollback_probe VALUES ('ok');")}}
	if err := stores[1].Migrate(ctx, good); err != nil {
		t.Fatalf("failed migration left partial state: %v", err)
	}
}

func TestPostgresCatalogOwnershipAndConcurrentCAS(t *testing.T) {
	file := testpostgres.DSNFile(t)
	dsn, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := OpenSQL(ctx, "pgx", string(dsn))
	if err != nil {
		t.Fatal("open PostgreSQL")
	}
	t.Cleanup(func() { s.Close() })
	if err := s.EnsureSchema(ctx, migrations.Postgres); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"owner", "other"} {
		if err := s.PutProject(ctx, testProject(id)); err != nil {
			t.Fatal(err)
		}
	}
	snap := testSnapshot("snap-owner")
	if err := s.PutSnapshot(ctx, "owner", snap); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSnapshot(ctx, "other", snap); !errors.Is(err, ErrConflict) {
		t.Fatalf("same snapshot registered to another owner: %v", err)
	}
	project, err := s.GetProject(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, name := range []string{"first", "second"} {
		wg.Go(func() { _, err := s.RenameProject(ctx, "owner", name, project.Version); results <- err })
	}
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("CAS winners=%d conflicts=%d", wins, conflicts)
	}
	if err := s.BeginSnapshotDeletion(ctx, snap.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if err := s.PutManifest(ctx, snap.SnapshotID, testManifest(snap.SnapshotID, "analysis")); !errors.Is(err, ErrConflict) {
		t.Fatalf("late manifest write: %v", err)
	}
	if err := s.DeleteSnapshot(ctx, snap.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSnapshot(ctx, "owner", snap); !errors.Is(err, ErrConflict) {
		t.Fatalf("late revival without frozen tree: %v", err)
	}
}
