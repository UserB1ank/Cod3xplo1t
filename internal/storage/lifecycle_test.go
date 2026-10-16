package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func TestSnapshotDeletionWaitsForActiveWork(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			p := newPathFixture("path-active", auditMainID, auditSnapID, "entry", "sink", 0.5)
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), p)
			if _, err := store.ClaimPath(p.ID, "worker", clockNearFuture(), []path.Status{path.StatusQueued}, "worker"); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := store.BeginSnapshotDeletion(ctx, auditSnapID); !errors.Is(err, ErrConflict) {
				t.Fatalf("delete with active work: %v", err)
			}
			pending, err := store.SnapshotDeletionPending(ctx, auditSnapID)
			if err != nil || pending {
				t.Fatalf("rejected deletion left a marker: %v %v", pending, err)
			}
			if _, err := store.ReleaseLease(p.ID, "worker", "worker", "finished"); err != nil {
				t.Fatal(err)
			}
			if err := store.BeginSnapshotDeletion(ctx, auditSnapID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ClaimPath(p.ID, "worker", clockNearFuture(), []path.Status{path.StatusQueued}, "worker"); !errors.Is(err, ErrConflict) {
				t.Fatalf("claim during deletion: %v", err)
			}
		})
	}
}

func TestProjectVersionMigrationPreservesExistingMetadata(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := OpenSQL(ctx, "sqlite", filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	previous := fstest.MapFS{}
	names, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range names {
		if entry.IsDir() || entry.Name() >= "0010" {
			continue
		}
		body, err := migrations.FS.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		previous[entry.Name()] = &fstest.MapFile{Data: body}
	}
	if err := store.EnsureSchema(ctx, previous); err != nil {
		t.Fatal(err)
	}
	stamp := formatTime(time.Now().UTC())
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO projects (id,name,source,identity_kind,identity,created_at,updated_at)
VALUES ('project-old','existing name','example.invalid/repo','git','example.invalid/repo',?,?)`, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx, migrations.FS); err != nil {
		t.Fatal(err)
	}
	project, err := store.GetProject(ctx, "project-old")
	if err != nil || project.Name != "existing name" || project.Version != 1 {
		t.Fatalf("migrated project=%+v err=%v", project, err)
	}
	updated, err := store.RenameProject(ctx, project.ID, "new name", project.Version)
	if err != nil || updated.Name != "new name" || updated.Version != 2 {
		t.Fatalf("conditional rename=%+v err=%v", updated, err)
	}
	if _, err := store.RenameProject(ctx, project.ID, "stale name", project.Version); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
}

func TestAuditBudgetAcrossSQLiteConnections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := filepath.Join(t.TempDir(), "store.db")
	first, err := OpenSQL(ctx, "sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := first.EnsureSchema(ctx, migrations.FS); err != nil {
		t.Fatal(err)
	}
	second, err := OpenSQL(ctx, "sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Error(err)
		}
	})
	audit := newAuditFixture(auditMainID, auditSnapID, 1)
	audit.Limits.MaxActiveLeases = 1
	p1 := newPathFixture("path-first", auditMainID, auditSnapID, "entry", "sink-1", 0.5)
	p2 := newPathFixture("path-second", auditMainID, auditSnapID, "entry", "sink-2", 0.4)
	seedAudit(t, first, audit, p1, p2)
	start := make(chan struct{})
	type result struct {
		path *path.Path
		err  error
	}
	results := make(chan result, 2)
	until := clockNearFuture()
	for i, store := range []*SQL{first, second} {
		p := []path.Path{p1, p2}[i]
		go func() {
			<-start
			got, err := store.ClaimPath(p.ID, p.ID, until, []path.Status{path.StatusQueued}, p.ID)
			results <- result{got, err}
		}()
	}
	close(start)
	var winner *path.Path
	limited := 0
	for range 2 {
		select {
		case got := <-results:
			if got.err == nil {
				if winner != nil {
					t.Fatal("both connections exceeded the audit budget")
				}
				winner = got.path
			} else if errors.Is(got.err, path.ErrBudgetExceeded) {
				limited++
			} else {
				t.Fatal(got.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("claims did not finish")
		}
	}
	if winner == nil || limited != 1 {
		t.Fatalf("winner=%v limited=%d", winner, limited)
	}
	if _, err := first.RenewLease(winner.ID, winner.LeaseOwner, until, winner.LeaseOwner); err != nil {
		t.Fatalf("renewal consumed an extra slot: %v", err)
	}
	if _, err := first.ReleaseLease(winner.ID, winner.LeaseOwner, winner.LeaseOwner, "finished"); err != nil {
		t.Fatal(err)
	}
	loser := p1
	if winner.ID == p1.ID {
		loser = p2
	}
	if _, err := second.ClaimPath(loser.ID, loser.ID, until, []path.Status{path.StatusQueued}, loser.ID); err != nil {
		t.Fatalf("released slot was not reusable: %v", err)
	}
}
