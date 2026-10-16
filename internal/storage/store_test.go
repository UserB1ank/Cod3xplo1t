package storage

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/migrations"

	_ "modernc.org/sqlite"
)

// storeFactory lets the same suite run against every implementation, which is
// how the memory store stays faithful to the SQL semantics.
type storeFactory struct {
	name string
	open func(t *testing.T) Store
}

func storeFactories() []storeFactory {
	return []storeFactory{
		{
			name: "memory",
			open: func(t *testing.T) Store { return NewMemory() },
		},
		{
			name: "sqlite",
			open: func(t *testing.T) Store {
				ctx := context.Background()
				db := filepath.Join(t.TempDir(), "codexploit.db")
				s, err := OpenSQL(ctx, "sqlite", db)
				if err != nil {
					t.Fatalf("OpenSQL: %v", err)
				}
				if err := s.EnsureSchema(ctx, migrations.FS); err != nil {
					t.Fatalf("EnsureSchema: %v", err)
				}
				t.Cleanup(func() {
					if err := s.Close(); err != nil {
						t.Errorf("Close: %v", err)
					}
				})
				return s
			},
		},
	}
}

func runForEachStore(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Helper()
	for _, f := range storeFactories() {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			fn(t, f.open(t))
		})
	}
}

func testProject(id string) Project {
	return Project{
		ID:           id,
		Name:         "fixture",
		Source:       "/srv/fixture",
		IdentityKind: "dir",
		Identity:     "/srv/fixture",
		CreatedAt:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func testSnapshot(id string) *repository.Snapshot {
	return &repository.Snapshot{
		SchemaVersion: repository.SchemaVersion,
		SnapshotID:    id,
		Identity:      repository.Identity{Kind: "dir", Name: "/srv/fixture"},
		VCS:           "none",
		Commit:        "content:deadbeef",
		CreatedAt:     time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
}

func testManifest(snapshotID, analysisID string) *analysis.Manifest {
	return &analysis.Manifest{
		SchemaVersion: analysis.SchemaVersion,
		SnapshotID:    snapshotID,
		AnalysisID:    analysisID,
		Engine:        analysis.DefaultEngine,
		RulesetHash:   "rules-1",
		ConfigHash:    "config-1",
		GeneratedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
}

const (
	snapID = "snap-0123456789abcdef0123456789abcdef"
	second = "snap-fedcba9876543210fedcba9876543210"
)

func TestProjectLifecycle(t *testing.T) {
	runForEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		if _, err := s.GetProject(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetProject(missing) = %v, want ErrNotFound", err)
		}
		p := testProject("proj-1")
		if err := s.PutProject(ctx, p); err != nil {
			t.Fatalf("PutProject: %v", err)
		}
		got, err := s.GetProject(ctx, p.ID)
		if err != nil {
			t.Fatalf("GetProject: %v", err)
		}
		if got.Source != p.Source || got.Identity != p.Identity || !got.CreatedAt.Equal(p.CreatedAt) {
			t.Fatalf("round trip mismatch: %+v vs %+v", got, p)
		}
		if got.UpdatedAt.IsZero() {
			t.Error("UpdatedAt was not set")
		}

		// Projects are mutable metadata: updating keeps the original creation time.
		updated := p
		updated.Name = "renamed"
		updated.CreatedAt = time.Time{}
		if err := s.PutProject(ctx, updated); err != nil {
			t.Fatalf("PutProject(update): %v", err)
		}
		got, err = s.GetProject(ctx, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != "renamed" {
			t.Errorf("name = %q, want renamed", got.Name)
		}
		if !got.CreatedAt.Equal(p.CreatedAt) {
			t.Errorf("CreatedAt changed on update: %s", got.CreatedAt)
		}

		if err := s.PutProject(ctx, testProject("proj-2")); err != nil {
			t.Fatal(err)
		}
		list, err := s.ListProjects(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].ID != "proj-1" || list[1].ID != "proj-2" {
			t.Fatalf("ListProjects = %+v", list)
		}
	})
}

func TestSnapshotRequiresKnownProject(t *testing.T) {
	runForEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		if err := s.PutSnapshot(ctx, "ghost", testSnapshot(snapID)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("PutSnapshot with unknown project = %v, want ErrNotFound", err)
		}
	})
}

func TestSnapshotRoundTripAndImmutability(t *testing.T) {
	runForEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		if err := s.PutProject(ctx, testProject("proj-1")); err != nil {
			t.Fatal(err)
		}
		snap := testSnapshot(snapID)
		if err := s.PutSnapshot(ctx, "proj-1", snap); err != nil {
			t.Fatalf("PutSnapshot: %v", err)
		}
		// Idempotent replay is allowed...
		if err := s.PutSnapshot(ctx, "proj-1", snap); err != nil {
			t.Fatalf("PutSnapshot replay: %v", err)
		}
		// ...but a different document under the same id is not.
		other := testSnapshot(snapID)
		other.Commit = "content:changed"
		if err := s.PutSnapshot(ctx, "proj-1", other); !errors.Is(err, ErrConflict) {
			t.Fatalf("PutSnapshot with modified content = %v, want ErrConflict", err)
		}

		got, err := s.GetSnapshot(ctx, snapID)
		if err != nil {
			t.Fatalf("GetSnapshot: %v", err)
		}
		if got.Commit != snap.Commit || got.Identity != snap.Identity || got.SnapshotID != snapID {
			t.Fatalf("snapshot round trip mismatch: %+v", got)
		}
		if got.Dir != "" {
			t.Errorf("stored snapshot exposes a directory: %q", got.Dir)
		}
		if _, err := s.GetSnapshot(ctx, second); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetSnapshot(missing) = %v, want ErrNotFound", err)
		}
	})
}

func TestManifestImmutability(t *testing.T) {
	runForEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		if err := s.PutProject(ctx, testProject("proj-1")); err != nil {
			t.Fatal(err)
		}
		if err := s.PutSnapshot(ctx, "proj-1", testSnapshot(snapID)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetManifest(ctx, snapID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetManifest before write = %v, want ErrNotFound", err)
		}
		if err := s.PutManifest(ctx, "ghost", testManifest(snapID, "analysis-1")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("PutManifest with unknown snapshot = %v, want ErrNotFound", err)
		}
		mf := testManifest(snapID, "analysis-1")
		if err := s.PutManifest(ctx, snapID, mf); err != nil {
			t.Fatalf("PutManifest: %v", err)
		}
		if err := s.PutManifest(ctx, snapID, mf); err != nil {
			t.Fatalf("PutManifest replay: %v", err)
		}
		got, err := s.GetManifest(ctx, snapID)
		if err != nil {
			t.Fatalf("GetManifest: %v", err)
		}
		if got.AnalysisID != mf.AnalysisID || got.SnapshotID != mf.SnapshotID {
			t.Fatalf("manifest round trip mismatch: %+v", got)
		}
		// A different analysis of the same snapshot must not overwrite evidence.
		if err := s.PutManifest(ctx, snapID, testManifest(snapID, "analysis-2")); !errors.Is(err, ErrConflict) {
			t.Fatalf("PutManifest with a new analysis id = %v, want ErrConflict", err)
		}
	})
}

func TestListAndDeleteSnapshots(t *testing.T) {
	runForEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		if err := s.PutProject(ctx, testProject("proj-1")); err != nil {
			t.Fatal(err)
		}
		if err := s.PutProject(ctx, testProject("proj-2")); err != nil {
			t.Fatal(err)
		}
		first := testSnapshot(snapID)
		first.CreatedAt = "2024-01-01T00:00:00Z"
		secondSnap := testSnapshot(second)
		secondSnap.CreatedAt = "2024-02-01T00:00:00Z"
		if err := s.PutSnapshot(ctx, "proj-1", first); err != nil {
			t.Fatal(err)
		}
		if err := s.PutSnapshot(ctx, "proj-2", secondSnap); err != nil {
			t.Fatal(err)
		}
		if err := s.PutManifest(ctx, snapID, testManifest(snapID, "analysis-1")); err != nil {
			t.Fatal(err)
		}

		all, err := s.ListSnapshots(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 2 || all[0].SnapshotID != snapID || all[1].SnapshotID != second {
			t.Fatalf("ListSnapshots = %+v", all)
		}
		if !all[0].ManifestPresent || all[0].AnalysisID != "analysis-1" {
			t.Errorf("manifest state not reflected: %+v", all[0])
		}
		if all[1].ManifestPresent {
			t.Errorf("unanalysed snapshot reports a manifest: %+v", all[1])
		}
		scoped, err := s.ListSnapshots(ctx, "proj-2")
		if err != nil {
			t.Fatal(err)
		}
		if len(scoped) != 1 || scoped[0].SnapshotID != second {
			t.Fatalf("project scoped list = %+v", scoped)
		}

		if err := s.DeleteSnapshot(ctx, snapID); err != nil {
			t.Fatalf("DeleteSnapshot: %v", err)
		}
		if _, err := s.GetSnapshot(ctx, snapID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetSnapshot after delete = %v, want ErrNotFound", err)
		}
		if _, err := s.GetManifest(ctx, snapID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetManifest after delete = %v, want ErrNotFound", err)
		}
		if err := s.DeleteSnapshot(ctx, snapID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("second DeleteSnapshot = %v, want ErrNotFound", err)
		}
	})
}

func TestMigrateIsIdempotentAndDetectsEmptySets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := OpenSQL(ctx, "sqlite", filepath.Join(t.TempDir(), "migrate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 3; i++ {
		if err := s.Migrate(ctx, migrations.FS); err != nil {
			t.Fatalf("Migrate run %d: %v", i, err)
		}
	}
	var applied int
	if err := s.DB().QueryRow(`SELECT COUNT(1) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if applied != len(names) {
		t.Fatalf("applied %d migrations, want %d", applied, len(names))
	}
	if err := s.EnsureSchema(ctx, fstest.MapFS{}); !errors.Is(err, ErrNoMigrations) {
		t.Fatalf("EnsureSchema on an empty set = %v, want ErrNoMigrations", err)
	}
	if err := s.Migrate(ctx, nil); err == nil {
		t.Fatal("Migrate(nil) succeeded")
	}
}

func TestMigrationStatementSplitting(t *testing.T) {
	t.Parallel()
	body := "-- a comment\nCREATE TABLE a (id TEXT);\n\nCREATE INDEX i ON a(id);\n"
	stmts := splitStatements(body)
	if len(stmts) != 2 {
		t.Fatalf("splitStatements returned %d statements: %#v", len(stmts), stmts)
	}
	if stmts[0] != "CREATE TABLE a (id TEXT)" || stmts[1] != "CREATE INDEX i ON a(id)" {
		t.Fatalf("unexpected statements: %#v", stmts)
	}
	if got := migrationVersion("migrations/0001_init.sql"); got != "0001" {
		t.Fatalf("migrationVersion = %q", got)
	}
}

func TestRebindForPostgres(t *testing.T) {
	t.Parallel()
	lite := &SQL{}
	if got := lite.rebind("SELECT 1 WHERE id = ?"); got != "SELECT 1 WHERE id = ?" {
		t.Errorf("sqlite rebind = %q", got)
	}
	pg := &SQL{postgres: true}
	if got := pg.rebind("INSERT INTO t (a, b) VALUES (?, ?)"); got != "INSERT INTO t (a, b) VALUES ($1, $2)" {
		t.Errorf("postgres rebind = %q", got)
	}
}

func TestOpenSQLRejectsUnknownAndEmptyDrivers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, err := OpenSQL(ctx, "", "x"); err == nil {
		t.Error("empty driver name was accepted")
	}
	if _, err := OpenSQL(ctx, "not-a-real-driver", "x"); err == nil {
		t.Error("unknown driver was accepted")
	}
}
