package lifecycle

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

type recordingSnapshots struct{ removed []string }

func (m *recordingSnapshots) Load(string) (*repository.Snapshot, error) { return nil, os.ErrNotExist }
func (m *recordingSnapshots) Remove(id string) error {
	m.removed = append(m.removed, id)
	return nil
}

func projectFixture(t *testing.T, store storage.FullStore, id string, snapshots ...string) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.CreateProject(ctx, storage.Project{ID: id, Name: "fixture", IdentityKind: "project", Identity: id}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	for _, snapshotID := range snapshots {
		snap := &repository.Snapshot{
			SchemaVersion: repository.SchemaVersion,
			SnapshotID:    snapshotID,
			Identity:      repository.Identity{Kind: "dir", Name: "/srv/fixture"},
			VCS:           "none",
			Commit:        "content:fixture",
			CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		}
		if err := store.PutSnapshot(ctx, id, snap); err != nil {
			t.Fatalf("PutSnapshot(%s): %v", snapshotID, err)
		}
	}
}

func TestProjectDeletionRemovesSnapshotsAndProjectAndIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := storage.NewMemory()
	projectFixture(t, store, "proj-del", "snap-del-1", "snap-del-2")
	manager := &recordingSnapshots{}
	projects := NewProjects(store, manager)
	if err := projects.Delete(ctx, "proj-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(manager.removed) != 2 {
		t.Fatalf("removed snapshots = %v, want both snapshots", manager.removed)
	}
	if _, err := store.GetProject(ctx, "proj-del"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("project survived: %v", err)
	}
	for _, snapshotID := range manager.removed {
		if _, err := store.GetSnapshot(ctx, snapshotID); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("snapshot %s survived: %v", snapshotID, err)
		}
	}
	deletion, err := store.ProjectDeletion(ctx, "proj-del")
	if err != nil || deletion.State != storage.ProjectDeletionCompleted {
		t.Fatalf("tombstone = %+v, %v", deletion, err)
	}
	if err := projects.Delete(ctx, "proj-del"); err != nil {
		t.Fatalf("idempotent Delete: %v", err)
	}
	if err := projects.Delete(ctx, "proj-missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing project Delete = %v, want not found", err)
	}
}

func TestProjectDeletionResumesPendingIntent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := storage.NewMemory()
	projectFixture(t, store, "proj-resume", "snap-resume")
	if _, err := store.BeginProjectDeletion(ctx, "proj-resume"); err != nil {
		t.Fatalf("BeginProjectDeletion: %v", err)
	}
	// This is the state a crash leaves behind: a pending tombstone, fenced
	// snapshots and the project row still present.
	manager := &recordingSnapshots{}
	if err := NewProjects(store, manager).Delete(ctx, "proj-resume"); err != nil {
		t.Fatalf("resume Delete: %v", err)
	}
	if len(manager.removed) != 1 || manager.removed[0] != "snap-resume" {
		t.Fatalf("snapshot cleanup = %v", manager.removed)
	}
	if _, err := store.GetProject(ctx, "proj-resume"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("project survived resume: %v", err)
	}
	if err := store.PutProject(ctx, storage.Project{ID: "proj-resume", Name: "late"}); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("late project write = %v, want conflict", err)
	}
}

func TestProjectDeletionWaitsForLiveImportAndRejectsActiveWork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := storage.NewMemory()
	if _, err := store.CreateProject(ctx, storage.Project{ID: "proj-live", Name: "live"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginProjectInput(ctx, "proj-live", "src-live", "uploaded_archive", "live.zip"); err != nil {
		t.Fatal(err)
	}
	projects := NewProjects(store, &recordingSnapshots{})
	if err := projects.Delete(ctx, "proj-live"); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("Delete during import = %v, want conflict", err)
	}
	if _, err := store.GetProject(ctx, "proj-live"); err != nil {
		t.Fatalf("rejected deletion removed the project: %v", err)
	}
	if _, err := store.FailProjectInput(ctx, "proj-live", "src-live", "import_failed", "fixture failure"); err != nil {
		t.Fatal(err)
	}
	if err := projects.Delete(ctx, "proj-live"); err != nil {
		t.Fatalf("Delete after failed import: %v", err)
	}
}
