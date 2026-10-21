package storage

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/testpostgres"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func TestPostgresProjectInputAndDeletionFences(t *testing.T) {
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
	t.Cleanup(func() { store.Close() })
	if err := store.EnsureSchema(ctx, migrations.Postgres); err != nil {
		t.Fatal(err)
	}

	p := testProject("proj-pg63")
	p.Description = "pg description"
	created, err := store.CreateProject(ctx, p)
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	input, err := store.GetProjectInput(ctx, created.ID)
	if err != nil || input.State != ProjectInputImporting || input.Version != 1 {
		t.Fatalf("input = %+v, %v", input, err)
	}
	if _, err := store.BeginProjectInput(ctx, created.ID, "src-pg", "git_repository", "repo"); err != nil {
		t.Fatal(err)
	}
	snap := testSnapshot("snap-pg63")
	if err := store.PutSnapshot(ctx, created.ID, snap); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteProjectInput(ctx, created.ID, "src-pg", snap.SnapshotID, 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginProjectInput(ctx, created.ID, "src-other", "git_repository", "other"); !errors.Is(err, ErrProjectInputFixed) {
		t.Fatalf("second source = %v, want fixed", err)
	}
	updated, err := store.UpdateProjectDetails(ctx, created.ID, "renamed", "new description", created.Version)
	if err != nil || updated.Description != "new description" {
		t.Fatalf("details = %+v, %v", updated, err)
	}

	seedAudit(t, store, newAuditFixture(auditMainID, snap.SnapshotID, 1),
		newPathFixture("path-pg63", auditMainID, snap.SnapshotID, "entry", "sink", 0.5))
	if _, err := store.BeginProjectDeletion(ctx, created.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("deletion with queued work = %v, want conflict", err)
	}
	if _, err := store.Transition(path.TransitionRequest{PathID: "path-pg63", To: path.StatusCancelled, Actor: "test", Reason: "settle"}); err != nil {
		t.Fatal(err)
	}
	intent, err := store.BeginProjectDeletion(ctx, created.ID)
	if err != nil || intent.State != ProjectDeletionPending {
		t.Fatalf("deletion intent = %+v, %v", intent, err)
	}
	if err := store.PutProject(ctx, testProject(created.ID)); !errors.Is(err, ErrConflict) {
		t.Fatalf("late project write = %v, want conflict", err)
	}
	if err := store.DeleteSnapshot(ctx, snap.SnapshotID); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if _, err := store.FinishProjectDeletion(ctx, created.ID); err != nil {
		t.Fatalf("FinishProjectDeletion: %v", err)
	}
	if _, err := store.GetProject(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("project survived: %v", err)
	}
	if done, err := store.ProjectDeletion(ctx, created.ID); err != nil || done.State != ProjectDeletionCompleted {
		t.Fatalf("tombstone = %+v, %v", done, err)
	}
	if err := store.PutProject(ctx, testProject(created.ID)); !errors.Is(err, ErrConflict) {
		t.Fatalf("late write after completion = %v", err)
	}
}
