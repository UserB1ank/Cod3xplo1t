package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func TestProjectInputLifecycleAndDetailsCAS(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store := tc.store
			p := testProject("proj-input-" + tc.name)
			p.Description = "first description"
			created, err := store.CreateProject(ctx, p)
			if err != nil {
				t.Fatalf("CreateProject: %v", err)
			}
			if created.Description != p.Description || created.Version != 1 {
				t.Fatalf("created project lost metadata: %+v", created)
			}
			input, err := store.GetProjectInput(ctx, created.ID)
			if err != nil {
				t.Fatalf("GetProjectInput: %v", err)
			}
			if input.State != ProjectInputImporting || input.Version != 1 || input.SourceID != "" {
				t.Fatalf("new input = %+v, want empty importing input", input)
			}
			input, err = store.BeginProjectInput(ctx, created.ID, "src-one", "uploaded_archive", "source.zip")
			if err != nil {
				t.Fatalf("BeginProjectInput: %v", err)
			}
			if input.State != ProjectInputImporting || input.SourceID != "src-one" || input.Version != 2 {
				t.Fatalf("bound input = %+v", input)
			}
			// A retry of the same source must not advance the version or change
			// the binding; it is the same import, not a new one.
			again, err := store.BeginProjectInput(ctx, created.ID, "src-one", "uploaded_archive", "source.zip")
			if err != nil || again.Version != input.Version {
				t.Fatalf("same-source retry = %+v, %v", again, err)
			}
			ready, err := store.CompleteProjectInput(ctx, created.ID, "src-one", "snap-ready", 3, 512)
			if err != nil {
				t.Fatalf("CompleteProjectInput: %v", err)
			}
			if ready.State != ProjectInputReady || ready.SnapshotID != "snap-ready" || ready.Files != 3 || ready.Bytes != 512 {
				t.Fatalf("ready input = %+v", ready)
			}
			if _, err := store.BeginProjectInput(ctx, created.ID, "src-two", "uploaded_archive", "other.zip"); !errors.Is(err, ErrConflict) {
				t.Fatalf("second source accepted after ready: %v", err)
			}
			if _, err := store.CompleteProjectInput(ctx, created.ID, "src-two", "snap-other", 1, 1); !errors.Is(err, ErrConflict) {
				t.Fatalf("second completion accepted after ready: %v", err)
			}
			if kept, err := store.FailProjectInput(ctx, created.ID, "src-two", "failed", "should not apply"); err != nil || kept.State != ProjectInputReady {
				t.Fatalf("ready input was failed by a stale attempt: %+v %v", kept, err)
			}

			updated, err := store.UpdateProjectDetails(ctx, created.ID, "renamed", "second description", created.Version)
			if err != nil {
				t.Fatalf("UpdateProjectDetails: %v", err)
			}
			if updated.Name != "renamed" || updated.Description != "second description" || updated.Version != created.Version+1 {
				t.Fatalf("updated project = %+v", updated)
			}
			if _, err := store.UpdateProjectDetails(ctx, created.ID, "stale", "stale", created.Version); !errors.Is(err, ErrConflict) {
				t.Fatalf("stale details update = %v, want conflict", err)
			}
			stored, err := store.GetProject(ctx, created.ID)
			if err != nil || stored.Name != "renamed" || stored.Description != "second description" {
				t.Fatalf("details not durable: %+v %v", stored, err)
			}
		})
	}
}

func TestLegacyProjectHasNoImplicitInput(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store := tc.store
			p := testProject("proj-legacy-" + tc.name)
			if err := store.PutProject(ctx, p); err != nil {
				t.Fatalf("PutProject: %v", err)
			}
			if _, err := store.GetProjectInput(ctx, p.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("legacy project has an implicit input: %v", err)
			}
			// The legacy creation path must keep working for callers that never
			// created an audit input.
			if err := store.PutProject(ctx, p); err != nil {
				t.Fatalf("legacy PutProject replay: %v", err)
			}
		})
	}
}

func TestProjectDeletionRefusesActiveWorkAndStaysRecoverable(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store := tc.store
			snap := testSnapshot("snap-project-delete-" + tc.name)
			p := testProject("proj-delete-" + tc.name)
			created, err := store.CreateProject(ctx, p)
			if err != nil {
				t.Fatalf("CreateProject: %v", err)
			}
			if err := store.PutSnapshot(ctx, created.ID, snap); err != nil {
				t.Fatalf("PutSnapshot: %v", err)
			}
			if _, err := store.BeginProjectInput(ctx, created.ID, "src-delete", "git_repository", "repo"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.CompleteProjectInput(ctx, created.ID, "src-delete", snap.SnapshotID, 1, 1); err != nil {
				t.Fatal(err)
			}
			seedAudit(t, store, newAuditFixture(auditMainID, snap.SnapshotID, 1),
				newPathFixture("path-project-delete", auditMainID, snap.SnapshotID, "entry", "sink", 0.8))

			if _, err := store.BeginProjectDeletion(ctx, created.ID); !errors.Is(err, ErrConflict) {
				t.Fatalf("deletion with queued work = %v, want conflict", err)
			}
			if _, err := store.ProjectDeletion(ctx, created.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("rejected deletion left intent: %v", err)
			}
			if _, err := store.Transition(path.TransitionRequest{
				PathID: "path-project-delete", To: path.StatusCancelled, Actor: "test", Reason: "settle fixture",
			}); err != nil {
				t.Fatalf("cancel path: %v", err)
			}
			intent, err := store.BeginProjectDeletion(ctx, created.ID)
			if err != nil {
				t.Fatalf("BeginProjectDeletion: %v", err)
			}
			if intent.State != ProjectDeletionPending {
				t.Fatalf("deletion intent = %+v", intent)
			}
			if err := store.PutProject(ctx, testProject(created.ID)); !errors.Is(err, ErrConflict) {
				t.Fatalf("late project write during deletion = %v, want conflict", err)
			}
			sources, ok := store.(SourceRepository)
			if !ok {
				t.Fatalf("store does not implement SourceRepository")
			}
			if err := sources.CreateSource(ctx, SourceDefinition{
				APIVersion: "codexploit/v1", ID: "src-late", ProjectID: created.ID, Name: "late",
				Kind: "local_folder", Location: "/repos/late", Version: 1,
			}); !errors.Is(err, ErrConflict) {
				t.Fatalf("late source during deletion = %v, want conflict", err)
			}
			if err := store.PutSnapshot(ctx, created.ID, testSnapshot("snap-late-"+tc.name)); !errors.Is(err, ErrConflict) {
				t.Fatalf("late snapshot during deletion = %v, want conflict", err)
			}

			if err := store.DeleteSnapshot(ctx, snap.SnapshotID); err != nil {
				t.Fatalf("DeleteSnapshot: %v", err)
			}
			if _, err := store.FinishProjectDeletion(ctx, created.ID); err != nil {
				t.Fatalf("FinishProjectDeletion: %v", err)
			}
			if _, err := store.GetProject(ctx, created.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("project survived deletion: %v", err)
			}
			if done, err := store.ProjectDeletion(ctx, created.ID); err != nil || done.State != ProjectDeletionCompleted {
				t.Fatalf("completed tombstone = %+v, %v", done, err)
			}
			if err := store.PutProject(ctx, testProject(created.ID)); !errors.Is(err, ErrConflict) {
				t.Fatalf("completed deletion allowed a late project: %v", err)
			}
			// Replaying Delete is idempotent: the caller learns the project is gone
			// instead of creating a second intent or resurrecting a row.
			if again, err := store.BeginProjectDeletion(ctx, created.ID); err != nil || again.State != ProjectDeletionCompleted {
				t.Fatalf("deletion replay = %+v, %v", again, err)
			}
			if again, err := store.FinishProjectDeletion(ctx, created.ID); err != nil || again.State != ProjectDeletionCompleted {
				t.Fatalf("finish replay = %+v, %v", again, err)
			}
		})
	}
}

func TestProjectDeletionRejectsFreshImportingInputButAllowsInterruptedOne(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store := tc.store
			p := testProject("proj-importing-" + tc.name)
			created, err := store.CreateProject(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.BeginProjectInput(ctx, created.ID, "src-live", "uploaded_directory", "directory"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.BeginProjectDeletion(ctx, created.ID); !errors.Is(err, ErrConflict) {
				t.Fatalf("deletion during import = %v, want conflict", err)
			}
			// An interrupted import is presented as failed after the staleness
			// window, so cleanup must not be blocked forever.
			input, err := store.GetProjectInput(ctx, created.ID)
			if err != nil {
				t.Fatal(err)
			}
			effective := EffectiveProjectInput(input, time.Now().Add(ProjectInputStaleAfter+time.Second))
			if effective.State != ProjectInputFailed || effective.FailureCode != "import_interrupted" {
				t.Fatalf("stale input = %+v", effective)
			}
		})
	}
}
