package storage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/testpostgres"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func TestPostgresSupervisorSessionSurvivesRestart(t *testing.T) {
	file := testpostgres.DSNFile(t)
	dsn, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := OpenSQL(ctx, "pgx", string(dsn))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx, migrations.Postgres); err != nil {
		t.Fatal(err)
	}
	project := testProject("proj-pg-supervisor")
	if _, err := store.CreateProject(ctx, project); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	session := SupervisorSession{ID: "ss-pg", ProjectID: project.ID, SnapshotID: "snap-pg", Title: "default", State: "ACTIVE", Messages: []SupervisorMessage{{ID: "sm-pg", SessionID: "ss-pg", ProjectID: project.ID, Role: "user", Content: "hello", ClientMessageID: "client-pg", Status: "complete", Seq: 1, CreatedAt: now}}, Runs: []SupervisorRun{}, Events: []SupervisorEvent{{ID: "se-pg", SessionID: "ss-pg", Seq: 1, Type: "turn_started", CreatedAt: now}}, CreatedAt: now, UpdatedAt: now}
	if _, err := store.CreateSupervisorSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQL(ctx, "pgx", string(dsn))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	stored, err := reopened.GetSupervisorSession(ctx, project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Messages) != 1 || stored.Messages[0].ClientMessageID != "client-pg" || len(stored.Events) != 1 || stored.Version != 1 {
		t.Fatalf("supervisor after restart = %+v", stored)
	}
	stored.Messages = append(stored.Messages, SupervisorMessage{ID: "sm-pg-2", SessionID: stored.ID, ProjectID: project.ID, Role: "assistant", Content: "answer", Status: "complete", Seq: 2, CreatedAt: now})
	if updated, err := reopened.SaveSupervisorSession(ctx, stored, stored.Version); err != nil || updated.Version != 2 {
		t.Fatalf("save = %+v %v", updated, err)
	}
	reloaded, err := reopened.GetSupervisorSession(ctx, project.ID, session.ID)
	if err != nil || reloaded.Version != 2 || len(reloaded.Messages) != 2 {
		t.Fatalf("reload after save = %+v %v", reloaded, err)
	}
	if _, err := reopened.SaveSupervisorSession(ctx, stored, stored.Version); err == nil {
		t.Fatal("stale session save was accepted")
	}
}
