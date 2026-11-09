package storage

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/testpostgres"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func TestPostgresSupervisorAuditBudgetCannotOversellAcrossInstances(t *testing.T) {
	a, b := postgresKnowledgeStores(t)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for _, store := range []*SQL{a, b} {
		group.Add(1)
		go func(store *SQL) {
			defer group.Done()
			_, err := store.ReserveAuditTokens("supervisor-budget-shared", 40000)
			results <- err
		}(store)
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("concurrent cross-instance reservations succeeded %d times, want 1", success)
	}
	budget, err := a.GetAuditBudget("supervisor-budget-shared")
	if err != nil {
		t.Fatal(err)
	}
	if budget.ReservedTokens != 40000 || budget.UsedTokens != 0 {
		t.Fatalf("shared budget = %+v", budget)
	}
}

func TestPostgresSupervisorRunFenceRejectsThePreviousOwner(t *testing.T) {
	a, b := postgresKnowledgeStores(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	project := testProject("supervisor-run-fence")
	if err := a.PutProject(ctx, project); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	session, err := a.CreateSupervisorSession(ctx, SupervisorSession{
		ID: "ss-run-fence", ProjectID: project.ID, SnapshotID: "snap-run-fence",
		State: "ACTIVE", Messages: []SupervisorMessage{}, Events: []SupervisorEvent{},
		Runs: []SupervisorRun{{
			ID: "srun-run-fence", SessionID: "ss-run-fence", ProjectID: project.ID,
			Status: "RUNNING", ExecutionOwner: "owner-old", LeaseEpoch: 3,
			HeartbeatAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
			LeaseUntil:  now.Add(-time.Second).Format(time.RFC3339Nano),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := b.GetSupervisorSession(ctx, project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimed.Runs[0].Status = "PAUSED"
	claimed.Runs[0].ExecutionOwner = "owner-new"
	claimed.Runs[0].LeaseEpoch = 4
	claimed.Runs[0].LeaseUntil = ""
	if _, err := b.SaveSupervisorSessionFenced(ctx, claimed, claimed.Version, SupervisorRunFence{
		RunID: claimed.Runs[0].ID, Owner: "owner-new", Epoch: 4,
		AllowExpired: true, Now: now.Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	stale, err := a.GetSupervisorSession(ctx, project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	stale.Messages = append(stale.Messages, SupervisorMessage{
		ID: "sm-late", SessionID: session.ID, ProjectID: project.ID,
		Role: "assistant", Content: "late", RunID: "srun-run-fence", Status: "complete",
		CreatedAt: now.Format(time.RFC3339Nano),
	})
	if _, err := a.SaveSupervisorSessionFenced(ctx, stale, stale.Version, SupervisorRunFence{
		RunID: "srun-run-fence", Owner: "owner-old", Epoch: 3,
		Now: now.Format(time.RFC3339Nano),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale supervisor write = %v, want conflict", err)
	}
}

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
	stored.Messages = append(stored.Messages, SupervisorMessage{
		ID: "sm-pg-2", SessionID: stored.ID, ProjectID: project.ID,
		Role: "assistant", Content: "本轮到 90/90 轮后暂停。",
		MessageKind: "paused", Status: "complete", Seq: 2, CreatedAt: now,
	})
	stored.Runs = append(stored.Runs, SupervisorRun{
		ID: "srun-pg", SessionID: stored.ID, ProjectID: project.ID,
		Status: "PAUSED", Runtime: "llm", Model: "fixture",
		ConfigVersion: "1", PromptVersion: "supervisor/v5", ToolDigest: "digest",
		StopReason: "round_limit", ModelTurns: 90, ToolCalls: 87,
		RoundLimit: 90, ToolCallLimit: 150, InputTokens: 10, OutputTokens: 2,
		VisibleMessageID: "sm-pg-2", FinalizerSource: "template",
		UserMessageID: "sm-pg", RootRunID: "srun-pg",
		ExecutionOwner: "recovery-owner", HeartbeatAt: now, LeaseUntil: now,
		Checkpoint: &SupervisorCheckpoint{
			SchemaVersion: 1, UserMessageID: "sm-pg", StopReason: "round_limit",
			ModelTurns: 90, ToolCalls: 87, InputTokens: 10, OutputTokens: 2,
			Completed: []string{}, Pending: []string{"continue"},
			ClaimIDs: []string{}, EvidenceIDs: []string{},
			NextAction: "send a new continue request", CreatedAt: now,
		},
		CreatedAt: now, UpdatedAt: now, Version: 1,
	})
	if updated, err := reopened.SaveSupervisorSession(ctx, stored, stored.Version); err != nil || updated.Version != 2 {
		t.Fatalf("save = %+v %v", updated, err)
	}
	reloaded, err := reopened.GetSupervisorSession(ctx, project.ID, session.ID)
	if err != nil || reloaded.Version != 2 || len(reloaded.Messages) != 2 || len(reloaded.Runs) != 1 {
		t.Fatalf("reload after save = %+v %v", reloaded, err)
	}
	if reloaded.Messages[1].MessageKind != "paused" ||
		reloaded.Runs[0].StopReason != "round_limit" ||
		reloaded.Runs[0].RoundLimit != 90 || reloaded.Runs[0].ToolCallLimit != 150 ||
		reloaded.Runs[0].VisibleMessageID != "sm-pg-2" ||
		reloaded.Runs[0].Checkpoint == nil ||
		reloaded.Runs[0].Checkpoint.UserMessageID != "sm-pg" {
		t.Fatalf("new supervisor fields after reload = %+v", reloaded)
	}
	if _, err := reopened.SaveSupervisorSession(ctx, stored, stored.Version); err == nil {
		t.Fatal("stale session save was accepted")
	}
}
