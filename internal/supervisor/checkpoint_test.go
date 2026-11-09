package supervisor

import (
	"context"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestStructuredCheckpointDerivesWritesPendingAndBudget(t *testing.T) {
	store := storage.NewMemory()
	project := storage.Project{ID: "proj-checkpoint-facts", Name: "fixture", Source: "/srv/fixture"}
	if _, err := store.CreateProject(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	service := New(store, nil, nil)
	session, err := service.CreateSession(context.Background(), project.ID, "snap-checkpoint", "checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := storage.SupervisorRun{
		ID: "srun-checkpoint-facts", SessionID: session.ID, ProjectID: project.ID,
		AuditID: session.AuditID, Status: RunRunning,
		ExecutionOwner: service.executionOwner, LeaseEpoch: 1,
		RoundLimit: 90, ToolCallLimit: 150,
	}
	user := storage.SupervisorMessage{ID: "sm-checkpoint-user", SessionID: session.ID, ProjectID: project.ID, RunID: run.ID, Role: "user", Content: "investigate", Status: "complete", Seq: 1, CreatedAt: now}
	assistant := storage.SupervisorMessage{
		ID: "sm-checkpoint-tools", SessionID: session.ID, ProjectID: project.ID, RunID: run.ID,
		Role: "assistant", Status: "complete", Seq: 2, CreatedAt: now,
		Calls: []storage.SupervisorCall{
			{ID: "call-claim", Name: "propose_claim", Arguments: `{}`},
			{ID: "call-evidence", Name: "attach_evidence", Arguments: `{}`},
			{ID: "call-finding", Name: "propose_finding", Arguments: `{}`},
			{ID: "call-failed", Name: "project_api", Arguments: `{}`},
			{ID: "call-pending", Name: "query_investigation_knowledge", Arguments: `{}`},
		},
	}
	session.Messages = append(session.Messages, user, assistant,
		storage.SupervisorMessage{ID: "tool-claim", SessionID: session.ID, ProjectID: project.ID, RunID: run.ID, Role: "tool", ToolCallID: "call-claim", Content: `{"ok":true,"result":{"claim_id":"claim-1","receipt_id":"receipt-1"}}`, Status: "complete", Seq: 3, CreatedAt: now},
		storage.SupervisorMessage{ID: "tool-evidence", SessionID: session.ID, ProjectID: project.ID, RunID: run.ID, Role: "tool", ToolCallID: "call-evidence", Content: `{"ok":true,"result":{"evidence_id":"evidence-1"}}`, Status: "complete", Seq: 4, CreatedAt: now},
		storage.SupervisorMessage{ID: "tool-finding", SessionID: session.ID, ProjectID: project.ID, RunID: run.ID, Role: "tool", ToolCallID: "call-finding", Content: `{"ok":true,"result":{"finding_id":"finding-1"}}`, Status: "complete", Seq: 5, CreatedAt: now},
		storage.SupervisorMessage{ID: "tool-failed", SessionID: session.ID, ProjectID: project.ID, RunID: run.ID, Role: "tool", ToolCallID: "call-failed", Content: `{"ok":false,"error_code":"TOOL_ERROR","message":"invalid query"}`, Status: "complete", Seq: 6, CreatedAt: now},
	)
	session.Runs = append(session.Runs, run)
	if _, err := store.SaveSupervisorSession(context.Background(), session, session.Version); err != nil {
		t.Fatal(err)
	}
	checkpoint := service.buildCheckpoint(context.Background(), session, run, StopToolLimit, 81, 120, 1000, 200, "tool limit")
	if checkpoint.SchemaVersion != 2 || checkpoint.CheckpointID == "" ||
		len(checkpoint.Completed) == 0 || len(checkpoint.Pending) == 0 ||
		len(checkpoint.ClaimIDs) != 1 || checkpoint.ClaimIDs[0] != "claim-1" ||
		len(checkpoint.EvidenceIDs) != 1 || checkpoint.EvidenceIDs[0] != "evidence-1" ||
		len(checkpoint.FindingIDs) != 1 || checkpoint.FindingIDs[0] != "finding-1" ||
		len(checkpoint.ReceiptIDs) != 1 || checkpoint.ReceiptIDs[0] != "receipt-1" {
		t.Fatalf("structured checkpoint = %+v", checkpoint)
	}
	if checkpoint.LastError == nil || checkpoint.LastError.Code != "TOOL_ERROR" ||
		checkpoint.Budget.RemainingRounds != 9 || checkpoint.Budget.RemainingToolCalls != 30 {
		t.Fatalf("checkpoint facts = %+v", checkpoint)
	}
	pendingFound := false
	for _, operation := range checkpoint.Operations {
		if operation.CallID == "call-pending" && operation.Status == "pending" {
			pendingFound = true
		}
	}
	if !pendingFound {
		t.Fatalf("unfinished tool not recorded: %+v", checkpoint.Operations)
	}
	second := service.buildCheckpoint(context.Background(), session, run, StopToolLimit, 81, 120, 1000, 200, "tool limit")
	if second.CheckpointID != checkpoint.CheckpointID {
		t.Fatalf("checkpoint digest is not deterministic: %q != %q", checkpoint.CheckpointID, second.CheckpointID)
	}
}

func TestSoftCheckpointSaveIsIdempotent(t *testing.T) {
	store := storage.NewMemory()
	project := storage.Project{ID: "proj-checkpoint-soft", Name: "fixture", Source: "/srv/fixture"}
	if _, err := store.CreateProject(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	service := New(store, nil, nil)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := storage.SupervisorRun{
		ID: "srun-checkpoint-soft", SessionID: "ss-checkpoint-soft", ProjectID: project.ID,
		AuditID: sessionBudgetID(project.ID, "snap-checkpoint-soft"), Status: RunRunning,
		ExecutionOwner: service.executionOwner, LeaseEpoch: 1, RoundLimit: 90, ToolCallLimit: 150,
	}
	session, err := store.CreateSupervisorSession(context.Background(), storage.SupervisorSession{
		ID: "ss-checkpoint-soft", ProjectID: project.ID, SnapshotID: "snap-checkpoint-soft",
		AuditID: run.AuditID, State: SessionActive,
		Messages: []storage.SupervisorMessage{{ID: "sm-soft-user", SessionID: "ss-checkpoint-soft", ProjectID: project.ID, RunID: run.ID, Role: "user", Content: "go", Status: "complete", Seq: 1, CreatedAt: now}},
		Runs:     []storage.SupervisorRun{run}, Events: []storage.SupervisorEvent{}, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.saveSoftCheckpoint(context.Background(), session, run, 81, 120, 1000, 200, "soft_90")
	if err != nil || !first {
		t.Fatalf("first soft checkpoint saved=%t err=%v", first, err)
	}
	second, err := service.saveSoftCheckpoint(context.Background(), session, run, 81, 120, 1000, 200, "soft_90")
	if err != nil || second {
		t.Fatalf("second soft checkpoint saved=%t err=%v", second, err)
	}
	stored, err := store.GetSupervisorSession(context.Background(), project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := 0
	for _, event := range stored.Events {
		if event.Type == "checkpoint_saved" {
			checkpoints++
		}
	}
	if checkpoints != 1 || stored.Runs[0].Checkpoint == nil {
		t.Fatalf("soft checkpoints = %d checkpoint=%+v", checkpoints, stored.Runs[0].Checkpoint)
	}
}

func sessionBudgetID(projectID, snapshotID string) string {
	return "supervisor-budget:" + projectID + ":" + snapshotID
}
