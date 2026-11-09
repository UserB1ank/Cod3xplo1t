package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func TestPostgresPathProposalDeduplicatesConcurrentSourcesAndRestarts(t *testing.T) {
	a, b := postgresKnowledgeStores(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := a.PutProject(ctx, testProject("owner")); err != nil {
		t.Fatal(err)
	}
	if err := a.PutSnapshot(ctx, "owner", testSnapshot(asgSnapshotID)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	configHash := "path-proposal-test"
	audit := path.Audit{
		ID: path.AuditID(asgSnapshotID, configHash), SnapshotID: asgSnapshotID,
		SCGVersion: "scg-v1", ASGVersion: "asg-v1", Status: path.AuditReady,
		Name: "Agent 新发现", Budget: path.DefaultBudget(), Limits: path.DefaultLimits(),
		ScoreVersion: path.ScoreVersion, ConfigHash: configHash,
		CountsByStatus: map[string]int{}, CountsByPathStatus: map[string]int{},
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	if err := a.CreateAudit(audit); err != nil {
		t.Fatal(err)
	}
	proposal := provisionalPath(audit, "entry-a", "sink-a", "edge-a", now)
	proposal.Discoveries[0].SessionID = "session-shared"
	proposal.Discoveries[0].RunID = "run-shared"
	var group sync.WaitGroup
	results := make(chan bool, 2)
	failures := make(chan error, 2)
	for _, store := range []*SQL{a, b} {
		group.Add(1)
		go func(store *SQL) {
			defer group.Done()
			_, created, err := store.AddProposedPath(ctx, proposal, "operator", proposal.Discoveries[0].RequestKey, 20)
			results <- created
			failures <- err
		}(store)
	}
	group.Wait()
	close(results)
	close(failures)
	createdCount := 0
	for created := range results {
		if created {
			createdCount++
		}
	}
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent replay created %d rows, want one", createdCount)
	}

	// A second connection reads the proposal after the first connection's
	// transaction; this is the process-restart boundary used by the deployment.
	reopened, err := b.GetPath(proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Discoveries) != 1 || reopened.Discoveries[0].KnowledgeViewID != "view-fixed" ||
		reopened.Discoveries[0].RequestDigest == "" {
		t.Fatalf("restart lost proposal provenance: %+v", reopened.Discoveries)
	}

	otherKey := provisionalPath(audit, "entry-a", "sink-a", "edge-a", now)
	otherKey.Discoveries[0].RequestKey = "different-request"
	otherKey.Discoveries[0].SessionID = "session-other"
	otherKey.Discoveries[0].RunID = "run-other"
	if _, created, err := a.AddProposedPath(ctx, otherKey, "operator", "different-request", 20); err != nil || created {
		t.Fatalf("second source for the same structural path: created=%t err=%v", created, err)
	}
	reopened, _ = b.GetPath(proposal.ID)
	if len(reopened.Discoveries) != 2 {
		t.Fatalf("second source was not retained: %+v", reopened.Discoveries)
	}
	changedReplay := provisionalPath(audit, "entry-a", "sink-a", "edge-a", now)
	changedReplay.Discoveries[0].SessionID = proposal.Discoveries[0].SessionID
	changedReplay.Discoveries[0].RunID = proposal.Discoveries[0].RunID
	changedReplay.Discoveries[0].RequestDigest = "changed-content"
	if _, _, err := a.AddProposedPath(ctx, changedReplay, "operator", proposal.Discoveries[0].RequestKey, 20); !errors.Is(err, path.ErrConflict) {
		t.Fatalf("same request key with changed digest = %v, want conflict", err)
	}

	conflict := provisionalPath(audit, "entry-a", "sink-b", "edge-b", now)
	conflict.Discoveries[0].RequestKey = "different-request"
	if _, _, err := a.AddProposedPath(ctx, conflict, "operator", "different-request", 20); !errors.Is(err, path.ErrConflict) {
		t.Fatalf("same request key for another path = %v, want conflict", err)
	}
	overBudget := provisionalPath(audit, "entry-b", "sink-b", "edge-c", now)
	overBudget.Discoveries[0].RequestKey = "over-budget"
	overBudget.Discoveries[0].RunID = "run-other"
	if _, _, err := a.AddProposedPath(ctx, overBudget, "operator", "over-budget", 1); !errors.Is(err, path.ErrBudgetExceeded) {
		t.Fatalf("per-run budget = %v, want ErrBudgetExceeded", err)
	}
}

func TestPostgresPathProposalRechecksRunOwnerAndLease(t *testing.T) {
	a, b := postgresKnowledgeStores(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	project := testProject("proposal-fence")
	snapshot := testSnapshot("snap-proposal-fence")
	if err := a.PutProject(ctx, project); err != nil {
		t.Fatal(err)
	}
	if err := a.PutSnapshot(ctx, project.ID, snapshot); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	audit := path.Audit{
		ID: path.AuditID(snapshot.SnapshotID, "proposal-fence"), SnapshotID: snapshot.SnapshotID,
		SCGVersion: "scg-v1", ASGVersion: "asg-v1", Status: path.AuditReady,
		Name: "Agent 新发现", Budget: path.DefaultBudget(), Limits: path.DefaultLimits(),
		ScoreVersion: path.ScoreVersion, ConfigHash: "proposal-fence",
		CountsByStatus: map[string]int{}, CountsByPathStatus: map[string]int{},
		CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano), Version: 1,
	}
	if err := a.CreateAudit(audit); err != nil {
		t.Fatal(err)
	}
	session, err := a.CreateSupervisorSession(ctx, SupervisorSession{
		ID: "ss-proposal-fence", ProjectID: project.ID, SnapshotID: snapshot.SnapshotID,
		State: "ACTIVE", Messages: []SupervisorMessage{}, Events: []SupervisorEvent{},
		Runs: []SupervisorRun{{
			ID: "srun-proposal-fence", SessionID: "ss-proposal-fence", ProjectID: project.ID,
			Status: "RUNNING", ExecutionOwner: "owner-live",
			LeaseEpoch: 11,
			LeaseUntil: now.Add(time.Minute).Format(time.RFC3339Nano),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	origin := path.ProposalOrigin{
		SessionID: session.ID, RunID: session.Runs[0].ID, ExecutionOwner: "owner-live", LeaseEpoch: 11,
	}
	proposalContext := path.WithProposalOrigin(ctx, origin)
	proposal := provisionalPath(audit, "entry-fence", "sink-fence", "edge-fence", now.Format(time.RFC3339Nano))
	proposal.Discoveries[0].Source = "supervisor"
	proposal.Discoveries[0].SessionID = session.ID
	proposal.Discoveries[0].RunID = session.Runs[0].ID
	if _, created, err := a.AddProposedPath(proposalContext, proposal, "operator", proposal.Discoveries[0].RequestKey, 20); err != nil || !created {
		t.Fatalf("active owner proposal = created:%t err:%v", created, err)
	}

	current, err := b.GetSupervisorSession(ctx, project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.Runs[0].LeaseEpoch = 12
	if _, err := b.SaveSupervisorSession(ctx, current, current.Version); err != nil {
		t.Fatal(err)
	}
	staleEpoch := provisionalPath(audit, "entry-stale-epoch", "sink-stale-epoch", "edge-stale-epoch", now.Format(time.RFC3339Nano))
	staleEpoch.Discoveries[0].Source = "supervisor"
	staleEpoch.Discoveries[0].SessionID = session.ID
	staleEpoch.Discoveries[0].RunID = session.Runs[0].ID
	staleEpoch.Discoveries[0].RequestKey = "stale-epoch-proposal"
	if _, _, err := b.AddProposedPath(proposalContext, staleEpoch, "operator", "stale-epoch-proposal", 20); !errors.Is(err, path.ErrConflict) {
		t.Fatalf("stale lease epoch proposal = %v, want ErrConflict", err)
	}

	current, err = b.GetSupervisorSession(ctx, project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.Runs[0].LeaseUntil = now.Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := b.SaveSupervisorSession(ctx, current, current.Version); err != nil {
		t.Fatal(err)
	}
	expiredOrigin := origin
	expiredOrigin.LeaseEpoch = 12
	expired := provisionalPath(audit, "entry-expired", "sink-expired", "edge-expired", now.Format(time.RFC3339Nano))
	expired.Discoveries[0].Source = "supervisor"
	expired.Discoveries[0].SessionID = session.ID
	expired.Discoveries[0].RunID = session.Runs[0].ID
	expired.Discoveries[0].RequestKey = "expired-proposal"
	if _, _, err := b.AddProposedPath(path.WithProposalOrigin(ctx, expiredOrigin), expired, "operator", "expired-proposal", 20); !errors.Is(err, path.ErrConflict) {
		t.Fatalf("expired lease proposal = %v, want ErrConflict", err)
	}

	current, err = b.GetSupervisorSession(ctx, project.ID, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.Runs[0].Status = "CANCELLED"
	current.Runs[0].LeaseUntil = ""
	if _, err := b.SaveSupervisorSession(ctx, current, current.Version); err != nil {
		t.Fatal(err)
	}
	late := provisionalPath(audit, "entry-late", "sink-late", "edge-late", now.Format(time.RFC3339Nano))
	late.Discoveries[0].Source = "supervisor"
	late.Discoveries[0].SessionID = session.ID
	late.Discoveries[0].RunID = session.Runs[0].ID
	late.Discoveries[0].RequestKey = "late-proposal"
	if _, _, err := b.AddProposedPath(path.WithProposalOrigin(ctx, expiredOrigin), late, "operator", "late-proposal", 20); !errors.Is(err, path.ErrConflict) {
		t.Fatalf("cancelled run proposal = %v, want ErrConflict", err)
	}
	paths, total, err := a.ListPaths(path.PathQuery{AuditID: audit.ID, Limit: 100})
	if err != nil || total != 1 || len(paths) != 1 {
		t.Fatalf("rejected postgres proposals changed path set: total=%d paths=%+v err=%v", total, paths, err)
	}
	events, err := a.ListEvents(path.EventQuery{AuditID: audit.ID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		switch event.Detail["request_key"] {
		case "stale-epoch-proposal", "expired-proposal", "late-proposal":
			t.Fatalf("rejected postgres proposal emitted event: %+v", event)
		}
	}
}

func provisionalPath(audit path.Audit, entry, target, edge, now string) path.Path {
	signature := path.Signature(audit.SnapshotID, entry, target, "hypothesis", []string{edge})
	return path.Path{
		ID:      path.PathID(audit.ID, audit.SnapshotID, entry, target, []string{edge}, "hypothesis"),
		AuditID: audit.ID, SnapshotID: audit.SnapshotID, SCGVersion: audit.SCGVersion, ASGVersion: audit.ASGVersion,
		EntryNodeID: entry, TargetNodeID: target, PathKind: "hypothesis", PathStatus: path.PathUnresolved,
		Status: path.StatusQueued, Signature: signature, Steps: []path.Step{},
		Budget: path.DefaultBudget(), Score: path.Score{ScoreVersion: path.ScoreVersion},
		Discoveries: []path.PathDiscovery{{
			Source: "human", Tool: "propose_path", KnowledgeViewID: "view-fixed",
			RequestKey: "request-" + edge, RequestDigest: "digest-" + edge, Basis: "hypothesis", CreatedAt: now,
			Evidence: []path.DiscoveryEvidence{{Kind: "source", File: "main.go", StartLine: 1, EndLine: 2}},
		}},
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}
}
