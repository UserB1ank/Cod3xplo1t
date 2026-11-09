package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func TestProposedPathRequiresCurrentRunOwnerAndLease(t *testing.T) {
	runForEachStore(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		project := testProject("project-proposal-fence")
		snapshot := testSnapshot("snap-proposal-fence")
		if err := store.PutProject(ctx, project); err != nil {
			t.Fatal(err)
		}
		if err := store.PutSnapshot(ctx, project.ID, snapshot); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		audit := newAuditFixture("audit-proposal-fence", snapshot.SnapshotID, 1)
		seedAudit(t, store.(FullStore), audit)
		proposalStore, ok := store.(path.ProposalStore)
		if !ok {
			t.Fatalf("%T does not implement path.ProposalStore", store)
		}
		supervisorStore, ok := store.(SupervisorStore)
		if !ok {
			t.Fatalf("%T does not implement SupervisorStore", store)
		}
		session, err := supervisorStore.CreateSupervisorSession(ctx, SupervisorSession{
			ID: "ss-proposal-fence", ProjectID: project.ID, SnapshotID: snapshot.SnapshotID,
			State: "ACTIVE", Messages: []SupervisorMessage{}, Events: []SupervisorEvent{},
			Runs: []SupervisorRun{{
				ID: "srun-proposal-fence", SessionID: "ss-proposal-fence",
				ProjectID: project.ID, Status: "RUNNING",
				ExecutionOwner: "owner-a",
				LeaseEpoch:     7,
				LeaseUntil:     now.Add(time.Minute).Format(time.RFC3339Nano),
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		origin := path.ProposalOrigin{
			SessionID: session.ID, RunID: session.Runs[0].ID, ExecutionOwner: "owner-a", LeaseEpoch: 7,
		}
		proposal := proposalForFence(audit, "path-proposal-fence", "request-proposal-fence", now)
		if _, created, err := proposalStore.AddProposedPath(
			path.WithProposalOrigin(ctx, origin), proposal, "operator", "request-proposal-fence", 20,
		); err != nil || !created {
			t.Fatalf("active proposal = created:%t err:%v", created, err)
		}
		staleOwnerOrigin := origin
		staleOwnerOrigin.ExecutionOwner = "owner-stale"
		staleOwner := proposalForFence(audit, "path-proposal-stale-owner", "request-proposal-stale-owner", now)
		if _, _, err := proposalStore.AddProposedPath(
			path.WithProposalOrigin(ctx, staleOwnerOrigin), staleOwner,
			"operator", "request-proposal-stale-owner", 20,
		); !errors.Is(err, path.ErrConflict) {
			t.Fatalf("stale owner proposal = %v, want path.ErrConflict", err)
		}
		staleEpochOrigin := origin
		staleEpochOrigin.LeaseEpoch = 6
		staleEpoch := proposalForFence(audit, "path-proposal-stale-epoch", "request-proposal-stale-epoch", now)
		if _, _, err := proposalStore.AddProposedPath(
			path.WithProposalOrigin(ctx, staleEpochOrigin), staleEpoch,
			"operator", "request-proposal-stale-epoch", 20,
		); !errors.Is(err, path.ErrConflict) {
			t.Fatalf("stale lease epoch proposal = %v, want path.ErrConflict", err)
		}

		current, err := supervisorStore.GetSupervisorSession(ctx, project.ID, session.ID)
		if err != nil {
			t.Fatal(err)
		}
		current.Runs[0].LeaseUntil = now.Add(-time.Minute).Format(time.RFC3339Nano)
		if _, err := supervisorStore.SaveSupervisorSession(ctx, current, current.Version); err != nil {
			t.Fatal(err)
		}
		expired := proposalForFence(audit, "path-proposal-expired", "request-proposal-expired", now)
		if _, _, err := proposalStore.AddProposedPath(
			path.WithProposalOrigin(ctx, origin), expired, "operator", "request-proposal-expired", 20,
		); !errors.Is(err, path.ErrConflict) {
			t.Fatalf("expired lease proposal = %v, want path.ErrConflict", err)
		}

		current, err = supervisorStore.GetSupervisorSession(ctx, project.ID, session.ID)
		if err != nil {
			t.Fatal(err)
		}
		current.Runs[0].Status = "CANCELLED"
		current.Runs[0].LeaseUntil = ""
		if _, err := supervisorStore.SaveSupervisorSession(ctx, current, current.Version); err != nil {
			t.Fatal(err)
		}
		late := proposalForFence(audit, "path-proposal-late", "request-proposal-late", now)
		if _, _, err := proposalStore.AddProposedPath(
			path.WithProposalOrigin(ctx, origin), late, "operator", "request-proposal-late", 20,
		); !errors.Is(err, path.ErrConflict) {
			t.Fatalf("late proposal = %v, want path.ErrConflict", err)
		}
		auditStore, ok := store.(AuditStore)
		if !ok {
			t.Fatalf("%T does not implement AuditStore", store)
		}
		paths, total, err := auditStore.ListPaths(path.PathQuery{AuditID: audit.ID, Limit: 100})
		if err != nil || total != 1 || len(paths) != 1 {
			t.Fatalf("rejected proposals changed path set: total=%d paths=%+v err=%v", total, paths, err)
		}
		events, err := auditStore.ListEvents(path.EventQuery{AuditID: audit.ID, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			switch event.Detail["request_key"] {
			case "request-proposal-stale-owner", "request-proposal-stale-epoch", "request-proposal-expired", "request-proposal-late":
				t.Fatalf("rejected proposal emitted event: %+v", event)
			}
		}
	})
}

func proposalForFence(audit path.Audit, id, requestKey string, now time.Time) path.Path {
	proposal := newPathFixture(id, audit.ID, audit.SnapshotID, "asgn-entry-fence", "asgn-sink-fence", 0.5)
	proposal.SCGVersion = audit.SCGVersion
	proposal.ASGVersion = audit.ASGVersion
	proposal.PathKind = "hypothesis"
	proposal.PathStatus = path.PathUnresolved
	proposal.Status = path.StatusQueued
	proposal.Discoveries = []path.PathDiscovery{{
		Source: "supervisor", Tool: "propose_path", SessionID: "ss-proposal-fence",
		RunID: "srun-proposal-fence", KnowledgeViewID: "view-proposal-fence",
		RequestKey: requestKey, RequestDigest: "digest-" + requestKey, Basis: "hypothesis",
		Evidence:  []path.DiscoveryEvidence{{Kind: "source", File: "main.go", StartLine: 1, EndLine: 2}},
		CreatedAt: now.Format(time.RFC3339Nano),
	}}
	proposal.Signature = path.Signature(
		audit.SnapshotID, proposal.EntryNodeID, proposal.TargetNodeID, "hypothesis", []string{id},
	)
	proposal.ID = path.PathID(
		audit.ID, audit.SnapshotID, proposal.EntryNodeID, proposal.TargetNodeID, []string{id}, "hypothesis",
	)
	return proposal
}
