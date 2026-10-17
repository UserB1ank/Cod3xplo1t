package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func findingObservationFixture() findings.Observation {
	return findings.Observation{
		ID:        "obs-1",
		FindingID: "find-group-1",
		Scope:     artifact.Scope{ProjectID: "project-a", SourceID: "source-a", SnapshotID: "snap-a"},
		TaskID:    "task-1",
		Producer: artifact.Producer{
			PluginID: "codexploit.static-patterns", PluginVersion: "1.0.0",
			InvocationID: "inv-1", TaskID: "task-1", ConfigDigest: "cfg-1",
		},
		RuleID: "CP001", RuleVersion: "1", RuleFamily: "codexploit.command-execution",
		Title: "Command execution with a non-literal argument", SeverityHint: "high",
		Status: verify.FindingCandidate, File: "main.go", Line: 6, EndLine: 6,
		EvidenceRefs: []string{"artifact-inv-1-native"},
		Limitations:  []string{"Alert location only"},
		Fingerprint:  "fingerprint-1", FingerprintVersion: findings.FingerprintVersion,
		CreatedAt: "2024-06-01T09:00:00Z",
	}
}

func seedFindingGroup(t *testing.T, store FullStore) {
	t.Helper()
	if err := store.PutProject(context.Background(), testProject("project-a")); err != nil {
		t.Fatal(err)
	}
	if err := store.PutSnapshot(context.Background(), "project-a", testSnapshot("snap-a")); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertFinding(verify.Finding{
		ID: "find-group-1", HypothesisID: "fp-1", AuditID: "task-1", SnapshotID: "snap-a",
		Title: "Command execution with a non-literal argument", Status: verify.FindingCandidate,
		Confidence: "candidate", CreatedAt: "2024-06-01T09:00:00Z", UpdatedAt: "2024-06-01T09:00:00Z", Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFindingObservationLedgerIsIdempotentAndScoped(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seedFindingGroup(t, tc.store)
			observation := findingObservationFixture()
			inserted, err := tc.store.UpsertFindingObservation(observation)
			if err != nil || !inserted {
				t.Fatalf("first insert = %v %v", inserted, err)
			}
			replay := observation
			replay.CreatedAt = "2024-06-01T09:05:00Z"
			if inserted, err := tc.store.UpsertFindingObservation(replay); err != nil || inserted {
				t.Fatalf("replay = %v %v", inserted, err)
			}
			changed := observation
			changed.Title = "different claim under the same id"
			if _, err := tc.store.UpsertFindingObservation(changed); !errors.Is(err, findings.ErrConflict) {
				t.Fatalf("changed replay = %v, want ErrConflict", err)
			}
			stored, err := tc.store.GetFindingObservation(observation.ID)
			if err != nil || stored.Title != observation.Title {
				t.Fatalf("GetFindingObservation = %+v %v", stored, err)
			}
			byFinding, err := tc.store.ListFindingObservations(observation.FindingID)
			if err != nil || len(byFinding) != 1 {
				t.Fatalf("by finding = %+v %v", byFinding, err)
			}
			byProject, total, err := tc.store.ListFindingObservationsByProject("project-a", 1, 0)
			if err != nil || total != 1 || len(byProject) != 1 {
				t.Fatalf("by project = %+v %d %v", byProject, total, err)
			}
			byTask, total, err := tc.store.ListFindingObservationsByTask("task-1", 1, 0)
			if err != nil || total != 1 || len(byTask) != 1 {
				t.Fatalf("by task = %+v %d %v", byTask, total, err)
			}
			if other, total, err := tc.store.ListFindingObservationsByProject("project-other", 10, 0); err != nil || total != 0 || len(other) != 0 {
				t.Fatalf("foreign project = %+v %d %v", other, total, err)
			}
		})
	}
}

func TestSeverityCASWritesAuditWithoutChangingTheVerdict(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seedFindingGroup(t, tc.store)
			audit := findings.SeverityAudit{
				ID: "audit-1", FindingID: "find-group-1", Version: 2,
				PreviousSeverity: "", Severity: "high", Reason: "reachable from the public handler",
				Actor: "tester", CreatedAt: "2024-06-01T09:01:00Z",
			}
			if err := tc.store.SetFindingSeverityWithAudit("find-group-1", "high", 1, audit); err != nil {
				t.Fatalf("SetFindingSeverityWithAudit: %v", err)
			}
			finding, err := tc.store.GetFinding("find-group-1")
			if err != nil || finding.Severity != "high" || finding.Version != 2 || finding.Status != verify.FindingCandidate {
				t.Fatalf("finding = %+v %v", finding, err)
			}
			audits, err := tc.store.ListFindingSeverityAudits("find-group-1")
			if err != nil || len(audits) != 1 || audits[0].Reason != audit.Reason || audits[0].Version != 2 {
				t.Fatalf("audits = %+v %v", audits, err)
			}
			if err := tc.store.SetFindingSeverityWithAudit("find-group-1", "low", 1, findings.SeverityAudit{ID: "audit-stale", FindingID: "find-group-1", Version: 2, Severity: "low", Reason: "stale", Actor: "tester"}); !errors.Is(err, verify.ErrConflict) {
				t.Fatalf("stale write = %v, want ErrConflict", err)
			}
			if audits, _ := tc.store.ListFindingSeverityAudits("find-group-1"); len(audits) != 1 {
				t.Fatalf("stale write appended an audit: %+v", audits)
			}
			if err := tc.store.SetFindingSeverityWithAudit("find-group-1", "critical", 2, findings.SeverityAudit{ID: "audit-bad", FindingID: "find-group-1", Version: 3, Severity: "critical", Reason: "bad", Actor: "tester"}); !errors.Is(err, verify.ErrInvalidArgument) {
				t.Fatalf("invalid grade = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestSnapshotCleanupRemovesObservationsAndSeverityAudits(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seedFindingGroup(t, tc.store)
			if _, err := tc.store.UpsertFindingObservation(findingObservationFixture()); err != nil {
				t.Fatal(err)
			}
			if err := tc.store.SetFindingSeverityWithAudit("find-group-1", "high", 1, findings.SeverityAudit{
				ID: "audit-cleanup", FindingID: "find-group-1", Version: 2, Severity: "high",
				Reason: "cleanup fixture", Actor: "tester",
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := tc.store.DeleteVerificationForSnapshot("snap-a"); err != nil {
				t.Fatal(err)
			}
			if _, err := tc.store.GetFindingObservation("obs-1"); !errors.Is(err, findings.ErrNotFound) {
				t.Fatalf("observation survived cleanup: %v", err)
			}
			if audits, err := tc.store.ListFindingSeverityAudits("find-group-1"); err != nil || len(audits) != 0 {
				t.Fatalf("audits survived cleanup: %+v %v", audits, err)
			}
			if _, err := tc.store.GetFinding("find-group-1"); !errors.Is(err, verify.ErrNotFound) {
				t.Fatalf("finding survived cleanup: %v", err)
			}
		})
	}
}
