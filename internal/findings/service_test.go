package findings_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

type findingsFixture struct {
	store *storage.Memory
	svc   *findings.Service
}

func TestTaskFindingLimitDeclaresTruncationForReportAggregation(t *testing.T) {
	f := newFindingsFixture(t)
	for i := range 10001 {
		if err := f.store.UpsertFinding(verify.Finding{ID: fmt.Sprintf("find-limit-%05d", i), HypothesisID: fmt.Sprintf("hyp-limit-%05d", i), AuditID: "task-limit", SnapshotID: "snap-a", Title: "Recorded candidate", Status: verify.FindingCandidate}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := f.svc.List(context.Background(), findings.ListQuery{ProjectID: "project-a", TaskID: "task-limit", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated {
		t.Fatal("task collection silently hid findings beyond its aggregation ceiling")
	}
}

func newFindingsFixture(t *testing.T) *findingsFixture {
	t.Helper()
	ctx := context.Background()
	store := storage.NewMemory()
	if err := store.PutProject(ctx, storage.Project{ID: "project-a", Name: "Project A"}); err != nil {
		t.Fatal(err)
	}
	for _, snapshotID := range []string{"snap-a", "snap-b"} {
		if err := store.PutSnapshot(ctx, "project-a", &repository.Snapshot{
			SchemaVersion: repository.SchemaVersion,
			SnapshotID:    snapshotID,
			Identity:      repository.Identity{Kind: "dir", Name: "/srv/fixture"},
			VCS:           "none",
			Commit:        "content:" + snapshotID,
			CreatedAt:     "2024-06-01T08:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
	}
	return &findingsFixture{store: store, svc: findings.NewService(store)}
}

func (f *findingsFixture) scope(snapshot string) artifact.Scope {
	return artifact.Scope{ProjectID: "project-a", SourceID: "source-a", SnapshotID: snapshot}
}

func (f *findingsFixture) input(candidateID, ruleID, file, task string) findings.RecordInput {
	return findings.RecordInput{
		Scope: f.scope("snap-a"), TaskID: task,
		Producer: artifact.Producer{
			PluginID: "codexploit.static-patterns", PluginVersion: "1.0.0",
			InvocationID: "inv-1", TaskID: task, ConfigDigest: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		CandidateID: candidateID, RuleID: ruleID, RuleVersion: "1",
		Title: "[" + ruleID + "] candidate", SeverityHint: "high",
		File: file, Line: 6, EndLine: 6,
		EvidenceRefs: []string{"artifact-native"}, Limitations: []string{"Alert location only"},
	}
}

func TestRecordGroupsEquivalentObservationsAndReplaysWithoutDuplicates(t *testing.T) {
	f := newFindingsFixture(t)
	ctx := context.Background()
	first, inserted, err := f.svc.Record(ctx, f.input("alert-1", "CP001", "main.go", "task-1"))
	if err != nil || !inserted || first.FindingID == "" || first.FingerprintVersion != findings.FingerprintVersion {
		t.Fatalf("first record = %+v %v %v", first, inserted, err)
	}
	replay, inserted, err := f.svc.Record(ctx, f.input("alert-1", "CP001", "main.go", "task-1"))
	if err != nil || inserted || replay.ID != first.ID || replay.FindingID != first.FindingID {
		t.Fatalf("replay = %+v %v %v", replay, inserted, err)
	}
	second := f.input("alert-2", "CP001", "main.go", "task-2")
	second.Producer.InvocationID = "inv-2"
	second.Producer.TaskID = "task-2"
	other, inserted, err := f.svc.Record(ctx, second)
	if err != nil || !inserted || other.FindingID != first.FindingID {
		t.Fatalf("second source = %+v %v %v", other, inserted, err)
	}
	group, err := f.svc.Get(ctx, first.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Observations) != 2 || group.Finding.Status != verify.FindingCandidate || group.Finding.Version != 1 {
		t.Fatalf("group = %+v", group)
	}
	if group.FingerprintVersion != findings.FingerprintVersion || len(group.Fingerprint) != 32 {
		t.Fatalf("group fingerprint = %+v", group)
	}
	result, err := f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a"})
	if err != nil || result.Total != 1 || len(result.Groups) != 1 || len(result.Groups[0].Observations) != 2 {
		t.Fatalf("list = %+v %v", result, err)
	}
	if result.Counts.Candidate["ungraded"] != 1 || result.Counts.Confirmed["high"] != 0 {
		t.Fatalf("counts = %+v", result.Counts)
	}
}

func TestRecordCandidatesSkipsRulelessCandidatesAndNeverMergesTitles(t *testing.T) {
	f := newFindingsFixture(t)
	ctx := context.Background()
	producer := f.input("", "CP001", "main.go", "task-1").Producer
	candidates := []plugin.Candidate{
		{ID: "cand-1", Status: "candidate", Title: "same title", RuleID: "CP001", RuleVersion: "1", SeverityHint: "high", File: "main.go", Line: 6, EvidenceRefs: []string{"ev-1"}},
		{ID: "cand-2", Status: "candidate", Title: "same title", RuleID: "CP999", RuleVersion: "1", SeverityHint: "high", File: "main.go", Line: 6, EvidenceRefs: []string{"ev-2"}},
		{ID: "cand-3", Status: "candidate", Title: "same title", File: "main.go", Line: 6},
	}
	count, err := f.svc.RecordCandidates(ctx, f.scope("snap-a"), "task-1", producer, candidates)
	if err != nil || count != 2 {
		t.Fatalf("RecordCandidates = %d %v", count, err)
	}
	otherScope := f.scope("snap-b")
	if _, err := f.svc.RecordCandidates(ctx, otherScope, "task-1", producer, candidates[:1]); err != nil {
		t.Fatal(err)
	}
	result, err := f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a"})
	if err != nil || result.Total != 3 {
		t.Fatalf("groups = %+v %v", result, err)
	}
	for _, group := range result.Groups {
		if group.Finding.Status != verify.FindingCandidate || group.Finding.Severity != "" {
			t.Fatalf("a plugin observation became a graded/confirmed finding: %+v", group.Finding)
		}
	}
}

func TestUndeclaredCrossToolEquivalenceIsNotMerged(t *testing.T) {
	f := newFindingsFixture(t)
	ctx := context.Background()
	first, _, err := f.svc.Record(ctx, f.input("alert-1", "CP001", "main.go", "task-1"))
	if err != nil {
		t.Fatal(err)
	}
	other := f.input("alert-other", "CP001", "main.go", "task-1")
	other.Producer.PluginID = "other.scanner"
	other.Producer.InvocationID = "inv-other"
	second, _, err := f.svc.Record(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if first.FindingID == second.FindingID {
		t.Fatalf("undeclared cross-tool rules merged: %+v %+v", first, second)
	}
}

func TestAssessSeverityRequiresReasonAndPreservesTheVerdict(t *testing.T) {
	f := newFindingsFixture(t)
	ctx := context.Background()
	observation, _, err := f.svc.Record(ctx, f.input("alert-1", "CP001", "main.go", "task-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AssessSeverity(ctx, observation.FindingID, "high", "", "tester", 1); !errors.Is(err, findings.ErrInvalid) {
		t.Fatalf("missing reason = %v, want ErrInvalid", err)
	}
	group, err := f.svc.AssessSeverity(ctx, observation.FindingID, "high", "reachable from the public handler", "tester", 1)
	if err != nil {
		t.Fatalf("AssessSeverity: %v", err)
	}
	if group.Finding.Severity != "high" || group.Finding.Version != 2 || group.Finding.Status != verify.FindingCandidate {
		t.Fatalf("finding = %+v", group.Finding)
	}
	if len(group.SeverityAudit) != 1 || group.SeverityAudit[0].Reason == "" || group.SeverityAudit[0].Version != 2 || group.SeverityAudit[0].Actor != "tester" {
		t.Fatalf("audit = %+v", group.SeverityAudit)
	}
	if _, err := f.svc.AssessSeverity(ctx, observation.FindingID, "low", "stale write", "tester", 1); !errors.Is(err, verify.ErrConflict) {
		t.Fatalf("stale grade = %v, want ErrConflict", err)
	}
	if _, err := f.svc.AssessSeverity(ctx, observation.FindingID, "critical", "bad grade", "tester", 2); !errors.Is(err, findings.ErrInvalid) {
		t.Fatalf("invalid grade = %v, want ErrInvalid", err)
	}
	result, err := f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a"})
	if err != nil || result.Counts.Candidate["high"] != 1 || result.Counts.Confirmed["high"] != 0 {
		t.Fatalf("counts = %+v %v", result.Counts, err)
	}
}

func TestListSeparatesCandidateAndConfirmedStatistics(t *testing.T) {
	f := newFindingsFixture(t)
	ctx := context.Background()
	first, _, err := f.svc.Record(ctx, f.input("alert-1", "CP001", "main.go", "task-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Record(ctx, f.input("alert-2", "CP002", "store.go", "task-1")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpsertFinding(verify.Finding{
		ID: "find-confirmed-1", HypothesisID: "hyp-confirmed-1", PathID: "path-1",
		AuditID: "task-1", SnapshotID: "snap-a", Title: "Confirmed SQL injection",
		Severity: "high", Status: verify.FindingConfirmed, Version: 1,
		Supporting: []string{"ev-1"}, CreatedAt: "2024-06-01T08:10:00Z", UpdatedAt: "2024-06-01T08:10:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	result, err := f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a"})
	if err != nil || result.Total != 3 || result.Counts.Candidate["ungraded"] != 2 || result.Counts.Confirmed["high"] != 1 {
		t.Fatalf("list = %+v %v", result, err)
	}
	candidates, err := f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a", Status: verify.FindingCandidate})
	if err != nil || candidates.Total != 2 {
		t.Fatalf("candidates = %+v %v", candidates, err)
	}
	confirmed, err := f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a", Status: verify.FindingConfirmed})
	if err != nil || confirmed.Total != 1 || confirmed.Groups[0].Finding.Severity != "high" {
		t.Fatalf("confirmed = %+v %v", confirmed, err)
	}
	page, err := f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a", Limit: 2})
	if err != nil || len(page.Groups) != 2 || page.Total != 3 {
		t.Fatalf("page = %+v %v", page, err)
	}
	next, err := f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a", Limit: 2, Offset: 2})
	if err != nil || len(next.Groups) != 1 || next.Total != 3 {
		t.Fatalf("next page = %+v %v", next, err)
	}
	// Grading a candidate stays candidate and does not change the confirmed count.
	graded, err := f.svc.AssessSeverity(ctx, first.FindingID, "medium", "public route", "tester", 1)
	if err != nil || graded.Finding.Status != verify.FindingCandidate {
		t.Fatalf("graded candidate = %+v %v", graded, err)
	}
	result, err = f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a"})
	if err != nil || result.Counts.Candidate["medium"] != 1 || result.Counts.Candidate["ungraded"] != 1 || result.Counts.Confirmed["high"] != 1 {
		t.Fatalf("counts after grading = %+v %v", result.Counts, err)
	}
}

func TestFallbackGroupsKeepEveryVerificationFindingAsASource(t *testing.T) {
	f := newFindingsFixture(t)
	ctx := context.Background()
	for _, finding := range []verify.Finding{
		{ID: "find-shared-1", HypothesisID: "hyp-shared-1", PathID: "path-shared", AuditID: "task-1", SnapshotID: "snap-a", Title: "first claim", Severity: "high", Status: verify.FindingConfirmed, Version: 1, CreatedAt: "2026-10-18T00:00:00Z", UpdatedAt: "2026-10-18T00:00:00Z"},
		{ID: "find-shared-2", HypothesisID: "hyp-shared-2", PathID: "path-shared", AuditID: "task-2", SnapshotID: "snap-a", Title: "second claim", Severity: "low", Status: verify.FindingConfirmed, Version: 1, CreatedAt: "2026-10-18T00:00:01Z", UpdatedAt: "2026-10-18T00:00:01Z"},
	} {
		if err := f.store.UpsertFinding(finding); err != nil {
			t.Fatal(err)
		}
	}
	result, err := f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a"})
	if err != nil || result.Total != 1 || len(result.Groups) != 1 || len(result.Groups[0].Members) != 2 {
		t.Fatalf("fallback group = %+v %v", result, err)
	}
	if result.Groups[0].Finding.Severity != "high" {
		t.Fatalf("canonical finding did not take the highest grade: %+v", result.Groups[0].Finding)
	}
}

func TestTaskFilterMatchesAnySourceObservation(t *testing.T) {
	f := newFindingsFixture(t)
	ctx := context.Background()
	first, _, err := f.svc.Record(ctx, f.input("alert-1", "CP001", "main.go", "task-1"))
	if err != nil {
		t.Fatal(err)
	}
	second := f.input("alert-2", "CP001", "main.go", "task-2")
	second.Producer.InvocationID = "inv-2"
	if _, _, err := f.svc.Record(ctx, second); err != nil {
		t.Fatal(err)
	}
	result, err := f.svc.List(ctx, findings.ListQuery{ProjectID: "project-a", TaskID: "task-2"})
	if err != nil || result.Total != 1 || len(result.Groups[0].Observations) != 2 || result.Groups[0].Finding.ID != first.FindingID {
		t.Fatalf("task filter = %+v %v", result, err)
	}
}

func TestStoredFingerprintVersionSurvivesAnUpgrade(t *testing.T) {
	f := newFindingsFixture(t)
	ctx := context.Background()
	observation := findings.Observation{
		ID: "obs-legacy", FindingID: "find-legacy",
		Scope: f.scope("snap-a"), TaskID: "task-1",
		Producer: artifact.Producer{PluginID: "codexploit.static-patterns", PluginVersion: "1.0.0", InvocationID: "inv-legacy", ConfigDigest: "0000000000000000000000000000000000000000000000000000000000000000"},
		RuleID:   "CP001", RuleVersion: "1", RuleFamily: "codexploit.command-execution",
		Title: "legacy", Status: verify.FindingCandidate, File: "main.go", Line: 6,
		Fingerprint: "0123456789abcdef0123456789abcdef", FingerprintVersion: "0",
		CreatedAt: "2024-06-01T08:00:00Z",
	}
	if err := f.store.UpsertFinding(verify.Finding{
		ID: "find-legacy", HypothesisID: "fp-0-0123456789abcdef0123456789abcdef", AuditID: "task-1",
		SnapshotID: "snap-a", Title: "legacy", Status: verify.FindingCandidate,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), UpdatedAt: time.Now().UTC().Format(time.RFC3339), Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpsertFindingObservation(observation); err != nil {
		t.Fatal(err)
	}
	group, err := f.svc.Get(ctx, "find-legacy")
	if err != nil {
		t.Fatal(err)
	}
	if group.FingerprintVersion != "0" || group.Fingerprint != observation.Fingerprint {
		t.Fatalf("stored fingerprint was recomputed: %+v", group)
	}
}
