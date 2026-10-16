package storage

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// The two backends must satisfy the verification contract, and FullStore must
// carry it: the API, the planner and the verifier are all handed one FullStore, so
// a backend that lost a method would break the phase rather than one call.
var (
	_ VerificationStore = (*Memory)(nil)
	_ VerificationStore = (*SQL)(nil)
	_ FullStore         = (*Memory)(nil)
	_ FullStore         = (*SQL)(nil)
)

const (
	verificationSnapID       = "snap-0123456789abcdef0123456789abcdef"
	verificationOtherSnapID  = "snap-fedcba9876543210fedcba9876543210"
	verificationAbsentSnapID = "snap-00000000000000000000000000000000"
	verificationHypothesisID = "hyp-00000000000000000000000000000001"
	verificationSecondHypID  = "hyp-00000000000000000000000000000002"
	verificationThirdHypID   = "hyp-00000000000000000000000000000003"
	verificationFourthHypID  = "hyp-00000000000000000000000000000004"
	verificationPathID       = "path-00000000000000000000000000000001"
	verificationOtherPathID  = "path-00000000000000000000000000000002"
	verificationAuditID      = "audit-00000000000000000000000000000001"
	verificationOtherAuditID = "audit-00000000000000000000000000000002"
	verificationRunID        = "vrun-00000000000000000000000000000001"
	verificationOtherRunID   = "vrun-00000000000000000000000000000002"
	verificationThirdRunID   = "vrun-00000000000000000000000000000003"
	verificationFourthRunID  = "vrun-00000000000000000000000000000004"
	verificationGhostRunID   = "vrun-000000000000000000000000000000ff"
)

// verificationRunFixture builds a run that carries every nested document the
// schema stores, so a codec that drops a column fails the comparison. The
// environment is deliberately non-default and the plan holds a static step (a
// query map) and a dynamic one (argv plus the approval it needs), so both step
// shapes round trip.
func verificationRunFixture(runID, hypothesisID, pathID, auditID, snapshotID string) verify.Run {
	environment := verify.Environment{
		Profile: "sandbox-restricted", SourceReadOnly: true, Network: verify.NetworkRestricted,
		AllowedHosts: []string{"target-service", "proxy-service"},
		CPUMillis:    2000, MemoryMB: 1024, DiskMB: 512, MaxProcesses: 128,
		MaxWrites: 16, TimeoutSeconds: 600, MountHostSocket: false,
	}
	plan := verify.Plan{
		SchemaVersion: verify.SchemaVersion,
		HypothesisID:  hypothesisID, FindingID: verify.FindingID(hypothesisID),
		PathID: pathID, AuditID: auditID, SnapshotID: snapshotID,
		SecurityGoal: "prevent SQL injection through the search route",
		Claim:        "the search parameter reaches the SQL sink",
		Steps: []verify.Step{
			{
				Kind:           verify.StepStaticCheck,
				StaticQuery:    map[string]string{"from": "http_request", "to": "sql_execution"},
				Expectation:    "the graph reports a dataflow edge from the request to the sink",
				Contradiction:  "the edge is a false positive reported by the taint engine",
				TimeoutSeconds: 30,
			},
			{
				Kind: verify.StepDynamicProof, Command: []string{"probe", "--target", "target-service"},
				Expectation: "the probe returns the marker", Contradiction: "the endpoint rejects the payload",
				TimeoutSeconds: 60, RequiresApproval: true,
			},
		},
		Environment: environment,
		Scope: verify.Scope{
			Repository: "codexploit/fixture", SnapshotID: snapshotID,
			AllowedTargets: []string{"target-service"}, AllowNetwork: true,
			RequiresHumanApproval: true, AuthorizedBy: "operator-1", AuthorizedAt: "2024-06-01T08:00:00Z",
		},
		Limitations: []string{"dynamic dispatch is not resolved", "the probe covers one route only"},
		GeneratedAt: "2024-06-01T09:00:00Z",
	}
	plan.PlanHash = verify.PlanHashOf(plan)
	exit := 0
	return verify.Run{
		ID: runID, HypothesisID: hypothesisID, FindingID: plan.FindingID, PathID: pathID,
		AuditID: auditID, SnapshotID: snapshotID, PlanHash: plan.PlanHash, Plan: plan,
		Environment: environment, EnvironmentDigest: environment.Digest(),
		Status: verify.VerifySucceeded, Outcome: verify.OutcomeConfirmed,
		Executor: "cli", ExecutorVersion: "1.2.3", NetworkAllowed: true, Approved: true,
		ApprovedBy: "operator-1", ApprovedAt: "2024-06-01T09:00:01Z", Owner: "worker-1",
		ExitCode: &exit, StopReason: verify.VerifyStopCompleted,
		Reproduction: "probe --target target-service",
		StartedAt:    "2024-06-01T09:00:01Z", FinishedAt: "2024-06-01T09:00:32Z", ElapsedMS: 31000,
		CreatedAt: "2024-06-01T09:00:00Z", UpdatedAt: "2024-06-01T09:00:32Z", Version: 1,
	}
}

// verificationEvidenceFixture builds evidence through the layer's only
// constructor, so the content hash and the derived id are the ones a real
// executor would produce.
func verificationEvidenceFixture(t *testing.T, kind verify.EvidenceKind, tool, content string, run verify.Run, createdAt string) verify.Evidence {
	t.Helper()
	object, err := verify.NewEvidence(kind, content, verify.EvidenceOptions{
		Tool: tool, ToolVersion: "1.0.0", SnapshotID: run.SnapshotID,
		HypothesisID: run.HypothesisID, FindingID: run.FindingID, PathID: run.PathID,
		VerificationRunID: run.ID, File: "internal/api/search.go", Line: 17, Now: createdAt,
	})
	if err != nil {
		t.Fatalf("NewEvidence(%s): %v", kind, err)
	}
	return object
}

// verificationFindingFixture builds a verdict with one populated list, one nil
// list and one empty list, so the codec is pinned on all three shapes.
func verificationFindingFixture(run verify.Run, title string, status verify.FindingStatus) verify.Finding {
	environment := run.EnvironmentDigest
	if environment == "" {
		environment = run.Environment.Digest()
	}
	return verify.Finding{
		ID: verify.FindingID(run.HypothesisID), HypothesisID: run.HypothesisID, PathID: run.PathID,
		AuditID: run.AuditID, SnapshotID: run.SnapshotID, Title: title, Severity: "high",
		Status: status, Confidence: "high",
		Supporting: []string{"ev-supporting-1"}, Contradicting: nil, Inconclusive: []string{},
		VerificationRunIDs: []string{run.ID}, Environments: []string{environment},
		ReproduceSteps: "probe --target target-service",
		Limitations:    []string{"dynamic dispatch is not resolved"},
		CreatedAt:      "2024-06-01T09:01:00Z", UpdatedAt: "2024-06-01T09:01:00Z", Version: 1,
	}
}

func seedVerificationRun(t *testing.T, store FullStore, run verify.Run) verify.Run {
	t.Helper()
	if err := store.CreateVerificationRun(run); err != nil {
		t.Fatalf("CreateVerificationRun(%s): %v", run.ID, err)
	}
	return run
}

func mustGetVerificationRun(t *testing.T, store FullStore, runID string) verify.Run {
	t.Helper()
	run, err := store.GetVerificationRun(runID)
	if err != nil {
		t.Fatalf("GetVerificationRun(%s): %v", runID, err)
	}
	return *run
}

func mustGetEvidence(t *testing.T, store FullStore, evidenceID string) verify.Evidence {
	t.Helper()
	object, err := store.GetEvidence(evidenceID)
	if err != nil {
		t.Fatalf("GetEvidence(%s): %v", evidenceID, err)
	}
	return *object
}

func mustGetFinding(t *testing.T, store FullStore, findingID string) verify.Finding {
	t.Helper()
	finding, err := store.GetFinding(findingID)
	if err != nil {
		t.Fatalf("GetFinding(%s): %v", findingID, err)
	}
	return *finding
}

func mustListVerificationRuns(t *testing.T, store FullStore, q verify.RunQuery) ([]verify.Run, int) {
	t.Helper()
	runs, total, err := store.ListVerificationRuns(q)
	if err != nil {
		t.Fatalf("ListVerificationRuns(%+v): %v", q, err)
	}
	return runs, total
}

func mustListEvidence(t *testing.T, store FullStore, q verify.EvidenceQuery) ([]verify.Evidence, int) {
	t.Helper()
	evidence, total, err := store.ListEvidence(q)
	if err != nil {
		t.Fatalf("ListEvidence(%+v): %v", q, err)
	}
	return evidence, total
}

func mustListFindings(t *testing.T, store FullStore, q verify.FindingQuery) ([]verify.Finding, int) {
	t.Helper()
	findings, total, err := store.ListFindings(q)
	if err != nil {
		t.Fatalf("ListFindings(%+v): %v", q, err)
	}
	return findings, total
}

func verificationRunIDs(runs []verify.Run) []string {
	out := make([]string, 0, len(runs))
	for _, run := range runs {
		out = append(out, run.ID)
	}
	return out
}

func verificationEvidenceIDs(evidence []verify.Evidence) []string {
	out := make([]string, 0, len(evidence))
	for _, object := range evidence {
		out = append(out, object.ID)
	}
	return out
}

func verificationFindingIDs(findings []verify.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.ID)
	}
	return out
}

func TestVerificationRunRoundTrip(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			run := verificationRunFixture(verificationRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID)
			// Evidence that names the run. `verification_runs` has no evidence_ids
			// column, so the run's evidence list is derived from the evidence table;
			// this is what pins that derivation too.
			evidence := []verify.Evidence{
				verificationEvidenceFixture(t, verify.EvidenceTest, "probe", "the probe returned the expected marker", run, "2024-06-01T09:00:10Z"),
				verificationEvidenceFixture(t, verify.EvidenceRuntimeLog, "probe", "the probe exited with status zero", run, "2024-06-01T09:00:11Z"),
			}
			if err := store.AppendEvidence(evidence); err != nil {
				t.Fatalf("AppendEvidence: %v", err)
			}
			run.EvidenceIDs = []string{evidence[0].ID, evidence[1].ID}
			sort.Strings(run.EvidenceIDs)
			if err := store.CreateVerificationRun(run); err != nil {
				t.Fatalf("CreateVerificationRun: %v", err)
			}

			got, err := store.GetVerificationRun(run.ID)
			if err != nil {
				t.Fatalf("GetVerificationRun: %v", err)
			}
			// The nested documents are the point of the test: a codec that drops a
			// step, a query map or an allowed host must fail here.
			if !reflect.DeepEqual(got.Plan, run.Plan) {
				t.Errorf("the plan did not round trip:\n got  %+v\n want %+v", got.Plan, run.Plan)
			}
			if !reflect.DeepEqual(got.Environment, run.Environment) {
				t.Errorf("the environment did not round trip:\n got  %+v\n want %+v", got.Environment, run.Environment)
			}
			if !reflect.DeepEqual(got.EvidenceIDs, run.EvidenceIDs) {
				t.Errorf("the derived evidence list = %v, want %v", got.EvidenceIDs, run.EvidenceIDs)
			}
			// Everything else must round trip field for field.
			view := *got
			view.Plan, view.Environment, view.EvidenceIDs = run.Plan, run.Environment, run.EvidenceIDs
			if !reflect.DeepEqual(view, run) {
				t.Errorf("run round trip mismatch:\n got  %+v\n want %+v", view, run)
			}

			// A caller may mutate what it received: the store must not share state
			// with it.
			got.Plan.Steps[0].Expectation = "mutated"
			got.Plan.Steps[0].StaticQuery["from"] = "mutated"
			got.Environment.AllowedHosts[0] = "mutated"
			got.EvidenceIDs[0] = "mutated"
			again := mustGetVerificationRun(t, store, run.ID)
			if !reflect.DeepEqual(again.Plan, run.Plan) || !reflect.DeepEqual(again.Environment, run.Environment) ||
				!reflect.DeepEqual(again.EvidenceIDs, run.EvidenceIDs) {
				t.Errorf("mutating a returned run changed the stored document: %+v", again)
			}

			if _, err := store.GetVerificationRun(verificationGhostRunID); !errors.Is(err, verify.ErrNotFound) {
				t.Errorf("GetVerificationRun(missing) = %v, want verify.ErrNotFound", err)
			}
			if err := store.CreateVerificationRun(verify.Run{Plan: run.Plan}); !errors.Is(err, verify.ErrInvalidArgument) {
				t.Errorf("CreateVerificationRun without an id = %v, want verify.ErrInvalidArgument", err)
			}
		})
	}
}

// TestVerificationRunEvidenceIDsAreDerived documents the one thing migration 0008
// cannot store. The table has no evidence_ids column, so a run's evidence list is
// the evidence that names it: a caller cannot make a run claim evidence that was
// never stored, and the field follows the evidence table.
func TestVerificationRunEvidenceIDsAreDerived(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			run := verificationRunFixture(verificationRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID)
			run.EvidenceIDs = []string{"ev-0000000000000000"}
			seedVerificationRun(t, store, run)
			got := mustGetVerificationRun(t, store, run.ID)
			if len(got.EvidenceIDs) != 0 {
				t.Errorf("a run claimed evidence that was never stored: %v", got.EvidenceIDs)
			}

			first := verificationEvidenceFixture(t, verify.EvidenceTest, "probe", "the probe returned the expected marker", run, "2024-06-01T09:00:10Z")
			second := verificationEvidenceFixture(t, verify.EvidenceRuntimeLog, "probe", "the probe exited with status zero", run, "2024-06-01T09:00:11Z")
			if err := store.AppendEvidence([]verify.Evidence{first, second}); err != nil {
				t.Fatalf("AppendEvidence: %v", err)
			}
			want := []string{first.ID, second.ID}
			sort.Strings(want)
			got = mustGetVerificationRun(t, store, run.ID)
			if !reflect.DeepEqual(got.EvidenceIDs, want) {
				t.Errorf("the derived evidence list = %v, want %v", got.EvidenceIDs, want)
			}
			// The listing carries the same derived list.
			runs, total := mustListVerificationRuns(t, store, verify.RunQuery{SnapshotID: verificationSnapID})
			if total != 1 || len(runs) != 1 || !reflect.DeepEqual(runs[0].EvidenceIDs, want) {
				t.Errorf("the listed run carries %v (total %d), want %v", runs, total, want)
			}
		})
	}
}

func TestVerificationRunUniquenessAndVersionChecks(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			run := seedVerificationRun(t, store, verificationRunFixture(verificationRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID))

			// The run id is a primary key.
			if err := store.CreateVerificationRun(run); !errors.Is(err, verify.ErrConflict) {
				t.Errorf("CreateVerificationRun(same id) = %v, want verify.ErrConflict", err)
			}
			// One plan for one hypothesis is one verification, whatever id it is
			// offered under.
			twin := verificationRunFixture(verificationOtherRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID)
			if err := store.CreateVerificationRun(twin); !errors.Is(err, verify.ErrConflict) {
				t.Errorf("CreateVerificationRun(same hypothesis and plan) = %v, want verify.ErrConflict", err)
			}

			// A wrong expected version is refused and writes nothing...
			stale := run
			stale.Status = verify.VerifyRunning
			if err := store.UpdateVerificationRun(stale, 7); !errors.Is(err, verify.ErrConflict) {
				t.Errorf("UpdateVerificationRun(expected 7) = %v, want verify.ErrConflict", err)
			}
			if got := mustGetVerificationRun(t, store, run.ID); got.Status != verify.VerifySucceeded || got.Version != 1 {
				t.Errorf("a refused update changed the run: %+v", got)
			}
			// ...the matching version is accepted and advances the counter...
			if err := store.UpdateVerificationRun(stale, 1); err != nil {
				t.Fatalf("UpdateVerificationRun(expected 1): %v", err)
			}
			updated := mustGetVerificationRun(t, store, run.ID)
			if updated.Status != verify.VerifyRunning || updated.Version != 2 {
				t.Errorf("after the update: status %s version %d, want RUNNING 2", updated.Status, updated.Version)
			}
			// ...a second write carrying the old version now conflicts...
			if err := store.UpdateVerificationRun(stale, 1); !errors.Is(err, verify.ErrConflict) {
				t.Errorf("UpdateVerificationRun with a stale version = %v, want verify.ErrConflict", err)
			}
			// ...and expectedVersion 0 skips the check.
			terminal := updated
			terminal.Status = verify.VerifySucceeded
			terminal.Outcome = verify.OutcomeConfirmed
			if err := store.UpdateVerificationRun(terminal, 0); err != nil {
				t.Fatalf("UpdateVerificationRun(expected 0): %v", err)
			}
			if got := mustGetVerificationRun(t, store, run.ID); got.Version != 3 || got.Outcome != verify.OutcomeConfirmed {
				t.Errorf("after the unchecked update: version %d outcome %s, want 3 CONFIRMED", got.Version, got.Outcome)
			}

			// A run cannot be moved onto another run's (hypothesis, plan_hash).
			other := seedVerificationRun(t, store, verificationRunFixture(verificationOtherRunID, verificationSecondHypID, verificationOtherPathID, verificationOtherAuditID, verificationSnapID))
			clash := other
			clash.HypothesisID = run.HypothesisID
			clash.PlanHash = run.PlanHash
			clash.Plan = run.Plan
			if err := store.UpdateVerificationRun(clash, 0); !errors.Is(err, verify.ErrConflict) {
				t.Errorf("UpdateVerificationRun onto another plan key = %v, want verify.ErrConflict", err)
			}
			if got := mustGetVerificationRun(t, store, other.ID); got.HypothesisID != verificationSecondHypID || got.PlanHash != other.PlanHash {
				t.Errorf("a refused update changed the other run: %+v", got)
			}

			ghost := verificationRunFixture(verificationGhostRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID)
			if err := store.UpdateVerificationRun(ghost, 0); !errors.Is(err, verify.ErrNotFound) {
				t.Errorf("UpdateVerificationRun(missing) = %v, want verify.ErrNotFound", err)
			}
		})
	}
}

func TestVerificationRunListingFilters(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			first := verificationRunFixture(verificationRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID)
			first.Status, first.Outcome = verify.VerifySucceeded, verify.OutcomeConfirmed
			first.CreatedAt = "2024-06-01T09:00:00Z"
			second := verificationRunFixture(verificationOtherRunID, verificationSecondHypID, verificationOtherPathID, verificationOtherAuditID, verificationSnapID)
			second.Status, second.Outcome = verify.VerifyFailed, verify.OutcomeInconclusive
			second.CreatedAt = "2024-06-01T09:10:00Z"
			third := verificationRunFixture(verificationThirdRunID, verificationHypothesisID, verificationOtherPathID, verificationAuditID, verificationOtherSnapID)
			third.Status, third.Outcome = verify.VerifyBlocked, verify.OutcomeBlocked
			third.CreatedAt = "2024-06-01T09:20:00Z"
			for _, run := range []verify.Run{first, second, third} {
				seedVerificationRun(t, store, run)
			}

			cases := []struct {
				name  string
				q     verify.RunQuery
				want  []string
				total int
			}{
				{"all", verify.RunQuery{}, []string{first.ID, second.ID, third.ID}, 3},
				{"snapshot", verify.RunQuery{SnapshotID: verificationSnapID}, []string{first.ID, second.ID}, 2},
				{"hypothesis", verify.RunQuery{HypothesisID: verificationHypothesisID}, []string{first.ID, third.ID}, 2},
				{"audit", verify.RunQuery{AuditID: verificationAuditID}, []string{first.ID, third.ID}, 2},
				{"path", verify.RunQuery{PathID: verificationPathID}, []string{first.ID}, 1},
				{"finding", verify.RunQuery{FindingID: verify.FindingID(verificationSecondHypID)}, []string{second.ID}, 1},
				{"plan hash", verify.RunQuery{PlanHash: third.PlanHash}, []string{third.ID}, 1},
				{"statuses", verify.RunQuery{Status: []verify.VerificationStatus{verify.VerifySucceeded, verify.VerifyBlocked}}, []string{first.ID, third.ID}, 2},
				{"outcome", verify.RunQuery{Outcome: []verify.Outcome{verify.OutcomeInconclusive}}, []string{second.ID}, 1},
				{"outcomes", verify.RunQuery{Outcome: []verify.Outcome{verify.OutcomeConfirmed, verify.OutcomeBlocked}}, []string{first.ID, third.ID}, 2},
				{"no match", verify.RunQuery{SnapshotID: verificationSnapID, Status: []verify.VerificationStatus{verify.VerifyTimedOut}}, []string{}, 0},
				{"limit", verify.RunQuery{Limit: 1}, []string{first.ID}, 3},
				{"offset", verify.RunQuery{Offset: 2}, []string{third.ID}, 3},
				{"limit and offset", verify.RunQuery{Limit: 1, Offset: 1}, []string{second.ID}, 3},
				{"offset past the end", verify.RunQuery{Offset: 9}, []string{}, 3},
			}
			for _, testCase := range cases {
				runs, total := mustListVerificationRuns(t, store, testCase.q)
				if total != testCase.total {
					t.Errorf("%s: total = %d, want %d", testCase.name, total, testCase.total)
				}
				if got := verificationRunIDs(runs); !reflect.DeepEqual(got, testCase.want) {
					t.Errorf("%s: ids = %v, want %v", testCase.name, got, testCase.want)
				}
			}
		})
	}
}

// TestAppendEvidenceIsAppendOnly pins the rule that makes evidence evidence: the
// identity of an object is its id, its content hash and its content.
// Re-appending that identity — even with a fresh timestamp — is a no-op that leaves
// the stored object (original CreatedAt included) authoritative, while a rewrite of
// the content is refused and leaves the stored bytes unchanged. There is no update
// method to reach for instead: a correction is a new object whose supersedes field
// points at the old one.
func TestAppendEvidenceIsAppendOnly(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			run := seedVerificationRun(t, store, verificationRunFixture(verificationRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID))
			object := verificationEvidenceFixture(t, verify.EvidenceTest, "probe", "the probe returned the expected marker", run, "2024-06-01T09:00:10Z")
			if err := store.AppendEvidence([]verify.Evidence{object}); err != nil {
				t.Fatalf("AppendEvidence: %v", err)
			}
			// An exact replay — twice in one batch as well — is a no-op, and the stored
			// document is exactly what was written.
			if err := store.AppendEvidence([]verify.Evidence{object, object}); err != nil {
				t.Fatalf("AppendEvidence(replay): %v", err)
			}
			if got := mustGetEvidence(t, store, object.ID); !reflect.DeepEqual(got, object) {
				t.Errorf("evidence round trip mismatch:\n got  %+v\n want %+v", got, object)
			}

			// Timestamps are provenance, not identity: a verifier that re-derives the
			// same object with a fresh clock is re-appending it, and the stored object
			// keeps its original CreatedAt.
			replayed := object
			replayed.CreatedAt = "2025-01-01T00:00:00Z"
			if err := store.AppendEvidence([]verify.Evidence{replayed}); err != nil {
				t.Fatalf("AppendEvidence(re-derived replay) = %v, want nil", err)
			}
			if err := store.AppendEvidence([]verify.Evidence{object, replayed}); err != nil {
				t.Fatalf("AppendEvidence(re-derived batch) = %v, want nil", err)
			}
			stored := mustGetEvidence(t, store, object.ID)
			if stored.CreatedAt != object.CreatedAt {
				t.Errorf("a replay rewrote the stored timestamp: %s, want %s", stored.CreatedAt, object.CreatedAt)
			}
			if !reflect.DeepEqual(stored, object) {
				t.Errorf("a replay changed the stored object:\n got  %+v\n want %+v", stored, object)
			}

			// The same id with content that no longer matches the stored content hash
			// is a rewrite, not a replay...
			staleHash := object
			staleHash.Content = "a different observation under the same hash"
			if err := store.AppendEvidence([]verify.Evidence{staleHash}); !errors.Is(err, verify.ErrConflict) {
				t.Fatalf("AppendEvidence(content that contradicts its hash) = %v, want verify.ErrConflict", err)
			}
			// ...and so is a rewrite of the content together with its hash.
			rewritten := object
			rewritten.Content = "an observation that replaces the stored one"
			rewritten.ContentHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			if err := store.AppendEvidence([]verify.Evidence{rewritten}); !errors.Is(err, verify.ErrConflict) {
				t.Fatalf("AppendEvidence(rewrite) = %v, want verify.ErrConflict", err)
			}
			if got := mustGetEvidence(t, store, object.ID); !reflect.DeepEqual(got, object) {
				t.Errorf("a refused append rewrote the stored object:\n got  %+v\n want %+v", got, object)
			}

			// A correction is a new object that points at the old one; both stay
			// readable.
			correction := verificationEvidenceFixture(t, verify.EvidenceTest, "probe", "the corrected observation of the same probe", run, "2024-06-01T09:00:20Z")
			correction.Supersedes = object.ID
			if err := store.AppendEvidence([]verify.Evidence{correction}); err != nil {
				t.Fatalf("AppendEvidence(correction): %v", err)
			}
			if got := mustGetEvidence(t, store, object.ID); !reflect.DeepEqual(got, object) {
				t.Errorf("the superseded object changed: %+v", got)
			}
			if got := mustGetEvidence(t, store, correction.ID); got.Supersedes != object.ID {
				t.Errorf("the correction does not point at what it corrects: %+v", got)
			}

			// A batch is all or nothing: an object that conflicts stores neither
			// itself nor the fresh object beside it.
			fresh := verificationEvidenceFixture(t, verify.EvidenceArtifact, "probe", "a fresh artifact produced by the same probe", run, "2024-06-01T09:00:30Z")
			if err := store.AppendEvidence([]verify.Evidence{fresh, rewritten}); !errors.Is(err, verify.ErrConflict) {
				t.Fatalf("AppendEvidence(partly conflicting batch) = %v, want verify.ErrConflict", err)
			}
			if _, err := store.GetEvidence(fresh.ID); !errors.Is(err, verify.ErrNotFound) {
				t.Errorf("a rejected batch stored part of itself: %v", err)
			}

			// An anonymous object cannot be stored, and a missing id is an argument
			// problem rather than a conflict.
			if err := store.AppendEvidence([]verify.Evidence{{Kind: verify.EvidenceTest}}); !errors.Is(err, verify.ErrInvalidArgument) {
				t.Errorf("AppendEvidence without an id = %v, want verify.ErrInvalidArgument", err)
			}
			if _, err := store.GetEvidence("ev-0000000000000000"); !errors.Is(err, verify.ErrNotFound) {
				t.Errorf("GetEvidence(missing) = %v, want verify.ErrNotFound", err)
			}
		})
	}
}

func TestEvidenceListingFilters(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			first := seedVerificationRun(t, store, verificationRunFixture(verificationRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID))
			second := seedVerificationRun(t, store, verificationRunFixture(verificationOtherRunID, verificationSecondHypID, verificationOtherPathID, verificationOtherAuditID, verificationSnapID))
			third := seedVerificationRun(t, store, verificationRunFixture(verificationThirdRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationOtherSnapID))

			firstObject := verificationEvidenceFixture(t, verify.EvidenceTest, "probe", "the probe returned marker one", first, "2024-06-01T09:00:10Z")
			secondObject := verificationEvidenceFixture(t, verify.EvidenceRuntimeLog, "probe", "the probe logged marker two", first, "2024-06-01T09:00:11Z")
			thirdObject := verificationEvidenceFixture(t, verify.EvidenceSource, "graph", "the search handler concatenates the parameter", second, "2024-06-01T09:00:12Z")
			fourthObject := verificationEvidenceFixture(t, verify.EvidenceArtifact, "probe", "the artifact captured marker four", third, "2024-06-01T09:00:13Z")
			if err := store.AppendEvidence([]verify.Evidence{firstObject, secondObject, thirdObject, fourthObject}); err != nil {
				t.Fatalf("AppendEvidence: %v", err)
			}
			findingID := verify.FindingID(verificationHypothesisID)

			cases := []struct {
				name  string
				q     verify.EvidenceQuery
				want  []string
				total int
			}{
				{"all", verify.EvidenceQuery{}, []string{firstObject.ID, secondObject.ID, thirdObject.ID, fourthObject.ID}, 4},
				{"snapshot", verify.EvidenceQuery{SnapshotID: verificationSnapID}, []string{firstObject.ID, secondObject.ID, thirdObject.ID}, 3},
				{"hypothesis", verify.EvidenceQuery{HypothesisID: verificationHypothesisID}, []string{firstObject.ID, secondObject.ID, fourthObject.ID}, 3},
				{"finding", verify.EvidenceQuery{FindingID: findingID}, []string{firstObject.ID, secondObject.ID, fourthObject.ID}, 3},
				{"path", verify.EvidenceQuery{PathID: verificationPathID}, []string{firstObject.ID, secondObject.ID, fourthObject.ID}, 3},
				{"verification run", verify.EvidenceQuery{VerificationRunID: first.ID}, []string{firstObject.ID, secondObject.ID}, 2},
				{"kinds", verify.EvidenceQuery{Kinds: []verify.EvidenceKind{verify.EvidenceTest, verify.EvidenceRuntimeLog}}, []string{firstObject.ID, secondObject.ID}, 2},
				{"one kind", verify.EvidenceQuery{Kinds: []verify.EvidenceKind{verify.EvidenceSource}}, []string{thirdObject.ID}, 1},
				{"snapshot and kind", verify.EvidenceQuery{SnapshotID: verificationSnapID, Kinds: []verify.EvidenceKind{verify.EvidenceTest}}, []string{firstObject.ID}, 1},
				{"no match", verify.EvidenceQuery{SnapshotID: verificationSnapID, PathID: verificationOtherPathID, Kinds: []verify.EvidenceKind{verify.EvidenceRule}}, []string{}, 0},
				{"limit", verify.EvidenceQuery{Limit: 1}, []string{firstObject.ID}, 4},
				{"offset", verify.EvidenceQuery{Offset: 2}, []string{thirdObject.ID, fourthObject.ID}, 4},
				{"offset past the end", verify.EvidenceQuery{Offset: 9}, []string{}, 4},
			}
			for _, testCase := range cases {
				evidence, total := mustListEvidence(t, store, testCase.q)
				if total != testCase.total {
					t.Errorf("%s: total = %d, want %d", testCase.name, total, testCase.total)
				}
				if got := verificationEvidenceIDs(evidence); !reflect.DeepEqual(got, testCase.want) {
					t.Errorf("%s: ids = %v, want %v", testCase.name, got, testCase.want)
				}
			}
		})
	}
}

func TestFindingListingFilters(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			first := verificationRunFixture(verificationRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID)
			second := verificationRunFixture(verificationOtherRunID, verificationSecondHypID, verificationOtherPathID, verificationAuditID, verificationSnapID)
			third := verificationRunFixture(verificationThirdRunID, verificationThirdHypID, verificationPathID, verificationOtherAuditID, verificationOtherSnapID)
			fourth := verificationRunFixture(verificationFourthRunID, verificationFourthHypID, verificationOtherPathID, verificationOtherAuditID, verificationOtherSnapID)
			findings := []verify.Finding{
				verificationFindingFixture(first, "the search parameter reaches the SQL sink", verify.FindingConfirmed),
				verificationFindingFixture(second, "the export endpoint reads a path from the request", verify.FindingCandidate),
				verificationFindingFixture(third, "the admin route is reachable without a session", verify.FindingBlocked),
				verificationFindingFixture(fourth, "the template engine evaluates attacker input", verify.FindingRefuted),
			}
			// Distinct creation times keep the listing order deterministic.
			timestamps := []string{"2024-06-01T09:01:00Z", "2024-06-01T09:02:00Z", "2024-06-01T09:03:00Z", "2024-06-01T09:04:00Z"}
			for i := range findings {
				findings[i].CreatedAt = timestamps[i]
				findings[i].UpdatedAt = timestamps[i]
				if err := store.UpsertFinding(findings[i]); err != nil {
					t.Fatalf("UpsertFinding(%s): %v", findings[i].ID, err)
				}
			}
			confirmed, candidate, blocked, refuted := findings[0].ID, findings[1].ID, findings[2].ID, findings[3].ID

			cases := []struct {
				name  string
				q     verify.FindingQuery
				want  []string
				total int
			}{
				{"all", verify.FindingQuery{}, []string{confirmed, candidate, blocked, refuted}, 4},
				{"audit", verify.FindingQuery{AuditID: verificationAuditID}, []string{confirmed, candidate}, 2},
				{"snapshot", verify.FindingQuery{SnapshotID: verificationSnapID}, []string{confirmed, candidate}, 2},
				{"path", verify.FindingQuery{PathID: verificationPathID}, []string{confirmed, blocked}, 2},
				{"statuses", verify.FindingQuery{Status: []verify.FindingStatus{verify.FindingConfirmed, verify.FindingRefuted}}, []string{confirmed, refuted}, 2},
				{"conclusive", verify.FindingQuery{ConclusiveOnly: true}, []string{confirmed, refuted}, 2},
				{"candidates", verify.FindingQuery{CandidatesOnly: true}, []string{candidate}, 1},
				{"candidates of another snapshot", verify.FindingQuery{SnapshotID: verificationOtherSnapID, CandidatesOnly: true}, []string{}, 0},
				{"conclusive and candidates", verify.FindingQuery{ConclusiveOnly: true, CandidatesOnly: true}, []string{}, 0},
				{"no match", verify.FindingQuery{SnapshotID: verificationOtherSnapID, Status: []verify.FindingStatus{verify.FindingConfirmed}}, []string{}, 0},
				{"limit", verify.FindingQuery{Limit: 1}, []string{confirmed}, 4},
				{"offset", verify.FindingQuery{Offset: 3}, []string{refuted}, 4},
				{"offset past the end", verify.FindingQuery{Offset: 9}, []string{}, 4},
			}
			for _, testCase := range cases {
				listed, total := mustListFindings(t, store, testCase.q)
				if total != testCase.total {
					t.Errorf("%s: total = %d, want %d", testCase.name, total, testCase.total)
				}
				if got := verificationFindingIDs(listed); !reflect.DeepEqual(got, testCase.want) {
					t.Errorf("%s: ids = %v, want %v", testCase.name, got, testCase.want)
				}
			}
		})
	}
}

func TestUpsertFindingByHypothesis(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			run := verificationRunFixture(verificationRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID)
			finding := verificationFindingFixture(run, "the search parameter reaches the SQL sink", verify.FindingCandidate)
			if err := store.UpsertFinding(finding); err != nil {
				t.Fatalf("UpsertFinding: %v", err)
			}
			if got := mustGetFinding(t, store, finding.ID); !reflect.DeepEqual(got, finding) {
				t.Errorf("finding round trip mismatch:\n got  %+v\n want %+v", got, finding)
			}

			// A re-upsert updates the row keyed by the hypothesis, keeps the original
			// creation time and advances the version.
			updated := finding
			updated.Status = verify.FindingConfirmed
			updated.Confidence = "high"
			updated.UpdatedAt = ""
			updated.CreatedAt = "2000-01-01T00:00:00Z"
			updated.Version = 0
			if err := store.UpsertFinding(updated); err != nil {
				t.Fatalf("UpsertFinding(update): %v", err)
			}
			got := mustGetFinding(t, store, finding.ID)
			if got.Status != verify.FindingConfirmed || got.Confidence != "high" {
				t.Errorf("the re-upsert did not update the verdict: %+v", got)
			}
			if got.CreatedAt != finding.CreatedAt {
				t.Errorf("CreatedAt = %s, want the original %s", got.CreatedAt, finding.CreatedAt)
			}
			if got.UpdatedAt == "" || got.Version != 2 {
				t.Errorf("after the re-upsert: UpdatedAt %q version %d, want a stamped time and version 2", got.UpdatedAt, got.Version)
			}
			// Never a duplicate row: the hypothesis is the key.
			if _, total := mustListFindings(t, store, verify.FindingQuery{SnapshotID: verificationSnapID}); total != 1 {
				t.Errorf("the re-upsert added a row: %d findings for the hypothesis, want 1", total)
			}

			// A second hypothesis is a second row.
			otherRun := verificationRunFixture(verificationOtherRunID, verificationSecondHypID, verificationOtherPathID, verificationOtherAuditID, verificationOtherSnapID)
			other := verificationFindingFixture(otherRun, "the export endpoint reads a path from the request", verify.FindingCandidate)
			if err := store.UpsertFinding(other); err != nil {
				t.Fatalf("UpsertFinding(second hypothesis): %v", err)
			}
			if _, total := mustListFindings(t, store, verify.FindingQuery{}); total != 2 {
				t.Errorf("findings = %d, want 2", total)
			}

			// The hypothesis is the key, so a verdict cannot arrive under a different
			// finding id for a hypothesis that already has one...
			renamed := finding
			renamed.ID = "find-0000000000000000"
			if err := store.UpsertFinding(renamed); !errors.Is(err, verify.ErrConflict) {
				t.Errorf("UpsertFinding with a different finding id = %v, want verify.ErrConflict", err)
			}
			// ...and a finding id already used by another hypothesis is not free.
			newRun := verificationRunFixture(verificationFourthRunID, verificationFourthHypID, verificationPathID, verificationAuditID, verificationSnapID)
			taken := verificationFindingFixture(newRun, "a verdict attempting to reuse an id", verify.FindingCandidate)
			taken.ID = finding.ID
			if err := store.UpsertFinding(taken); !errors.Is(err, verify.ErrConflict) {
				t.Errorf("UpsertFinding with a taken finding id = %v, want verify.ErrConflict", err)
			}
			// A finding without a hypothesis has no key.
			if err := store.UpsertFinding(verify.Finding{ID: "find-0000000000000001", Title: "no key"}); !errors.Is(err, verify.ErrInvalidArgument) {
				t.Errorf("UpsertFinding without a hypothesis = %v, want verify.ErrInvalidArgument", err)
			}
			if _, err := store.GetFinding("find-00000000000000ff"); !errors.Is(err, verify.ErrNotFound) {
				t.Errorf("GetFinding(missing) = %v, want verify.ErrNotFound", err)
			}
			if _, total := mustListFindings(t, store, verify.FindingQuery{}); total != 2 {
				t.Errorf("the refused upserts changed the table: %d findings, want 2", total)
			}
		})
	}
}

func TestDeleteVerificationForSnapshot(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			run := seedVerificationRun(t, store, verificationRunFixture(verificationRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID))
			otherRun := seedVerificationRun(t, store, verificationRunFixture(verificationOtherRunID, verificationSecondHypID, verificationOtherPathID, verificationOtherAuditID, verificationSnapID))
			survivor := seedVerificationRun(t, store, verificationRunFixture(verificationThirdRunID, verificationThirdHypID, verificationPathID, verificationAuditID, verificationOtherSnapID))

			object := verificationEvidenceFixture(t, verify.EvidenceTest, "probe", "the probe returned the expected marker", run, "2024-06-01T09:00:10Z")
			otherObject := verificationEvidenceFixture(t, verify.EvidenceSource, "graph", "the search handler concatenates the parameter", otherRun, "2024-06-01T09:00:11Z")
			// Evidence whose snapshot id was written wrong cannot outlive the run that
			// produced it: the run is what identifies it.
			misTagged := verificationEvidenceFixture(t, verify.EvidenceArtifact, "probe", "the artifact captured the marker", run, "2024-06-01T09:00:12Z")
			misTagged.SnapshotID = verificationOtherSnapID
			survivorObject := verificationEvidenceFixture(t, verify.EvidenceRuntimeLog, "probe", "the probe of the other snapshot logged its marker", survivor, "2024-06-01T09:00:13Z")
			if err := store.AppendEvidence([]verify.Evidence{object, otherObject, misTagged, survivorObject}); err != nil {
				t.Fatalf("AppendEvidence: %v", err)
			}

			finding := verificationFindingFixture(run, "the search parameter reaches the SQL sink", verify.FindingConfirmed)
			otherFinding := verificationFindingFixture(otherRun, "the export endpoint reads a path from the request", verify.FindingCandidate)
			survivorFinding := verificationFindingFixture(survivor, "the admin route is reachable without a session", verify.FindingBlocked)
			for _, verdict := range []verify.Finding{finding, otherFinding, survivorFinding} {
				if err := store.UpsertFinding(verdict); err != nil {
					t.Fatalf("UpsertFinding(%s): %v", verdict.ID, err)
				}
			}

			if removed, err := store.DeleteVerificationForSnapshot(verificationAbsentSnapID); err != nil || removed != 0 {
				t.Errorf("DeleteVerificationForSnapshot(absent) = %d, %v, want 0, nil", removed, err)
			}
			removed, err := store.DeleteVerificationForSnapshot(verificationSnapID)
			if err != nil || removed != 2 {
				t.Fatalf("DeleteVerificationForSnapshot = %d, %v, want 2, nil", removed, err)
			}

			for _, runID := range []string{run.ID, otherRun.ID} {
				if _, err := store.GetVerificationRun(runID); !errors.Is(err, verify.ErrNotFound) {
					t.Errorf("the run %s survived: %v", runID, err)
				}
			}
			if _, total := mustListVerificationRuns(t, store, verify.RunQuery{SnapshotID: verificationSnapID}); total != 0 {
				t.Errorf("the runs of the deleted snapshot survived: %d", total)
			}
			for _, evidenceID := range []string{object.ID, otherObject.ID, misTagged.ID} {
				if _, err := store.GetEvidence(evidenceID); !errors.Is(err, verify.ErrNotFound) {
					t.Errorf("the evidence %s survived: %v", evidenceID, err)
				}
			}
			if _, total := mustListEvidence(t, store, verify.EvidenceQuery{SnapshotID: verificationSnapID}); total != 0 {
				t.Errorf("the evidence of the deleted snapshot survived: %d", total)
			}
			// The survivor's snapshot keeps exactly its own evidence: the mis-tagged
			// object went with the run that produced it.
			evidence, total := mustListEvidence(t, store, verify.EvidenceQuery{SnapshotID: verificationOtherSnapID})
			if total != 1 || !reflect.DeepEqual(verificationEvidenceIDs(evidence), []string{survivorObject.ID}) {
				t.Errorf("the surviving evidence = %v (total %d), want only %s", verificationEvidenceIDs(evidence), total, survivorObject.ID)
			}
			for _, findingID := range []string{finding.ID, otherFinding.ID} {
				if _, err := store.GetFinding(findingID); !errors.Is(err, verify.ErrNotFound) {
					t.Errorf("the finding %s survived: %v", findingID, err)
				}
			}
			if _, total := mustListFindings(t, store, verify.FindingQuery{SnapshotID: verificationSnapID}); total != 0 {
				t.Errorf("the findings of the deleted snapshot survived: %d", total)
			}

			// The other snapshot is untouched, runs and all.
			if got := mustGetVerificationRun(t, store, survivor.ID); got.ID != survivor.ID {
				t.Errorf("deleting one snapshot removed another run: %+v", got)
			}
			if got := mustGetEvidence(t, store, survivorObject.ID); got.ID != survivorObject.ID {
				t.Errorf("deleting one snapshot removed another snapshot's evidence: %+v", got)
			}
			if got := mustGetFinding(t, store, survivorFinding.ID); got.ID != survivorFinding.ID {
				t.Errorf("deleting one snapshot removed another snapshot's finding: %+v", got)
			}
			if _, total := mustListVerificationRuns(t, store, verify.RunQuery{SnapshotID: verificationOtherSnapID}); total != 1 {
				t.Errorf("the other snapshot's runs = %d, want 1", total)
			}
		})
	}
}

// TestDeleteSnapshotRemovesVerification is the wiring point: deleting a snapshot
// must take its verification runs, evidence and findings with it, or a deleted
// snapshot keeps answering verification queries.
func TestDeleteSnapshotRemovesVerification(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			ctx := context.Background()
			project := testProject("proj-verification")
			if err := store.PutProject(ctx, project); err != nil {
				t.Fatalf("PutProject: %v", err)
			}
			for _, snapshotID := range []string{verificationSnapID, verificationOtherSnapID} {
				if err := store.PutSnapshot(ctx, project.ID, testSnapshot(snapshotID)); err != nil {
					t.Fatalf("PutSnapshot(%s): %v", snapshotID, err)
				}
			}
			run := seedVerificationRun(t, store, verificationRunFixture(verificationRunID, verificationHypothesisID, verificationPathID, verificationAuditID, verificationSnapID))
			survivor := seedVerificationRun(t, store, verificationRunFixture(verificationOtherRunID, verificationSecondHypID, verificationOtherPathID, verificationOtherAuditID, verificationOtherSnapID))
			object := verificationEvidenceFixture(t, verify.EvidenceTest, "probe", "the probe returned the expected marker", run, "2024-06-01T09:00:10Z")
			survivorObject := verificationEvidenceFixture(t, verify.EvidenceRuntimeLog, "probe", "the probe of the other snapshot logged its marker", survivor, "2024-06-01T09:00:11Z")
			if err := store.AppendEvidence([]verify.Evidence{object, survivorObject}); err != nil {
				t.Fatalf("AppendEvidence: %v", err)
			}
			finding := verificationFindingFixture(run, "the search parameter reaches the SQL sink", verify.FindingConfirmed)
			survivorFinding := verificationFindingFixture(survivor, "the export endpoint reads a path from the request", verify.FindingCandidate)
			for _, verdict := range []verify.Finding{finding, survivorFinding} {
				if err := store.UpsertFinding(verdict); err != nil {
					t.Fatalf("UpsertFinding(%s): %v", verdict.ID, err)
				}
			}

			if err := store.DeleteSnapshot(ctx, verificationSnapID); err != nil {
				t.Fatalf("DeleteSnapshot: %v", err)
			}
			if _, err := store.GetVerificationRun(run.ID); !errors.Is(err, verify.ErrNotFound) {
				t.Errorf("GetVerificationRun after DeleteSnapshot = %v, want verify.ErrNotFound", err)
			}
			if _, total := mustListVerificationRuns(t, store, verify.RunQuery{SnapshotID: verificationSnapID}); total != 0 {
				t.Errorf("ListVerificationRuns after DeleteSnapshot = %d, want 0", total)
			}
			if _, err := store.GetEvidence(object.ID); !errors.Is(err, verify.ErrNotFound) {
				t.Errorf("GetEvidence after DeleteSnapshot = %v, want verify.ErrNotFound", err)
			}
			if _, total := mustListEvidence(t, store, verify.EvidenceQuery{SnapshotID: verificationSnapID}); total != 0 {
				t.Errorf("ListEvidence after DeleteSnapshot = %d, want 0", total)
			}
			if _, err := store.GetFinding(finding.ID); !errors.Is(err, verify.ErrNotFound) {
				t.Errorf("GetFinding after DeleteSnapshot = %v, want verify.ErrNotFound", err)
			}
			if _, total := mustListFindings(t, store, verify.FindingQuery{SnapshotID: verificationSnapID}); total != 0 {
				t.Errorf("ListFindings after DeleteSnapshot = %d, want 0", total)
			}

			// The other snapshot keeps everything.
			if got := mustGetVerificationRun(t, store, survivor.ID); got.ID != survivor.ID {
				t.Errorf("the surviving run = %+v", got)
			}
			if got := mustGetEvidence(t, store, survivorObject.ID); got.ID != survivorObject.ID {
				t.Errorf("the surviving evidence = %+v", got)
			}
			if got := mustGetFinding(t, store, survivorFinding.ID); got.ID != survivorFinding.ID {
				t.Errorf("the surviving finding = %+v", got)
			}
		})
	}
}
