package verify

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- in-memory Store fake ----------------------------------------------------
//
// The storage backends are implemented in parallel elsewhere, so the verifier is
// tested against a fake that honours the contract the store declares: runs carry an
// optimistic version, evidence is append-only and content-addressed, and a finding
// is keyed by its id.

type memoryVerifyStore struct {
	mu sync.Mutex

	runs     map[string]Run
	evidence map[string]Evidence
	findings map[string]Finding

	createRunCalls     int
	appendEvidenceCall int
	upsertFindingCalls int
}

func newMemoryVerifyStore() *memoryVerifyStore {
	return &memoryVerifyStore{
		runs:     map[string]Run{},
		evidence: map[string]Evidence{},
		findings: map[string]Finding{},
	}
}

func (s *memoryVerifyStore) CreateVerificationRun(run Run) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createRunCalls++
	if _, exists := s.runs[run.ID]; exists {
		return fmt.Errorf("%w: run %s", ErrConflict, run.ID)
	}
	if run.Version == 0 {
		run.Version = 1
	}
	s.runs[run.ID] = run
	return nil
}

func (s *memoryVerifyStore) GetVerificationRun(runID string) (*Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		return nil, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	copied := run
	return &copied, nil
}

func (s *memoryVerifyStore) ListVerificationRuns(q RunQuery) ([]Run, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Run{}
	for _, run := range s.runs {
		if q.HypothesisID != "" && run.HypothesisID != q.HypothesisID {
			continue
		}
		if q.FindingID != "" && run.FindingID != q.FindingID {
			continue
		}
		if q.SnapshotID != "" && run.SnapshotID != q.SnapshotID {
			continue
		}
		if q.PlanHash != "" && run.PlanHash != q.PlanHash {
			continue
		}
		if len(q.Status) > 0 && !containsStatus(q.Status, run.Status) {
			continue
		}
		out = append(out, run)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, len(out), nil
}

func (s *memoryVerifyStore) UpdateVerificationRun(run Run, expectedVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.runs[run.ID]
	if !ok {
		return fmt.Errorf("%w: run %s", ErrNotFound, run.ID)
	}
	if expectedVersion != 0 && current.Version != expectedVersion {
		return fmt.Errorf("%w: run %s is at version %d, not %d", ErrConflict, run.ID, current.Version, expectedVersion)
	}
	if run.Version <= current.Version {
		run.Version = current.Version + 1
	}
	s.runs[run.ID] = run
	return nil
}

func (s *memoryVerifyStore) AppendEvidence(evidence []Evidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendEvidenceCall++
	for _, object := range evidence {
		if existing, ok := s.evidence[object.ID]; ok {
			if existing.ContentHash != object.ContentHash || existing.Content != object.Content {
				return fmt.Errorf("%w: evidence %s already exists with different content", ErrConflict, object.ID)
			}
			continue
		}
		s.evidence[object.ID] = object
	}
	return nil
}

func (s *memoryVerifyStore) GetEvidence(evidenceID string) (*Evidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, ok := s.evidence[evidenceID]
	if !ok {
		return nil, fmt.Errorf("%w: evidence %s", ErrNotFound, evidenceID)
	}
	copied := object
	return &copied, nil
}

func (s *memoryVerifyStore) ListEvidence(q EvidenceQuery) ([]Evidence, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Evidence{}
	for _, object := range s.evidence {
		if q.VerificationRunID != "" && object.VerificationRunID != q.VerificationRunID {
			continue
		}
		if q.FindingID != "" && object.FindingID != q.FindingID {
			continue
		}
		if q.SnapshotID != "" && object.SnapshotID != q.SnapshotID {
			continue
		}
		if len(q.Kinds) > 0 && !containsKind(q.Kinds, object.Kind) {
			continue
		}
		out = append(out, object)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, len(out), nil
}

func (s *memoryVerifyStore) UpsertFinding(finding Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertFindingCalls++
	s.findings[finding.ID] = finding
	return nil
}

func (s *memoryVerifyStore) GetFinding(findingID string) (*Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	finding, ok := s.findings[findingID]
	if !ok {
		return nil, fmt.Errorf("%w: finding %s", ErrNotFound, findingID)
	}
	copied := finding
	return &copied, nil
}

func (s *memoryVerifyStore) ListFindings(q FindingQuery) ([]Finding, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Finding{}
	for _, finding := range s.findings {
		if q.AuditID != "" && finding.AuditID != q.AuditID {
			continue
		}
		if q.SnapshotID != "" && finding.SnapshotID != q.SnapshotID {
			continue
		}
		if len(q.Status) > 0 && !containsFindingStatus(q.Status, finding.Status) {
			continue
		}
		if q.ConclusiveOnly && !finding.Status.Conclusive() {
			continue
		}
		if q.CandidatesOnly && finding.Status != FindingCandidate {
			continue
		}
		out = append(out, finding)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, len(out), nil
}

func (s *memoryVerifyStore) DeleteVerificationForSnapshot(snapshotID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, run := range s.runs {
		if run.SnapshotID == snapshotID {
			delete(s.runs, id)
			removed++
		}
	}
	for id, object := range s.evidence {
		if object.SnapshotID == snapshotID {
			delete(s.evidence, id)
		}
	}
	for id, finding := range s.findings {
		if finding.SnapshotID == snapshotID {
			delete(s.findings, id)
		}
	}
	return removed, nil
}

// totals reports how many objects the store holds, so a refused request can be
// asserted to have written nothing at all.
func (s *memoryVerifyStore) totals() (runs, evidence, findings int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runs), len(s.evidence), len(s.findings)
}

func (s *memoryVerifyStore) runCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createRunCalls
}

func containsStatus(values []VerificationStatus, want VerificationStatus) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsFindingStatus(values []FindingStatus, want FindingStatus) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsKind(values []EvidenceKind, want EvidenceKind) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// --- fixtures ----------------------------------------------------------------

// servicePlan builds a plan that does not need an approval: static steps only.
func servicePlan(t *testing.T, steps ...Step) Plan {
	t.Helper()
	if len(steps) == 0 {
		steps = []Step{commandStep("the read succeeds", "the read is rejected")}
	}
	plan := Plan{
		SchemaVersion: SchemaVersion,
		HypothesisID:  "hyp-svc-1",
		FindingID:     FindingID("hyp-svc-1"),
		PathID:        "path-svc-1",
		AuditID:       "audit-svc-1",
		SnapshotID:    "snap-svc-1",
		SecurityGoal:  "high",
		Claim:         "the export endpoint reads a path from the request",
		Steps:         steps,
		Environment:   DefaultEnvironment(),
		Scope:         Scope{Repository: "repo-1", SnapshotID: "snap-svc-1", AuthorizedBy: "operator-1"},
		GeneratedAt:   "2024-01-01T00:00:00Z",
		Limitations:   []string{"the dynamic proof needs a deployed target"},
	}
	prepared, err := Prepare(plan)
	if err != nil {
		t.Fatalf("fixture plan does not pass Prepare: %v", err)
	}
	return prepared.Plan
}

// dynamicPlan builds a plan whose steps make it require a recorded approval.
func dynamicPlan(t *testing.T) Plan {
	t.Helper()
	return servicePlan(t, Step{
		Kind:             StepDynamicProof,
		Command:          []string{"prove", "the", "read"},
		Expectation:      "the read succeeds",
		Contradiction:    "permission denied",
		RequiresApproval: true,
	})
}

func confirmedScript() []StepOutcome {
	return []StepOutcome{{
		Kind: EvidenceRuntimeLog, ExitCode: intPtr(0),
		Content: "step[0] echo observation\nexit_code=0\nthe read succeeded",
	}}
}

func newTestVerifier(t *testing.T, executor Executor) (*Verifier, *memoryVerifyStore) {
	t.Helper()
	store := newMemoryVerifyStore()
	verifier := NewVerifier(store, executor)
	fixed := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)
	verifier.Now = func() time.Time { return fixed }
	return verifier, store
}

// --- Verify: the verdict contract --------------------------------------------

func TestVerifyConfirmedRunProducesConfirmedFinding(t *testing.T) {
	executor := NewScriptedExecutor(confirmedScript())
	verifier, _ := newTestVerifier(t, executor)

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: servicePlan(t), Owner: "operator-1"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != VerifySucceeded {
		t.Fatalf("run status = %s, want SUCCEEDED (stop %s, error %s)", run.Status, run.StopReason, run.Error)
	}
	if run.Outcome != OutcomeConfirmed {
		t.Fatalf("outcome = %s (%s), want CONFIRMED", run.Outcome, run.StopReason)
	}
	if run.StartedAt == "" || run.FinishedAt == "" {
		t.Fatalf("the run did not record its window: %+v", run)
	}
	if run.EnvironmentDigest != run.Environment.Digest() {
		t.Fatalf("environment digest = %s, want %s", run.EnvironmentDigest, run.Environment.Digest())
	}
	if run.Executor != "scripted" {
		t.Fatalf("executor = %q, want scripted", run.Executor)
	}
	if len(run.EvidenceIDs) == 0 {
		t.Fatal("the run recorded no evidence")
	}

	finding, err := verifier.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if finding.Status != FindingConfirmed {
		t.Fatalf("finding status = %s, want confirmed", finding.Status)
	}
	if finding.HypothesisID != run.HypothesisID || finding.PathID != run.PathID {
		t.Fatalf("finding is not tied to the hypothesis: %+v", finding)
	}
	if len(finding.Supporting) == 0 {
		t.Fatalf("a confirmation needs supporting evidence: %+v", finding)
	}
	if len(finding.Contradicting) != 0 {
		t.Fatalf("unexpected contradicting evidence: %+v", finding.Contradicting)
	}
	if !reflect.DeepEqual(finding.VerificationRunIDs, []string{run.ID}) {
		t.Fatalf("run ids = %v, want [%s]", finding.VerificationRunIDs, run.ID)
	}
	if !reflect.DeepEqual(finding.Environments, []string{run.EnvironmentDigest}) {
		t.Fatalf("environments = %v, want [%s]", finding.Environments, run.EnvironmentDigest)
	}
	if finding.ReproduceSteps == "" {
		t.Fatal("a confirmed finding must carry the reproduction steps")
	}
	if len(finding.Limitations) == 0 {
		t.Fatal("the plan's limitations must be carried onto the finding")
	}
	// The evidence the finding points at exists and belongs to the run.
	evidence, _, err := verifier.ListEvidence(EvidenceQuery{VerificationRunID: run.ID})
	if err != nil {
		t.Fatalf("ListEvidence: %v", err)
	}
	if len(evidence) != len(run.EvidenceIDs) {
		t.Fatalf("stored evidence = %d, run lists %d", len(evidence), len(run.EvidenceIDs))
	}
	for _, object := range evidence {
		if object.VerificationRunID != run.ID {
			t.Fatalf("evidence %s belongs to run %q", object.ID, object.VerificationRunID)
		}
		if hashContent(object.Content) != object.ContentHash {
			t.Fatalf("evidence %s content does not match its hash", object.ID)
		}
	}
}

func TestVerifyDemotesConfirmationWithoutReproductionEvidence(t *testing.T) {
	// The executor claims CONFIRMED but produced only a static source observation
	// and no reproduction steps: DeriveOutcome must demote it.
	executor := NewScriptedExecutor([]StepOutcome{{
		Kind:    EvidenceSource,
		Content: "handler.go:42 looks like a path read",
	}})
	verifier, _ := newTestVerifier(t, executor)
	plan := servicePlan(t)

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Outcome != OutcomeInconclusive {
		t.Fatalf("outcome = %s, want INCONCLUSIVE: a confirmation without reproduction evidence must be demoted", run.Outcome)
	}
	finding, err := verifier.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if finding.Status != FindingInconclusive {
		t.Fatalf("finding status = %s, want inconclusive", finding.Status)
	}
	if len(finding.Supporting) != 0 {
		t.Fatalf("a demoted confirmation must not have supporting evidence: %+v", finding.Supporting)
	}
	if len(finding.Inconclusive) == 0 {
		t.Fatalf("the observation belongs in the inconclusive list: %+v", finding)
	}
}

func TestVerifyRefutationWithoutContradictingEvidenceIsInconclusive(t *testing.T) {
	// The executor claims REFUTED but carries no contradicting evidence: "we did
	// not reproduce it" is exactly the answer that must not be recorded as a
	// refutation.
	object, err := NewEvidence(EvidenceRuntimeLog, "step[0] echo observation\nexit_code=0\nnothing happened", EvidenceOptions{
		Tool: "hostile", SnapshotID: "snap-svc-1", HypothesisID: "hyp-svc-1",
		FindingID: FindingID("hyp-svc-1"), Now: "2024-03-04T05:06:07Z",
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	hostile := &hostileExecutor{result: Result{
		Outcome: OutcomeRefuted, Reason: "we could not reproduce it",
		Reproduction: "step 0: nothing happened",
		Evidence:     []Evidence{object}, StopReason: VerifyStopCompleted,
	}}
	verifier, _ := newTestVerifier(t, hostile)

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: servicePlan(t)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Outcome == OutcomeRefuted {
		t.Fatal("a verdict of REFUTED without contradicting evidence must never be recorded")
	}
	if run.Outcome != OutcomeInconclusive {
		t.Fatalf("outcome = %s, want INCONCLUSIVE", run.Outcome)
	}
	finding, err := verifier.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if finding.Status == FindingRefuted {
		t.Fatal("finding must not be refuted without contradicting evidence")
	}
	if finding.Status != FindingInconclusive {
		t.Fatalf("finding status = %s, want inconclusive", finding.Status)
	}
	if len(finding.Contradicting) != 0 {
		t.Fatalf("contradicting evidence appeared from nowhere: %+v", finding.Contradicting)
	}
	if len(finding.Inconclusive) != 1 {
		t.Fatalf("the observation belongs in the inconclusive list: %+v", finding)
	}
}

func TestVerifyRealRefutationKeepsContradiction(t *testing.T) {
	executor := NewScriptedExecutor([]StepOutcome{{
		Kind: EvidenceRuntimeLog, ExitCode: intPtr(0),
		Content:     "step[0] echo observation\npermission denied",
		Contradicts: "the control rejects the request with permission denied",
	}})
	verifier, _ := newTestVerifier(t, executor)
	// The adapter observed a contradiction through the step's own contradiction
	// phrase, which is how a real adapter tells the verifier what it saw.
	plan := servicePlan(t, Step{
		Kind:          StepStaticCheck,
		Command:       []string{"echo", "observation"},
		Expectation:   "the read succeeds",
		Contradiction: "permission denied",
	})

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Outcome != OutcomeRefuted {
		t.Fatalf("outcome = %s (%s), want REFUTED", run.Outcome, run.StopReason)
	}
	finding, err := verifier.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if finding.Status != FindingRefuted {
		t.Fatalf("finding status = %s, want refuted", finding.Status)
	}
	if len(finding.Contradicting) == 0 {
		t.Fatal("a refutation must keep its contradicting evidence")
	}
	if len(finding.Supporting) != 0 {
		t.Fatalf("a refutation is made of contradicting evidence, not supporting evidence: %+v", finding.Supporting)
	}
}

func TestVerifyBlockedRunYieldsBlockedFinding(t *testing.T) {
	verifier, _ := newTestVerifier(t, NewUnsupportedExecutor("noop", "0", "no adapter for this step kind"))
	plan := servicePlan(t)

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != VerifyBlocked {
		t.Fatalf("run status = %s, want BLOCKED", run.Status)
	}
	if run.StopReason != VerifyStopUnsupported {
		t.Fatalf("stop reason = %s, want %s", run.StopReason, VerifyStopUnsupported)
	}
	if run.ExitCode != nil {
		t.Fatalf("a blocked run did not produce a process verdict: exit code %v", *run.ExitCode)
	}
	finding, err := verifier.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if finding.Status != FindingBlocked {
		t.Fatalf("finding status = %s, want blocked", finding.Status)
	}
	if finding.Status == FindingRefuted {
		t.Fatal("a blocked run must never be recorded as a refutation")
	}
}

func TestVerifyBlockedRunFromCancellationYieldsBlockedFinding(t *testing.T) {
	executor := NewScriptedExecutor(confirmedScript())
	executor.StepDelay = 30 * time.Millisecond
	verifier, _ := newTestVerifier(t, executor)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	run, err := verifier.Verify(ctx, VerifyRequest{Plan: servicePlan(t)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != VerifyCancelled {
		t.Fatalf("run status = %s, want CANCELLED", run.Status)
	}
	finding, err := verifier.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if finding.Status != FindingBlocked {
		t.Fatalf("finding status = %s, want blocked: a cancellation is not a refutation", finding.Status)
	}
}

// --- Verify: authorization and preparation -----------------------------------

func TestVerifyApprovalRequiredWritesNothing(t *testing.T) {
	executor := NewScriptedExecutor(confirmedScript())
	verifier, store := newTestVerifier(t, executor)

	_, err := verifier.Verify(context.Background(), VerifyRequest{Plan: dynamicPlan(t)})
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("err = %v, want ErrApprovalRequired", err)
	}
	if runs, evidence, findings := store.totals(); runs != 0 || evidence != 0 || findings != 0 {
		t.Fatalf("a refused approval wrote %d runs, %d evidence, %d findings; want nothing", runs, evidence, findings)
	}
	if executor.Calls() != 0 {
		t.Fatalf("the executor ran %d times despite the refusal", executor.Calls())
	}
}

func TestVerifyApprovalWithoutANameWritesNothing(t *testing.T) {
	executor := NewScriptedExecutor(confirmedScript())
	verifier, store := newTestVerifier(t, executor)

	_, err := verifier.Verify(context.Background(), VerifyRequest{Plan: dynamicPlan(t), Approved: true, ApprovedBy: "   "})
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("err = %v, want ErrApprovalRequired", err)
	}
	if runs, _, _ := store.totals(); runs != 0 {
		t.Fatalf("a refused approval wrote %d runs", runs)
	}
}

func TestVerifyNetworkPlanWithoutScopeIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	// Prepare validates the plan before Authorize sees it, and a network policy the
	// scope does not allow is a builder error: the plan is internally inconsistent.
	// The guarantee under test is the same either way — nothing runs and nothing is
	// written.
	executor := NewScriptedExecutor(confirmedScript())
	verifier, store := newTestVerifier(t, executor)

	plan := servicePlan(t)
	plan.Environment.Network = NetworkTargetOnly
	plan.Environment.AllowedHosts = []string{"target.internal"}
	_, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("err = %v, want ErrInvalidPlan (validation runs before authorization)", err)
	}
	if runs, evidence, findings := store.totals(); runs != 0 || evidence != 0 || findings != 0 {
		t.Fatalf("a refused network plan wrote %d runs, %d evidence, %d findings; want nothing", runs, evidence, findings)
	}
	if executor.Calls() != 0 {
		t.Fatalf("the executor ran %d times despite the refusal", executor.Calls())
	}
}

func TestAuthorizeDeniesScopeAndVerifyWritesNothing(t *testing.T) {
	// Authorize is the scope gate. It is exercised directly because Prepare already
	// rejects the plans it would deny, and the point of the test is that the gate
	// itself still refuses and that a refusal from Verify leaves no trace.
	plan := servicePlan(t)
	plan.Environment.Network = NetworkTargetOnly
	plan.Environment.AllowedHosts = []string{"target.internal"}
	prepared := &Prepared{Plan: plan, Environment: plan.Environment}
	if err := Authorize(prepared, false, ""); !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("Authorize = %v, want ErrScopeDenied", err)
	}

	executor := NewScriptedExecutor(confirmedScript())
	verifier, store := newTestVerifier(t, executor)
	// The denial path through Verify is the same one the approval tests cover: the
	// call returns before any write. This asserts the "writes nothing" half.
	if _, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan}); err == nil {
		t.Fatal("a plan the scope does not allow was accepted")
	}
	if runs, evidence, findings := store.totals(); runs != 0 || evidence != 0 || findings != 0 {
		t.Fatalf("a denied scope wrote %d runs, %d evidence, %d findings; want nothing", runs, evidence, findings)
	}
	if executor.Calls() != 0 {
		t.Fatalf("the executor ran %d times despite the denial", executor.Calls())
	}
}

func TestVerifyInvalidPlanSurfacesAsIs(t *testing.T) {
	executor := NewScriptedExecutor(confirmedScript())
	verifier, store := newTestVerifier(t, executor)

	plan := servicePlan(t)
	plan.Claim = ""
	_, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("err = %v, want ErrInvalidPlan", err)
	}
	if !strings.Contains(err.Error(), "claim is required") {
		t.Fatalf("err = %v, want the builder error surfaced verbatim", err)
	}
	if runs, _, _ := store.totals(); runs != 0 {
		t.Fatalf("an invalid plan wrote %d runs", runs)
	}
}

func TestVerifyRefusesMissingWiring(t *testing.T) {
	if _, err := NewVerifier(nil, NewScriptedExecutor(nil)).Verify(context.Background(), VerifyRequest{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("no store: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := NewVerifier(newMemoryVerifyStore(), nil).Verify(context.Background(), VerifyRequest{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("no executor: err = %v, want ErrInvalidArgument", err)
	}
}

func TestVerifyApprovedDynamicPlanRunsOnce(t *testing.T) {
	executor := NewScriptedExecutor(confirmedScript())
	verifier, _ := newTestVerifier(t, executor)

	run, err := verifier.Verify(context.Background(), VerifyRequest{
		Plan: dynamicPlan(t), Approved: true, ApprovedBy: "operator-1", Owner: "owner-1",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !run.Approved || run.ApprovedBy != "operator-1" || run.ApprovedAt == "" {
		t.Fatalf("the approval was not recorded: %+v", run)
	}
	if run.Status != VerifySucceeded || run.Outcome != OutcomeConfirmed {
		t.Fatalf("run = %s/%s, want SUCCEEDED/CONFIRMED", run.Status, run.Outcome)
	}
	if run.Owner != "owner-1" {
		t.Fatalf("owner = %q, want owner-1", run.Owner)
	}
	if executor.Calls() != 1 {
		t.Fatalf("executor calls = %d, want 1", executor.Calls())
	}
}

func TestVerifyReplayReturnsExistingRunAndExecutesOnce(t *testing.T) {
	executor := NewScriptedExecutor(confirmedScript())
	verifier, store := newTestVerifier(t, executor)
	plan := servicePlan(t)

	first, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	second, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("replay produced run %s, want %s", second.ID, first.ID)
	}
	if executor.Calls() != 1 {
		t.Fatalf("executor calls = %d, want 1: the same plan is a replay, not a second attempt", executor.Calls())
	}
	if store.runCount() != 1 {
		t.Fatalf("runs created = %d, want 1", store.runCount())
	}
	if runs, _, findings := store.totals(); runs != 1 || findings != 1 {
		t.Fatalf("store holds %d runs and %d findings, want 1 and 1", runs, findings)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("the replay returned a different run:\nfirst  %+v\nsecond %+v", first, second)
	}
}

func TestVerifyDerivesTheSameRunIDFromTheSamePlan(t *testing.T) {
	executor := NewScriptedExecutor(confirmedScript())
	verifier, _ := newTestVerifier(t, executor)
	plan := servicePlan(t)

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	prepared, err := Prepare(plan)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if want := VerificationRunID(plan.HypothesisID, prepared.PlanHash); run.ID != want {
		t.Fatalf("run id = %s, want %s", run.ID, want)
	}
}

// --- Verify: redaction -------------------------------------------------------

func TestVerifyStoresRedactedEvidenceWithMatchingHash(t *testing.T) {
	// The observation carries every material class Redact must remove. The address
	// uses the reserved .test domain on purpose: it must exercise the e-mail pattern
	// without being anyone's address.
	secret := "correct-horse-battery-staple"
	bearerValue := "abcdefghijklmnopqrstuvwxyz0123456789"
	privateKeyBody := "c2VjcmV0LWtleS1tYXRlcmlhbC1nb2VzLWhlcmU="
	log := strings.Join([]string{
		"step[0] tool run",
		"password=" + secret,
		"Authorization: Bearer " + bearerValue,
		"contact: person@host.test",
		"-----BEGIN RSA PRIVATE KEY-----",
		privateKeyBody,
		"-----END RSA PRIVATE KEY-----",
	}, "\n")
	executor := NewScriptedExecutor([]StepOutcome{{
		Kind: EvidenceRuntimeLog, ExitCode: intPtr(0), Content: log,
	}})
	verifier, _ := newTestVerifier(t, executor)

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: servicePlan(t)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	stored, _, err := verifier.ListEvidence(EvidenceQuery{VerificationRunID: run.ID})
	if err != nil {
		t.Fatalf("ListEvidence: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("no evidence was stored")
	}
	var redactedEvidence *Evidence
	for i := range stored {
		if stored[i].Kind == EvidenceRuntimeLog {
			redactedEvidence = &stored[i]
		}
	}
	if redactedEvidence == nil {
		t.Fatalf("the runtime log was not stored: %+v", stored)
	}
	if !redactedEvidence.Redacted {
		t.Fatalf("evidence was not marked redacted: %+v", *redactedEvidence)
	}
	if redactedEvidence.RedactionNotes == "" {
		t.Fatal("redaction must say what it removed")
	}
	if !strings.Contains(redactedEvidence.RedactionNotes, "secret-like assignment") {
		t.Fatalf("redaction notes %q do not name the class", redactedEvidence.RedactionNotes)
	}
	for _, forbidden := range []string{secret, bearerValue, privateKeyBody, "person@host.test", "BEGIN RSA PRIVATE KEY"} {
		if strings.Contains(redactedEvidence.Content, forbidden) {
			t.Fatalf("stored content still contains %q:\n%s", forbidden, redactedEvidence.Content)
		}
	}
	if hashContent(redactedEvidence.Content) != redactedEvidence.ContentHash {
		t.Fatalf("the stored hash does not cover the stored content")
	}
	// The id is derived from the stored (redacted) content within the scope the
	// evidence belongs to: a run-scoped object must include its run, otherwise two
	// runs producing identical bytes would collapse onto one another.
	if wantID := DeriveEvidenceID(*redactedEvidence); redactedEvidence.ID != wantID {
		t.Fatalf("evidence id %s was not derived from the stored content (want %s)", redactedEvidence.ID, wantID)
	}
}

// --- Verify: inconsistent executor results -----------------------------------

type hostileExecutor struct {
	result Result
	// results, when set, is consumed one entry per call so a test can drive two
	// different plans against the same verifier.
	results []Result
	calls   int
}

func (h *hostileExecutor) Capabilities() ExecutorCapabilities {
	return ExecutorCapabilities{Name: "hostile", Version: "1", SupportsCommands: true, ReportsExitCode: true}
}

func (h *hostileExecutor) Execute(ctx context.Context, plan Plan, env Environment) (Result, error) {
	h.calls++
	if len(h.results) > 0 {
		index := h.calls - 1
		if index >= len(h.results) {
			index = len(h.results) - 1
		}
		return h.results[index], nil
	}
	return h.result, nil
}

func TestVerifyDiscardsEvidenceThatFailsValidation(t *testing.T) {
	// The executor hand-built an evidence object: no tool, and a hash that does not
	// cover its content. ValidateResult must reject it, so nothing is stored and the
	// run is honestly blocked rather than confirmed.
	hostile := &hostileExecutor{result: Result{
		Outcome:      OutcomeConfirmed,
		Reason:       "trust me",
		Reproduction: "step 0: did the thing",
		Evidence: []Evidence{{
			ID: "ev-not-built-by-NewEvidence", Kind: EvidenceRuntimeLog,
			SnapshotID: "snap-svc-1", Content: "unverified bytes",
			ContentHash: "sha256:0000",
		}},
		StopReason: VerifyStopCompleted,
	}}
	verifier, store := newTestVerifier(t, hostile)

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: servicePlan(t)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Outcome != OutcomeBlocked {
		t.Fatalf("outcome = %s, want BLOCKED: the result failed validation", run.Outcome)
	}
	if _, evidence, _ := store.totals(); evidence != 0 {
		t.Fatalf("invalid evidence was stored: %d objects", evidence)
	}
	finding, err := verifier.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if finding.Status != FindingBlocked {
		t.Fatalf("finding status = %s, want blocked", finding.Status)
	}
	if !strings.Contains(run.Error, "content does not match its hash") {
		t.Fatalf("the run does not explain the rejection: %q", run.Error)
	}
}

func TestVerifyExecutorFailureIsRecordedAsBlocked(t *testing.T) {
	hostile := &failingExecutor{}
	verifier, _ := newTestVerifier(t, hostile)

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: servicePlan(t)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Status != VerifyBlocked {
		t.Fatalf("run status = %s, want BLOCKED", run.Status)
	}
	if !strings.Contains(run.Error, "environment unreachable") {
		t.Fatalf("run error = %q, want the executor failure", run.Error)
	}
	finding, err := verifier.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if finding.Status != FindingBlocked {
		t.Fatalf("finding status = %s, want blocked", finding.Status)
	}
}

type failingExecutor struct{}

func (f *failingExecutor) Capabilities() ExecutorCapabilities {
	return ExecutorCapabilities{Name: "failing", Version: "1", SupportsCommands: true}
}

func (f *failingExecutor) Execute(ctx context.Context, plan Plan, env Environment) (Result, error) {
	return Result{}, errors.New("environment unreachable")
}

// echoingExecutor is a deterministic adapter that turns each step's command into
// distinct evidence, so two plans for the same hypothesis produce different
// evidence objects rather than collapsing into one content-addressed id.
type echoingExecutor struct {
	calls int
}

func (e *echoingExecutor) Capabilities() ExecutorCapabilities {
	return ExecutorCapabilities{Name: "echoing", Version: "1", SupportsCommands: true, ReportsExitCode: true}
}

func (e *echoingExecutor) Execute(ctx context.Context, plan Plan, env Environment) (Result, error) {
	e.calls++
	result := Result{Outcome: OutcomeConfirmed, Reason: "reproduced", StopReason: VerifyStopCompleted}
	exit := 0
	result.ExitCode = &exit
	for index, step := range plan.Steps {
		object, err := NewEvidence(EvidenceRuntimeLog, fmt.Sprintf("step[%d] command=%s reproduced", index, strings.Join(step.Command, " ")), EvidenceOptions{
			Tool: "echoing", ToolVersion: "1", SnapshotID: plan.SnapshotID,
			HypothesisID: plan.HypothesisID, FindingID: plan.FindingID, PathID: plan.PathID,
			Now: "2024-03-04T05:06:07Z",
		})
		if err != nil {
			return Result{}, err
		}
		result.Evidence = append(result.Evidence, object)
		result.Reproduction += fmt.Sprintf("step %d: %s\n", index, strings.Join(step.Command, " "))
	}
	return result, nil
}

func TestVerifySecondRunOfTheSameHypothesisKeepsPriorEvidence(t *testing.T) {
	// A different plan for the same hypothesis is a new run, and the finding keeps
	// both run ids and both evidence sets: verification history is not overwritten.
	store := newMemoryVerifyStore()
	executor := &echoingExecutor{}
	verifier := NewVerifier(store, executor)
	fixed := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)
	verifier.Now = func() time.Time { return fixed }

	firstPlan := servicePlan(t)
	secondPlan := servicePlan(t, Step{
		Kind:          StepStaticCheck,
		Command:       []string{"echo", "a", "different", "observation"},
		Expectation:   "the read succeeds",
		Contradiction: "the read is rejected",
	})

	first, err := verifier.Verify(context.Background(), VerifyRequest{Plan: firstPlan})
	if err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	second, err := verifier.Verify(context.Background(), VerifyRequest{Plan: secondPlan})
	if err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	if first.ID == second.ID {
		t.Fatal("two different plans must not share a run id")
	}
	if first.EvidenceIDs[0] == second.EvidenceIDs[0] {
		t.Fatal("the two plans produced identical evidence, so the test cannot tell accumulation from overwriting")
	}
	finding, err := verifier.GetFinding(first.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if len(finding.VerificationRunIDs) != 2 {
		t.Fatalf("run ids = %v, want both runs", finding.VerificationRunIDs)
	}
	if finding.Version < 2 {
		t.Fatalf("finding version = %d, want it to advance", finding.Version)
	}
	if len(finding.Supporting) != 2 {
		t.Fatalf("supporting evidence = %v, want evidence from both runs", finding.Supporting)
	}
	if executor.calls != 2 {
		t.Fatalf("executor calls = %d, want 2", executor.calls)
	}
}

// --- Verifier reads ----------------------------------------------------------

func TestVerifierReadPassThroughs(t *testing.T) {
	executor := NewScriptedExecutor(confirmedScript())
	verifier, _ := newTestVerifier(t, executor)
	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: servicePlan(t)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	got, err := verifier.GetRun(run.ID)
	if err != nil || got.ID != run.ID {
		t.Fatalf("GetRun = %+v, %v", got, err)
	}
	runs, total, err := verifier.ListRuns(RunQuery{HypothesisID: run.HypothesisID})
	if err != nil || total != 1 || len(runs) != 1 {
		t.Fatalf("ListRuns = %d/%d, %v", len(runs), total, err)
	}
	if _, err := verifier.GetEvidence(run.EvidenceIDs[0]); err != nil {
		t.Fatalf("GetEvidence: %v", err)
	}
	findings, total, err := verifier.ListFindings(FindingQuery{SnapshotID: run.SnapshotID})
	if err != nil || total != 1 || len(findings) != 1 {
		t.Fatalf("ListFindings = %d/%d, %v", len(findings), total, err)
	}
	filtered, _, err := verifier.ListFindingsWithApply(FindingQuery{}, func(in []Finding) []Finding {
		out := []Finding{}
		for _, finding := range in {
			if finding.Status == FindingConfirmed {
				out = append(out, finding)
			}
		}
		return out
	})
	if err != nil || len(filtered) != 1 {
		t.Fatalf("ListFindingsWithApply = %d, %v", len(filtered), err)
	}
	if _, err := verifier.GetRun("vrun-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetRun(missing) = %v, want ErrNotFound", err)
	}
}

// --- report fixture helper ---------------------------------------------------

// reportFindings builds one finding per status with its evidence, so the report
// renderers are tested against the whole vocabulary.
func reportFixture(t *testing.T) ([]Finding, map[string][]Evidence) {
	t.Helper()
	now := "2024-03-04T05:06:07Z"
	findings := []Finding{}
	evidence := map[string][]Evidence{}
	add := func(status FindingStatus, severity, title, content string, kind EvidenceKind, contradicting bool) Finding {
		id := FindingID("hyp-" + title)
		object, err := NewEvidence(kind, content, EvidenceOptions{
			Tool: "fixture", SnapshotID: "snap-report-1", FindingID: id, HypothesisID: "hyp-" + title,
			File: "internal/api/handler.go", Line: 42, Now: now,
		})
		if err != nil {
			t.Fatalf("NewEvidence: %v", err)
		}
		if contradicting {
			object = MarkContradicting(object, "the control rejects the request")
		}
		finding := Finding{
			ID: id, HypothesisID: "hyp-" + title, PathID: "path-" + title, AuditID: "audit-report-1",
			SnapshotID: "snap-report-1", Title: title, Severity: severity, Status: status,
			Confidence: "high", VerificationRunIDs: []string{"vrun-" + title},
			Environments: []string{"env-fixture"}, ReproduceSteps: "step 1: run the proof",
			Limitations: []string{"no deployed target for the last hop"},
			CreatedAt:   now, UpdatedAt: now, Version: 1,
		}
		switch {
		case contradicting:
			finding.Contradicting = []string{object.ID}
		case status == FindingConfirmed:
			finding.Supporting = []string{object.ID}
		default:
			finding.Inconclusive = []string{object.ID}
		}
		findings = append(findings, finding)
		evidence[id] = []Evidence{object}
		return finding
	}
	add(FindingConfirmed, "high", "path traversal in export", "confirmed by reproduction", EvidenceRuntimeLog, false)
	add(FindingRefuted, "low", "ssrf in webhook", "the control rejects the request", EvidenceRuntimeLog, true)
	add(FindingInconclusive, "medium", "weak hashing in tokens", "the evidence is insufficient", EvidenceSource, false)
	add(FindingBlocked, "critical", "deserialization in cache", "no adapter for this step kind", EvidenceEnvironment, false)
	add(FindingCandidate, "high", "unverified candidate", "not yet verified", EvidenceSource, false)
	return findings, evidence
}

// --- the evidence-list merge rule ---------------------------------------------

// TestVerifyContradictingEvidenceNeverLandsInSupporting pins the observed failure
// directly: a run whose only evidence contradicts the claim must produce a
// refutation whose supporting list holds only the hypothesis-side citations, never
// the contradicting object.
func TestVerifyContradictingEvidenceNeverLandsInSupporting(t *testing.T) {
	plan := servicePlan(t)
	citation, err := NewEvidence(EvidenceSource, "source note: the control is registered on this path", EvidenceOptions{
		Tool: "planner", SnapshotID: plan.SnapshotID, HypothesisID: plan.HypothesisID,
		FindingID: plan.FindingID, PathID: plan.PathID, Now: "2024-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	contradiction, err := NewEvidence(EvidenceRuntimeLog, "permission denied", EvidenceOptions{
		Tool: "hostile", SnapshotID: plan.SnapshotID, HypothesisID: plan.HypothesisID,
		FindingID: plan.FindingID, PathID: plan.PathID, Now: "2024-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	contradiction = MarkContradicting(contradiction, "the control rejects the request")

	store := newMemoryVerifyStore()
	// The planner already derived the candidate and filed its citation as a lead.
	// The planner's own build keeps citations in Supporting and leaves the
	// inconclusive ownership to verification, so seeding it there is the harder
	// case: the merge must move it out, not leave it as apparent proof.
	if err := store.AppendEvidence([]Evidence{citation, contradiction}); err != nil {
		t.Fatalf("AppendEvidence: %v", err)
	}
	if err := store.UpsertFinding(Finding{
		ID: plan.FindingID, HypothesisID: plan.HypothesisID, PathID: plan.PathID,
		AuditID: plan.AuditID, SnapshotID: plan.SnapshotID, Title: plan.Claim,
		Status: FindingCandidate, Supporting: []string{citation.ID}, Contradicting: []string{},
		Inconclusive: []string{}, VerificationRunIDs: []string{},
		Environments: []string{}, CreatedAt: "2024-01-01T00:00:00Z",
		UpdatedAt: "2024-01-01T00:00:00Z", Version: 1,
	}); err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}

	// The run's only evidence is the contradicting object.
	hostile := &hostileExecutor{result: Result{
		Outcome: OutcomeRefuted, Reason: "the control rejects the request",
		Evidence: []Evidence{contradiction}, StopReason: VerifyStopCompleted,
	}}
	verifier := NewVerifier(store, hostile)
	verifier.Now = func() time.Time { return time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC) }

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Outcome != OutcomeRefuted {
		t.Fatalf("outcome = %s, want REFUTED", run.Outcome)
	}
	finding, err := verifier.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if finding.Status != FindingRefuted {
		t.Fatalf("finding status = %s, want refuted", finding.Status)
	}
	if len(finding.Contradicting) == 0 {
		t.Fatal("a refutation kept no contradicting evidence")
	}
	if !contains(finding.Contradicting, contradiction.ID) {
		t.Fatalf("the contradicting object is not in the contradicting list: %+v", finding.Contradicting)
	}
	if contains(finding.Supporting, contradiction.ID) {
		t.Fatalf("the contradicting object leaked into the supporting list: %+v", finding.Supporting)
	}
	if contains(finding.Supporting, citation.ID) {
		t.Fatalf("a refutation kept a hypothesis-side citation as support: %+v", finding.Supporting)
	}
	if !contains(finding.Inconclusive, citation.ID) {
		t.Fatalf("the hypothesis-side citation was lost or misfiled: supporting=%+v inconclusive=%+v",
			finding.Supporting, finding.Inconclusive)
	}
	assertDisjointLists(t, finding)
}

// TestVerifyPlentifulSupportingEvidenceWithoutContradictionIsInconclusive pins the
// other half: support that no contradiction backs is not a verdict. The executor
// claims REFUTED; DeriveOutcome refuses, and no list is allowed to promote it.
func TestVerifyPlentifulSupportingEvidenceWithoutContradictionIsInconclusive(t *testing.T) {
	plan := servicePlan(t)
	evidence := []Evidence{}
	for i := 0; i < 3; i++ {
		object, err := NewEvidence(EvidenceRuntimeLog, fmt.Sprintf("step[%d] reproduced the read", i), EvidenceOptions{
			Tool: "hostile", SnapshotID: plan.SnapshotID, HypothesisID: plan.HypothesisID,
			FindingID: plan.FindingID, PathID: plan.PathID, Now: "2024-01-01T00:00:00Z",
		})
		if err != nil {
			t.Fatalf("NewEvidence: %v", err)
		}
		evidence = append(evidence, object)
	}
	hostile := &hostileExecutor{result: Result{
		Outcome: OutcomeRefuted, Reason: "we could not reproduce it",
		Reproduction: "step 0: the read succeeded",
		Evidence:     evidence, StopReason: VerifyStopCompleted,
	}}
	verifier, _ := newTestVerifier(t, hostile)

	run, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if run.Outcome != OutcomeInconclusive {
		t.Fatalf("outcome = %s, want INCONCLUSIVE: no contradicting evidence exists", run.Outcome)
	}
	finding, err := verifier.GetFinding(run.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if finding.Status != FindingInconclusive {
		t.Fatalf("finding status = %s, want inconclusive", finding.Status)
	}
	if len(finding.Contradicting) != 0 {
		t.Fatalf("contradicting evidence appeared without any: %+v", finding.Contradicting)
	}
	if len(finding.Supporting) != 0 {
		t.Fatalf("an inconclusive finding claims support: %+v", finding.Supporting)
	}
	if len(finding.Inconclusive) != len(evidence) {
		t.Fatalf("inconclusive evidence = %d, want %d", len(finding.Inconclusive), len(evidence))
	}
	assertDisjointLists(t, finding)
}

// TestVerifyMergeNeverMovesAnIDBetweenLists seeds a finding whose contradicting
// list already holds an id that a later run would classify as supporting. The id
// must stay contradicting, and must not appear twice.
func TestVerifyMergeNeverMovesAnIDBetweenLists(t *testing.T) {
	plan := servicePlan(t)
	hostile := &hostileExecutor{}
	verifier, store := newTestVerifier(t, hostile)
	verifier.Now = func() time.Time { return time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC) }

	// A first, confirming run produces the reproduction evidence the later merge
	// will see. The plan is then submitted again to prove the replay path.
	hostile.result = Result{
		Outcome: OutcomeConfirmed, Reason: "reproduced",
		Reproduction: "step 0: the read succeeded",
		Evidence:     []Evidence{newFixtureEvidence(t, plan, EvidenceRuntimeLog, "step[0] the read succeeded")},
		StopReason:   VerifyStopCompleted,
	}
	first, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	produced := evidenceOfFinding(t, verifier, first.FindingID)
	if len(produced) != 1 {
		t.Fatalf("first run produced %d evidence objects, want 1", len(produced))
	}
	id := produced[0].ID

	// A replay must not write anything, so the finding's lists stay as they were.
	replay, err := verifier.Verify(context.Background(), VerifyRequest{Plan: plan})
	if err != nil {
		t.Fatalf("replay Verify: %v", err)
	}
	if replay.ID != first.ID {
		t.Fatalf("replay produced run %s, want %s", replay.ID, first.ID)
	}
	if hostile.calls != 1 {
		t.Fatalf("executor calls = %d, want 1: the same plan is a replay", hostile.calls)
	}

	// Seed the mistake this rule exists to prevent: the same id in two lists, with
	// the contradicting one already filed.
	seed, err := verifier.GetFinding(first.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	seed.Supporting = []string{id}
	seed.Contradicting = []string{id}
	seed.Inconclusive = []string{}
	seed.Status = FindingRefuted
	if err := store.UpsertFinding(*seed); err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}

	// A different plan for the same hypothesis runs again and returns the same
	// evidence, which the merge must file exactly once, as contradicting.
	secondPlan := servicePlan(t, Step{
		Kind: StepStaticCheck, Command: []string{"echo", "the read succeeded again"},
		Expectation: "the read succeeds", Contradiction: "the read is rejected",
	})
	second, err := verifier.Verify(context.Background(), VerifyRequest{Plan: secondPlan})
	if err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	if second.Outcome != OutcomeConfirmed {
		t.Fatalf("second outcome = %s, want CONFIRMED", second.Outcome)
	}
	finding, err := verifier.GetFinding(first.FindingID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if contains(finding.Supporting, id) {
		t.Fatalf("an id that was already contradicting was moved into support: %+v", finding.Supporting)
	}
	if !contains(finding.Contradicting, id) {
		t.Fatalf("the contradicting id was dropped: %+v", finding.Contradicting)
	}
	assertDisjointLists(t, finding)
}

// newFixtureEvidence builds one deterministic evidence object for a plan.
func newFixtureEvidence(t *testing.T, plan Plan, kind EvidenceKind, content string) Evidence {
	t.Helper()
	object, err := NewEvidence(kind, content, EvidenceOptions{
		Tool: "fixture", ToolVersion: "1", SnapshotID: plan.SnapshotID,
		HypothesisID: plan.HypothesisID, FindingID: plan.FindingID, PathID: plan.PathID,
		Now: "2024-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	return object
}

// evidenceOfFinding reads the stored evidence attached to a finding. It reads
// through the store rather than through a hand-held list, because a real backend
// derives Run.EvidenceIDs on read rather than from what a caller wrote.
func evidenceOfFinding(t *testing.T, verifier *Verifier, findingID string) []Evidence {
	t.Helper()
	evidence, _, err := verifier.ListEvidence(EvidenceQuery{FindingID: findingID, Limit: 100})
	if err != nil {
		t.Fatalf("ListEvidence(%s): %v", findingID, err)
	}
	if len(evidence) == 0 {
		t.Fatalf("finding %s has no evidence", findingID)
	}
	return evidence
}

// assertDisjointLists is the invariant made mechanical: an evidence id belongs to
// exactly one of the three lists.
func assertDisjointLists(t *testing.T, finding *Finding) {
	t.Helper()
	seen := map[string]string{}
	for _, group := range []struct {
		name string
		ids  []string
	}{
		{"supporting", finding.Supporting},
		{"contradicting", finding.Contradicting},
		{"inconclusive", finding.Inconclusive},
	} {
		within := map[string]struct{}{}
		for _, id := range group.ids {
			if _, duplicate := within[id]; duplicate {
				t.Fatalf("finding %s lists %s twice in %s", finding.ID, id, group.name)
			}
			within[id] = struct{}{}
			if other, ok := seen[id]; ok {
				t.Fatalf("finding %s lists %s in both %s and %s", finding.ID, id, other, group.name)
			}
			seen[id] = group.name
		}
	}
}
