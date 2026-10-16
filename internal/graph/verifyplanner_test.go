package graph_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// verifyStatement is the claim the fixture hypothesis records. It is deliberately
// distinct so a plan or a finding that lost it fails loudly.
const verifyStatement = "the request name reaches the query without parameterisation"

// verifyRunLimitation is the caveat the fixture agent run carries. It is written
// here as a value no other layer produces, so a test can prove the limitations
// really travel from the run that recorded the claim.
const verifyRunLimitation = "the fixture run could not trace the request name through the ORM"

// verifyStamp makes every timestamp the planner derives deterministic.
var verifyStamp = time.Date(2024, 6, 1, 9, 0, 0, 0, time.UTC)

// verifyFixture is one real graph plus one stored hypothesis and its producing
// run, which is everything the planner reads.
type verifyFixture struct {
	*agentFixture
	planner     *graph.VerifyPlanner
	hypothesis  *agent.Hypothesis
	target      path.Path
	scope       verify.Scope
	environment verify.Environment
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	fixture := newAgentFixture(t)
	target := fixture.paths[0]
	runID := agent.RunID(target.ID, "scripted", 1)
	run := agent.Run{
		ID: runID, PathID: target.ID, AuditID: fixture.auditID, SnapshotID: agentSnapID,
		Runtime: "scripted", RuntimeVersion: "1", Status: agent.RunSucceeded,
		Task: agent.Task{
			SchemaVersion: agent.SchemaVersion, SnapshotID: agentSnapID, PathID: target.ID,
			AuditID: fixture.auditID,
			// A real task always carries a security goal; the plan inherits it when
			// the hypothesis does not restate one.
			SecurityGoal: "establish whether attacker-controlled input reaches the sensitive operation",
			Limitations:  []string{verifyRunLimitation},
		},
		CreatedAt: agent.NowString(verifyStamp), UpdatedAt: agent.NowString(verifyStamp), Version: 1,
	}
	if err := fixture.store.CreateRun(run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	hypothesis := agent.Hypothesis{
		ID:    agent.HypothesisID(target.ID, verifyStatement),
		RunID: runID, PathID: target.ID, AuditID: fixture.auditID, SnapshotID: agentSnapID,
		SecurityGoal: "establish whether attacker-controlled input reaches the sensitive operation",
		Statement:    verifyStatement, Status: agent.HypothesisCandidate, Confidence: "medium",
		Supporting: []agent.EvidenceRef{
			{Kind: agent.EvidenceSource, ID: "sym-support", File: "web/server.go", Line: 12, Summary: "the handler concatenates the request name"},
			{Kind: agent.EvidenceStatic, ID: "cs-1", Summary: "call site cs-1 is unresolved"},
		},
		Contradicting: []agent.EvidenceRef{
			{Kind: agent.EvidenceSource, ID: "sym-contra", File: "web/server.go", Line: 42, Summary: "the query builder binds the name"},
		},
		FindingCandidate: true,
		SeverityHint:     "high",
		Digest:           agent.Digest(verifyStatement),
	}
	if err := fixture.store.SaveHypotheses([]agent.Hypothesis{hypothesis}); err != nil {
		t.Fatalf("SaveHypotheses: %v", err)
	}
	stored, err := fixture.store.GetHypothesis(hypothesis.ID)
	if err != nil {
		t.Fatalf("GetHypothesis: %v", err)
	}
	planner := graph.NewVerifyPlanner(fixture.store, fixture.scg)
	planner.Now = func() time.Time { return verifyStamp }
	return &verifyFixture{
		agentFixture: fixture,
		planner:      planner,
		hypothesis:   stored,
		target:       target,
		scope:        verify.Scope{Repository: "example.invalid/svc", AllowedTargets: []string{"app.invalid"}},
		environment:  verify.Environment{Profile: "sandbox-verify", SourceReadOnly: true, Network: verify.NetworkNone},
	}
}

func TestVerifyPlannerBuildsAPreparedPlan(t *testing.T) {
	t.Parallel()
	fixture := newVerifyFixture(t)
	prepared, err := fixture.planner.BuildPlan(context.Background(), fixture.hypothesis.ID, fixture.scope, fixture.environment)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	// Prepare is what makes a plan executable; a planner that returned an
	// unprepared plan would turn a builder bug into a broken run.
	if err := verify.ValidatePlan(prepared.Plan); err != nil {
		t.Fatalf("the built plan does not validate: %v", err)
	}
	plan := prepared.Plan
	if plan.Claim != verifyStatement {
		t.Errorf("claim = %q, want the hypothesis statement", plan.Claim)
	}
	if plan.SecurityGoal == "" {
		t.Error("the plan carries no security goal")
	}
	if plan.FindingID != verify.FindingID(fixture.hypothesis.ID) {
		t.Errorf("finding id = %q, want the derived finding", plan.FindingID)
	}
	if plan.HypothesisID != fixture.hypothesis.ID || plan.PathID != fixture.target.ID ||
		plan.AuditID != fixture.auditID || plan.SnapshotID != agentSnapID {
		t.Errorf("the plan does not identify its hypothesis, path, audit and snapshot: %+v", plan)
	}
	if plan.PlanHash == "" || plan.PlanHash != verify.PlanHashOf(plan) {
		t.Errorf("plan hash %q is not the hash of the plan", plan.PlanHash)
	}
	if plan.Scope.Repository != fixture.scope.Repository {
		t.Errorf("the scope was not passed through: %+v", plan.Scope)
	}
	if plan.Scope.SnapshotID != agentSnapID {
		t.Errorf("the scope snapshot was not filled from the hypothesis: %+v", plan.Scope)
	}
	if plan.Environment.Profile != "sandbox-verify" {
		t.Errorf("environment profile = %q", plan.Environment.Profile)
	}
	if plan.Environment.CPUMillis != verify.DefaultEnvironment().CPUMillis {
		t.Errorf("the environment was not normalized: %+v", plan.Environment)
	}

	kinds := map[verify.StepKind]bool{}
	for _, step := range plan.Steps {
		kinds[step.Kind] = true
		if strings.TrimSpace(step.Expectation) == "" {
			t.Errorf("step %s has no expectation", step.Kind)
		}
		if strings.TrimSpace(step.Contradiction) == "" {
			t.Errorf("step %s states no contradiction", step.Kind)
		}
	}
	if !kinds[verify.StepStaticCheck] {
		t.Error("the plan has no static check of the reachability claim")
	}
	if !kinds[verify.StepDataflowProbe] {
		t.Error("the plan has no dataflow probe for the gap it must close")
	}
	if kinds[verify.StepDynamicProof] {
		t.Error("a plan without network authorization carries a dynamic proof")
	}

	// The limitations the plan inherits are the whole reason it is honest about
	// what it is testing.
	limitations := strings.Join(plan.Limitations, "\n")
	for _, want := range []string{"not dataflow", "not its effectiveness", verifyRunLimitation} {
		if !strings.Contains(limitations, want) {
			t.Errorf("the plan does not carry the limitation %q:\n%s", want, limitations)
		}
	}
}

func TestVerifyPlannerAddsAnApprovalGatedDynamicProofOnlyForNetwork(t *testing.T) {
	t.Parallel()
	fixture := newVerifyFixture(t)
	scope := verify.Scope{
		Repository: "example.invalid/svc", AllowNetwork: true,
		AllowedTargets: []string{"app.invalid"}, RequiresHumanApproval: true,
	}
	environment := verify.Environment{
		Profile: "sandbox-verify", SourceReadOnly: true,
		Network: verify.NetworkTargetOnly, AllowedHosts: []string{"app.invalid"},
	}
	prepared, err := fixture.planner.BuildPlan(context.Background(), fixture.hypothesis.ID, scope, environment)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	var dynamic *verify.Step
	for i := range prepared.Plan.Steps {
		if prepared.Plan.Steps[i].Kind == verify.StepDynamicProof {
			dynamic = &prepared.Plan.Steps[i]
		}
	}
	if dynamic == nil {
		t.Fatal("a network-authorized plan carries no dynamic proof")
	}
	if !dynamic.RequiresApproval {
		t.Error("the dynamic proof is not marked as requiring approval")
	}
	if len(dynamic.Command) == 0 {
		t.Error("the dynamic proof names no command")
	}
	if !prepared.NeedsApproval {
		t.Error("a plan with a dynamic proof must report that it needs approval")
	}
	// The gate is real: the same plan is refused without a recorded approver and
	// accepted once one is named.
	if err := verify.Authorize(prepared, false, ""); !errors.Is(err, verify.ErrApprovalRequired) {
		t.Errorf("Authorize without an approval = %v, want ErrApprovalRequired", err)
	}
	if err := verify.Authorize(prepared, true, "operator"); err != nil {
		t.Errorf("Authorize with an approval = %v", err)
	}
}

func TestVerifyPlannerEnsureFindingIsIdempotent(t *testing.T) {
	t.Parallel()
	fixture := newVerifyFixture(t)
	ctx := context.Background()

	first, err := fixture.planner.EnsureFinding(ctx, fixture.hypothesis.ID)
	if err != nil {
		t.Fatalf("EnsureFinding: %v", err)
	}
	if first.ID != verify.FindingID(fixture.hypothesis.ID) {
		t.Errorf("finding id = %q, want the derived id", first.ID)
	}
	if first.Status != verify.FindingCandidate {
		t.Errorf("status = %q, want candidate", first.Status)
	}
	if first.Title != verifyStatement {
		t.Errorf("title = %q, want the hypothesis statement", first.Title)
	}
	if first.Severity != "high" {
		t.Errorf("severity = %q, want the hypothesis severity hint", first.Severity)
	}
	// Every citation the hypothesis records lands in Supporting: the
	// contradicting/inconclusive lists belong to the verification service, and a
	// citation written into them would be read as a verdict the planner never
	// reached. The polarity survives as the contradiction marker on the object.
	if len(first.Supporting) != 3 || len(first.Contradicting) != 0 || len(first.Inconclusive) != 0 {
		t.Fatalf("the seeded finding misclassified its citations: %+v", first)
	}

	evidence, total, err := fixture.store.ListEvidence(verify.EvidenceQuery{FindingID: first.ID, Limit: 100})
	if err != nil {
		t.Fatalf("ListEvidence: %v", err)
	}
	if total != 3 || len(evidence) != 3 {
		t.Fatalf("evidence total = %d, want one object per distinct citation", total)
	}
	kinds := map[verify.EvidenceKind]int{}
	marked := 0
	for _, object := range evidence {
		kinds[object.Kind]++
		if object.Tool != "hypothesis-evidence" || object.ToolVersion != "1" {
			t.Errorf("evidence %s names tool %q@%q", object.ID, object.Tool, object.ToolVersion)
		}
		if object.SnapshotID != agentSnapID || object.HypothesisID != fixture.hypothesis.ID || object.FindingID != first.ID {
			t.Errorf("evidence %s lost its provenance: %+v", object.ID, object)
		}
		if object.Content == "" || object.ContentHash == "" {
			t.Errorf("evidence %s has no content or hash", object.ID)
		}
		if strings.HasPrefix(object.RedactionNotes, verify.ContradictionMarker) {
			marked++
			if !strings.Contains(object.Content, "sym-contra") {
				t.Errorf("the marked evidence is not the contradicting citation: %+v", object)
			}
		}
	}
	if marked != 1 {
		t.Errorf("marked evidence = %d, want exactly the one contradicting citation", marked)
	}
	if kinds[verify.EvidenceSource] != 2 {
		t.Errorf("source evidence = %d, want the two file citations", kinds[verify.EvidenceSource])
	}
	if kinds[verify.EvidenceStaticQuery] != 1 {
		t.Errorf("static_query evidence = %d, want the one id-only citation", kinds[verify.EvidenceStaticQuery])
	}

	// A second derivation is byte-identical: it neither rewrites the document nor
	// moves its version, and it adds no evidence.
	second, err := fixture.planner.EnsureFinding(ctx, fixture.hypothesis.ID)
	if err != nil {
		t.Fatalf("second EnsureFinding: %v", err)
	}
	if second.ID != first.ID || second.Status != first.Status {
		t.Errorf("the second run produced a different finding: %+v", second)
	}
	if second.UpdatedAt != first.UpdatedAt || second.Version != first.Version {
		t.Errorf("a re-derivation moved the stored document: version %d -> %d, updated %s -> %s",
			first.Version, second.Version, first.UpdatedAt, second.UpdatedAt)
	}
	if len(second.Supporting) != len(first.Supporting) || len(second.Contradicting) != len(first.Contradicting) ||
		len(second.Inconclusive) != len(first.Inconclusive) {
		t.Errorf("the second run duplicated citations: %+v", second)
	}
	evidenceAgain, totalAgain, err := fixture.store.ListEvidence(verify.EvidenceQuery{FindingID: first.ID, Limit: 100})
	if err != nil {
		t.Fatalf("ListEvidence: %v", err)
	}
	if totalAgain != total || len(evidenceAgain) != len(evidence) {
		t.Errorf("evidence grew from %d to %d on a re-run", total, totalAgain)
	}
}

func TestVerifyPlannerNeverSeedsAfterVerification(t *testing.T) {
	t.Parallel()
	fixture := newVerifyFixture(t)
	ctx := context.Background()
	finding, err := fixture.planner.EnsureFinding(ctx, fixture.hypothesis.ID)
	if err != nil {
		t.Fatalf("EnsureFinding: %v", err)
	}

	// A verification has settled the claim and consumed the lists; re-deriving the
	// candidate must not reset the verdict.
	finding.Status = verify.FindingConfirmed
	finding.Confidence = "high"
	finding.Supporting = []string{}
	finding.Contradicting = []string{}
	finding.Inconclusive = []string{}
	if err := fixture.store.UpsertFinding(*finding); err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}
	settled, err := fixture.store.GetFinding(finding.ID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	again, err := fixture.planner.EnsureFinding(ctx, fixture.hypothesis.ID)
	if err != nil {
		t.Fatalf("EnsureFinding: %v", err)
	}
	if again.Status != verify.FindingConfirmed || again.Confidence != "high" {
		t.Errorf("the settled finding was reset: %+v", again)
	}
	// Even with empty lists, a conclusive finding is never re-seeded: the lists
	// belong to verification after the first run.
	if len(again.Supporting) != 0 || len(again.Contradicting) != 0 || len(again.Inconclusive) != 0 {
		t.Errorf("a settled finding was re-seeded: %+v", again)
	}
	if again.UpdatedAt != settled.UpdatedAt || again.Version != settled.Version {
		t.Errorf("re-deriving a settled finding moved it: version %d -> %d", settled.Version, again.Version)
	}

	// A candidate whose lists are already populated is not re-seeded either: the
	// planner writes once.
	populated := *again
	populated.Status = verify.FindingCandidate
	populated.Supporting = []string{"ev-already-there"}
	if err := fixture.store.UpsertFinding(populated); err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}
	untouched, err := fixture.planner.EnsureFinding(ctx, fixture.hypothesis.ID)
	if err != nil {
		t.Fatalf("EnsureFinding: %v", err)
	}
	if len(untouched.Supporting) != 1 || untouched.Supporting[0] != "ev-already-there" {
		t.Errorf("the planner rewrote a populated finding: %+v", untouched)
	}
}

func TestVerifyPlannerReportsAMissingHypothesisAsNotFound(t *testing.T) {
	t.Parallel()
	fixture := newVerifyFixture(t)
	ctx := context.Background()
	if _, err := fixture.planner.EnsureFinding(ctx, "hyp-does-not-exist"); !errors.Is(err, verify.ErrNotFound) {
		t.Errorf("EnsureFinding on an unknown hypothesis = %v, want ErrNotFound", err)
	}
	if _, err := fixture.planner.BuildPlan(ctx, "hyp-does-not-exist", fixture.scope, fixture.environment); !errors.Is(err, verify.ErrNotFound) {
		t.Errorf("BuildPlan on an unknown hypothesis = %v, want ErrNotFound", err)
	}
}
