package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// The verification tests drive a real graph, a real agent run and a real store
// through a deterministic executor. They deliberately use app.Build rather than a
// hand-wired server, because the bug they are looking for — a verdict that reaches
// a finding without the evidence to carry it — lives in the wiring, not in the
// handler.

// newVerificationEnv serves a runtime with both the agent and the verification
// layer wired, and replaces the scripted executor with answer's own.
func newVerificationEnv(t *testing.T, script []verify.StepOutcome, answer func(goal string) agent.Answer) *testEnv {
	t.Helper()
	rt, err := app.Build(context.Background(), app.Config{
		Workspace: filepath.Join(t.TempDir(), "work"),
		DBPath:    "memory",
		Agent: app.AgentConfig{
			Enabled:            true,
			Runtime:            app.AgentRuntimeScripted,
			ScriptedAnswerJSON: agentTestPlaceholderAnswer(t),
			MaxToolCalls:       30,
		},
		Verification: app.VerificationConfig{
			Enabled:       true,
			Executor:      app.VerifyExecutorScripted,
			ScriptedSteps: script,
		},
	})
	if err != nil {
		t.Fatalf("app.Build with verification: %v", err)
	}
	if rt.Verifier == nil || rt.VerifyPlanner == nil {
		t.Fatalf("the configured verification layer was not wired")
	}
	rt.Agent.Runtime = &echoRuntime{Answer: answer}
	return serveTestEnv(t, rt, false)
}

// verificationHypothesis identifies the chain a verification test needs: the audit
// that owns the claim, the snapshot it was recorded over, and the claim itself.
type verificationHypothesis struct {
	AuditID      string
	SnapshotID   string
	PathID       string
	HypothesisID string
}

// createVerifiableHypothesis freezes the fixture, audits it, runs one agent over
// it and returns the claim that run recorded.
func createVerifiableHypothesis(t *testing.T, ts *httptest.Server) verificationHypothesis {
	t.Helper()
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})
	resp := startRun(t, ts, "/api/audits/"+audit.Audit.ID+"/runs", map[string]any{}, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("start run = %d, want 200 (%s)", resp.status, resp.body)
	}
	var batch runBatch
	resp.decode(t, &batch)
	if len(batch.Runs) != 1 {
		t.Fatalf("run batch = %s", resp.body)
	}
	run := batch.Runs[0]
	page := do(t, ts, http.MethodGet, "/api/paths/"+run.PathID+"/hypotheses", nil, nil)
	if page.status != http.StatusOK {
		t.Fatalf("path hypotheses = %d (%s)", page.status, page.body)
	}
	var listed struct {
		Hypotheses []agent.Hypothesis `json:"hypotheses"`
	}
	page.decode(t, &listed)
	if len(listed.Hypotheses) != 1 {
		t.Fatalf("the run recorded %d hypotheses, want 1: %s", len(listed.Hypotheses), page.body)
	}
	return verificationHypothesis{
		AuditID: audit.Audit.ID, SnapshotID: snapID,
		PathID: run.PathID, HypothesisID: listed.Hypotheses[0].ID,
	}
}

// verificationBody is the request shape every test posts. The scope authorizes the
// fixture's repository, and the environment is the least-privilege default with the
// explicitly required read-only flag.
func verificationBody(approved bool, approvedBy string) map[string]any {
	body := map[string]any{
		"approved": approved,
		"scope": map[string]any{
			"repository":      "example.invalid/svc",
			"allowed_targets": []string{"app.invalid"},
		},
		"environment": map[string]any{
			"profile":          "sandbox-test",
			"source_read_only": true,
			"network":          "none",
		},
	}
	if approvedBy != "" {
		body["approved_by"] = approvedBy
	}
	return body
}

// postVerification posts one verification request and returns the raw response.
func postVerification(t *testing.T, ts *httptest.Server, hypothesisID string, body map[string]any) response {
	t.Helper()
	return do(t, ts, http.MethodPost, "/api/hypotheses/"+hypothesisID+"/verifications", body, nil)
}

// confirmingScript answers every plan step with reproduction evidence, which is
// what a confirmation must rest on.
func confirmingScript() []verify.StepOutcome {
	return []verify.StepOutcome{
		{Kind: verify.EvidenceTest, Content: "ok the claim reproduced", Command: "verify test claim"},
		{Kind: verify.EvidenceRuntimeLog, Content: "runtime log: the claim reproduced"},
	}
}

func TestVerificationFindingIsIdempotentAndListed(t *testing.T) {
	t.Parallel()
	env := newVerificationEnv(t, nil, agentTestAnswer)
	ts := env.ts
	hypothesis := createVerifiableHypothesis(t, ts)

	first := do(t, ts, http.MethodPost, "/api/hypotheses/"+hypothesis.HypothesisID+"/finding", nil, nil)
	if first.status != http.StatusOK {
		t.Fatalf("ensure finding = %d, want 200 (%s)", first.status, first.body)
	}
	var finding verify.Finding
	first.decode(t, &finding)
	if finding.ID != verify.FindingID(hypothesis.HypothesisID) {
		t.Errorf("finding id = %q, want the derived id", finding.ID)
	}
	if finding.Status != verify.FindingCandidate {
		t.Errorf("status = %q, want candidate", finding.Status)
	}
	if finding.HypothesisID != hypothesis.HypothesisID || finding.AuditID != hypothesis.AuditID ||
		finding.SnapshotID != hypothesis.SnapshotID || finding.PathID != hypothesis.PathID {
		t.Errorf("the finding lost its provenance: %+v", finding)
	}
	// The hypothesis's own citation is seeded into Supporting; the contradicting
	// and inconclusive lists belong to the verification service.
	if len(finding.Supporting) != 1 || len(finding.Contradicting) != 0 || len(finding.Inconclusive) != 0 {
		t.Fatalf("the seeded finding misclassified its citation: %+v", finding)
	}

	// Re-running converges: same finding, no duplicated evidence.
	second := do(t, ts, http.MethodPost, "/api/hypotheses/"+hypothesis.HypothesisID+"/finding", nil, nil)
	if second.status != http.StatusOK {
		t.Fatalf("second ensure finding = %d (%s)", second.status, second.body)
	}
	var again verify.Finding
	second.decode(t, &again)
	if again.ID != finding.ID || len(again.Supporting) != len(finding.Supporting) ||
		again.UpdatedAt != finding.UpdatedAt || again.Version != finding.Version {
		t.Errorf("the second derivation changed the finding: %+v, want %+v", again, finding)
	}

	// The write goes through the idempotency wrapper like every other write.
	headers := map[string]string{"Idempotency-Key": "finding-key-1"}
	keyed := do(t, ts, http.MethodPost, "/api/hypotheses/"+hypothesis.HypothesisID+"/finding", nil, headers)
	replay := do(t, ts, http.MethodPost, "/api/hypotheses/"+hypothesis.HypothesisID+"/finding", nil, headers)
	if string(keyed.body) != string(replay.body) || replay.header.Get("Idempotent-Replay") != "true" {
		t.Errorf("the idempotent replay differs:\n%s\n%s", keyed.body, replay.body)
	}

	list := do(t, ts, http.MethodGet, "/api/findings?audit_id="+hypothesis.AuditID, nil, nil)
	if list.status != http.StatusOK {
		t.Fatalf("list findings = %d (%s)", list.status, list.body)
	}
	var page struct {
		Findings []verify.Finding `json:"findings"`
		Total    int              `json:"total"`
	}
	list.decode(t, &page)
	if page.Total != 1 || len(page.Findings) != 1 || page.Findings[0].ID != finding.ID {
		t.Errorf("findings page = %s", list.body)
	}

	// The detail carries the evidence grouped by what it does to the claim.
	detail := do(t, ts, http.MethodGet, "/api/findings/"+finding.ID, nil, nil)
	if detail.status != http.StatusOK {
		t.Fatalf("get finding = %d (%s)", detail.status, detail.body)
	}
	var document findingDetail
	detail.decode(t, &document)
	if document.Finding.ID != finding.ID {
		t.Errorf("finding detail = %+v", document.Finding)
	}
	if len(document.Evidence.Supporting) != 1 || document.Evidence.Supporting[0].Kind != verify.EvidenceSource {
		t.Errorf("grouped evidence = %+v", document.Evidence)
	}
	if len(document.Verifications) != 0 {
		t.Errorf("a candidate finding already carries verifications: %+v", document.Verifications)
	}

	// The evidence object itself is readable, with its provenance intact.
	evidenceID := finding.Supporting[0]
	one := do(t, ts, http.MethodGet, "/api/evidence/"+evidenceID, nil, nil)
	if one.status != http.StatusOK {
		t.Fatalf("get evidence = %d (%s)", one.status, one.body)
	}
	var object verify.Evidence
	one.decode(t, &object)
	if object.Kind != verify.EvidenceSource || object.File != "main.go" || object.Line != 12 {
		t.Errorf("evidence = %+v", object)
	}
	if object.Tool != "hypothesis-evidence" || object.SnapshotID != hypothesis.SnapshotID {
		t.Errorf("evidence lost its provenance: %+v", object)
	}
	if !strings.Contains(object.Content, "main.go:12") {
		t.Errorf("evidence content does not name its location: %q", object.Content)
	}
}

func TestVerificationConfirmsOnlyWithReproductionEvidence(t *testing.T) {
	t.Parallel()
	env := newVerificationEnv(t, confirmingScript(), agentTestAnswer)
	ts := env.ts
	hypothesis := createVerifiableHypothesis(t, ts)

	resp := postVerification(t, ts, hypothesis.HypothesisID, verificationBody(true, "operator"))
	if resp.status != http.StatusOK {
		t.Fatalf("verify = %d, want 200 (%s)", resp.status, resp.body)
	}
	var run verify.Run
	resp.decode(t, &run)
	if run.Outcome != verify.OutcomeConfirmed {
		t.Fatalf("outcome = %s, want CONFIRMED (%s)", run.Outcome, resp.body)
	}
	if run.Status != verify.VerifySucceeded {
		t.Errorf("status = %s, want SUCCEEDED", run.Status)
	}
	// The document carries the plan, the environment digest and the approval.
	if run.PlanHash == "" || len(run.Plan.Steps) == 0 || run.EnvironmentDigest == "" {
		t.Errorf("the run lost its plan or environment: %+v", run)
	}
	if !run.Approved || run.ApprovedBy != "operator" || run.ApprovedAt == "" {
		t.Errorf("the approval was not recorded on the run: %+v", run)
	}
	if len(run.EvidenceIDs) == 0 {
		t.Error("a confirmation recorded no evidence")
	}

	evidence := do(t, ts, http.MethodGet, "/api/verifications/"+run.ID+"/evidence", nil, nil)
	if evidence.status != http.StatusOK {
		t.Fatalf("verification evidence = %d (%s)", evidence.status, evidence.body)
	}
	var objects struct {
		Evidence []verify.Evidence `json:"evidence"`
		Total    int               `json:"total"`
	}
	evidence.decode(t, &objects)
	if objects.Total == 0 {
		t.Fatalf("the run's evidence is empty: %s", evidence.body)
	}
	sawReproduction := false
	for _, object := range objects.Evidence {
		if object.Kind == verify.EvidenceTest || object.Kind == verify.EvidenceRuntimeLog {
			sawReproduction = true
		}
		if object.VerificationRunID != run.ID {
			t.Errorf("evidence %s does not belong to run %s", object.ID, run.ID)
		}
	}
	if !sawReproduction {
		t.Errorf("a confirmation without reproduction evidence: %s", evidence.body)
	}

	finding := do(t, ts, http.MethodGet, "/api/findings/"+verify.FindingID(hypothesis.HypothesisID), nil, nil)
	if finding.status != http.StatusOK {
		t.Fatalf("get finding = %d (%s)", finding.status, finding.body)
	}
	var document findingDetail
	finding.decode(t, &document)
	if document.Finding.Status != verify.FindingConfirmed {
		t.Errorf("finding status = %s, want confirmed", document.Finding.Status)
	}
	if len(document.Finding.Supporting) == 0 || len(document.Evidence.Contradicting) != 0 {
		t.Errorf("a confirmation must rest on supporting evidence: %+v", document.Finding)
	}
	if len(document.Verifications) != 1 || document.Verifications[0].ID != run.ID {
		t.Errorf("the finding does not carry its verification: %+v", document.Verifications)
	}

	// The listing filters by outcome and by status.
	byOutcome := do(t, ts, http.MethodGet, "/api/verifications?outcome=CONFIRMED&hypothesis_id="+hypothesis.HypothesisID, nil, nil)
	if byOutcome.status != http.StatusOK || !strings.Contains(string(byOutcome.body), run.ID) {
		t.Errorf("outcome filter = %d %s", byOutcome.status, byOutcome.body)
	}
	// An unknown evidence kind is refused rather than treated as "no filter".
	badKind := do(t, ts, http.MethodGet, "/api/verifications/"+run.ID+"/evidence?kind=BOGUS", nil, nil)
	if badKind.status != http.StatusBadRequest {
		t.Errorf("unknown evidence kind = %d, want 400 (%s)", badKind.status, badKind.body)
	}
	byKind := do(t, ts, http.MethodGet, "/api/verifications/"+run.ID+"/evidence?kind=test", nil, nil)
	if byKind.status != http.StatusOK {
		t.Errorf("evidence kind filter = %d (%s)", byKind.status, byKind.body)
	}
	var filtered struct {
		Evidence []verify.Evidence `json:"evidence"`
		Total    int               `json:"total"`
	}
	byKind.decode(t, &filtered)
	if filtered.Total == 0 {
		t.Errorf("the test-kind filter returned nothing: %s", byKind.body)
	}
	for _, object := range filtered.Evidence {
		if object.Kind != verify.EvidenceTest {
			t.Errorf("the kind filter returned %s", object.Kind)
		}
	}
}

func TestVerificationWithoutReproductionIsInconclusive(t *testing.T) {
	t.Parallel()
	// The script answers every step, so the executor claims confirmation; neither
	// answer is reproduction evidence, so the derivation must demote it.
	script := []verify.StepOutcome{
		{Kind: verify.EvidenceSource, Content: "source: the handler concatenates the name"},
		{Kind: verify.EvidenceStaticQuery, Content: "query: no dataflow answer"},
	}
	env := newVerificationEnv(t, script, agentTestAnswer)
	ts := env.ts
	hypothesis := createVerifiableHypothesis(t, ts)

	resp := postVerification(t, ts, hypothesis.HypothesisID, verificationBody(false, ""))
	if resp.status != http.StatusOK {
		t.Fatalf("verify = %d (%s)", resp.status, resp.body)
	}
	var run verify.Run
	resp.decode(t, &run)
	if run.Outcome != verify.OutcomeInconclusive {
		t.Fatalf("outcome = %s, want INCONCLUSIVE: a static restatement is not proof (%s)", run.Outcome, resp.body)
	}
	finding := do(t, ts, http.MethodGet, "/api/findings/"+verify.FindingID(hypothesis.HypothesisID), nil, nil)
	var document findingDetail
	finding.decode(t, &document)
	if document.Finding.Status != verify.FindingInconclusive {
		t.Errorf("finding status = %s, want inconclusive", document.Finding.Status)
	}
	// An inconclusive run is not a refutation.
	if document.Finding.Status == verify.FindingRefuted {
		t.Errorf("an inconclusive run was recorded as a refutation: %+v", document.Finding)
	}
}

func TestVerificationRefutedNeedsContradictingEvidence(t *testing.T) {
	t.Parallel()
	script := []verify.StepOutcome{
		{Kind: verify.EvidenceRuntimeLog, Content: "permission denied", Contradicts: "the control rejects the request"},
		{Kind: verify.EvidenceSource, Content: "source note: the control is registered on this path"},
	}
	env := newVerificationEnv(t, script, agentTestAnswer)
	ts := env.ts
	hypothesis := createVerifiableHypothesis(t, ts)

	resp := postVerification(t, ts, hypothesis.HypothesisID, verificationBody(false, ""))
	if resp.status != http.StatusOK {
		t.Fatalf("verify = %d (%s)", resp.status, resp.body)
	}
	var run verify.Run
	resp.decode(t, &run)
	if run.Outcome != verify.OutcomeRefuted {
		t.Fatalf("outcome = %s, want REFUTED (%s)", run.Outcome, resp.body)
	}
	finding := do(t, ts, http.MethodGet, "/api/findings/"+verify.FindingID(hypothesis.HypothesisID), nil, nil)
	var document findingDetail
	finding.decode(t, &document)
	if document.Finding.Status != verify.FindingRefuted {
		t.Fatalf("finding status = %s, want refuted", document.Finding.Status)
	}
	if len(document.Finding.Contradicting) == 0 || len(document.Evidence.Contradicting) == 0 {
		t.Errorf("a refutation kept no contradicting evidence: %+v", document.Finding)
	}
	// The verdict rests on the contradiction, and no evidence object may be claimed
	// by two lists at once: an id in both is the overlap that makes a report
	// unreadable.
	groups := map[string][]string{
		"supporting": document.Finding.Supporting, "contradicting": document.Finding.Contradicting,
		"inconclusive": document.Finding.Inconclusive,
	}
	seen := map[string]string{}
	for name, ids := range groups {
		for _, id := range ids {
			if other, ok := seen[id]; ok {
				t.Errorf("evidence %s is in both %s and %s", id, other, name)
			}
			seen[id] = name
		}
	}
}

func TestVerificationBlockedWhenTheExecutorCannotRunThePlan(t *testing.T) {
	t.Parallel()
	env := newVerificationEnv(t, nil, agentTestAnswer)
	ts := env.ts
	hypothesis := createVerifiableHypothesis(t, ts)
	// The honest fallback: an executor that runs nothing must produce a blocked
	// finding rather than a silent gap a report would read as "nothing found".
	env.rt.Verifier.Executor = verify.NewUnsupportedExecutor("unsupported", "1", "no executor is configured for this step kind")

	resp := postVerification(t, ts, hypothesis.HypothesisID, verificationBody(false, ""))
	if resp.status != http.StatusOK {
		t.Fatalf("verify = %d (%s)", resp.status, resp.body)
	}
	var run verify.Run
	resp.decode(t, &run)
	if run.Outcome != verify.OutcomeBlocked || run.Status != verify.VerifyBlocked {
		t.Fatalf("run = %s/%s, want BLOCKED/BLOCKED (%s)", run.Outcome, run.Status, resp.body)
	}
	if run.StopReason != verify.VerifyStopUnsupported {
		t.Errorf("stop reason = %q, want %q", run.StopReason, verify.VerifyStopUnsupported)
	}
	finding := do(t, ts, http.MethodGet, "/api/findings/"+verify.FindingID(hypothesis.HypothesisID), nil, nil)
	var document findingDetail
	finding.decode(t, &document)
	if document.Finding.Status != verify.FindingBlocked {
		t.Errorf("finding status = %s, want blocked (a blocked run is never a refutation)", document.Finding.Status)
	}
}

func TestVerificationApprovalGateWritesNothingWithoutAnApprover(t *testing.T) {
	t.Parallel()
	env := newVerificationEnv(t, confirmingScript(), agentTestAnswer)
	ts := env.ts
	hypothesis := createVerifiableHypothesis(t, ts)

	// A dynamic proof needs a recorded human approval. The scope authorizes the
	// network; the request names nobody.
	body := map[string]any{
		"approved": false,
		"scope": map[string]any{
			"repository":              "example.invalid/svc",
			"allowed_targets":         []string{"app.invalid"},
			"allow_network":           true,
			"requires_human_approval": true,
		},
		"environment": map[string]any{
			"profile":          "sandbox-test",
			"source_read_only": true,
			"network":          "target_only",
			"allowed_hosts":    []string{"app.invalid"},
		},
	}
	resp := postVerification(t, ts, hypothesis.HypothesisID, body)
	if resp.status != http.StatusConflict {
		t.Fatalf("unapproved dynamic proof = %d, want 409 (%s)", resp.status, resp.body)
	}
	var failure errorResponse
	resp.decode(t, &failure)
	if failure.Code != "approval_required" {
		t.Errorf("code = %q, want approval_required", failure.Code)
	}
	// Nothing was written: no run exists and the finding is still a candidate.
	runs := do(t, ts, http.MethodGet, "/api/verifications?hypothesis_id="+hypothesis.HypothesisID, nil, nil)
	var page struct {
		Total int `json:"total"`
	}
	runs.decode(t, &page)
	if page.Total != 0 {
		t.Errorf("a refused plan wrote %d run(s): %s", page.Total, runs.body)
	}
	finding := do(t, ts, http.MethodGet, "/api/findings/"+verify.FindingID(hypothesis.HypothesisID), nil, nil)
	var document findingDetail
	finding.decode(t, &document)
	if document.Finding.Status != verify.FindingCandidate {
		t.Errorf("finding status = %s, want candidate", document.Finding.Status)
	}

	// An explicit scope violation is a different answer: the environment wants
	// egress the scope withholds.
	denied := map[string]any{
		"approved": true, "approved_by": "operator",
		"scope":       map[string]any{"repository": "example.invalid/svc"},
		"environment": map[string]any{"profile": "sandbox-test", "source_read_only": true, "network": "target_only", "allowed_hosts": []string{"app.invalid"}},
	}
	deniedResp := postVerification(t, ts, hypothesis.HypothesisID, denied)
	if deniedResp.status != http.StatusConflict {
		t.Fatalf("scope violation = %d, want 409 (%s)", deniedResp.status, deniedResp.body)
	}
	var deniedFailure errorResponse
	deniedResp.decode(t, &deniedFailure)
	if deniedFailure.Code != "scope_denied" {
		t.Errorf("code = %q, want scope_denied", deniedFailure.Code)
	}

	// And with a named approver the same plan runs.
	body["approved"] = true
	body["approved_by"] = "operator"
	approved := postVerification(t, ts, hypothesis.HypothesisID, body)
	if approved.status != http.StatusOK {
		t.Fatalf("approved dynamic proof = %d (%s)", approved.status, approved.body)
	}
	var run verify.Run
	approved.decode(t, &run)
	if !run.Approved || run.ApprovedBy != "operator" || run.ApprovedAt == "" {
		t.Errorf("the approval was not recorded: %+v", run)
	}
	if !run.NetworkAllowed {
		t.Errorf("the run does not record that the scope allowed network: %+v", run)
	}
}

func TestVerificationReplayExecutesOnce(t *testing.T) {
	t.Parallel()
	env := newVerificationEnv(t, confirmingScript(), agentTestAnswer)
	ts := env.ts
	hypothesis := createVerifiableHypothesis(t, ts)
	executor, ok := env.rt.Verifier.Executor.(*verify.ScriptedExecutor)
	if !ok {
		t.Fatalf("the configured executor is %T, want the scripted replay", env.rt.Verifier.Executor)
	}

	first := postVerification(t, ts, hypothesis.HypothesisID, verificationBody(false, ""))
	if first.status != http.StatusOK {
		t.Fatalf("first verify = %d (%s)", first.status, first.body)
	}
	var firstRun verify.Run
	first.decode(t, &firstRun)

	// The same plan for the same hypothesis is the same verification: a replay
	// returns the existing run and executes nothing.
	second := postVerification(t, ts, hypothesis.HypothesisID, verificationBody(false, ""))
	if second.status != http.StatusOK {
		t.Fatalf("replay = %d (%s)", second.status, second.body)
	}
	var secondRun verify.Run
	second.decode(t, &secondRun)
	if secondRun.ID != firstRun.ID {
		t.Errorf("the replay produced a new run %s, want %s", secondRun.ID, firstRun.ID)
	}
	if calls := executor.Calls(); calls != 1 {
		t.Errorf("the executor ran %d time(s), want 1: a replay must not execute again", calls)
	}
	runs := do(t, ts, http.MethodGet, "/api/verifications?hypothesis_id="+hypothesis.HypothesisID, nil, nil)
	var page struct {
		Total int `json:"total"`
	}
	runs.decode(t, &page)
	if page.Total != 1 {
		t.Errorf("the listing holds %d run(s), want 1", page.Total)
	}
}

func TestVerificationReportFormats(t *testing.T) {
	t.Parallel()
	env := newVerificationEnv(t, confirmingScript(), agentTestAnswer)
	ts := env.ts
	hypothesis := createVerifiableHypothesis(t, ts)
	resp := postVerification(t, ts, hypothesis.HypothesisID, verificationBody(false, ""))
	if resp.status != http.StatusOK {
		t.Fatalf("verify = %d (%s)", resp.status, resp.body)
	}

	sarif := do(t, ts, http.MethodGet, "/api/audits/"+hypothesis.AuditID+"/report?format=sarif", nil, nil)
	if sarif.status != http.StatusOK {
		t.Fatalf("sarif report = %d (%s)", sarif.status, sarif.body)
	}
	if got := sarif.header.Get("Content-Type"); got != "application/sarif+json" {
		t.Errorf("sarif content type = %q, want application/sarif+json", got)
	}
	var document struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif.body, &document); err != nil {
		t.Fatalf("sarif report is not JSON: %v\n%s", err, sarif.body)
	}
	if document.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", document.Version)
	}
	if len(document.Runs) != 1 || len(document.Runs[0].Results) == 0 {
		t.Fatalf("sarif report carries no result: %s", sarif.body)
	}

	markdown := do(t, ts, http.MethodGet, "/api/audits/"+hypothesis.AuditID+"/report?format=md", nil, nil)
	if markdown.status != http.StatusOK {
		t.Fatalf("markdown report = %d (%s)", markdown.status, markdown.body)
	}
	if got := markdown.header.Get("Content-Type"); got != "text/markdown" {
		t.Errorf("markdown content type = %q, want text/markdown", got)
	}
	if !strings.Contains(string(markdown.body), "refuted means contradicting evidence exists") {
		t.Errorf("the markdown report does not restate the caveats:\n%s", markdown.body)
	}

	jsonReport := do(t, ts, http.MethodGet, "/api/audits/"+hypothesis.AuditID+"/report?format=json", nil, nil)
	if jsonReport.status != http.StatusOK || jsonReport.header.Get("Content-Type") != "application/json" {
		t.Fatalf("json report = %d %q (%s)", jsonReport.status, jsonReport.header.Get("Content-Type"), jsonReport.body)
	}

	// A candidate is not a finding: it appears only when it is asked for.
	candidates := do(t, ts, http.MethodPost, "/api/hypotheses/"+hypothesis.HypothesisID+"/finding", nil, nil)
	if candidates.status != http.StatusOK {
		t.Fatalf("ensure finding = %d (%s)", candidates.status, candidates.body)
	}
	withoutCandidates := do(t, ts, http.MethodGet, "/api/audits/"+hypothesis.AuditID+"/report?format=json", nil, nil)
	if strings.Contains(string(withoutCandidates.body), `"status": "candidate"`) {
		t.Errorf("the report shows a candidate finding by default: %s", withoutCandidates.body)
	}

	unknown := do(t, ts, http.MethodGet, "/api/audits/"+hypothesis.AuditID+"/report?format=xml", nil, nil)
	if unknown.status != http.StatusBadRequest {
		t.Fatalf("unknown report format = %d, want 400 (%s)", unknown.status, unknown.body)
	}
	var failure errorResponse
	unknown.decode(t, &failure)
	if failure.Code != "invalid_request" || !strings.Contains(failure.Error, "sarif") {
		t.Errorf("unknown format error = %+v, want it to name the valid formats", failure)
	}
	missing := do(t, ts, http.MethodGet, "/api/audits/audit-does-not-exist/report?format=md", nil, nil)
	if missing.status != http.StatusNotFound {
		t.Errorf("report for an unknown audit = %d, want 404 (%s)", missing.status, missing.body)
	}
}

func TestVerificationUnavailableIs501(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	cases := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/api/hypotheses/hyp-any/finding", nil},
		{http.MethodPost, "/api/hypotheses/hyp-any/verifications", map[string]any{"scope": map[string]any{"repository": "r"}}},
		{http.MethodGet, "/api/verifications", nil},
		{http.MethodGet, "/api/verifications/vrun-any", nil},
		{http.MethodGet, "/api/findings", nil},
		{http.MethodGet, "/api/evidence/ev-any", nil},
		{http.MethodGet, "/api/audits/audit-any/report?format=md", nil},
	}
	for _, testCase := range cases {
		resp := do(t, ts, testCase.method, testCase.path, testCase.body, nil)
		if resp.status != http.StatusNotImplemented {
			t.Errorf("%s %s = %d, want 501 (%s)", testCase.method, testCase.path, resp.status, resp.body)
			continue
		}
		var failure errorResponse
		resp.decode(t, &failure)
		if failure.Code != "verification_unavailable" {
			t.Errorf("%s %s code = %q, want verification_unavailable", testCase.method, testCase.path, failure.Code)
		}
	}
}

func TestVerificationRoutesRequireTheRightCapability(t *testing.T) {
	t.Parallel()
	env := newVerificationEnv(t, nil, agentTestAnswer)
	ts := env.ts

	// Every verification route refuses an anonymous caller.
	for _, path := range []string{"/api/verifications", "/api/findings", "/api/evidence/ev-any"} {
		if resp := doAs(t, ts, "", http.MethodGet, path, nil, nil); resp.status != http.StatusUnauthorized {
			t.Errorf("anonymous GET %s = %d, want 401", path, resp.status)
		}
	}
	// A reader may read the surface but never write it.
	if resp := doAs(t, ts, readerSecret, http.MethodGet, "/api/findings", nil, nil); resp.status != http.StatusOK {
		t.Errorf("reader GET /api/findings = %d, want 200 (%s)", resp.status, resp.body)
	}
	readerFinding := doAs(t, ts, readerSecret, http.MethodPost, "/api/hypotheses/hyp-any/finding", nil, nil)
	if readerFinding.status != http.StatusForbidden {
		t.Errorf("reader POST finding = %d, want 403 (%s)", readerFinding.status, readerFinding.body)
	}
	readerVerify := doAs(t, ts, readerSecret, http.MethodPost, "/api/hypotheses/hyp-any/verifications",
		map[string]any{"scope": map[string]any{"repository": "r"}}, nil)
	if readerVerify.status != http.StatusForbidden {
		t.Errorf("reader POST verifications = %d, want 403 (%s)", readerVerify.status, readerVerify.body)
	}
}

func TestVerificationRoutesReportNotFoundAndBadRequests(t *testing.T) {
	t.Parallel()
	env := newVerificationEnv(t, nil, agentTestAnswer)
	ts := env.ts
	hypothesis := createVerifiableHypothesis(t, ts)

	notFound := []string{
		"/api/verifications/vrun-does-not-exist",
		"/api/verifications/vrun-does-not-exist/evidence",
		"/api/findings/find-does-not-exist",
		"/api/evidence/ev-does-not-exist",
	}
	for _, path := range notFound {
		resp := do(t, ts, http.MethodGet, path, nil, nil)
		if resp.status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (%s)", path, resp.status, resp.body)
		}
	}
	unknownHypothesis := do(t, ts, http.MethodPost, "/api/hypotheses/hyp-does-not-exist/finding", nil, nil)
	if unknownHypothesis.status != http.StatusNotFound {
		t.Errorf("finding for an unknown hypothesis = %d, want 404 (%s)", unknownHypothesis.status, unknownHypothesis.body)
	}

	bad := []string{
		"/api/verifications?status=BOGUS",
		"/api/verifications?outcome=NOPE",
		"/api/verifications?limit=abc",
		"/api/verifications?offset=-1",
		"/api/findings?status=BOGUS",
		"/api/findings?conclusive=maybe",
	}
	for _, path := range bad {
		resp := do(t, ts, http.MethodGet, path, nil, nil)
		if resp.status != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400 (%s)", path, resp.status, resp.body)
		}
	}
	if resp := do(t, ts, http.MethodGet, "/api/findings?conclusive=true&candidates=true", nil, nil); resp.status != http.StatusBadRequest {
		t.Errorf("disjoint finding filters = %d, want 400 (%s)", resp.status, resp.body)
	}

	// A caller-supplied plan for another hypothesis is refused rather than
	// attached to the claim in the URL.
	foreign := map[string]any{"plan": map[string]any{
		"schema_version": 1,
		"hypothesis_id":  "hyp-somewhere-else",
		"finding_id":     "find-somewhere-else",
		"path_id":        hypothesis.PathID,
		"audit_id":       hypothesis.AuditID,
		"snapshot_id":    hypothesis.SnapshotID,
		"security_goal":  "a goal",
		"claim":          "a claim",
		"steps": []any{map[string]any{
			"kind": "static_check", "static_query": map[string]string{"query": "path.reachability"},
			"expectation": "the path resolves", "contradiction": "the path does not resolve",
		}},
		"environment": map[string]any{"profile": "sandbox-test", "source_read_only": true, "network": "none"},
		"scope":       map[string]any{"repository": "example.invalid/svc"},
	}}
	resp := postVerification(t, ts, hypothesis.HypothesisID, foreign)
	if resp.status != http.StatusBadRequest {
		t.Fatalf("plan for another hypothesis = %d, want 400 (%s)", resp.status, resp.body)
	}

	// A caller-supplied plan that does not validate is a 400 with the reason.
	invalid := map[string]any{"plan": map[string]any{
		"schema_version": 1,
		"hypothesis_id":  hypothesis.HypothesisID,
		"finding_id":     verify.FindingID(hypothesis.HypothesisID),
		"path_id":        hypothesis.PathID,
		"audit_id":       hypothesis.AuditID,
		"snapshot_id":    hypothesis.SnapshotID,
		"security_goal":  "a goal",
		"claim":          "a claim",
		"steps":          []any{},
		"environment":    map[string]any{"source_read_only": true},
		"scope":          map[string]any{"repository": "example.invalid/svc"},
	}}
	invalidResp := postVerification(t, ts, hypothesis.HypothesisID, invalid)
	if invalidResp.status != http.StatusBadRequest {
		t.Fatalf("invalid plan = %d, want 400 (%s)", invalidResp.status, invalidResp.body)
	}
	var failure errorResponse
	invalidResp.decode(t, &failure)
	if failure.Code != "invalid_request" || !strings.Contains(failure.Error, "step") {
		t.Errorf("invalid plan error = %+v, want the validation reason", failure)
	}
}

func TestVerificationEvidenceContentIsStoredRedacted(t *testing.T) {
	t.Parallel()
	secret := "password=hunter2"
	answer := func(goal string) agent.Answer {
		out := agentTestAnswer(goal)
		out.SupportingEvidence = []agent.AnswerEvidence{
			{Kind: agent.EvidenceSource, Ref: "ev-secret", File: "main.go", Line: 12, Summary: "the handler reads " + secret},
		}
		return out
	}
	env := newVerificationEnv(t, nil, answer)
	ts := env.ts
	hypothesis := createVerifiableHypothesis(t, ts)

	resp := do(t, ts, http.MethodPost, "/api/hypotheses/"+hypothesis.HypothesisID+"/finding", nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("ensure finding = %d (%s)", resp.status, resp.body)
	}
	var finding verify.Finding
	resp.decode(t, &finding)
	if len(finding.Supporting) != 1 {
		t.Fatalf("the finding has no citation: %s", resp.body)
	}
	evidence := do(t, ts, http.MethodGet, "/api/evidence/"+finding.Supporting[0], nil, nil)
	if evidence.status != http.StatusOK {
		t.Fatalf("get evidence = %d (%s)", evidence.status, evidence.body)
	}
	var object verify.Evidence
	evidence.decode(t, &object)
	if !object.Redacted || object.RedactionNotes == "" {
		t.Errorf("the secret-bearing evidence was not redacted: %+v", object)
	}
	if strings.Contains(object.Content, "hunter2") {
		t.Errorf("the stored evidence leaks the secret: %q", object.Content)
	}
	if !strings.Contains(object.Content, "[redacted]") {
		t.Errorf("the stored evidence does not record the redaction: %q", object.Content)
	}
}
