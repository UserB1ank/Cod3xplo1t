package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// TestVerifyCLISurface pins the P6 command surface on a CLI-built workspace: a
// verification starts from the CLI's own runtime configuration (no API), and every
// read and the report are reachable afterwards.
func TestVerifyCLISurface(t *testing.T) {
	// Not parallel: the CLI writes to stdout, which is process-wide.
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)
	auditID, goal := cliAuditAndGoal(t, workspace, db, snapID)
	answer := cliAgentAnswer(goal)

	// One agent run records the claim the verification is about.
	if _, err := captureStdout(t, func() error {
		return runAgent(context.Background(), []string{
			"run", auditID, "--runtime", "scripted", "--agent-scripted-answer", answer,
			"--max-tool-calls", "10", "--workspace", workspace, "--db", db,
		})
	}); err != nil {
		t.Fatalf("run the agent: %v", err)
	}
	out, err := captureStdout(t, func() error {
		return runAgent(context.Background(), []string{
			"hypotheses", "list", "--audit", auditID, "--json", "--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("hypotheses list: %v\n%s", err, out)
	}
	var page struct {
		Hypotheses []agent.Hypothesis `json:"hypotheses"`
	}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("hypotheses output is not JSON: %v\n%s", err, out)
	}
	if len(page.Hypotheses) == 0 {
		t.Fatalf("the agent run recorded no hypothesis: %s", out)
	}
	hypothesisID := page.Hypotheses[0].ID

	// Without an executor the error names the flags that configure one, not a
	// silent "nothing happened".
	_, err = captureStdout(t, func() error {
		return runVerify(context.Background(), []string{
			"verify", hypothesisID, "--repository", "example.invalid/svc",
			"--workspace", workspace, "--db", db,
		})
	})
	if err == nil || !strings.Contains(err.Error(), "--executor") {
		t.Errorf("verify without an executor = %v, want an error naming --executor", err)
	}

	// An unknown hypothesis names the command that would create one. The unsupported
	// executor is used because a scripted run without a script is refused earlier,
	// with its own message.
	_, err = captureStdout(t, func() error {
		return runVerify(context.Background(), []string{
			"verify", "hyp-does-not-exist", "--executor", "unsupported", "--repository", "example.invalid/svc",
			"--workspace", workspace, "--db", db,
		})
	})
	if err == nil || !strings.Contains(err.Error(), "audit") || !strings.Contains(err.Error(), "run") {
		t.Errorf("verify on an unknown hypothesis = %v, want an error naming audit/run", err)
	}

	// A scripted executor with no script would block every step, and a blocked run is
	// not a refutation: the missing flag is reported instead of a bare BLOCKED.
	_, err = captureStdout(t, func() error {
		return runVerify(context.Background(), []string{
			"verify", hypothesisID, "--executor", "scripted", "--repository", "example.invalid/svc",
			"--workspace", workspace, "--db", db,
		})
	})
	if err == nil || !strings.Contains(err.Error(), "--scripted-steps") {
		t.Errorf("verify --executor scripted without steps = %v, want an error naming --scripted-steps", err)
	}

	// A malformed script is refused with the flag named.
	_, err = captureStdout(t, func() error {
		return runVerify(context.Background(), []string{
			"verify", hypothesisID, "--executor", "scripted", "--scripted-steps", "{not json",
			"--repository", "example.invalid/svc", "--workspace", workspace, "--db", db,
		})
	})
	if err == nil || !strings.Contains(err.Error(), "step outcomes") {
		t.Errorf("verify with a malformed script = %v, want an error naming the shape", err)
	}

	// The honest fallback gives the read surface a blocked run to examine. The
	// output carries what an operator needs: status, outcome, reason and the
	// evidence count.
	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), []string{
			"verify", hypothesisID, "--executor", "unsupported", "--repository", "example.invalid/svc",
			"--profile", "sandbox-cli", "--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	for _, want := range []string{"verification", "hypothesis", "finding", "status", "BLOCKED", "outcome", "reason", "evidence"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output is missing %q:\n%s", want, out)
		}
	}

	// verifications list and show
	readArgs := func(extra ...string) []string {
		args := []string{"--executor", "unsupported", "--workspace", workspace, "--db", db}
		return append(extra, args...)
	}
	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("verifications", "list", "--hypothesis", hypothesisID))
	})
	if err != nil {
		t.Fatalf("verifications list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "VERIFICATION") || !strings.Contains(out, "BLOCKED") {
		t.Errorf("verifications list does not show the run:\n%s", out)
	}

	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("verifications", "list", "--hypothesis", hypothesisID, "--json"))
	})
	if err != nil {
		t.Fatalf("verifications list --json: %v\n%s", err, out)
	}
	var listing struct {
		Verifications []verify.Run `json:"verifications"`
		Total         int          `json:"total"`
	}
	if err := json.Unmarshal([]byte(out), &listing); err != nil {
		t.Fatalf("verifications output is not JSON: %v\n%s", err, out)
	}
	if listing.Total != 1 || len(listing.Verifications) != 1 {
		t.Fatalf("verifications list = %s", out)
	}
	run := listing.Verifications[0]
	if run.Outcome != verify.OutcomeBlocked {
		t.Errorf("outcome = %s, want BLOCKED", run.Outcome)
	}

	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("verifications", "show", run.ID, "--json"))
	})
	if err != nil {
		t.Fatalf("verifications show: %v\n%s", err, out)
	}
	var shown verify.Run
	if err := json.Unmarshal([]byte(out), &shown); err != nil {
		t.Fatalf("show output is not JSON: %v\n%s", err, out)
	}
	if shown.ID != run.ID || shown.PlanHash == "" || len(shown.Plan.Steps) == 0 {
		t.Errorf("verifications show = %+v", shown)
	}

	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("verifications", "show", "vrun-does-not-exist"))
	})
	if err == nil {
		t.Errorf("show of an unknown verification = %v, want an error\n%s", err, out)
	}

	// The evidence read validates its kind filter rather than silently ignoring it.
	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("verifications", "evidence", run.ID))
	})
	if err != nil {
		t.Fatalf("verifications evidence: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no evidence object matches") && !strings.Contains(out, "EVIDENCE") {
		t.Errorf("verifications evidence printed neither a table nor a reason:\n%s", out)
	}
	if _, err := captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("verifications", "evidence", run.ID, "--kind", "BOGUS"))
	}); err == nil || !strings.Contains(err.Error(), "unknown evidence kind") {
		t.Errorf("verifications evidence --kind BOGUS = %v, want an error naming the kinds", err)
	}

	// findings list and show
	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("findings", "list", "--audit", auditID))
	})
	if err != nil {
		t.Fatalf("findings list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "FINDING") || !strings.Contains(out, "blocked") {
		t.Errorf("findings list does not show the blocked finding:\n%s", out)
	}

	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("findings", "show", verify.FindingID(hypothesisID), "--json"))
	})
	if err != nil {
		t.Fatalf("findings show: %v\n%s", err, out)
	}
	var detail struct {
		Finding verify.Finding `json:"finding"`
	}
	if err := json.Unmarshal([]byte(out), &detail); err != nil {
		t.Fatalf("finding output is not JSON: %v\n%s", err, out)
	}
	if detail.Finding.Status != verify.FindingBlocked || detail.Finding.HypothesisID != hypothesisID {
		t.Errorf("findings show = %+v", detail.Finding)
	}

	// A report is Markdown by default and restates the caveats.
	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("report", auditID, "--format", "md"))
	})
	if err != nil {
		t.Fatalf("report: %v\n%s", err, out)
	}
	if !strings.Contains(out, "blocked means the verification could not run") {
		t.Errorf("the report does not restate the caveats:\n%s", out)
	}

	// An unknown format is refused with the vocabulary.
	_, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("report", auditID, "--format", "xml"))
	})
	if err == nil || !strings.Contains(err.Error(), "sarif") {
		t.Errorf("report --format xml = %v, want an error naming the formats", err)
	}

	// --out writes the report to a file instead of stdout.
	target := filepath.Join(t.TempDir(), "report.sarif")
	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("report", auditID, "--format", "sarif", "--out", target))
	})
	if err != nil {
		t.Fatalf("report --out: %v\n%s", err, out)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read the report file: %v", err)
	}
	var sarif struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &sarif); err != nil {
		t.Fatalf("the written report is not SARIF JSON: %v\n%s", err, body)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", sarif.Version)
	}

	// A real end-to-end dry run: prepare, authorize, execute, derive the outcome,
	// store the evidence and upsert the finding. The plan has two steps, so the
	// script has two entries and both produce reproduction evidence.
	confirmScript, err := json.Marshal([]verify.StepOutcome{
		{Kind: verify.EvidenceTest, Content: "ok the claim reproduced", Command: "verify test claim"},
		{Kind: verify.EvidenceRuntimeLog, Content: "runtime log: the claim reproduced"},
	})
	if err != nil {
		t.Fatalf("marshal the confirming script: %v", err)
	}
	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), []string{
			"verify", hypothesisID, "--executor", "scripted", "--scripted-steps", string(confirmScript),
			"--repository", "example.invalid/svc", "--profile", "sandbox-confirmed",
			"--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("scripted dry run: %v\n%s", err, out)
	}
	for _, want := range []string{"CONFIRMED", "SUCCEEDED", "evidence", "2 step(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("the confirming dry run is missing %q:\n%s", want, out)
		}
	}

	// A refutation needs contradicting evidence, so the script marks one step as
	// contradicting and leaves the other as a source note (a runtime log beside it
	// would be a confirmation, and a mixed replay refuses to refute). The profile
	// differs so the plan hash differs: the same plan would otherwise be a replay.
	refuteScript, err := json.Marshal([]verify.StepOutcome{
		{Kind: verify.EvidenceRuntimeLog, Content: "permission denied", Contradicts: "the control rejects the request"},
		{Kind: verify.EvidenceSource, Content: "source note: the control is registered on this path"},
	})
	if err != nil {
		t.Fatalf("marshal the refuting script: %v", err)
	}
	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), []string{
			"verify", hypothesisID, "--executor", "scripted", "--scripted-steps", string(refuteScript),
			"--repository", "example.invalid/svc", "--profile", "sandbox-refuted",
			"--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("scripted refutation: %v\n%s", err, out)
	}
	if !strings.Contains(out, "REFUTED") {
		t.Errorf("the refuting dry run is not REFUTED:\n%s", out)
	}

	// The finding carries the second verdict, and both runs are stored.
	out, err = captureStdout(t, func() error {
		return runVerify(context.Background(), readArgs("findings", "show", verify.FindingID(hypothesisID), "--json"))
	})
	if err != nil {
		t.Fatalf("findings show: %v\n%s", err, out)
	}
	if err := json.Unmarshal([]byte(out), &detail); err != nil {
		t.Fatalf("finding output is not JSON: %v\n%s", err, out)
	}
	if detail.Finding.Status != verify.FindingRefuted {
		t.Errorf("finding status = %s, want refuted", detail.Finding.Status)
	}
	if len(detail.Finding.Contradicting) == 0 {
		t.Errorf("the refutation kept no contradicting evidence: %+v", detail.Finding)
	}
}
