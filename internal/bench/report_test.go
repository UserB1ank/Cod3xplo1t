package bench

import (
	"encoding/json"
	"strings"
	"testing"
)

func sample(runtime, task string, tokens int, source string, label, predicted string) Sample {
	return Sample{
		Runtime: runtime, TaskID: task, Group: "seeded", Label: label, Predicted: predicted,
		Status: "SUCCEEDED", StopReason: "completed", UsageSource: source,
		InputTokens: tokens / 2, OutputTokens: tokens - tokens/2,
		ModelRequests: 2, ToolCalls: 1, ElapsedMS: 100, ObligationsTotal: 4, ObligationsClosed: 4,
		EvidenceItems: 2, ValidEvidence: 2,
	}
}

func TestZeroOrMissingUsageIsUnavailableNotCheap(t *testing.T) {
	samples := []Sample{
		sample("pi", "t1", 0, "reported", "vulnerable", "candidate"),
		sample("pi", "t2", 0, "", "safe", "inconclusive"),
	}
	summary := Aggregate("pi", samples, 2)
	if summary.Available != 0 || summary.Unavailable != 2 {
		t.Fatalf("summary = %+v, want both samples unavailable", summary)
	}
	if summary.CostPerConfirmed != nil {
		t.Fatalf("cost per confirmed finding = %v, want N/A", *summary.CostPerConfirmed)
	}
	report := Build("set", 2, nil, samples, []string{"pi", "llm"})
	if report.Verdict != "insufficient_evidence" {
		t.Fatalf("verdict = %q, want insufficient_evidence", report.Verdict)
	}
}

func TestMissingRunsAreFailedNotZero(t *testing.T) {
	samples := []Sample{sample("pi", "t1", 120, "reported", "vulnerable", "candidate")}
	summary := Aggregate("pi", samples, 3)
	if summary.Missing != 2 {
		t.Fatalf("missing = %d, want 2", summary.Missing)
	}
	report := Build("set", 3, nil, samples, []string{"pi", "llm"})
	if report.Verdict != "insufficient_evidence" {
		t.Fatalf("verdict = %q, want insufficient_evidence", report.Verdict)
	}
}

func TestFixtureIsNotARealWinner(t *testing.T) {
	scripted := []Sample{sample("pi", "t1", 0, "reported", "vulnerable", "candidate")}
	report := Build("golden", 1, scripted, nil, []string{"pi", "llm"})
	if report.Verdict != "real_run_pending" {
		t.Fatalf("verdict = %q, want real_run_pending", report.Verdict)
	}
	if len(report.Real) != 0 {
		t.Fatalf("real = %+v, want empty", report.Real)
	}
}

func TestComparableReportKeepsRawNumbers(t *testing.T) {
	var samples []Sample
	for index := 0; index < MinimumSamplesPerRuntime; index++ {
		label, predicted := "vulnerable", "candidate"
		if index%2 == 1 {
			label, predicted = "safe", "refuted"
		}
		samples = append(samples, sample("pi", "t", 100+index*10, "reported", label, predicted))
	}
	summary := Aggregate("pi", samples, MinimumSamplesPerRuntime)
	if summary.Available != MinimumSamplesPerRuntime || summary.Candidate.Recall == nil || summary.Candidate.FalsePositiveRate == nil {
		t.Fatalf("summary = %+v, want candidate rates over available samples", summary)
	}
	if *summary.Candidate.Recall != 1 || *summary.Candidate.FalsePositiveRate != 0 {
		t.Fatalf("candidate recall/FP = %v/%v", *summary.Candidate.Recall, *summary.Candidate.FalsePositiveRate)
	}
	if summary.TokenP50 == nil || summary.TokenP95 == nil {
		t.Fatal("token percentiles were not computed")
	}
	report := Build("set", MinimumSamplesPerRuntime, nil, samples, []string{"pi", "llm"})
	if report.Verdict != "insufficient_evidence" {
		t.Fatalf("verdict = %q, want insufficient_evidence because llm is missing", report.Verdict)
	}
}

func TestCandidateConfusionMatrixDistinguishesRefuted(t *testing.T) {
	samples := []Sample{
		sample("pi", "vulnerable-candidate", 100, "reported", "vulnerable", "candidate"),
		sample("pi", "vulnerable-refuted", 100, "reported", "vulnerable", "refuted"),
		sample("pi", "safe-candidate", 100, "reported", "safe", "candidate"),
		sample("pi", "safe-refuted", 100, "reported", "safe", "refuted"),
	}

	summary := Aggregate("pi", samples, len(samples))
	candidate := summary.Candidate
	if candidate.TruePositives != 1 || candidate.FalseNegatives != 1 ||
		candidate.FalsePositives != 1 || candidate.TrueNegatives != 1 {
		t.Fatalf("matrix = %+v, want TP/FN/FP/TN = 1/1/1/1", candidate)
	}
	if candidate.Recall == nil || *candidate.Recall != 0.5 {
		t.Fatalf("candidate recall = %v, want 0.5", candidate.Recall)
	}
	if candidate.FalsePositiveRate == nil || *candidate.FalsePositiveRate != 0.5 {
		t.Fatalf("candidate false-positive rate = %v, want 0.5", candidate.FalsePositiveRate)
	}
	if candidate.Specificity == nil || *candidate.Specificity != 0.5 {
		t.Fatalf("candidate specificity = %v, want 0.5", candidate.Specificity)
	}
}

func TestCandidateRatesSeparateAbstentionFailureAndNonBinaryLabels(t *testing.T) {
	failed := sample("pi", "failed", 100, "reported", "vulnerable", "refuted")
	failed.Status = "FAILED"
	environmentFailed := sample("pi", "environment-failed", 0, "reported", "safe", "refuted")
	environmentFailed.Status = "FAILED"
	samples := []Sample{
		sample("pi", "vulnerable-candidate", 100, "", "vulnerable", "candidate"),
		sample("pi", "vulnerable-inconclusive", 100, "", "vulnerable", "inconclusive"),
		failed,
		environmentFailed,
		sample("pi", "safe-refuted", 100, "", "safe", "refuted"),
		sample("pi", "undecidable-candidate", 100, "", "undecidable", "candidate"),
		sample("pi", "edge-refuted", 100, "", "edge", "refuted"),
	}

	summary := Aggregate("pi", samples, len(samples))
	candidate := summary.Candidate
	if candidate.TruePositives != 1 || candidate.FalseNegatives != 0 ||
		candidate.FalsePositives != 0 || candidate.TrueNegatives != 1 {
		t.Fatalf("matrix = %+v, want only successful conclusive binary outcomes", candidate)
	}
	if candidate.Abstained != 1 || candidate.ExecutionFailures != 2 {
		t.Fatalf("candidate abstained/failures = %d/%d, want 1/2", candidate.Abstained, candidate.ExecutionFailures)
	}
	if summary.Undecidable != 1 || summary.Edge != 1 {
		t.Fatalf("undecidable/edge = %d/%d, want 1/1", summary.Undecidable, summary.Edge)
	}
	if summary.Outcomes.Undecidable.Candidate != 1 || summary.Outcomes.Edge.Refuted != 1 {
		t.Fatalf("outcomes = %+v, want non-binary labels preserved separately", summary.Outcomes)
	}
	if candidate.Coverage == nil || *candidate.Coverage != 0.4 {
		t.Fatalf("candidate coverage = %v, want 2 conclusive successful decisions / 5 binary samples", candidate.Coverage)
	}
	if summary.SuccessRate != float64(len(samples)-2)/float64(len(samples)) {
		t.Fatalf("success rate = %v, want execution failures included in denominator", summary.SuccessRate)
	}
}

func TestDynamicVerificationIsSeparateFromCandidateDetection(t *testing.T) {
	vulnerableAttempt := sample("pi", "vulnerable-verified", 100, "reported", "vulnerable", "candidate")
	vulnerableAttempt.VerificationStatus = "confirmed"
	vulnerableMiss := sample("pi", "vulnerable-miss", 100, "reported", "vulnerable", "candidate")
	vulnerableMiss.VerificationStatus = "refuted"
	safeExact := sample("pi", "safe-verified", 100, "reported", "safe", "refuted")
	safeExact.VerificationStatus = "refuted"
	safeFalseConfirmation := sample("pi", "safe-false-confirmation", 100, "reported", "safe", "refuted")
	safeFalseConfirmation.VerificationStatus = "confirmed"
	environmentFailure := sample("pi", "environment-error", 100, "reported", "vulnerable", "inconclusive")
	environmentFailure.VerificationStatus = "error"

	summary := Aggregate("pi", []Sample{
		vulnerableAttempt, vulnerableMiss, safeExact, safeFalseConfirmation, environmentFailure,
	}, 5)
	verification := summary.Verification
	if verification.Attempted != 5 || verification.ConfirmedSamples != 2 ||
		verification.RefutedSamples != 2 || verification.Errors != 1 {
		t.Fatalf("verification = %+v, want 5 attempts, 2 confirmed, 2 refuted, 1 error", verification)
	}
	if verification.VulnerableAttempted != 3 || verification.VulnerableConfirmed != 1 {
		t.Fatalf("vulnerable verification = %d/%d, want 1/3", verification.VulnerableConfirmed, verification.VulnerableAttempted)
	}
	if verification.SuccessRate == nil || *verification.SuccessRate != 1.0/3.0 {
		t.Fatalf("verification success rate = %v, want 1/3", verification.SuccessRate)
	}
	if verification.SafeAttempted != 2 || verification.FalseConfirmations != 1 {
		t.Fatalf("safe verification = %+v, want 1 false confirmation / 2 attempts", verification)
	}
	if verification.FalseConfirmationRate == nil || *verification.FalseConfirmationRate != 0.5 {
		t.Fatalf("false-confirmation rate = %v, want 0.5", verification.FalseConfirmationRate)
	}
	if summary.Candidate.TruePositives != 2 || summary.Candidate.TrueNegatives != 2 {
		t.Fatalf("candidate matrix changed by verification = %+v", summary.Candidate)
	}
}

func TestVerificationErrorNeverBecomesRefuted(t *testing.T) {
	sample := sample("pi", "target-timeout", 100, "reported", "vulnerable", "candidate")
	sample.VerificationStatus = "error"

	summary := Aggregate("pi", []Sample{sample}, 1)
	if summary.Verification.RefutedSamples != 0 || summary.Verification.Errors != 1 {
		t.Fatalf("verification = %+v, environment failure must remain an error", summary.Verification)
	}
	if summary.Verification.VulnerableConfirmed != 0 {
		t.Fatalf("vulnerable confirmed = %d, want 0", summary.Verification.VulnerableConfirmed)
	}
}

func TestVerificationCoverageCountsOnlyBinaryAttempts(t *testing.T) {
	vulnerable := sample("pi", "vulnerable", 100, "reported", "vulnerable", "candidate")
	vulnerable.VerificationStatus = "confirmed"
	undecidable := sample("pi", "undecidable", 100, "reported", "undecidable", "inconclusive")
	undecidable.VerificationStatus = "inconclusive"

	summary := Aggregate("pi", []Sample{vulnerable, undecidable}, 2)
	if summary.Verification.Attempted != 2 {
		t.Fatalf("attempted = %d, want all verification attempts retained", summary.Verification.Attempted)
	}
	if summary.Verification.Coverage == nil || *summary.Verification.Coverage != 1 {
		t.Fatalf("coverage = %v, want binary attempted / binary samples = 1/1", summary.Verification.Coverage)
	}
}

func TestReportVersionSeparatesCandidateAndVerificationMetrics(t *testing.T) {
	if Version != 2 {
		t.Fatalf("Version = %d, want 2 for the corrected metric schema", Version)
	}
	encoded, err := json.Marshal(Aggregate("pi", []Sample{sample("pi", "t1", 100, "reported", "vulnerable", "candidate")}, 1))
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, field := range []string{`"candidate"`, `"verification"`, `"outcomes"`, `"execution_failures"`} {
		if !strings.Contains(text, field) {
			t.Fatalf("encoded summary %s does not contain %s", text, field)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["recall"]; ok {
		t.Fatalf("encoded summary %s still exposes an ambiguous top-level recall field", text)
	}
}
