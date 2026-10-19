package bench

import "testing"

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
			label, predicted = "safe", "inconclusive"
		}
		samples = append(samples, sample("pi", "t", 100+index*10, "reported", label, predicted))
	}
	summary := Aggregate("pi", samples, MinimumSamplesPerRuntime)
	if summary.Available != MinimumSamplesPerRuntime || summary.Recall == nil || summary.FalsePositive == nil {
		t.Fatalf("summary = %+v, want rates over available samples", summary)
	}
	if *summary.Recall != 1 || *summary.FalsePositive != 0 {
		t.Fatalf("recall/FP = %v/%v", *summary.Recall, *summary.FalsePositive)
	}
	if summary.TokenP50 == nil || summary.TokenP95 == nil {
		t.Fatal("token percentiles were not computed")
	}
	report := Build("set", MinimumSamplesPerRuntime, nil, samples, []string{"pi", "llm"})
	if report.Verdict != "insufficient_evidence" {
		t.Fatalf("verdict = %q, want insufficient_evidence because llm is missing", report.Verdict)
	}
}
