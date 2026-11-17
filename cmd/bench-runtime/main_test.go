package main

import (
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/bench"
)

func TestMarkdownSeparatesCandidateAndVerificationMetrics(t *testing.T) {
	samples := []bench.Sample{
		{
			Runtime: "pi", TaskID: "vulnerable", Label: "vulnerable", Predicted: "candidate",
			Status: "SUCCEEDED", StopReason: "completed", UsageSource: "reported",
			InputTokens: 80, OutputTokens: 20, VerificationStatus: "confirmed",
		},
		{
			Runtime: "pi", TaskID: "safe", Label: "safe", Predicted: "refuted",
			Status: "SUCCEEDED", StopReason: "completed", UsageSource: "reported",
			InputTokens: 80, OutputTokens: 20, VerificationStatus: "refuted",
		},
	}
	report := bench.Build("r0", 2, nil, samples, []string{"pi", "llm"})
	text := markdown(report)
	for _, expected := range []string{
		"## Candidate classification",
		"| runtime | samples | success | execution failures | TP | FN | FP | TN | abstained | coverage | recall | FPR | specificity | tokens p50/p95 |",
		"## Dynamic verification",
		"| runtime | attempted | vulnerable confirmed | vulnerable attempts | success | safe false confirmations | safe attempts | false-confirmation rate | refuted | inconclusive | errors |",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("markdown is missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "| recall | FP |") {
		t.Fatalf("markdown still uses ambiguous recall/FP columns:\n%s", text)
	}
}
