// Command bench-runtime aggregates a runtime comparison into a machine-readable
// report. Real-model samples are only included with the explicit --allow-real
// flag; without them the report says the real run is pending instead of treating
// fixture results as a quality win.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/bench"
)

type inputFile struct {
	Dataset      string         `json:"dataset"`
	ExpectedRuns int            `json:"expected_runs"`
	Runtimes     []string       `json:"runtimes"`
	Fixture      []bench.Sample `json:"fixture"`
	Real         []bench.Sample `json:"real"`
}

func main() {
	samplesPath := flag.String("samples", "", "JSON file with the fixture and real samples")
	outPath := flag.String("out", "bench-report.json", "machine-readable report path")
	markdownPath := flag.String("markdown", "", "optional Markdown summary path")
	allowReal := flag.Bool("allow-real", false, "include real-model samples (explicit opt-in)")
	flag.Parse()

	input := inputFile{}
	if strings.TrimSpace(*samplesPath) != "" {
		raw, err := os.ReadFile(*samplesPath)
		if err != nil {
			fail("read samples: %v", err)
		}
		if err := json.Unmarshal(raw, &input); err != nil {
			fail("parse samples: %v", err)
		}
		if input.ExpectedRuns <= 0 {
			fail("samples must declare expected_runs > 0")
		}
	}
	runtimes := input.Runtimes
	if len(runtimes) == 0 {
		runtimes = []string{"llm", "pi"}
	}
	real := input.Real
	if !*allowReal {
		real = nil
	}
	report := bench.Build(input.Dataset, input.ExpectedRuns, input.Fixture, real, runtimes)
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fail("encode report: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*outPath, encoded, 0o600); err != nil {
		fail("write report: %v", err)
	}
	if strings.TrimSpace(*markdownPath) != "" {
		if err := os.WriteFile(*markdownPath, []byte(markdown(report)), 0o600); err != nil {
			fail("write markdown: %v", err)
		}
	}
	fmt.Printf("verdict: %s\nreport: %s\n", report.Verdict, *outPath)
	if report.Verdict == "real_run_pending" {
		fmt.Println("real-model data was not provided; fixture results are a contract check, not a quality comparison")
	}
}

func markdown(report bench.Report) string {
	var out strings.Builder
	fmt.Fprintf(&out, "# Runtime comparison report (%s)\n\n", report.Verdict)
	fmt.Fprintf(&out, "- dataset: %s\n- expected runs per runtime: %d\n- generated: %s\n\n", report.Dataset, report.ExpectedRuns, report.GeneratedAt)
	writeCandidate := func(title string, summaries []bench.Summary) {
		if len(summaries) == 0 {
			return
		}
		fmt.Fprintf(&out, "## %s\n\n", title)
		out.WriteString("| runtime | samples | success | execution failures | TP | FN | FP | TN | abstained | coverage | recall | FPR | specificity | tokens p50/p95 | requests | calls | repairs |\n")
		out.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
		for _, summary := range summaries {
			tokens := "n/a"
			if summary.TokenP50 != nil && summary.TokenP95 != nil {
				tokens = fmt.Sprintf("%d/%d", *summary.TokenP50, *summary.TokenP95)
			}
			candidate := summary.Candidate
			fmt.Fprintf(&out, "| %s | %d | %.2f | %d | %d | %d | %d | %d | %d | %s | %s | %s | %s | %s | %d | %d | %d |\n",
				summary.Runtime, summary.Samples, summary.SuccessRate, summary.ExecutionFailures,
				candidate.TruePositives, candidate.FalseNegatives, candidate.FalsePositives, candidate.TrueNegatives,
				candidate.Abstained, formatRate(candidate.Coverage), formatRate(candidate.Recall),
				formatRate(candidate.FalsePositiveRate), formatRate(candidate.Specificity), tokens,
				summary.ModelRequests, summary.ToolCalls, summary.Repairs)
		}
		out.WriteString("\n")
	}
	writeVerification := func(title string, summaries []bench.Summary) {
		if len(summaries) == 0 {
			return
		}
		fmt.Fprintf(&out, "## %s\n\n", title)
		out.WriteString("| runtime | attempted | vulnerable confirmed | vulnerable attempts | success | safe false confirmations | safe attempts | false-confirmation rate | refuted | inconclusive | errors | coverage |\n")
		out.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
		for _, summary := range summaries {
			verification := summary.Verification
			fmt.Fprintf(&out, "| %s | %d | %d | %d | %s | %d | %d | %s | %d | %d | %d | %s |\n",
				summary.Runtime, verification.Attempted, verification.VulnerableConfirmed,
				verification.VulnerableAttempted, formatRate(verification.SuccessRate),
				verification.FalseConfirmations, verification.SafeAttempted,
				formatRate(verification.FalseConfirmationRate), verification.RefutedSamples,
				verification.Inconclusive, verification.Errors, formatRate(verification.Coverage))
		}
		out.WriteString("\n")
	}
	for _, group := range []struct {
		label   string
		fixture []bench.Summary
		real    []bench.Summary
	}{{"Fixture (scripted contract)", report.Fixture, nil}, {"Real models", nil, report.Real}} {
		summaries := group.fixture
		if group.real != nil {
			summaries = group.real
		}
		writeCandidate("Candidate classification: "+group.label, summaries)
		writeVerification("Dynamic verification: "+group.label, summaries)
	}
	if len(report.Notes) > 0 {
		out.WriteString("## Notes\n\n")
		for _, note := range report.Notes {
			fmt.Fprintf(&out, "- %s\n", note)
		}
	}
	return out.String()
}

func formatRate(value *float64) string {
	if value == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2f", *value)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
