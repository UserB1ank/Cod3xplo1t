// Package bench aggregates runtime comparison results. It never guesses: a
// sample without reported usage is unavailable, a missing run is failed, and a
// scripted replay is reported separately from real-model data.
package bench

import (
	"fmt"
	"sort"
	"time"
)

// Version of the report format.
const Version = 1

// MinimumSamplesPerRuntime is the smallest evidence base the report will treat as
// comparable. Below it the verdict is insufficient evidence, not a winner.
const MinimumSamplesPerRuntime = 20

// Sample is one finished run of one task on one runtime.
type Sample struct {
	Runtime       string `json:"runtime"`
	TaskID        string `json:"task_id"`
	Group         string `json:"group"`
	Label         string `json:"label"`     // vulnerable, safe, undecidable, edge
	Predicted     string `json:"predicted"` // candidate, refuted, inconclusive
	Status        string `json:"status"`
	StopReason    string `json:"stop_reason"`
	UsageSource   string `json:"usage_source"` // reported, legacy_estimate, empty
	InputTokens   int    `json:"input_tokens"`
	OutputTokens  int    `json:"output_tokens"`
	ModelRequests int    `json:"model_requests"`
	ToolCalls     int    `json:"tool_calls"`
	Repairs       int    `json:"repairs"`
	Novelty       []int  `json:"novelty,omitempty"`
	ElapsedMS     int64  `json:"elapsed_ms"`
	// EvidenceItems and ValidEvidence measure traceability; a citation that does
	// not resolve is not evidence.
	EvidenceItems int `json:"evidence_items"`
	ValidEvidence int `json:"valid_evidence"`
	// ConfirmedFindings is only non-zero when a real verifier confirmed them; the
	// cost per confirmed finding is N/A otherwise.
	ConfirmedFindings int `json:"confirmed_findings"`
	ObligationsTotal  int `json:"obligations_total"`
	ObligationsClosed int `json:"obligations_closed"`
}

// TokenTotal is the reported usage. A legacy estimate is not a real measurement.
func (s Sample) TokenTotal() int { return s.InputTokens + s.OutputTokens }

// ReportedUsage tells whether the host has a real measurement for the sample.
func (s Sample) ReportedUsage() bool {
	return s.UsageSource == "reported" && s.TokenTotal() > 0
}

// Summary is the aggregation of one runtime's samples.
type Summary struct {
	Runtime          string         `json:"runtime"`
	Samples          int            `json:"samples"`
	Available        int            `json:"available"`
	Unavailable      int            `json:"unavailable"`
	Missing          int            `json:"missing"`
	SuccessRate      float64        `json:"success_rate"`
	Recall           *float64       `json:"recall,omitempty"`
	FalsePositive    *float64       `json:"false_positive_rate,omitempty"`
	ObligationRatio  float64        `json:"obligation_closure_ratio"`
	Inconclusive     int            `json:"inconclusive"`
	StopReasons      map[string]int `json:"stop_reasons"`
	TokenP50         *int           `json:"token_p50,omitempty"`
	TokenP95         *int           `json:"token_p95,omitempty"`
	ElapsedP50MS     *int64         `json:"elapsed_p50_ms,omitempty"`
	ModelRequests    int            `json:"model_requests"`
	ToolCalls        int            `json:"tool_calls"`
	Repairs          int            `json:"repairs"`
	EvidenceValid    float64        `json:"evidence_valid_rate"`
	CostPerConfirmed *float64       `json:"cost_per_confirmed_finding,omitempty"`
	Notes            []string       `json:"notes,omitempty"`
}

// Report is the machine-readable comparison. Fixture is the scripted contract
// run; Real is the opt-in real-model run (nil when it was not run).
type Report struct {
	Version      int       `json:"version"`
	GeneratedAt  string    `json:"generated_at"`
	Dataset      string    `json:"dataset,omitempty"`
	ExpectedRuns int       `json:"expected_runs"`
	Fixture      []Summary `json:"fixture,omitempty"`
	Real         []Summary `json:"real,omitempty"`
	Verdict      string    `json:"verdict"`
	Notes        []string  `json:"notes,omitempty"`
}

// Aggregate builds one runtime's summary. expected is the number of runs the
// evaluation plan promised for this runtime; fewer samples are reported as
// missing, never as zero cost.
func Aggregate(runtime string, samples []Sample, expected int) Summary {
	summary := Summary{Runtime: runtime, StopReasons: map[string]int{}, ModelRequests: 0, Notes: []string{}}
	var available []Sample
	for _, sample := range samples {
		if sample.Runtime != runtime {
			continue
		}
		summary.Samples++
		summary.ModelRequests += sample.ModelRequests
		summary.ToolCalls += sample.ToolCalls
		summary.Repairs += sample.Repairs
		summary.StopReasons[sample.StopReason]++
		if !sample.ReportedUsage() {
			summary.Unavailable++
			summary.Notes = append(summary.Notes, fmt.Sprintf("%s has no reported usage (%s)", sample.TaskID, usageLabel(sample)))
			continue
		}
		available = append(available, sample)
		summary.Available++
		if sample.Status == "SUCCEEDED" {
			summary.SuccessRate++
		}
		if sample.ObligationsTotal > 0 {
			summary.ObligationRatio += float64(sample.ObligationsClosed) / float64(sample.ObligationsTotal)
		}
		if sample.Predicted == "inconclusive" {
			summary.Inconclusive++
		}
		if sample.EvidenceItems > 0 {
			summary.EvidenceValid += float64(sample.ValidEvidence) / float64(sample.EvidenceItems)
		}
	}
	if expected > summary.Samples {
		summary.Missing = expected - summary.Samples
		summary.Notes = append(summary.Notes, fmt.Sprintf("%d of %d planned runs are missing", summary.Missing, expected))
	}
	if summary.Available > 0 {
		summary.SuccessRate /= float64(summary.Available)
		summary.ObligationRatio /= float64(summary.Available)
		summary.EvidenceValid /= float64(summary.Available)
		summary.TokenP50, summary.TokenP95 = percentile(available, func(s Sample) int { return s.TokenTotal() })
		summary.ElapsedP50MS = percentileElapsed(available)
		summary.Recall, summary.FalsePositive = rates(available)
		confirmed := 0
		for _, sample := range available {
			confirmed += sample.ConfirmedFindings
		}
		if confirmed > 0 {
			tokens := 0
			for _, sample := range available {
				tokens += sample.TokenTotal()
			}
			cost := float64(tokens) / float64(confirmed)
			summary.CostPerConfirmed = &cost
		} else {
			summary.Notes = append(summary.Notes, "cost per confirmed finding is N/A: no verifier-confirmed finding")
		}
	}
	return summary
}

func usageLabel(sample Sample) string {
	if sample.UsageSource == "" {
		return "source not recorded"
	}
	return sample.UsageSource
}

func percentile(samples []Sample, value func(Sample) int) (*int, *int) {
	if len(samples) == 0 {
		return nil, nil
	}
	values := make([]int, 0, len(samples))
	for _, sample := range samples {
		values = append(values, value(sample))
	}
	sort.Ints(values)
	p50 := values[(len(values)-1)*50/100]
	p95 := values[(len(values)-1)*95/100]
	return &p50, &p95
}

func percentileElapsed(samples []Sample) *int64 {
	if len(samples) == 0 {
		return nil
	}
	values := make([]int64, 0, len(samples))
	for _, sample := range samples {
		values = append(values, sample.ElapsedMS)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	p50 := values[(len(values)-1)*50/100]
	return &p50
}

func rates(samples []Sample) (*float64, *float64) {
	var tp, fn, fp, tn int
	for _, sample := range samples {
		positive := sample.Label == "vulnerable"
		conclusive := sample.Predicted == "candidate" || sample.Predicted == "refuted"
		switch {
		case positive && conclusive:
			tp++
		case positive && !conclusive:
			fn++
		case !positive && conclusive:
			fp++
		default:
			tn++
		}
	}
	if tp+fn == 0 || fp+tn == 0 {
		return nil, nil
	}
	recall := float64(tp) / float64(tp+fn)
	falsePositive := float64(fp) / float64(fp+tn)
	return &recall, &falsePositive
}

// Build assembles the report and decides the verdict. It never names a winner:
// it says whether the evidence is comparable and reports the raw numbers.
func Build(dataset string, expected int, fixtureSamples, realSamples []Sample, runtimes []string) Report {
	report := Report{Version: Version, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Dataset: dataset, ExpectedRuns: expected}
	for _, runtime := range runtimes {
		if len(fixtureSamples) > 0 {
			report.Fixture = append(report.Fixture, Aggregate(runtime, fixtureSamples, expected))
		}
		if len(realSamples) > 0 {
			report.Real = append(report.Real, Aggregate(runtime, realSamples, expected))
		}
	}
	switch {
	case len(realSamples) == 0:
		report.Verdict = "real_run_pending"
		report.Notes = append(report.Notes, "no real-model samples were provided; fixture results are a contract check, not a quality comparison")
	case insufficient(report.Real):
		report.Verdict = "insufficient_evidence"
		report.Notes = append(report.Notes, "at least one real runtime lacks available samples or planned runs; no winner is claimed")
	default:
		report.Verdict = "comparable"
		report.Notes = append(report.Notes, "numbers are raw per-runtime measurements; choosing a default runtime is a human decision")
	}
	return report
}

func insufficient(summaries []Summary) bool {
	for _, summary := range summaries {
		if summary.Available < MinimumSamplesPerRuntime || summary.Unavailable > 0 || summary.Missing > 0 {
			return true
		}
	}
	return len(summaries) < 2
}
