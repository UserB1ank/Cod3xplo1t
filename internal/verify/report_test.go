package verify

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// The report engine is pure, so its tests are too: findings and evidence in,
// bytes out. The assertions cover what a consumer actually does with the output —
// parse it — rather than only that some substring appears.

func reportOptions(format string, mutate func(*ReportOptions)) ReportOptions {
	opts := ReportOptions{
		Format: format, Title: "Verification report", AuditID: "audit-report-1",
		SnapshotID: "snap-report-1",
		Now:        func() time.Time { return time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC) },
	}
	if mutate != nil {
		mutate(&opts)
	}
	return opts
}

func TestRenderReportRejectsUnknownFormat(t *testing.T) {
	findings, evidence := reportFixture(t)
	if _, err := RenderReport(findings, evidence, reportOptions("html", nil)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestRenderReportRejectsUnknownStatus(t *testing.T) {
	findings, evidence := reportFixture(t)
	findings[0].Status = "probably"
	if _, err := RenderReport(findings, evidence, reportOptions("json", nil)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestRenderReportMarkdownIncludesEverySection(t *testing.T) {
	findings, evidence := reportFixture(t)
	rendered, err := RenderReport(findings, evidence, reportOptions("md", nil))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	document := string(rendered)
	for _, want := range []string{
		"# Verification report",
		"| status | severity | title |",
		"### Evidence",
		"### Reproduce",
		"### Limitations",
		"How to read this report",
		"path traversal in export",
		"ssrf in webhook",
		"weak hashing in tokens",
		"deserialization in cache",
		"audit-report-1",
		"snap-report-1",
		"env-fixture",
		"step 1: run the proof",
		"no deployed target for the last hop",
		"internal/api/handler.go:42",
		"```",
	} {
		if !strings.Contains(document, want) {
			t.Fatalf("markdown is missing %q:\n%s", want, document)
		}
	}
	// The blocked and inconclusive findings must be present, not silently dropped.
	if !strings.Contains(document, "blocked") || !strings.Contains(document, "inconclusive") {
		t.Fatalf("the report does not show every status:\n%s", document)
	}
}

func TestRenderReportMarkdownHidesCandidatesByDefault(t *testing.T) {
	findings, evidence := reportFixture(t)
	rendered, err := RenderReport(findings, evidence, reportOptions("md", nil))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if strings.Contains(string(rendered), "unverified candidate") {
		t.Fatalf("a candidate finding was rendered without IncludeCandidates:\n%s", rendered)
	}
	withCandidates, err := RenderReport(findings, evidence, reportOptions("md", func(opts *ReportOptions) {
		opts.IncludeCandidates = true
	}))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	document := string(withCandidates)
	if !strings.Contains(document, "unverified candidate") {
		t.Fatalf("IncludeCandidates did not include the candidate:\n%s", document)
	}
	if strings.Index(document, "unverified candidate") < strings.Index(document, "deserialization in cache") {
		t.Fatalf("candidates must sort after the verified statuses:\n%s", document)
	}
}

func TestRenderReportMarkdownRespectsMaxFindings(t *testing.T) {
	findings, evidence := reportFixture(t)
	rendered, err := RenderReport(findings, evidence, reportOptions("md", func(opts *ReportOptions) {
		opts.IncludeCandidates = true
		opts.MaxFindings = 2
	}))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	document := string(rendered)
	if strings.Contains(document, "weak hashing in tokens") || strings.Contains(document, "deserialization in cache") {
		t.Fatalf("MaxFindings did not bound the report:\n%s", document)
	}
	if !strings.Contains(document, "path traversal in export") {
		t.Fatalf("MaxFindings dropped the highest-ranked finding:\n%s", document)
	}
}

func TestRenderReportStatesTheCaveats(t *testing.T) {
	findings, evidence := reportFixture(t)
	for _, format := range []string{"md", "json", "sarif"} {
		rendered, err := RenderReport(findings, evidence, reportOptions(format, nil))
		if err != nil {
			t.Fatalf("RenderReport(%s): %v", format, err)
		}
		document := string(rendered)
		for _, concept := range []string{"confirmed", "refuted", "inconclusive", "blocked"} {
			if !strings.Contains(document, concept) {
				t.Fatalf("%s report does not mention %q, so it does not state the caveats:\n%s", format, concept, document)
			}
		}
		if !strings.Contains(document, "not a refutation") {
			t.Fatalf("%s report does not say that inconclusive and blocked are not refutations:\n%s", format, document)
		}
	}
}

func TestRenderReportJSONIsStableAndParseable(t *testing.T) {
	findings, evidence := reportFixture(t)
	rendered, err := RenderReport(findings, evidence, reportOptions("json", nil))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	var document struct {
		SchemaVersion int               `json:"schema_version"`
		GeneratedAt   string            `json:"generated_at"`
		AuditID       string            `json:"audit_id"`
		SnapshotID    string            `json:"snapshot_id"`
		Findings      []json.RawMessage `json:"findings"`
		Evidence      map[string][]struct {
			ID   string `json:"evidence_id"`
			Kind string `json:"kind"`
		} `json:"evidence"`
		Caveats []string `json:"caveats"`
	}
	if err := json.Unmarshal(rendered, &document); err != nil {
		t.Fatalf("the JSON document is not parseable: %v\n%s", err, rendered)
	}
	if document.SchemaVersion != ReportSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", document.SchemaVersion, ReportSchemaVersion)
	}
	if document.GeneratedAt != "2024-03-04T05:06:07Z" {
		t.Fatalf("generated_at = %q, want the injected clock", document.GeneratedAt)
	}
	if document.AuditID != "audit-report-1" || document.SnapshotID != "snap-report-1" {
		t.Fatalf("scope fields = %q/%q", document.AuditID, document.SnapshotID)
	}
	if len(document.Findings) != 4 {
		t.Fatalf("findings = %d, want the four verified statuses", len(document.Findings))
	}
	if len(document.Evidence) != 4 {
		t.Fatalf("evidence groups = %d, want one per finding", len(document.Evidence))
	}
	for _, group := range document.Evidence {
		if len(group) != 1 || group[0].ID == "" || group[0].Kind == "" {
			t.Fatalf("evidence group is incomplete: %+v", group)
		}
	}
	if len(document.Caveats) == 0 {
		t.Fatal("the JSON document does not carry the caveats")
	}

	// Two renderings of the same input are byte-identical: a report is diffable.
	again, err := RenderReport(findings, evidence, reportOptions("json", nil))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if string(again) != string(rendered) {
		t.Fatal("two renderings of the same findings differ")
	}
}

func TestRenderReportJSONKeepsNonCandidateFindings(t *testing.T) {
	findings, evidence := reportFixture(t)
	rendered, err := RenderReport(findings, evidence, reportOptions("json", func(opts *ReportOptions) {
		opts.IncludeCandidates = true
	}))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	document := string(rendered)
	if !strings.Contains(document, `"status": "candidate"`) {
		t.Fatalf("candidate status missing:\n%s", document)
	}
	if !strings.Contains(document, `"supporting_evidence"`) || !strings.Contains(document, `"contradicting_evidence"`) {
		t.Fatalf("the three evidence lists must stay apart:\n%s", document)
	}
}

func TestRenderReportSARIFIsValidJSONWithRequiredKeys(t *testing.T) {
	findings, evidence := reportFixture(t)
	rendered, err := RenderReport(findings, evidence, reportOptions("sarif", nil))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	// The task's own proof requirement: the document must survive json.Unmarshal.
	var document struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID               string `json:"id"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						DefaultConfiguration *struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(rendered, &document); err != nil {
		t.Fatalf("the SARIF document is not valid JSON: %v\n%s", err, rendered)
	}
	if document.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", document.Version)
	}
	if !strings.Contains(document.Schema, "sarif") {
		t.Fatalf("$schema = %q, want the SARIF schema URI", document.Schema)
	}
	if len(document.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(document.Runs))
	}
	run := document.Runs[0]
	if run.Tool.Driver.Name == "" || run.Tool.Driver.Version == "" {
		t.Fatalf("tool.driver is incomplete: %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != len(run.Results) {
		t.Fatalf("rules = %d, results = %d: every result needs its rule", len(run.Tool.Driver.Rules), len(run.Results))
	}

	byLevel := map[string]string{}
	byRule := map[string]int{}
	for _, result := range run.Results {
		if result.RuleID == "" {
			t.Fatal("a result has no ruleId")
		}
		if result.Message.Text == "" {
			t.Fatalf("result %s has no message", result.RuleID)
		}
		if len(result.Locations) != 1 {
			t.Fatalf("result %s has %d locations, want the evidence location", result.RuleID, len(result.Locations))
		}
		location := result.Locations[0].PhysicalLocation
		if location.ArtifactLocation.URI != "internal/api/handler.go" {
			t.Fatalf("artifact uri = %q, want the evidence file", location.ArtifactLocation.URI)
		}
		if location.Region == nil || location.Region.StartLine != 42 {
			t.Fatalf("region = %+v, want startLine 42", location.Region)
		}
		if !strings.Contains(result.Message.Text, "not a refutation") {
			t.Fatalf("result %s does not carry the caveats", result.RuleID)
		}
		byLevel[result.RuleID] = result.Level
		byRule[result.RuleID] = len(result.Suppressions)
		if result.Suppressions != nil {
			if result.Suppressions[0].Kind == "" {
				t.Fatalf("result %s has a suppression without a kind", result.RuleID)
			}
		}
		if result.RuleID == "" {
			t.Fatal("empty rule id")
		}
	}

	// The level mapping is the contract: confirmed -> error, refuted -> none with a
	// suppression, inconclusive -> warning, blocked -> note.
	wantLevel := map[FindingStatus]string{
		FindingConfirmed:    "error",
		FindingRefuted:      "none",
		FindingInconclusive: "warning",
		FindingBlocked:      "note",
	}
	for _, finding := range findings {
		if finding.Status == FindingCandidate {
			continue
		}
		ruleID := sarifRuleID(finding)
		if byLevel[ruleID] != wantLevel[finding.Status] {
			t.Fatalf("rule %s level = %q, want %q", ruleID, byLevel[ruleID], wantLevel[finding.Status])
		}
		if finding.Status == FindingRefuted && byRule[ruleID] != 1 {
			t.Fatalf("a refuted result must be suppressed, rule %s has %d suppressions", ruleID, byRule[ruleID])
		}
	}
}

func TestRenderReportSARIFHandlesMissingEvidence(t *testing.T) {
	findings, _ := reportFixture(t)
	rendered, err := RenderReport(findings, nil, reportOptions("sarif", nil))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	var document struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(rendered, &document); err != nil {
		t.Fatalf("the SARIF document is not valid JSON: %v", err)
	}
	if len(document.Runs) != 1 || len(document.Runs[0].Results) != 4 {
		t.Fatalf("a missing evidence map must not drop findings: %+v", document.Runs)
	}
}

func TestRenderReportEmptyFindingsIsStillAValidDocument(t *testing.T) {
	for _, format := range []string{"md", "json", "sarif"} {
		rendered, err := RenderReport(nil, nil, reportOptions(format, nil))
		if err != nil {
			t.Fatalf("RenderReport(%s): %v", format, err)
		}
		if len(rendered) == 0 {
			t.Fatalf("%s rendered nothing", format)
		}
		if !json.Valid(rendered) && format != "md" {
			t.Fatalf("%s output is not valid JSON:\n%s", format, rendered)
		}
	}
}

func TestRenderReportExcerptIsBoundedAndMarked(t *testing.T) {
	findings, evidence := reportFixture(t)
	// Larger than the report excerpt, smaller than the evidence cap, and free of
	// anything the redactor would rewrite, so the excerpt is the only transformation.
	// The filler carries spaces on purpose: one long unbroken token would be redacted
	// as an opaque value.
	long := strings.Repeat("the step reported no location here ", (maxReportExcerpt*2)/34+1)
	object, err := NewEvidence(EvidenceRuntimeLog, long, EvidenceOptions{
		Tool: "fixture", SnapshotID: "snap-report-1", FindingID: findings[0].ID, Now: "2024-03-04T05:06:07Z",
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if object.Redacted {
		t.Fatal("fixture evidence was unexpectedly redacted")
	}
	findings[0].Supporting = []string{object.ID}
	evidence[findings[0].ID] = []Evidence{object}

	rendered, err := RenderReport(findings, evidence, reportOptions("md", nil))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	document := string(rendered)
	if !strings.Contains(document, "[excerpt truncated]") {
		t.Fatal("a long excerpt was not marked as truncated")
	}
	if strings.Contains(document, long) {
		t.Fatal("the report embedded the whole evidence object")
	}
	if len(document) > maxReportExcerpt*4 {
		t.Fatalf("the report is %d bytes, larger than a bounded excerpt should allow", len(document))
	}
}

func TestRenderReportRedactedEvidenceIsMarked(t *testing.T) {
	findings, evidence := reportFixture(t)
	object, err := NewEvidence(EvidenceRuntimeLog, "password=hunter2secret", EvidenceOptions{
		Tool: "fixture", SnapshotID: "snap-report-1", FindingID: findings[0].ID, Now: "2024-03-04T05:06:07Z",
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if !object.Redacted {
		t.Fatal("fixture evidence was not redacted")
	}
	findings[0].Supporting = []string{object.ID}
	evidence[findings[0].ID] = []Evidence{object}

	rendered, err := RenderReport(findings, evidence, reportOptions("md", nil))
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	document := string(rendered)
	if !strings.Contains(document, "redacted: true") {
		t.Fatalf("the report does not say the content was redacted:\n%s", document)
	}
	if strings.Contains(document, "hunter2secret") {
		t.Fatalf("the report reprinted the secret:\n%s", document)
	}
}
