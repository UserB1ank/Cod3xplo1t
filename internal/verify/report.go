package verify

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// The report engine renders findings and their evidence. It is pure: it reads the
// findings and the evidence map it is handed and returns bytes. It writes nothing,
// queries nothing and decides nothing — the statuses it prints were already derived
// by verification.
//
// Every renderer states the same caveats, because the difference between
// "confirmed", "refuted", "inconclusive" and "blocked" is the product's central
// honesty rule, and a report that flattens them is worse than no report.

// Report schema and tool identity.
const (
	// ReportSchemaVersion identifies the JSON document shape.
	ReportSchemaVersion = 1
	// ReportToolName and ReportToolVersion identify the report engine in SARIF and
	// in the JSON document.
	ReportToolName    = "codexploit-report"
	ReportToolVersion = "1"
	// reportSARIFSchema is the canonical SARIF 2.1.0 schema URI.
	reportSARIFSchema = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	// maxReportExcerpt bounds the content shown for one evidence object.
	maxReportExcerpt = 2000
	// defaultMaxFindings bounds a rendered report when the caller sets no limit.
	defaultMaxFindings = 500
)

// Caveats is the honest reading instruction attached to every rendered report. The
// four lines are the vocabulary's definition, not a disclaimer.
var Caveats = []string{
	"confirmed means reproduction evidence exists and nothing contradicts it",
	"refuted means contradicting evidence exists, which is not the same as failing to reproduce",
	"inconclusive means the verification ran but settled nothing; it is not a refutation",
	"blocked means the verification could not run; it is not a refutation either",
}

// ReportOptions selects and bounds one rendered report.
type ReportOptions struct {
	// Format is md, json or sarif. An unknown format is refused, never defaulted.
	Format string
	// Title heads a Markdown report.
	Title string
	// AuditID and SnapshotID identify the scope the report covers.
	AuditID    string
	SnapshotID string
	// IncludeCandidates includes `candidate` findings, which are unverified
	// hypotheses. Off by default, because a report of findings should not read as a
	// report of vulnerabilities.
	IncludeCandidates bool
	// MaxFindings bounds the report. Zero uses a small default; a negative value
	// means no limit.
	MaxFindings int
	// Now stamps generated_at. It is a field rather than package state so two
	// renderings of the same findings can be compared byte for byte.
	Now func() time.Time
}

// Report is the stable JSON document.
type Report struct {
	SchemaVersion int                   `json:"schema_version"`
	GeneratedAt   string                `json:"generated_at"`
	AuditID       string                `json:"audit_id"`
	SnapshotID    string                `json:"snapshot_id"`
	Findings      []ReportFinding       `json:"findings"`
	Evidence      map[string][]Evidence `json:"evidence"`
	// Caveats repeats the vocabulary's reading instruction in the document itself,
	// so a consumer that only ever sees the JSON still gets it.
	Caveats []string `json:"caveats"`
}

// ReportFinding is one finding as a report shows it, with its evidence resolved and
// counted.
type ReportFinding struct {
	Finding    Finding    `json:"finding"`
	Title      string     `json:"title"`
	Status     string     `json:"status"`
	Severity   string     `json:"severity,omitempty"`
	Hypothesis string     `json:"hypothesis_id"`
	PathID     string     `json:"path_id,omitempty"`
	AuditID    string     `json:"audit_id,omitempty"`
	SnapshotID string     `json:"snapshot_id,omitempty"`
	Evidence   []Evidence `json:"evidence"`
	// EvidenceCounts is the count per list, so a table can show "2 supporting, 1
	// contradicting" without walking the lists.
	EvidenceCounts EvidenceCounts `json:"evidence_counts"`
}

// EvidenceCounts is how many evidence objects sit in each of the three lists.
type EvidenceCounts struct {
	Supporting    int `json:"supporting"`
	Contradicting int `json:"contradicting"`
	Inconclusive  int `json:"inconclusive"`
}

// RenderReport renders findings and their evidence.
//
// evidence is keyed by finding id; a finding with no entry still renders, with an
// empty evidence list, because a missing evidence map must not make a finding
// disappear.
func RenderReport(findings []Finding, evidence map[string][]Evidence, opts ReportOptions) ([]byte, error) {
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = "md"
	}
	document, err := buildReport(findings, evidence, opts)
	if err != nil {
		return nil, err
	}
	switch format {
	case "md", "markdown":
		return renderMarkdown(document, opts), nil
	case "json":
		return renderJSON(document)
	case "sarif":
		return renderSARIF(document)
	default:
		return nil, fmt.Errorf("%w: unknown report format %q (want md, json or sarif)", ErrInvalidArgument, opts.Format)
	}
}

// buildReport selects, orders and resolves the findings once, so all three
// renderers see exactly the same document.
func buildReport(findings []Finding, evidence map[string][]Evidence, opts ReportOptions) (Report, error) {
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	selected := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if !ValidFindingStatus(finding.Status) {
			return Report{}, fmt.Errorf("%w: finding %s has unknown status %q", ErrInvalidArgument, finding.ID, finding.Status)
		}
		if finding.Status == FindingCandidate && !opts.IncludeCandidates {
			continue
		}
		selected = append(selected, finding)
	}
	sortFindings(selected)
	limit := opts.MaxFindings
	if limit == 0 {
		limit = defaultMaxFindings
	}
	if limit > 0 && len(selected) > limit {
		selected = selected[:limit]
	}

	document := Report{
		SchemaVersion: ReportSchemaVersion,
		GeneratedAt:   NowString(now),
		AuditID:       opts.AuditID,
		SnapshotID:    opts.SnapshotID,
		Findings:      make([]ReportFinding, 0, len(selected)),
		Evidence:      map[string][]Evidence{},
		Caveats:       append([]string(nil), Caveats...),
	}
	for _, finding := range selected {
		list := resolveEvidence(finding, evidence)
		document.Findings = append(document.Findings, ReportFinding{
			Finding: finding, Title: reportTitle(finding), Status: string(finding.Status),
			Severity: finding.Severity, Hypothesis: finding.HypothesisID, PathID: finding.PathID,
			AuditID: finding.AuditID, SnapshotID: finding.SnapshotID,
			Evidence: list,
			EvidenceCounts: EvidenceCounts{
				Supporting: len(finding.Supporting), Contradicting: len(finding.Contradicting),
				Inconclusive: len(finding.Inconclusive),
			},
		})
		if len(list) > 0 {
			document.Evidence[finding.ID] = list
		}
	}
	return document, nil
}

// resolveEvidence collects a finding's evidence from the map, in the order of the
// three lists, and de-duplicates it.
func resolveEvidence(finding Finding, evidence map[string][]Evidence) []Evidence {
	if evidence == nil {
		return []Evidence{}
	}
	index := map[string]Evidence{}
	for _, object := range evidence[finding.ID] {
		index[object.ID] = object
	}
	out := []Evidence{}
	seen := map[string]struct{}{}
	for _, group := range [][]string{finding.Supporting, finding.Contradicting, finding.Inconclusive} {
		for _, id := range group {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			if object, ok := index[id]; ok {
				out = append(out, object)
			}
		}
	}
	return out
}

// sortFindings orders a report: confirmed first, then refuted, inconclusive,
// blocked, candidate, and within a status the highest severity and then the id.
// The order is total, so two renderings of the same set are identical.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if statusRank(left.Status) != statusRank(right.Status) {
			return statusRank(left.Status) < statusRank(right.Status)
		}
		if severityRank(left.Severity) != severityRank(right.Severity) {
			return severityRank(left.Severity) < severityRank(right.Severity)
		}
		return left.ID < right.ID
	})
}

func statusRank(status FindingStatus) int {
	switch status {
	case FindingConfirmed:
		return 0
	case FindingRefuted:
		return 1
	case FindingInconclusive:
		return 2
	case FindingBlocked:
		return 3
	default:
		return 4
	}
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium", "moderate":
		return 2
	case "low":
		return 3
	case "":
		return 5
	default:
		return 4
	}
}

func reportTitle(finding Finding) string {
	if strings.TrimSpace(finding.Title) != "" {
		return strings.Join(strings.Fields(finding.Title), " ")
	}
	if strings.TrimSpace(finding.HypothesisID) != "" {
		return "hypothesis " + finding.HypothesisID
	}
	return "finding " + finding.ID
}

// --- Markdown ----------------------------------------------------------------

func renderMarkdown(document Report, opts ReportOptions) []byte {
	var b strings.Builder
	title := strings.TrimSpace(opts.Title)
	if title == "" {
		title = "Verification report"
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "- generated_at: %s\n", document.GeneratedAt)
	if document.AuditID != "" {
		fmt.Fprintf(&b, "- audit_id: %s\n", document.AuditID)
	}
	if document.SnapshotID != "" {
		fmt.Fprintf(&b, "- snapshot_id: %s\n", document.SnapshotID)
	}
	fmt.Fprintf(&b, "- findings: %d\n", len(document.Findings))
	b.WriteString("\n## How to read this report\n\n")
	for _, caveat := range document.Caveats {
		fmt.Fprintf(&b, "- %s\n", caveat)
	}

	b.WriteString("\n## Findings\n\n")
	if len(document.Findings) == 0 {
		b.WriteString("No findings matched this report's filters.\n")
	} else {
		b.WriteString("| status | severity | title | hypothesis | path | evidence (supporting/contradicting/inconclusive) |\n")
		b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
		for _, item := range document.Findings {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %d/%d/%d |\n",
				tableCell(item.Status), tableCell(orDash(item.Severity)), tableCell(item.Title),
				tableCell(item.Hypothesis), tableCell(orDash(item.PathID)),
				item.EvidenceCounts.Supporting, item.EvidenceCounts.Contradicting, item.EvidenceCounts.Inconclusive)
		}
	}

	for _, item := range document.Findings {
		fmt.Fprintf(&b, "\n## %s (%s)\n\n", item.Title, item.Status)
		fmt.Fprintf(&b, "- finding_id: %s\n", item.Finding.ID)
		fmt.Fprintf(&b, "- hypothesis_id: %s\n", item.Hypothesis)
		if item.PathID != "" {
			fmt.Fprintf(&b, "- path_id: %s\n", item.PathID)
		}
		if item.AuditID != "" {
			fmt.Fprintf(&b, "- audit_id: %s\n", item.AuditID)
		}
		if item.SnapshotID != "" {
			fmt.Fprintf(&b, "- snapshot_id: %s\n", item.SnapshotID)
		}
		if item.Severity != "" {
			fmt.Fprintf(&b, "- severity: %s\n", item.Severity)
		}
		if item.Finding.Confidence != "" {
			fmt.Fprintf(&b, "- confidence: %s\n", item.Finding.Confidence)
		}
		fmt.Fprintf(&b, "- environments: %s\n", orDash(strings.Join(item.Finding.Environments, ", ")))
		fmt.Fprintf(&b, "- runs: %s\n", orDash(strings.Join(item.Finding.VerificationRunIDs, ", ")))

		b.WriteString("\n### Evidence\n\n")
		if len(item.Evidence) == 0 {
			b.WriteString("No evidence objects are attached; the verdict rests on the run record alone.\n")
		}
		for _, object := range item.Evidence {
			fmt.Fprintf(&b, "#### %s `%s`\n\n", object.Kind, object.ID)
			fmt.Fprintf(&b, "- tool: %s", object.Tool)
			if object.ToolVersion != "" {
				fmt.Fprintf(&b, "@%s", object.ToolVersion)
			}
			b.WriteString("\n")
			if location := evidenceLocation(object); location != "" {
				fmt.Fprintf(&b, "- location: %s\n", location)
			}
			fmt.Fprintf(&b, "- list: %s\n", evidenceList(item, object.ID))
			if object.Redacted {
				fmt.Fprintf(&b, "- redacted: true (%s)\n", orDash(object.RedactionNotes))
			}
			if object.Supersedes != "" {
				fmt.Fprintf(&b, "- supersedes: %s\n", object.Supersedes)
			}
			b.WriteString("\n```\n")
			b.WriteString(excerpt(object.Content, maxReportExcerpt))
			b.WriteString("\n```\n\n")
		}

		b.WriteString("### Reproduce\n\n")
		if strings.TrimSpace(item.Finding.ReproduceSteps) == "" {
			b.WriteString("No reproduction steps were recorded.\n")
		} else {
			b.WriteString("```\n")
			b.WriteString(excerpt(item.Finding.ReproduceSteps, MaxReproduction))
			b.WriteString("\n```\n")
		}

		b.WriteString("\n### Limitations\n\n")
		if len(item.Finding.Limitations) == 0 {
			b.WriteString("None recorded.\n")
		}
		for _, limitation := range item.Finding.Limitations {
			fmt.Fprintf(&b, "- %s\n", limitation)
		}
	}
	return []byte(b.String())
}

func evidenceList(item ReportFinding, evidenceID string) string {
	switch {
	case contains(item.Finding.Supporting, evidenceID):
		return "supporting"
	case contains(item.Finding.Contradicting, evidenceID):
		return "contradicting"
	case contains(item.Finding.Inconclusive, evidenceID):
		return "inconclusive"
	default:
		return "unlisted"
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// excerpt bounds what a report shows for one evidence object and marks the cut, so
// a truncated quote is never mistaken for the whole record.
func excerpt(content string, limit int) string {
	trimmed := strings.TrimRight(content, "\n")
	if limit <= 0 || len(trimmed) <= limit {
		return trimmed
	}
	cut := trimmed[:limit]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "\n[excerpt truncated]"
}

func evidenceLocation(object Evidence) string {
	file := strings.TrimSpace(object.File)
	if file == "" && object.Line == 0 {
		return ""
	}
	if object.Line > 0 {
		return fmt.Sprintf("%s:%d", file, object.Line)
	}
	return file
}

func tableCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	return value
}

// --- JSON --------------------------------------------------------------------

func renderJSON(document Report) ([]byte, error) {
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: cannot encode the report: %v", ErrInvalidArgument, err)
	}
	return append(encoded, '\n'), nil
}

// --- SARIF -------------------------------------------------------------------

// SARIF 2.1.0, minimal but valid: the three keys a consumer requires are version,
// $schema and runs, and every run needs tool.driver. Results carry a ruleId, a
// level mapped from the finding status, a message and the locations the evidence
// points at.

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	FullDescription  *sarifMessage     `json:"fullDescription,omitempty"`
	DefaultConfig    *sarifRuleConfig  `json:"defaultConfiguration,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifMessage       `json:"message"`
	Locations    []sarifLocation    `json:"locations,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
	Properties   map[string]string  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

func renderSARIF(document Report) ([]byte, error) {
	run := sarifRun{Tool: sarifTool{Driver: sarifDriver{
		Name: ReportToolName, Version: ReportToolVersion, Rules: []sarifRule{},
	}}, Results: []sarifResult{}}
	seenRule := map[string]struct{}{}
	for _, item := range document.Findings {
		ruleID := sarifRuleID(item.Finding)
		if _, ok := seenRule[ruleID]; !ok {
			seenRule[ruleID] = struct{}{}
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               ruleID,
				Name:             sarifRuleName(item.Finding),
				ShortDescription: sarifMessage{Text: item.Title},
				DefaultConfig:    &sarifRuleConfig{Level: sarifLevel(item.Status)},
				Properties: map[string]string{
					"status": item.Status,
				},
			})
		}
		result := sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(item.Status),
			Message: sarifMessage{Text: sarifMessageText(item)},
			Properties: map[string]string{
				"status":      item.Status,
				"finding_id":  item.Finding.ID,
				"hypothesis":  item.Hypothesis,
				"evidence":    fmt.Sprintf("supporting=%d contradicting=%d inconclusive=%d", item.EvidenceCounts.Supporting, item.EvidenceCounts.Contradicting, item.EvidenceCounts.Inconclusive),
				"audit_id":    item.AuditID,
				"snapshot_id": item.SnapshotID,
			},
		}
		if result.Properties["audit_id"] == "" {
			delete(result.Properties, "audit_id")
		}
		if result.Properties["snapshot_id"] == "" {
			delete(result.Properties, "snapshot_id")
		}
		if item.Status == string(FindingRefuted) {
			// A refutation is reported as a suppressed result: the finding exists and
			// is recorded, but it is not a defect, and a consumer that ignores
			// suppressions must not read it as one.
			result.Suppressions = []sarifSuppression{{
				Kind:          "inSource",
				Justification: "verification refuted this hypothesis: contradicting evidence exists, so there is no defect to fix",
			}}
		}
		if location, ok := sarifLocationOf(item); ok {
			result.Locations = []sarifLocation{location}
		}
		run.Results = append(run.Results, result)
	}
	log := sarifLog{Version: "2.1.0", Schema: reportSARIFSchema, Runs: []sarifRun{run}}
	encoded, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: cannot encode SARIF: %v", ErrInvalidArgument, err)
	}
	return append(encoded, '\n'), nil
}

// sarifLevel maps a finding status onto a SARIF level. `refuted` is `none`: it is
// a recorded absence, not a warning.
func sarifLevel(status string) string {
	switch FindingStatus(status) {
	case FindingConfirmed:
		return "error"
	case FindingRefuted:
		return "none"
	case FindingInconclusive:
		return "warning"
	default:
		return "note"
	}
}

func sarifRuleID(finding Finding) string {
	if strings.TrimSpace(finding.ID) != "" {
		return finding.ID
	}
	return "codexploit/verification"
}

func sarifRuleName(finding Finding) string {
	title := reportTitle(finding)
	if len(title) > 64 {
		title = title[:64]
	}
	return title
}

func sarifMessageText(item ReportFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", item.Status, item.Title)
	if item.Severity != "" {
		fmt.Fprintf(&b, " (severity %s)", item.Severity)
	}
	fmt.Fprintf(&b, "\nhypothesis %s", item.Hypothesis)
	fmt.Fprintf(&b, "\nevidence: %d supporting, %d contradicting, %d inconclusive",
		item.EvidenceCounts.Supporting, item.EvidenceCounts.Contradicting, item.EvidenceCounts.Inconclusive)
	if len(item.Evidence) > 0 {
		fmt.Fprintf(&b, "\nsee evidence %s produced by %s", item.Evidence[0].ID, item.Evidence[0].Tool)
	}
	for _, caveat := range Caveats {
		fmt.Fprintf(&b, "\ncaveat: %s", caveat)
	}
	return b.String()
}

func sarifLocationOf(item ReportFinding) (sarifLocation, bool) {
	for _, object := range item.Evidence {
		if strings.TrimSpace(object.File) == "" {
			continue
		}
		location := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: strings.ReplaceAll(object.File, "\\", "/")},
		}}
		if object.Line > 0 {
			location.PhysicalLocation.Region = &sarifRegion{StartLine: object.Line}
		}
		return location, true
	}
	return sarifLocation{}, false
}
