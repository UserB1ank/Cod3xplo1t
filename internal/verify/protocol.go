package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Errors. Each names a different operator action: an invalid plan is a builder bug,
// a denied scope is an authorization decision, and a missing approval is a human
// gate that was not opened.
var (
	ErrInvalidPlan      = errors.New("verify: invalid plan")
	ErrInvalidResult    = errors.New("verify: invalid result")
	ErrScopeDenied      = errors.New("verify: scope denied")
	ErrApprovalRequired = errors.New("verify: approval required")
	ErrUnsupportedStep  = errors.New("verify: unsupported step")
	ErrNotFound         = errors.New("verify: not found")
	ErrConflict         = errors.New("verify: conflict")
	ErrInvalidArgument  = errors.New("verify: invalid argument")
)

// Caps on an environment. They are ceilings, not defaults: a plan may ask for less,
// never for more, because a verification that can exhaust the host is a denial of
// service with extra steps.
const (
	MaxCPUMillis       = 8000
	MaxMemoryMB        = 8192
	MaxDiskMB          = 4096
	MaxProcesses       = 512
	MaxTimeoutSecs     = 3600
	MaxSteps           = 20
	MaxEvidenceContent = 64000
	MaxReasonChars     = 2000
	MaxReproduction    = 4000
)

// ValidatePlan checks a plan before anything executes it.
func ValidatePlan(plan Plan) error {
	var problems []string
	if plan.SchemaVersion != SchemaVersion {
		problems = append(problems, fmt.Sprintf("schema_version is %d, want %d", plan.SchemaVersion, SchemaVersion))
	}
	for name, value := range map[string]string{
		"hypothesis_id": plan.HypothesisID, "finding_id": plan.FindingID,
		"path_id": plan.PathID, "audit_id": plan.AuditID, "snapshot_id": plan.SnapshotID,
		"security_goal": plan.SecurityGoal, "claim": plan.Claim,
	} {
		if strings.TrimSpace(value) == "" {
			problems = append(problems, name+" is required")
		}
	}
	if len(plan.Steps) == 0 {
		problems = append(problems, "a plan needs at least one step")
	}
	if len(plan.Steps) > MaxSteps {
		problems = append(problems, fmt.Sprintf("%d steps exceeds the limit of %d", len(plan.Steps), MaxSteps))
	}
	for i, step := range plan.Steps {
		where := fmt.Sprintf("steps[%d]", i)
		if !ValidStepKind(step.Kind) {
			problems = append(problems, where+".kind is unknown")
		}
		switch step.Kind {
		case StepStaticCheck, StepDataflowProbe, StepDependencyProbe, StepManualReview:
			if len(step.StaticQuery) == 0 && len(step.Command) == 0 {
				problems = append(problems, where+" needs a static_query or a command")
			}
		case StepDynamicProof:
			if len(step.Command) == 0 {
				problems = append(problems, where+" is a dynamic proof and needs a command")
			}
			if !step.RequiresApproval {
				problems = append(problems, where+" is a dynamic proof and must be marked as requiring approval")
			}
		}
		if strings.TrimSpace(step.Expectation) == "" {
			problems = append(problems, where+".expectation is required: a step that does not say what it expects cannot fail")
		}
		if strings.TrimSpace(step.Contradiction) == "" {
			problems = append(problems, where+".contradiction is required: stating what would disprove the claim up front is what keeps a confirmation from being a coincidence")
		}
		if step.TimeoutSeconds > MaxTimeoutSecs {
			problems = append(problems, fmt.Sprintf("%s.timeout_seconds exceeds %d", where, MaxTimeoutSecs))
		}
		if len(step.Command) > 0 && len(step.Command[0]) == 0 {
			problems = append(problems, where+".command[0] must not be empty")
		}
	}
	env := plan.Environment.Normalize()
	if !env.SourceReadOnly {
		problems = append(problems, "environment.source_read_only must be true: verification reads the snapshot and writes only to its scratch space")
	}
	if env.MountHostSocket {
		problems = append(problems, "environment.mount_host_socket must be false: the host container socket is never exposed to a verification")
	}
	if env.CPUMillis > MaxCPUMillis || env.MemoryMB > MaxMemoryMB || env.DiskMB > MaxDiskMB ||
		env.MaxProcesses > MaxProcesses || env.TimeoutSeconds > MaxTimeoutSecs {
		problems = append(problems, "environment quotas exceed the allowed ceilings")
	}
	if env.Network == NetworkRestricted && len(env.AllowedHosts) == 0 {
		problems = append(problems, "environment.network is restricted but allowed_hosts is empty")
	}
	if env.Network != NetworkNone && !plan.Scope.AllowNetwork {
		problems = append(problems, "the environment wants network access but the scope does not allow it")
	}
	if strings.TrimSpace(plan.Scope.Repository) == "" {
		problems = append(problems, "scope.repository is required: verification runs only against an authorized repository")
	}
	if plan.Scope.SnapshotID != "" && plan.Scope.SnapshotID != plan.SnapshotID {
		problems = append(problems, fmt.Sprintf("scope authorized snapshot %s but the plan targets %s", plan.Scope.SnapshotID, plan.SnapshotID))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidPlan, strings.Join(problems, "; "))
	}
	return nil
}

// Prepared is a plan that passed validation, with its hash and derived limits. A
// caller that holds a Prepared has no excuse for executing an unvalidated plan.
type Prepared struct {
	Plan          Plan
	Environment   Environment
	PlanHash      string
	NeedsApproval bool
}

// Prepare validates and normalises a plan.
func Prepare(plan Plan) (*Prepared, error) {
	if err := ValidatePlan(plan); err != nil {
		return nil, err
	}
	plan.Environment = plan.Environment.Normalize()
	plan.PlanHash = PlanHashOf(plan)
	return &Prepared{Plan: plan, Environment: plan.Environment, PlanHash: plan.PlanHash, NeedsApproval: plan.NeedsApproval()}, nil
}

// Authorize checks a plan against its scope and an approval record.
//
// It is the gate the design's §11 requires: a plan that needs network access or a
// dynamic proof runs only when the scope allows it and, when the plan is high risk,
// only after a human approval is recorded — not asserted.
func Authorize(prepared *Prepared, approved bool, approvedBy string) error {
	if prepared == nil {
		return fmt.Errorf("%w: no prepared plan", ErrInvalidPlan)
	}
	plan := prepared.Plan
	if prepared.Environment.Network != NetworkNone {
		if !plan.Scope.AllowNetwork {
			return fmt.Errorf("%w: the plan needs %s network access and the scope allows none", ErrScopeDenied, prepared.Environment.Network)
		}
		if plan.Scope.Repository == "" {
			return fmt.Errorf("%w: network access requires an authorized repository", ErrScopeDenied)
		}
	}
	if prepared.NeedsApproval && (!approved || strings.TrimSpace(approvedBy) == "") {
		return fmt.Errorf("%w: this plan contains a step that requires a recorded human approval", ErrApprovalRequired)
	}
	return nil
}

// DeriveOutcome turns what an executor reported into a verdict, and refuses to
// promote a verdict the evidence does not support.
//
// This is the package's central honesty rule:
//   - CONFIRMED needs reproduction evidence (a runtime log or a test) plus a
//     reproduction description, and it is demoted to INCONCLUSIVE if anything
//     contradicts it;
//   - REFUTED needs contradicting evidence, because "we did not reproduce it" is
//     exactly the answer that must not be recorded as a refutation;
//   - everything else is INCONCLUSIVE, and a run that could not start is BLOCKED.
func DeriveOutcome(result Result, plan Plan) (Outcome, string) {
	if result.Outcome == OutcomeBlocked {
		return OutcomeBlocked, nonEmptyReason(result.Reason, "the verification could not run")
	}
	reproducing, contradicting := 0, 0
	for _, evidence := range result.Evidence {
		switch evidence.Kind {
		case EvidenceRuntimeLog, EvidenceTest:
			if evidence.Supersedes == "" {
				reproducing++
			}
		case EvidenceSource, EvidenceStaticQuery, EvidenceRule:
			// Static evidence can support or contradict, and the executor says which by
			// where it puts it; see below.
		}
	}
	contradicting = len(result.ContradictingEvidence())
	switch result.Outcome {
	case OutcomeConfirmed:
		if reproducing == 0 || strings.TrimSpace(result.Reproduction) == "" {
			return OutcomeInconclusive, "a confirmation needs reproduction evidence and the steps that reproduced it; neither was provided"
		}
		if contradicting > 0 {
			return OutcomeInconclusive, "the result claims confirmation but carries contradicting evidence; the contradiction is the stronger signal"
		}
		return OutcomeConfirmed, nonEmptyReason(result.Reason, "reproduced with evidence")
	case OutcomeRefuted:
		if contradicting == 0 {
			return OutcomeInconclusive, "a refutation needs contradicting evidence; failing to reproduce is not a refutation"
		}
		return OutcomeRefuted, nonEmptyReason(result.Reason, "contradicting evidence exists")
	case OutcomeInconclusive:
		return OutcomeInconclusive, nonEmptyReason(result.Reason, "the evidence is insufficient to conclude")
	default:
		return OutcomeInconclusive, "the executor reported no verdict"
	}
}

func nonEmptyReason(reason, fallback string) string {
	if strings.TrimSpace(reason) == "" {
		return fallback
	}
	if len(reason) > MaxReasonChars {
		return reason[:MaxReasonChars]
	}
	return reason
}

// ContradictingEvidence returns the evidence the executor marked as contradicting
// the hypothesis. Executors set it by kind: see MarkContradicting.
func (r Result) ContradictingEvidence() []Evidence {
	out := make([]Evidence, 0, len(r.Evidence))
	for _, evidence := range r.Evidence {
		if strings.HasPrefix(evidence.RedactionNotes, ContradictionMarker) {
			out = append(out, evidence)
		}
	}
	return out
}

// ContradictionMarker prefixes the redaction notes of evidence that contradicts the
// hypothesis. It is a marker rather than a field so the evidence object keeps one
// shape, and it is stripped when the evidence is displayed.
const ContradictionMarker = "contradicts: "

// MarkContradicting records that an evidence object contradicts the hypothesis.
func MarkContradicting(evidence Evidence, reason string) Evidence {
	note := ContradictionMarker + strings.TrimSpace(reason)
	if evidence.RedactionNotes == "" {
		evidence.RedactionNotes = note
	} else {
		evidence.RedactionNotes = note + "; " + evidence.RedactionNotes
	}
	return evidence
}

// ValidateResult checks an executor's result before it is stored.
func ValidateResult(result Result, plan Plan) error {
	var problems []string
	if !ValidOutcome(result.Outcome) {
		problems = append(problems, fmt.Sprintf("outcome %q is unknown", result.Outcome))
	}
	if len(result.Reason) > MaxReasonChars {
		problems = append(problems, fmt.Sprintf("reason exceeds %d characters", MaxReasonChars))
	}
	if len(result.Reproduction) > MaxReproduction {
		problems = append(problems, fmt.Sprintf("reproduction exceeds %d characters", MaxReproduction))
	}
	for i, evidence := range result.Evidence {
		where := fmt.Sprintf("evidence[%d]", i)
		if !ValidEvidenceKind(evidence.Kind) {
			problems = append(problems, where+".kind is unknown")
		}
		if strings.TrimSpace(evidence.Tool) == "" {
			problems = append(problems, where+".tool is required: evidence without a producer cannot be re-checked")
		}
		if evidence.ContentHash == "" || hashContent(evidence.Content) != evidence.ContentHash {
			problems = append(problems, where+" content does not match its hash")
		}
		if evidence.SnapshotID == "" {
			evidence.SnapshotID = plan.SnapshotID
		}
		if evidence.SnapshotID != plan.SnapshotID {
			problems = append(problems, where+" belongs to another snapshot")
		}
		if len(evidence.Content) > MaxEvidenceContent {
			problems = append(problems, fmt.Sprintf("%s.content exceeds %d characters", where, MaxEvidenceContent))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidResult, strings.Join(problems, "; "))
	}
	return nil
}

// --- evidence construction and redaction -------------------------------------

var (
	// Written as an interpreted string because the pattern needs a backtick inside
	// its character class, which a raw string literal cannot carry.
	secretAssignment = regexp.MustCompile("(?i)\\b(password|passwd|secret|token|api[_-]?key|apikey|authorization|credential|private[_-]?key)\\b(\\s*[:=]\\s*)([^\\s\"'`,;]{3,})")
	bearerToken      = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	privateKeyBlock  = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	emailAddress     = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	longOpaque       = regexp.MustCompile(`\b[A-Za-z0-9+/=_-]{32,}\b`)
)

// Redact removes material a verification log must never store: credentials,
// authorization headers, private keys, e-mail addresses and long opaque strings.
//
// The transformation is recorded rather than hidden: the evidence says it was
// redacted and why, so a reviewer knows the stored bytes differ from what the tool
// printed. Redacting silently would make the hash of a log disagree with the log.
func Redact(content string) (string, bool, string) {
	notes := []string{}
	out := content
	apply := func(re *regexp.Regexp, replacement string, label string) {
		if re.MatchString(out) {
			out = re.ReplaceAllString(out, replacement)
			notes = append(notes, label)
		}
	}
	apply(privateKeyBlock, "[redacted private key block]", "private key block")
	apply(secretAssignment, "${1}${2}[redacted]", "secret-like assignment")
	apply(bearerToken, "${1} [redacted]", "authorization header")
	apply(emailAddress, "[redacted address]", "e-mail address")
	apply(longOpaque, "[redacted opaque value]", "long opaque value")
	redacted := len(notes) > 0
	if len(out) > MaxEvidenceContent {
		out = out[:MaxEvidenceContent]
		notes = append(notes, "content truncated to the evidence limit")
		redacted = true
	}
	sort.Strings(notes)
	return out, redacted, strings.Join(notes, "; ")
}

func hashContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NewEvidence builds an evidence object. It is the only constructor, so redaction,
// hashing and id derivation cannot be skipped.
type EvidenceOptions struct {
	Tool              string
	ToolVersion       string
	SnapshotID        string
	HypothesisID      string
	FindingID         string
	PathID            string
	VerificationRunID string
	File              string
	Line              int
	Supersedes        string
	Now               string
}

// NewEvidence redacts, hashes and identifies one evidence object.
func NewEvidence(kind EvidenceKind, content string, opts EvidenceOptions) (Evidence, error) {
	if !ValidEvidenceKind(kind) {
		return Evidence{}, fmt.Errorf("%w: unknown evidence kind %q", ErrInvalidArgument, kind)
	}
	if strings.TrimSpace(opts.Tool) == "" {
		return Evidence{}, fmt.Errorf("%w: evidence needs the tool that produced it", ErrInvalidArgument)
	}
	if strings.TrimSpace(opts.SnapshotID) == "" {
		return Evidence{}, fmt.Errorf("%w: evidence needs a snapshot id", ErrInvalidArgument)
	}
	redactedContent, wasRedacted, notes := Redact(content)
	evidence := Evidence{
		Kind: kind, Tool: opts.Tool, ToolVersion: opts.ToolVersion,
		SnapshotID: opts.SnapshotID, HypothesisID: opts.HypothesisID, FindingID: opts.FindingID,
		PathID: opts.PathID, VerificationRunID: opts.VerificationRunID,
		File: opts.File, Line: opts.Line,
		Content: redactedContent, ContentHash: hashContent(redactedContent),
		Redacted: wasRedacted, RedactionNotes: notes, Supersedes: opts.Supersedes,
		CreatedAt: opts.Now,
	}
	// The id is scoped by the narrowest relationship the evidence belongs to, so two
	// runs never share an object just because they produced the same bytes.
	evidence.ID = DeriveEvidenceID(evidence)
	if evidence.CreatedAt == "" {
		evidence.CreatedAt = NowString(nowUTC())
	}
	return evidence, nil
}
