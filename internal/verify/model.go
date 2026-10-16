// Package verify turns hypotheses into verified findings, or into honestly
// unresolved ones.
//
// The design is explicit about what verification may claim (§3.4, §11): a finding
// is not established by failing to reproduce it. `refuted` requires contradicting
// evidence, `inconclusive` means the evidence is insufficient, and `blocked` means
// the verification could not run at all. The three are different answers, and the
// whole package exists to keep them apart.
//
// Two more rules shape it:
//
//   - evidence is immutable and content-addressed. A correction is a new object
//     that supersedes the old one, never an edit, because evidence that can be
//     rewritten is not evidence;
//   - verification runs inside a declared scope and budget. Network access and
//     dynamic proof-of-concept execution require an approval that is recorded with
//     the run, and the executor never receives the host's container socket.
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SchemaVersion identifies the serialised shape of a plan and of a result.
const SchemaVersion = 1

// FindingStatus is the verdict vocabulary (design §3.4).
type FindingStatus string

const (
	// FindingCandidate is where every finding starts: a hypothesis with evidence,
	// not yet verified.
	FindingCandidate FindingStatus = "candidate"
	// FindingConfirmed means reproduction evidence exists and nothing contradicts it.
	FindingConfirmed FindingStatus = "confirmed"
	// FindingRefuted means contradicting evidence exists: a control demonstrably
	// blocks the path, or the claimed sink cannot be reached with attacker data.
	FindingRefuted FindingStatus = "refuted"
	// FindingInconclusive means the verification ran but settled nothing. This is not
	// a refutation.
	FindingInconclusive FindingStatus = "inconclusive"
	// FindingBlocked means the verification could not run: missing scope approval,
	// missing environment, unsupported target.
	FindingBlocked FindingStatus = "blocked"
)

// AllFindingStatuses returns the vocabulary.
func AllFindingStatuses() []FindingStatus {
	return []FindingStatus{FindingCandidate, FindingConfirmed, FindingRefuted, FindingInconclusive, FindingBlocked}
}

// ValidFindingStatus reports whether a status is known.
func ValidFindingStatus(s FindingStatus) bool {
	for _, known := range AllFindingStatuses() {
		if s == known {
			return true
		}
	}
	return false
}

// Conclusive reports whether verification has finished for a finding. A blocked
// finding is not conclusive: it may be verifiable later.
func (s FindingStatus) Conclusive() bool {
	return s == FindingConfirmed || s == FindingRefuted || s == FindingInconclusive
}

// VerificationStatus is the lifecycle of one attempt.
type VerificationStatus string

const (
	VerifyCreated   VerificationStatus = "CREATED"
	VerifyApproved  VerificationStatus = "APPROVED"
	VerifyRunning   VerificationStatus = "RUNNING"
	VerifySucceeded VerificationStatus = "SUCCEEDED"
	VerifyFailed    VerificationStatus = "FAILED"
	VerifyBlocked   VerificationStatus = "BLOCKED"
	VerifyCancelled VerificationStatus = "CANCELLED"
	VerifyTimedOut  VerificationStatus = "TIMED_OUT"
)

// AllVerificationStatuses returns the vocabulary.
func AllVerificationStatuses() []VerificationStatus {
	return []VerificationStatus{VerifyCreated, VerifyApproved, VerifyRunning, VerifySucceeded,
		VerifyFailed, VerifyBlocked, VerifyCancelled, VerifyTimedOut}
}

// ValidVerificationStatus reports whether a status is known.
func ValidVerificationStatus(s VerificationStatus) bool {
	for _, known := range AllVerificationStatuses() {
		if s == known {
			return true
		}
	}
	return false
}

// Terminal reports whether no further transition is expected.
func (s VerificationStatus) Terminal() bool {
	switch s {
	case VerifySucceeded, VerifyFailed, VerifyBlocked, VerifyCancelled, VerifyTimedOut:
		return true
	}
	return false
}

// EvidenceKind classifies an evidence object (design §3.4).
type EvidenceKind string

const (
	EvidenceSource      EvidenceKind = "source"
	EvidenceStaticQuery EvidenceKind = "static_query"
	EvidenceRule        EvidenceKind = "rule"
	EvidenceRuntimeLog  EvidenceKind = "runtime_log"
	EvidenceTest        EvidenceKind = "test"
	EvidenceEnvironment EvidenceKind = "environment"
	EvidenceArtifact    EvidenceKind = "artifact"
)

// AllEvidenceKinds returns the vocabulary.
func AllEvidenceKinds() []EvidenceKind {
	return []EvidenceKind{EvidenceSource, EvidenceStaticQuery, EvidenceRule, EvidenceRuntimeLog,
		EvidenceTest, EvidenceEnvironment, EvidenceArtifact}
}

// ValidEvidenceKind reports whether a kind is known.
func ValidEvidenceKind(k EvidenceKind) bool {
	for _, known := range AllEvidenceKinds() {
		if k == known {
			return true
		}
	}
	return false
}

// StepKind is one kind of verification step.
type StepKind string

const (
	StepStaticCheck     StepKind = "static_check"
	StepDataflowProbe   StepKind = "dataflow_probe"
	StepDynamicProof    StepKind = "dynamic_proof"
	StepDependencyProbe StepKind = "dependency_probe"
	StepManualReview    StepKind = "manual_review"
)

// AllStepKinds returns the vocabulary.
func AllStepKinds() []StepKind {
	return []StepKind{StepStaticCheck, StepDataflowProbe, StepDynamicProof, StepDependencyProbe, StepManualReview}
}

// ValidStepKind reports whether a step kind is known.
func ValidStepKind(k StepKind) bool {
	for _, known := range AllStepKinds() {
		if k == known {
			return true
		}
	}
	return false
}

// NetworkPolicy bounds what a verification environment may reach.
type NetworkPolicy string

const (
	// NetworkNone is the default: no egress at all.
	NetworkNone NetworkPolicy = "none"
	// NetworkTargetOnly allows the authorized target only.
	NetworkTargetOnly NetworkPolicy = "target_only"
	// NetworkRestricted is a declared allowlist the operator configured.
	NetworkRestricted NetworkPolicy = "restricted"
)

// ValidNetworkPolicy reports whether a policy is known.
func ValidNetworkPolicy(p NetworkPolicy) bool {
	switch p {
	case NetworkNone, NetworkTargetOnly, NetworkRestricted:
		return true
	}
	return false
}

// Environment bounds one verification run (design §11: least privilege, quotas,
// timeouts, controlled network, temporary credentials, read-only source).
type Environment struct {
	// Profile names the execution profile: a container image, a VM template or a
	// named worker pool. The executor adapter interprets it; this package validates
	// that it is declared, because an undeclared environment is unreproducible.
	Profile string `json:"profile"`
	// SourceReadOnly must be true. A verification may read the snapshot and write
	// only inside its own scratch space.
	SourceReadOnly bool          `json:"source_read_only"`
	Network        NetworkPolicy `json:"network"`
	// AllowedHosts is required when Network is restricted or target_only.
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	CPUMillis    int      `json:"cpu_millis"`
	MemoryMB     int      `json:"memory_mb"`
	DiskMB       int      `json:"disk_mb"`
	MaxProcesses int      `json:"max_processes"`
	// MaxWrites bounds the number of filesystem writes; zero means "scratch only,
	// no limit within it".
	MaxWrites      int `json:"max_writes"`
	TimeoutSeconds int `json:"timeout_seconds"`
	// MountHostSocket must stay false. It exists as a field so a plan that asks for
	// it can be rejected explicitly instead of being silently impossible.
	MountHostSocket bool `json:"mount_host_socket"`
}

// DefaultEnvironment returns the least-privilege starting point.
func DefaultEnvironment() Environment {
	return Environment{
		Profile: "sandbox-default", SourceReadOnly: true, Network: NetworkNone,
		CPUMillis: 1000, MemoryMB: 512, DiskMB: 256, MaxProcesses: 64,
		MaxWrites: 0, TimeoutSeconds: 300, MountHostSocket: false,
	}
}

// Normalize fills unset quotas with the defaults, which are deliberately small.
func (e Environment) Normalize() Environment {
	d := DefaultEnvironment()
	if strings.TrimSpace(e.Profile) == "" {
		e.Profile = d.Profile
	}
	if !ValidNetworkPolicy(e.Network) {
		e.Network = d.Network
	}
	if e.CPUMillis <= 0 {
		e.CPUMillis = d.CPUMillis
	}
	if e.MemoryMB <= 0 {
		e.MemoryMB = d.MemoryMB
	}
	if e.DiskMB <= 0 {
		e.DiskMB = d.DiskMB
	}
	if e.MaxProcesses <= 0 {
		e.MaxProcesses = d.MaxProcesses
	}
	if e.MaxWrites < 0 {
		e.MaxWrites = 0
	}
	if e.TimeoutSeconds <= 0 {
		e.TimeoutSeconds = d.TimeoutSeconds
	}
	return e
}

// Digest is a stable identity of the environment, so a result can be tied to the
// environment that produced it.
func (e Environment) Digest() string {
	h := sha256.New()
	hosts := append([]string(nil), e.AllowedHosts...)
	sort.Strings(hosts)
	fields := []string{
		"codexploit/verify-environment/v1", e.Profile, fmt.Sprint(e.SourceReadOnly),
		string(e.Network), strings.Join(hosts, ","), fmt.Sprint(e.CPUMillis),
		fmt.Sprint(e.MemoryMB), fmt.Sprint(e.DiskMB), fmt.Sprint(e.MaxProcesses),
		fmt.Sprint(e.MaxWrites), fmt.Sprint(e.TimeoutSeconds), fmt.Sprint(e.MountHostSocket),
	}
	for _, field := range fields {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return "env-" + hex.EncodeToString(h.Sum(nil)[:8])
}

// Step is one unit of a verification plan.
type Step struct {
	Kind StepKind `json:"kind"`
	// Command is the argv the executor runs inside the environment. It is never a
	// shell string: an executor that needs a shell is a red flag, not a feature.
	Command []string `json:"command,omitempty"`
	// StaticQuery names a graph query for a static step, instead of a command.
	StaticQuery map[string]string `json:"static_query,omitempty"`
	Expectation string            `json:"expectation"`
	// Contradiction is what would disprove the hypothesis at this step: stating it up
	// front is what keeps a "confirmation" from being a coincidence.
	Contradiction  string `json:"contradiction"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	// RequiresApproval marks a step a human must approve before it runs.
	RequiresApproval bool `json:"requires_approval"`
}

// Scope is the authorization a verification runs under (design §11: authorized
// repositories, targets and isolated environments only).
type Scope struct {
	// Repository is the authorized repository identifier.
	Repository string `json:"repository"`
	SnapshotID string `json:"snapshot_id"`
	// AllowedTargets are the hosts or services a dynamic step may contact.
	AllowedTargets []string `json:"allowed_targets,omitempty"`
	// AllowNetwork must be true for any step that needs egress; the plan's
	// environment network policy is then checked against it.
	AllowNetwork bool `json:"allow_network"`
	// RequiresHumanApproval marks plans whose steps include dynamic proofs.
	RequiresHumanApproval bool `json:"requires_human_approval"`
	// AuthorizedBy records who declared the scope.
	AuthorizedBy string `json:"authorized_by,omitempty"`
	AuthorizedAt string `json:"authorized_at,omitempty"`
}

// Plan is what a verification would do. Its hash is the dedup key: the same plan
// for the same hypothesis is the same verification.
type Plan struct {
	SchemaVersion int    `json:"schema_version"`
	HypothesisID  string `json:"hypothesis_id"`
	FindingID     string `json:"finding_id"`
	PathID        string `json:"path_id"`
	AuditID       string `json:"audit_id"`
	SnapshotID    string `json:"snapshot_id"`
	SecurityGoal  string `json:"security_goal"`
	// Claim is the hypothesis statement being tested, verbatim.
	Claim       string      `json:"claim"`
	Steps       []Step      `json:"steps"`
	Environment Environment `json:"environment"`
	Scope       Scope       `json:"scope"`
	Limitations []string    `json:"limitations"`
	GeneratedAt string      `json:"generated_at"`
	PlanHash    string      `json:"plan_hash"`
}

// PlanHashOf derives the plan hash from everything that changes what the plan does.
func PlanHashOf(plan Plan) string {
	h := sha256.New()
	fields := []string{
		"codexploit/verify-plan/v1", plan.HypothesisID, plan.SnapshotID,
		plan.SecurityGoal, plan.Claim, plan.Environment.Digest(),
	}
	for _, field := range fields {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	for _, step := range plan.Steps {
		for _, field := range []string{
			string(step.Kind), strings.Join(step.Command, "\x00"), fmt.Sprint(step.StaticQuery),
			step.Expectation, step.Contradiction, fmt.Sprint(step.TimeoutSeconds), fmt.Sprint(step.RequiresApproval),
		} {
			fmt.Fprintf(h, "%d:%s", len(field), field)
		}
	}
	return "plan-" + hex.EncodeToString(h.Sum(nil)[:8])
}

// NeedsApproval reports whether the plan requires a recorded human approval.
func (p Plan) NeedsApproval() bool {
	if p.Scope.RequiresHumanApproval {
		return true
	}
	for _, step := range p.Steps {
		if step.RequiresApproval || step.Kind == StepDynamicProof {
			return true
		}
	}
	return false
}

// Evidence is one immutable, content-addressed object (design §3.4).
type Evidence struct {
	ID                string       `json:"evidence_id"`
	Kind              EvidenceKind `json:"kind"`
	Tool              string       `json:"tool"`
	ToolVersion       string       `json:"tool_version,omitempty"`
	SnapshotID        string       `json:"snapshot_id"`
	HypothesisID      string       `json:"hypothesis_id,omitempty"`
	FindingID         string       `json:"finding_id,omitempty"`
	PathID            string       `json:"path_id,omitempty"`
	VerificationRunID string       `json:"verification_run_id,omitempty"`
	File              string       `json:"file,omitempty"`
	Line              int          `json:"line,omitempty"`
	ContentHash       string       `json:"content_hash"`
	Content           string       `json:"content"`
	// Redacted records that the stored content is a redacted transformation of what
	// the tool produced. The hash covers the redacted bytes, so hash and content
	// always agree.
	Redacted       bool   `json:"redacted"`
	RedactionNotes string `json:"redaction_notes,omitempty"`
	// Supersedes points at the evidence this object corrects.
	Supersedes string `json:"supersedes,omitempty"`
	CreatedAt  string `json:"created_at"`
}

// Outcome is the verdict of one verification run.
type Outcome string

const (
	OutcomeConfirmed    Outcome = "CONFIRMED"
	OutcomeRefuted      Outcome = "REFUTED"
	OutcomeInconclusive Outcome = "INCONCLUSIVE"
	OutcomeBlocked      Outcome = "BLOCKED"
)

// ValidOutcome reports whether an outcome is known.
func ValidOutcome(o Outcome) bool {
	switch o {
	case OutcomeConfirmed, OutcomeRefuted, OutcomeInconclusive, OutcomeBlocked:
		return true
	}
	return false
}

// FindingStatusOf maps an outcome onto the finding status it establishes.
func (o Outcome) FindingStatus() FindingStatus {
	switch o {
	case OutcomeConfirmed:
		return FindingConfirmed
	case OutcomeRefuted:
		return FindingRefuted
	case OutcomeBlocked:
		return FindingBlocked
	default:
		return FindingInconclusive
	}
}

// Run is one attempt to verify one hypothesis.
type Run struct {
	ID                string             `json:"run_id"`
	HypothesisID      string             `json:"hypothesis_id"`
	FindingID         string             `json:"finding_id"`
	PathID            string             `json:"path_id"`
	AuditID           string             `json:"audit_id"`
	SnapshotID        string             `json:"snapshot_id"`
	PlanHash          string             `json:"plan_hash"`
	Plan              Plan               `json:"plan"`
	Environment       Environment        `json:"environment"`
	EnvironmentDigest string             `json:"environment_digest"`
	Status            VerificationStatus `json:"status"`
	Outcome           Outcome            `json:"outcome,omitempty"`
	Executor          string             `json:"executor"`
	ExecutorVersion   string             `json:"executor_version,omitempty"`
	NetworkAllowed    bool               `json:"network_allowed"`
	Approved          bool               `json:"approved"`
	ApprovedBy        string             `json:"approved_by,omitempty"`
	ApprovedAt        string             `json:"approved_at,omitempty"`
	Owner             string             `json:"owner,omitempty"`
	ExitCode          *int               `json:"exit_code,omitempty"`
	StopReason        string             `json:"stop_reason,omitempty"`
	Error             string             `json:"error,omitempty"`
	// Reproduction is the shortest set of steps that reproduced the result, or the
	// reason it could not be reproduced.
	Reproduction string `json:"reproduction,omitempty"`
	// EvidenceIDs is derived on read from the evidence objects that name this run,
	// not stored on the run. A denormalised list could drift and let a run cite
	// evidence that does not exist; deriving it makes that structurally impossible.
	EvidenceIDs []string `json:"evidence_ids"`
	StartedAt   string   `json:"started_at,omitempty"`
	FinishedAt  string   `json:"finished_at,omitempty"`
	ElapsedMS   int64    `json:"elapsed_ms"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	Version     int64    `json:"version"`
}

// Stop reasons of a verification run.
const (
	VerifyStopCompleted   = "completed"
	VerifyStopUnsupported = "unsupported_step"
	VerifyStopNoApproval  = "approval_required"
	VerifyStopScopeDenied = "scope_denied"
	VerifyStopExecutorErr = "executor_failed"
	VerifyStopTimeout     = "timed_out"
	VerifyStopCancelled   = "cancelled"
	VerifyStopBudget      = "budget_exceeded"
)

// Result is what an executor reports back.
type Result struct {
	Outcome Outcome `json:"outcome"`
	// Reason is the one-line justification, and it must name the evidence: a verdict
	// without a reason cannot be reviewed.
	Reason string `json:"reason"`
	// Reproduction holds the steps that reproduced the outcome.
	Reproduction string     `json:"reproduction,omitempty"`
	Evidence     []Evidence `json:"evidence"`
	ExitCode     *int       `json:"exit_code,omitempty"`
	StopReason   string     `json:"stop_reason,omitempty"`
	Err          string     `json:"error,omitempty"`
}

// Finding is the durable verdict about one hypothesis.
type Finding struct {
	ID           string        `json:"finding_id"`
	HypothesisID string        `json:"hypothesis_id"`
	PathID       string        `json:"path_id"`
	AuditID      string        `json:"audit_id"`
	SnapshotID   string        `json:"snapshot_id"`
	Title        string        `json:"title"`
	Severity     string        `json:"severity,omitempty"`
	Status       FindingStatus `json:"status"`
	Confidence   string        `json:"confidence,omitempty"`
	// The three evidence lists stay apart: a contradiction is the interesting part,
	// and "we could not tell" is not "we disproved it".
	Supporting         []string `json:"supporting_evidence"`
	Contradicting      []string `json:"contradicting_evidence"`
	Inconclusive       []string `json:"inconclusive_evidence"`
	VerificationRunIDs []string `json:"verification_run_ids"`
	Environments       []string `json:"environments"`
	ReproduceSteps     string   `json:"reproduce_steps,omitempty"`
	Limitations        []string `json:"limitations"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
	Version            int64    `json:"version"`
}

// FindingID derives a finding id from its hypothesis: a finding is the verdict
// about one claim, so the claim identifies it.
func FindingID(hypothesisID string) string {
	return "find-" + digest16("codexploit/finding/v1", hypothesisID)
}

// VerificationRunID derives a run id from the plan it executes. The same plan for
// the same hypothesis is the same verification, which is what makes a rerun a
// replay.
func VerificationRunID(hypothesisID, planHash string) string {
	return "vrun-" + digest16("codexploit/verification-run/v1", hypothesisID, planHash)
}

// EvidenceID derives the id of an evidence object from its content alone.
//
// It is the unscoped content identity; evidence that belongs to a verification run
// uses ScopedEvidenceID instead, because two runs producing the same bytes are two
// objects with two provenances, not one object with two claims.
func EvidenceID(kind EvidenceKind, snapshotID, content string) string {
	return "ev-" + digest16("codexploit/evidence/v1", string(kind), snapshotID, content)
}

// evidenceScope returns the narrowest relationship an evidence object belongs to.
// It is the one place the scope precedence is defined, so the constructor and any
// caller that recomputes an id cannot disagree about it.
// The scope is the claim the evidence is about, not the attempt that produced it:
// the verification run is stamped onto the object after it was built, so including
// it would give the object an id its fields only reproduce once the service has
// added to it. Two runs of one hypothesis that produce identical bytes therefore
// share the object, which is what content addressing means here.
func evidenceScope(v Evidence) string {
	return firstNonEmpty(v.HypothesisID, v.FindingID, v.PathID)
}

// DeriveEvidenceID recomputes the id of an evidence object from its own fields.
//
// NewEvidence uses it, and so does any test that wants to check the derivation, so
// the constructor and a recomputation cannot disagree about the formula.
func DeriveEvidenceID(v Evidence) string {
	if scope := evidenceScope(v); scope != "" {
		return ScopedEvidenceID(v.Kind, v.SnapshotID, scope, v.ContentHash)
	}
	return EvidenceID(v.Kind, v.SnapshotID, v.ContentHash)
}

// ScopedEvidenceID derives the id of an evidence object within its scope: the
// verification run, or the hypothesis when there is no run yet.
//
// Content addressing is deliberately per scope. If the id covered the content
// alone, a second run that produced identical bytes would collapse onto the first
// object and keep the first run's provenance — the second run's evidence list,
// which is derived from that provenance, would come back empty.
func ScopedEvidenceID(kind EvidenceKind, snapshotID, scope, content string) string {
	return "ev-" + digest16("codexploit/evidence/v1", string(kind), snapshotID, scope, content)
}

func digest16(fields ...string) string {
	h := sha256.New()
	for _, field := range fields {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// NowString formats a timestamp the way the API and storage expect.
func NowString(t time.Time) string { return t.UTC().Format(time.RFC3339) }
