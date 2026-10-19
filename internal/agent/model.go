// Package agent runs bounded audit agents over AuditPaths.
//
// The split the design insists on is enforced here: the Go orchestrator owns the
// process, the lease, the deadline and the budget, and the agent owns nothing but
// its bounded reasoning. An agent may ask for a whitelisted read-only tool call or
// for a wider exploration; the orchestrator decides, executes and records. That is
// why a run is a row in a database rather than a session inside the adapter: it
// survives a crashed process, and every exchange is auditable afterwards.
//
// Two rules shape the package:
//
//   - no hidden reasoning is stored or requested. Runs persist the task, the tool
//     exchanges, the expansion decisions and the structured answer — never a chain
//     of thought (implementation guide §9.2);
//   - the agent cannot widen its own limits. Exploration is bounded by a policy
//     that arrives with the task, and expansion happens only through an explicit
//     request the orchestrator approves, shrinks, defers or rejects (§9.3).
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SchemaVersion identifies the serialised shape of a task and of an agent answer.
const SchemaVersion = 1

// RunStatus is the lifecycle of one agent run. It is deliberately separate from
// the path status: a run can fail while its path stays queued for another attempt.
type RunStatus string

const (
	RunCreated        RunStatus = "CREATED"
	RunRunning        RunStatus = "RUNNING"
	RunPausing        RunStatus = "PAUSING"
	RunPaused         RunStatus = "PAUSED"
	RunCancelling     RunStatus = "CANCELLING"
	RunSucceeded      RunStatus = "SUCCEEDED"
	RunFailed         RunStatus = "FAILED"
	RunCancelled      RunStatus = "CANCELLED"
	RunTimedOut       RunStatus = "TIMED_OUT"
	RunBudgetExceeded RunStatus = "BUDGET_EXCEEDED"
	RunInvalidOutput  RunStatus = "INVALID_OUTPUT"
)

// AllRunStatuses returns the vocabulary.
func AllRunStatuses() []RunStatus {
	return []RunStatus{RunCreated, RunRunning, RunPausing, RunPaused, RunCancelling,
		RunSucceeded, RunFailed, RunCancelled, RunTimedOut, RunBudgetExceeded, RunInvalidOutput}
}

// ValidRunStatus reports whether a status is known.
func ValidRunStatus(s RunStatus) bool {
	for _, known := range AllRunStatuses() {
		if s == known {
			return true
		}
	}
	return false
}

// Terminal reports whether no further event is expected.
func (s RunStatus) Terminal() bool {
	switch s {
	case RunSucceeded, RunFailed, RunCancelled, RunTimedOut, RunBudgetExceeded, RunInvalidOutput:
		return true
	}
	return false
}

// Stop reasons the orchestrator records when it ends a run.
const (
	StopCompleted      = "completed"
	StopDeadline       = "deadline_exceeded"
	StopToolBudget     = "tool_call_budget_exceeded"
	StopTokenBudget    = "token_budget_exceeded"
	StopInvalidOutput  = "invalid_output"
	StopRepeatedOutput = "repeated_output_without_new_evidence"
	StopCancelled      = "cancelled"
	StopAdapterFailed  = "adapter_failed"
	StopLeaseLost      = "lease_lost"
	StopPathNotActive  = "path_not_active"
)

// Event types of a run. A request and its result share a CallID.
const (
	EventRunCreated       = "run_created"
	EventRunStarted       = "run_started"
	EventTaskDelivered    = "task_delivered"
	EventToolRequested    = "tool_requested"
	EventToolAllowed      = "tool_allowed"
	EventToolResult       = "tool_result"
	EventToolDenied       = "tool_denied"
	EventExpansionAsked   = "expansion_requested"
	EventExpansionDecided = "expansion_decided"
	EventOutputReceived   = "output_received"
	EventOutputRejected   = "output_rejected"
	EventHypothesis       = "hypothesis_recorded"
	EventRunHeartbeat     = "run_heartbeat"
	EventRunFinished      = "run_finished"
	EventRunError         = "run_error"
)

// Expansion decisions.
const (
	ExpansionApproved = "approved"
	ExpansionShrunk   = "shrunk"
	ExpansionDeferred = "deferred"
	ExpansionRejected = "rejected"
)

// Evidence classes copied from the design's confidence model.
const (
	EvidenceSource  = "source"
	EvidenceStatic  = "static_query"
	EvidenceRule    = "rule"
	EvidenceRuntime = "runtime_log"
	EvidenceTest    = "test"
	EvidenceSlice   = "code_slice"
	EvidenceAgent   = "agent_assertion"
)

// ExplorationPolicy bounds what one run may do (implementation guide §9.3).
type ExplorationPolicy struct {
	MaxHops      int `json:"max_hops"`
	MaxBranches  int `json:"max_branches"`
	MaxToolCalls int `json:"max_tool_calls"`
	// MaxExpansions bounds how often a run may ask for more room; the requests are
	// cheap to make and expensive to grant, so the count is part of the budget.
	MaxExpansions int `json:"max_expansions"`
	// AllowedTools is the whitelist. An empty list means no tool may be called,
	// which is the safe default: a run that needs a tool has to be configured for it.
	AllowedTools []string `json:"allowed_tools"`
	// TimeoutSeconds bounds the whole run.
	TimeoutSeconds int `json:"timeout_seconds"`
	// TokenBudget bounds reported token usage; zero means "not enforced".
	TokenBudget int `json:"token_budget"`
	// MaxRepeatedOutputs stops a run that keeps producing the same answer without
	// new evidence.
	MaxRepeatedOutputs int `json:"max_repeated_outputs"`
}

// DefaultExplorationPolicy returns the documented starting values: 2 hops, 4 active
// branches, 30 tool calls.
func DefaultExplorationPolicy() ExplorationPolicy {
	return ExplorationPolicy{
		MaxHops: 2, MaxBranches: 4, MaxToolCalls: 30, MaxExpansions: 3,
		TimeoutSeconds: 600, TokenBudget: 0, MaxRepeatedOutputs: 2,
		AllowedTools: []string{},
	}
}

// Normalize fills unset fields with the defaults and clamps negatives to zero.
func (p ExplorationPolicy) Normalize() ExplorationPolicy {
	d := DefaultExplorationPolicy()
	if p.MaxHops <= 0 {
		p.MaxHops = d.MaxHops
	}
	if p.MaxBranches <= 0 {
		p.MaxBranches = d.MaxBranches
	}
	if p.MaxToolCalls <= 0 {
		p.MaxToolCalls = d.MaxToolCalls
	}
	if p.MaxExpansions < 0 {
		p.MaxExpansions = 0
	}
	if p.TimeoutSeconds <= 0 {
		p.TimeoutSeconds = d.TimeoutSeconds
	}
	if p.MaxRepeatedOutputs <= 0 {
		p.MaxRepeatedOutputs = d.MaxRepeatedOutputs
	}
	if p.AllowedTools == nil {
		p.AllowedTools = []string{}
	}
	sort.Strings(p.AllowedTools)
	p.AllowedTools = dedupe(p.AllowedTools)
	return p
}

// Allows reports whether a tool may be called under this policy.
func (p ExplorationPolicy) Allows(tool string) bool {
	for _, allowed := range p.AllowedTools {
		if allowed == tool {
			return true
		}
	}
	return false
}

// Budget is the wall-clock and token allowance of one run.
type Budget struct {
	TimeoutSeconds int `json:"timeout_seconds"`
	TokenBudget    int `json:"token_budget"`
}

// Task is what one run is given (implementation guide §9.2). It is stored verbatim
// with the run: judging an answer requires knowing the question.
type Task struct {
	// PriorFindings are read-only knowledge from other tasks on this snapshot.
	PriorFindings []PriorFinding `json:"prior_findings,omitempty"`
	SchemaVersion int            `json:"schema_version"`
	SnapshotID    string         `json:"snapshot_id"`
	PathID        string         `json:"path_id"`
	AuditID       string         `json:"audit_id"`
	SecurityGoal  string         `json:"security_goal"`
	PathSummary   string         `json:"path_summary"`
	// SourceSinkRefs names the input and the sensitive operation, with the SCG and
	// ASG ids that make them auditable.
	SourceSinkRefs SourceSinkRefs `json:"source_sink_refs"`
	// MinimalCodeSlice is the bounded source the agent may read. It is produced by
	// the graph service, not gathered by the agent.
	MinimalCodeSlice []SliceSection `json:"minimal_code_slice"`
	// EvidenceRefs are the facts already established; the agent must not restate
	// them as new findings.
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
	// UnresolvedQuestions is the reason the run exists.
	UnresolvedQuestions []string          `json:"unresolved_questions"`
	Exploration         ExplorationPolicy `json:"exploration_policy"`
	Budget              Budget            `json:"token_budget"`
	// Limitations restates what the upstream layers could not establish, so the
	// agent does not treat them as settled.
	Limitations []string `json:"limitations"`
	CreatedAt   string   `json:"created_at"`
}

type PriorFinding struct {
	FindingID                string   `json:"finding_id"`
	AuditID                  string   `json:"audit_id"`
	Title                    string   `json:"title"`
	Status                   string   `json:"status"`
	Severity                 string   `json:"severity,omitempty"`
	SupportingEvidenceIDs    []string `json:"supporting_evidence_ids"`
	ContradictingEvidenceIDs []string `json:"contradicting_evidence_ids"`
	InconclusiveEvidenceIDs  []string `json:"inconclusive_evidence_ids"`
}

// SourceSinkRefs identifies the ends of the path.
type SourceSinkRefs struct {
	EntryNodeID   string   `json:"entry_node_id"`
	EntrySubject  string   `json:"entry_subject"`
	TargetNodeID  string   `json:"target_node_id"`
	TargetSubject string   `json:"target_subject"`
	Inputs        []string `json:"inputs"`
	Controls      []string `json:"controls"`
	Assets        []string `json:"assets"`
	Boundaries    []string `json:"boundaries"`
	SCGRefs       []string `json:"scg_refs"`
	ASGRefs       []string `json:"asg_refs"`
}

// SliceSection is one window of source code the agent may read.
type SliceSection struct {
	File      string `json:"file"`
	Symbol    string `json:"symbol,omitempty"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Reason    string `json:"reason,omitempty"`
	Content   string `json:"content"`
}

// EvidenceRef points at a fact the run may rely on.
type EvidenceRef struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Summary string `json:"summary,omitempty"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
}

// Answer is the structured output a runtime must produce. Unknown fields are
// rejected rather than ignored: an adapter that invents a field is a bug to find,
// not a feature to accommodate.
type Answer struct {
	SchemaVersion         int              `json:"schema_version"`
	SecurityGoal          string           `json:"security_goal"`
	Hypothesis            HypothesisDraft  `json:"hypothesis"`
	SupportingEvidence    []AnswerEvidence `json:"supporting_evidence"`
	ContradictingEvidence []AnswerEvidence `json:"contradicting_evidence"`
	NextAction            string           `json:"next_action"`
	RequestedExpansion    *ExpansionAsk    `json:"requested_expansion,omitempty"`
	FindingCandidate      bool             `json:"finding_candidate"`
	SeverityHint          string           `json:"severity_hint,omitempty"`
	// Notes is a short explicit justification. It is not a reasoning transcript and
	// must stay within the length cap.
	Notes string `json:"notes,omitempty"`
}

// HypothesisDraft is the claim the agent is making.
type HypothesisDraft struct {
	Statement  string `json:"statement"`
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
}

// AnswerEvidence is evidence the agent cites. A citation without a location is
// rejected: an unverifiable claim is not evidence.
type AnswerEvidence struct {
	Kind    string `json:"kind"`
	Ref     string `json:"ref,omitempty"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Quote   string `json:"quote,omitempty"`
	Summary string `json:"summary,omitempty"`
}

// ExpansionAsk is the §9.3 expansion request: target, purpose, expected gain, cost.
type ExpansionAsk struct {
	TargetNodeID  string `json:"target_node_id"`
	Purpose       string `json:"purpose"`
	ExpectedGain  string `json:"expected_gain"`
	EstimatedCost string `json:"estimated_cost"`
	Hops          int    `json:"additional_hops,omitempty"`
	ToolCalls     int    `json:"additional_tool_calls,omitempty"`
}

// ToolRequest is a whitelisted read-only tool call the agent asks for. The
// orchestrator executes it; the agent never touches the process, the network or
// the filesystem itself.
type ToolRequest struct {
	CallID string            `json:"call_id"`
	Tool   string            `json:"tool"`
	Args   map[string]string `json:"args"`
}

// ToolResult is what the orchestrator returns for one call.
type ToolResult struct {
	CallID    string   `json:"call_id"`
	Tool      string   `json:"tool"`
	OK        bool     `json:"ok"`
	Result    string   `json:"result,omitempty"`
	Error     string   `json:"error,omitempty"`
	Refs      []string `json:"refs,omitempty"`
	ElapsedMS int64    `json:"elapsed_ms"`
}

// Run is one execution of a runtime over one path.
type Run struct {
	ID             string            `json:"run_id"`
	PathID         string            `json:"path_id"`
	AuditID        string            `json:"audit_id"`
	SnapshotID     string            `json:"snapshot_id"`
	Runtime        string            `json:"runtime"`
	RuntimeVersion string            `json:"runtime_version"`
	Status         RunStatus         `json:"status"`
	Task           Task              `json:"task"`
	Exploration    ExplorationPolicy `json:"exploration"`
	Budget         Budget            `json:"budget"`
	ToolCalls      int               `json:"tool_calls"`
	Expansions     int               `json:"expansions"`
	InputTokens    int               `json:"input_tokens"`
	OutputTokens   int               `json:"output_tokens"`
	ElapsedMS      int64             `json:"elapsed_ms"`
	Owner          string            `json:"owner,omitempty"`
	LeaseEpoch     int64             `json:"lease_epoch,omitempty"`
	StartedAt      string            `json:"started_at,omitempty"`
	DeadlineAt     string            `json:"deadline_at,omitempty"`
	HeartbeatAt    string            `json:"heartbeat_at,omitempty"`
	FinishedAt     string            `json:"finished_at,omitempty"`
	ExitCode       *int              `json:"exit_code,omitempty"`
	StopReason     string            `json:"stop_reason,omitempty"`
	Error          string            `json:"error,omitempty"`
	Answer         *Answer           `json:"answer,omitempty"`
	CreatedAt      string            `json:"created_at"`
	UpdatedAt      string            `json:"updated_at"`
	Version        int64             `json:"version"`
}

// Event is one append-only entry of a run's exchange log.
type Event struct {
	ID        string            `json:"event_id"`
	RunID     string            `json:"run_id"`
	PathID    string            `json:"path_id"`
	Seq       int64             `json:"seq"`
	Type      string            `json:"type"`
	CallID    string            `json:"call_id,omitempty"`
	Tool      string            `json:"tool,omitempty"`
	Actor     string            `json:"actor"`
	Summary   string            `json:"summary,omitempty"`
	Detail    map[string]string `json:"detail,omitempty"`
	CreatedAt string            `json:"created_at"`
}

// Hypothesis is a stored claim produced by a run. It is not a finding: the
// verification phase decides whether a finding candidate becomes confirmed.
type Hypothesis struct {
	ID               string        `json:"hypothesis_id"`
	RunID            string        `json:"run_id"`
	PathID           string        `json:"path_id"`
	AuditID          string        `json:"audit_id"`
	SnapshotID       string        `json:"snapshot_id"`
	SecurityGoal     string        `json:"security_goal"`
	Statement        string        `json:"statement"`
	Status           string        `json:"status"`
	Confidence       string        `json:"confidence"`
	Supporting       []EvidenceRef `json:"supporting_evidence"`
	Contradicting    []EvidenceRef `json:"contradicting_evidence"`
	NextAction       string        `json:"next_action,omitempty"`
	FindingCandidate bool          `json:"finding_candidate"`
	SeverityHint     string        `json:"severity_hint,omitempty"`
	Digest           string        `json:"digest"`
	CreatedAt        string        `json:"created_at"`
	UpdatedAt        string        `json:"updated_at"`
}

// Hypothesis statuses. `candidate` is what a run may assert; the others are
// reachable only through verification.
const (
	HypothesisCandidate    = "candidate"
	HypothesisConfirmed    = "confirmed"
	HypothesisRefuted      = "refuted"
	HypothesisInconclusive = "inconclusive"
)

// ValidHypothesisStatus restricts what an agent answer may claim.
func ValidHypothesisStatus(status string) bool {
	switch status {
	case HypothesisCandidate, HypothesisInconclusive, HypothesisRefuted:
		return true
	default:
		// "confirmed" is deliberately absent: only verification may confirm.
		return false
	}
}

// RunID derives a run id from what the run is: path, runtime and attempt number.
func RunID(pathID, runtime string, attempt int) string {
	return "run-" + digest16("codexploit/agent-run/v1", pathID, runtime, fmt.Sprint(attempt))
}

// HypothesisID derives the id of a hypothesis from its path and its statement, so
// the same claim recorded twice is one hypothesis.
func HypothesisID(pathID, statement string) string {
	return "hyp-" + digest16("codexploit/hypothesis/v1", pathID, normalizeStatement(statement))
}

// Digest is the idempotency key of a claim inside a path.
func Digest(statement string) string {
	return digest16("codexploit/hypothesis-digest/v1", normalizeStatement(statement))
}

// EventID derives the id of a run event from its position in the run log.
func EventID(runID string, seq int64) string {
	return "aev-" + digest16("codexploit/agent-event/v1", runID, fmt.Sprint(seq))
}

func digest16(fields ...string) string {
	h := sha256.New()
	for _, field := range fields {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// normalizeStatement makes whitespace and case irrelevant to hypothesis identity:
// the same claim phrased with different spacing is the same claim.
func normalizeStatement(statement string) string {
	return strings.Join(strings.Fields(strings.ToLower(statement)), " ")
}

// NowString formats a timestamp the way the API and storage expect.
func NowString(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// NodeIDs returns every graph node id a task references, which is what an
// expansion decision and a coverage check iterate over.
func (t Task) NodeIDs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	add(t.SourceSinkRefs.EntryNodeID)
	add(t.SourceSinkRefs.TargetNodeID)
	for _, id := range t.SourceSinkRefs.Inputs {
		add(id)
	}
	for _, id := range t.SourceSinkRefs.Controls {
		add(id)
	}
	for _, id := range t.SourceSinkRefs.Assets {
		add(id)
	}
	sort.Strings(out)
	return out
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
