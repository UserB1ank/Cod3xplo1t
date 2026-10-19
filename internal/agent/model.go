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
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SchemaVersion identifies the serialised shape of a task and of an agent answer.
// Version 1 predates the obligation checklist; a stored run that used it stays
// readable, and a task is only held to the checklist it actually carries.
const SchemaVersion = 1

// SchemaVersionObligations is the protocol version that carries a checklist of
// obligations. A task at this version must carry exactly one obligation of each
// kind, and an answer must answer every one of them.
const SchemaVersionObligations = 2

// Obligation kinds: the four questions one path must answer before its run may
// claim a conclusion. The host derives them from the path's shape, never the
// model: a model that invents its own questions can always declare them answered.
const (
	ObligationSource  = "source_is_attacker_controlled"
	ObligationFlow    = "flow_reaches_sink"
	ObligationControl = "control_ineffective_or_absent"
	ObligationSink    = "sink_is_sensitive"
)

// AllObligationKinds returns the vocabulary in the order a checklist carries it.
func AllObligationKinds() []string {
	return []string{ObligationSource, ObligationFlow, ObligationControl, ObligationSink}
}

// ValidObligationKind reports whether a kind is part of the vocabulary.
func ValidObligationKind(kind string) bool {
	for _, known := range AllObligationKinds() {
		if kind == known {
			return true
		}
	}
	return false
}

// Verdicts an obligation may carry. `unknown` is a first-class answer: it must
// name the blocker that makes the question undecidable, and it makes the run's
// conclusion inconclusive.
const (
	VerdictMet     = "met"
	VerdictNotMet  = "not_met"
	VerdictUnknown = "unknown"
)

// Blocker codes name why an obligation could not be decided. They are the
// vocabulary a scheduler groups by when it asks which capability is missing.
const (
	BlockerUnresolvedCall     = "unresolved_call"
	BlockerDynamicDispatch    = "dynamic_dispatch"
	BlockerExternalDependency = "external_dependency"
	BlockerControlUnassessed  = "control_unassessed"
	BlockerBudget             = "budget"
)

// AllBlockers returns the blocker vocabulary.
func AllBlockers() []string {
	return []string{
		BlockerUnresolvedCall, BlockerDynamicDispatch, BlockerExternalDependency,
		BlockerControlUnassessed, BlockerBudget,
	}
}

// ValidBlocker reports whether a blocker code is known.
func ValidBlocker(blocker string) bool {
	for _, known := range AllBlockers() {
		if blocker == known {
			return true
		}
	}
	return false
}

// Obligation is one question a path must answer. ID is derived from the path and
// the kind, so the same path always yields the same checklist; Kind is what an
// answer references, because a scripted or external adapter cannot know an id it
// was never shown.
type Obligation struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Subject  string   `json:"subject"`
	Question string   `json:"question"`
	Evidence []string `json:"evidence_refs,omitempty"`
}

// ObligationID derives the stable id of one obligation of one path.
func ObligationID(pathID, kind string) string {
	return "ob-" + digest16("codexploit/obligation/v1", pathID, kind)[:12]
}

// ObligationVerdict is the answer to one obligation. An unknown verdict must name
// a blocker; a closed verdict must not.
type ObligationVerdict struct {
	Kind    string `json:"kind"`
	Verdict string `json:"verdict"`
	Blocker string `json:"blocker,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

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
	EventRunCreated         = "run_created"
	EventRunStarted         = "run_started"
	EventTaskDelivered      = "task_delivered"
	EventToolRequested      = "tool_requested"
	EventToolBatchRequested = "tool_batch_requested"
	EventToolBatchSettled   = "tool_batch_settled"
	EventToolAllowed        = "tool_allowed"
	EventToolResult         = "tool_result"
	EventToolDenied         = "tool_denied"
	EventExpansionAsked     = "expansion_requested"
	EventExpansionDecided   = "expansion_decided"
	EventOutputReceived     = "output_received"
	// Turn-control events. They are explicit decisions, not reasoning: a permit
	// granted, a proposal accepted, a correction requested or refused.
	EventModelPermitRequested = "model_permit_requested"
	EventModelPermitGranted   = "model_permit_granted"
	EventModelPermitDenied    = "model_permit_denied"
	EventAnswerProposed       = "answer_proposed"
	EventAnswerAccepted       = "answer_accepted"
	EventAnswerRepairAsked    = "answer_repair_requested"
	EventAnswerRejected       = "answer_rejected"
	EventRepairAsked          = "repair_requested"
	EventRepairGranted        = "repair_granted"
	EventRepairRefused        = "repair_refused"
	EventOutputRejected       = "output_rejected"
	EventHypothesis           = "hypothesis_recorded"
	EventRunHeartbeat         = "run_heartbeat"
	EventRunFinished          = "run_finished"
	EventRunError             = "run_error"
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
	// MaxCallsPerTurn bounds one assistant turn's tool batch (1..8, default 4).
	// The host reserves budget for the whole batch before running any of it.
	MaxCallsPerTurn int `json:"max_calls_per_turn"`
	// ToolConcurrency bounds how many calls of one batch execute at once (1..4,
	// default 1). Results still pair with provider history in source order.
	ToolConcurrency int `json:"tool_concurrency"`
}

// DefaultExplorationPolicy returns the documented starting values: 2 hops, 4 active
// branches, 30 tool calls.
func DefaultExplorationPolicy() ExplorationPolicy {
	return ExplorationPolicy{
		MaxHops: 2, MaxBranches: 4, MaxToolCalls: 30, MaxExpansions: 3,
		TimeoutSeconds: 600, TokenBudget: 0, MaxRepeatedOutputs: 2,
		MaxCallsPerTurn: 4, ToolConcurrency: 1,
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
	if p.MaxCallsPerTurn <= 0 {
		p.MaxCallsPerTurn = d.MaxCallsPerTurn
	}
	if p.MaxCallsPerTurn > 8 {
		p.MaxCallsPerTurn = 8
	}
	if p.ToolConcurrency <= 0 {
		p.ToolConcurrency = d.ToolConcurrency
	}
	if p.ToolConcurrency > 4 {
		p.ToolConcurrency = 4
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
	// Obligations is the checklist this task must answer. It is empty for a task
	// built before the checklist existed; such a task is validated as version 1.
	Obligations []Obligation `json:"obligations,omitempty"`
	CreatedAt   string       `json:"created_at"`
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
	// Obligations answers the task's checklist by kind. Required when the task
	// carries one; a conclusive hypothesis requires every verdict to be closed.
	Obligations []ObligationVerdict `json:"obligations,omitempty"`
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
	CallID string          `json:"call_id"`
	Tool   string          `json:"tool"`
	Args   json.RawMessage `json:"args"`
	// LegacyArgs is how a protocol-v1 adapter (the CLI JSON lines, a scripted Go
	// value) reports its string-valued arguments. The host converts only the
	// fields the tool schema declares, then validates the result like any other
	// request; the strings never reach a tool.
	LegacyArgs map[string]string `json:"-"`
}

// ToolBatch is one assistant turn's tool calls. It is submitted whole so the host
// can reserve budget in source order before any call runs; the reply pairs with
// provider history in the same source order.
type ToolBatch struct {
	RoundID string        `json:"round_id"`
	Calls   []ToolRequest `json:"calls"`
}

// BudgetReceipt is the host's authoritative statement of what is left. A model
// reading a tool result must never have to estimate its own remaining budget.
type BudgetReceipt struct {
	CallsLeft         int    `json:"calls_left"`
	TokensLeft        *int   `json:"tokens_left"`
	RepairsLeft       int    `json:"repairs_left"`
	ObligationsClosed int    `json:"obligations_closed"`
	ObligationsTotal  int    `json:"obligations_total"`
	BudgetEnforced    bool   `json:"budget_enforced"`
	UsageSource       string `json:"usage_source"`
}

// ToolResultEnvelope is the one model-facing shape of a tool result: outcome,
// payload (or error) and the host's budget receipt.
type ToolResultEnvelope struct {
	OK     bool           `json:"ok"`
	Result string         `json:"result,omitempty"`
	Error  string         `json:"error,omitempty"`
	Budget *BudgetReceipt `json:"budget,omitempty"`
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

// RunMetrics is what a run cost and what it produced, in numbers a benchmark can
// compare across builds.
//
// Every counter is the orchestrator's own observation, never the adapter's claim:
// an exchange is one executed tool call, an invalid call is a tool that answered
// with an error, and a truncation is a result the orchestrator cut before handing
// it back. Novelty is recorded per exchange: how many evidence ids that exchange
// reported that no earlier exchange of the run had reported, which is what makes
// "the run stopped learning" measurable instead of a feeling.
//
// Rounds is the documented turn count. Today's protocol allows one tool call per
// adapter turn, so a run takes one turn per exchange plus the turn that answered;
// an adapter that batches calls under one turn will report a smaller number once
// the protocol carries turn boundaries.
type RunMetrics struct {
	// Rounds is the real provider-request count when Source is "reported". For an
	// adapter without turn control it is the legacy exchanges+1 estimate, and
	// Source says so; a stored record is never silently rewritten.
	Rounds        int    `json:"rounds"`
	ModelRequests int    `json:"model_requests,omitempty"`
	Repairs       int    `json:"repairs,omitempty"`
	Exchanges     int    `json:"exchanges"`
	Novelty       []int  `json:"novelty,omitempty"`
	InvalidCalls  int    `json:"invalid_calls"`
	Truncations   int    `json:"truncations"`
	Source        string `json:"source,omitempty"`
}

// Where a run's counters came from. A missing source is an older record: it is
// "unknown", never "zero".
const (
	MetricsSourceReported       = "reported"
	MetricsSourceLegacyEstimate = "legacy_estimate"
)

// Decisions returned by the orchestrator for each control request.
const (
	DecisionContinue = "continue"
	DecisionRepair   = "repair"
	DecisionStop     = "stop"
	DecisionPause    = "pause"
	DecisionAccepted = "accepted"
	DecisionRejected = "rejected"
)

// PermitRequest asks the host for permission to start one provider request. The
// adapter supplies the evidence the host needs to reserve budget: the input token
// estimate, its basis, and the provider's output limit.
type PermitRequest struct {
	RequestID           string `json:"request_id"`
	RoundID             string `json:"round_id"`
	Generation          int64  `json:"generation"`
	Model               string `json:"model,omitempty"`
	InputTokensEstimate int    `json:"input_tokens_estimate"`
	MaxOutputTokens     int    `json:"max_output_tokens"`
	EstimateBasis       string `json:"estimate_basis,omitempty"`
}

// PermitDecision is the host's answer to one permit request.
type PermitDecision struct {
	Decision       string `json:"decision"`
	Reason         string `json:"reason,omitempty"`
	ReservedTokens int    `json:"reserved_tokens,omitempty"`
}

// AnswerProposal offers raw structured output for validation.
type AnswerProposal struct {
	RequestID string `json:"request_id"`
	Raw       []byte `json:"raw"`
}

// AnswerDecision is the host's verdict on one proposed answer.
type AnswerDecision struct {
	Decision    string `json:"decision"`
	Reason      string `json:"reason,omitempty"`
	RepairsUsed int    `json:"repairs_used,omitempty"`
}

// RepairRequest asks whether one protocol correction may be attempted.
type RepairRequest struct {
	RequestID string `json:"request_id"`
	Kind      string `json:"kind"`
	Reason    string `json:"reason,omitempty"`
}

// RepairDecision is the host's answer to one repair request.
type RepairDecision struct {
	Decision    string `json:"decision"`
	Reason      string `json:"reason,omitempty"`
	RepairsUsed int    `json:"repairs_used,omitempty"`
}

// RepairPolicy is the host's single correction budget. One policy governs answer
// validation, malformed tool calls and invalid arguments, so an adapter cannot get
// a second budget by failing in a different way.
type RepairPolicy struct {
	Max            int
	MaxReasonChars int
}

// DefaultRepairPolicy is the #38 budget: two corrections, each at most 300 bytes.
func DefaultRepairPolicy() RepairPolicy {
	return RepairPolicy{Max: 2, MaxReasonChars: 300}
}

// Normalize fills an unset policy.
func (p RepairPolicy) Normalize() RepairPolicy {
	d := DefaultRepairPolicy()
	if p.Max <= 0 {
		p.Max = d.Max
	}
	if p.MaxReasonChars <= 0 {
		p.MaxReasonChars = d.MaxReasonChars
	}
	return p
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
	// Metrics is nil for a run that never started an adapter, and absent for a
	// record stored before the field existed.
	Metrics *RunMetrics `json:"metrics,omitempty"`
	// Aliases is the run's versioned model-facing alias table. The ledger and every
	// business reference stay canonical; only the projection uses short names. A
	// resumed run keeps the table it was created with.
	Aliases *AliasTable `json:"alias_table,omitempty"`
	// ToolSchemaDigest pins the exact native tool contracts the run used. A
	// resumed run under a different schema must not reinterpret old calls.
	ToolSchemaDigest string `json:"tool_schema_digest,omitempty"`
	// Pin records the runtime, model and configuration versions used for the run.
	// It is nil for a run stored before the field existed.
	Pin       *RuntimePin `json:"pin,omitempty"`
	CreatedAt string      `json:"created_at"`
	UpdatedAt string      `json:"updated_at"`
	Version   int64       `json:"version"`
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
