package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Validation errors. Each one names a different operator action: an adapter that
// returns invalid JSON is a bug in the adapter, an answer that claims confirmation
// is a policy violation, and an answer that cites nothing is not evidence.
var (
	ErrInvalidTask      = errors.New("agent: invalid task")
	ErrInvalidAnswer    = errors.New("agent: invalid answer")
	ErrUnsupportedTool  = errors.New("agent: tool is not allowed for this run")
	ErrBudgetExhausted  = errors.New("agent: budget exhausted")
	ErrExpansionRefused = errors.New("agent: expansion refused")
	ErrRunNotFound      = errors.New("agent: run not found")
	ErrRunNotRunning    = errors.New("agent: run is not running")
	ErrPathNotActive    = errors.New("agent: path is not in an active state")
	// ErrInvalidArgument is for a call the orchestrator should never have made — a
	// missing run id, a negative budget. It is deliberately distinct from
	// ErrConflict, which means "stored state disagrees with you".
	ErrInvalidArgument = errors.New("agent: invalid argument")
	ErrNotFound        = errors.New("agent: not found")
	ErrConflict        = errors.New("agent: version conflict")
)

// Caps on the answer. They exist so an adapter cannot make the orchestrator store
// an essay, and so "no hidden reasoning" is a limit and not a request.
const (
	MaxStatementChars  = 2000
	MaxNotesChars      = 1000
	MaxEvidenceItems   = 20
	MaxQuoteChars      = 500
	MaxNextAction      = 500
	MaxExpansionText   = 500
	MaxToolArgs        = 12
	MaxToolArgChars    = 2000
	MaxToolResultChars = 20000
)

// ValidateTask rejects a task the orchestrator should never have built.
func ValidateTask(task Task) error {
	var problems []string
	if task.SchemaVersion != SchemaVersion {
		problems = append(problems, fmt.Sprintf("schema_version is %d, want %d", task.SchemaVersion, SchemaVersion))
	}
	if strings.TrimSpace(task.PathID) == "" {
		problems = append(problems, "path_id is required")
	}
	if strings.TrimSpace(task.SnapshotID) == "" {
		problems = append(problems, "snapshot_id is required")
	}
	if strings.TrimSpace(task.SecurityGoal) == "" {
		problems = append(problems, "security_goal is required: a run without a goal cannot be judged")
	}
	if task.SourceSinkRefs.EntryNodeID == "" || task.SourceSinkRefs.TargetNodeID == "" {
		problems = append(problems, "source_sink_refs must name both ends of the path")
	}
	if len(task.EvidenceRefs) == 0 {
		problems = append(problems, "evidence_refs is empty: a task must arrive with the facts already established")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidTask, strings.Join(problems, "; "))
	}
	return nil
}

// DecodeAnswer parses and validates a structured answer.
//
// Unknown fields are rejected: an adapter that invents a field is producing
// something the orchestrator would silently drop, which is exactly the failure mode
// this protocol exists to prevent.
func DecodeAnswer(raw []byte, task Task) (*Answer, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%w: empty output", ErrInvalidAnswer)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var answer Answer
	if err := decoder.Decode(&answer); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAnswer, err)
	}
	if err := ValidateAnswer(&answer, task); err != nil {
		return nil, err
	}
	return &answer, nil
}

// ValidateAnswer checks the answer against the protocol and against the task it
// answers.
func ValidateAnswer(answer *Answer, task Task) error {
	var problems []string
	if answer == nil {
		return fmt.Errorf("%w: no answer", ErrInvalidAnswer)
	}
	if answer.SchemaVersion != SchemaVersion {
		problems = append(problems, fmt.Sprintf("schema_version is %d, want %d", answer.SchemaVersion, SchemaVersion))
	}
	if strings.TrimSpace(answer.SecurityGoal) == "" {
		problems = append(problems, "security_goal is required")
	} else if task.SecurityGoal != "" && answer.SecurityGoal != task.SecurityGoal {
		problems = append(problems, fmt.Sprintf("security_goal %q does not answer the task goal %q", answer.SecurityGoal, task.SecurityGoal))
	}
	if strings.TrimSpace(answer.Hypothesis.Statement) == "" {
		problems = append(problems, "hypothesis.statement is required: a run must say what it claims")
	}
	if len(answer.Hypothesis.Statement) > MaxStatementChars {
		problems = append(problems, fmt.Sprintf("hypothesis.statement exceeds %d characters", MaxStatementChars))
	}
	if !ValidHypothesisStatus(answer.Hypothesis.Status) {
		problems = append(problems, fmt.Sprintf("hypothesis.status %q is not one a run may assert (only candidate, inconclusive or refuted; confirmation belongs to verification)", answer.Hypothesis.Status))
	}
	if strings.TrimSpace(answer.Hypothesis.Confidence) == "" {
		problems = append(problems, "hypothesis.confidence is required")
	}
	if len(answer.Notes) > MaxNotesChars {
		problems = append(problems, fmt.Sprintf("notes exceeds %d characters; explicit justification only, no reasoning transcript", MaxNotesChars))
	}
	if len(answer.NextAction) > MaxNextAction {
		problems = append(problems, fmt.Sprintf("next_action exceeds %d characters", MaxNextAction))
	}
	if answer.FindingCandidate && len(answer.SupportingEvidence) == 0 {
		problems = append(problems, "a finding candidate must cite supporting evidence")
	}
	if len(answer.SupportingEvidence) > MaxEvidenceItems || len(answer.ContradictingEvidence) > MaxEvidenceItems {
		problems = append(problems, fmt.Sprintf("evidence lists are limited to %d items each", MaxEvidenceItems))
	}
	problems = append(problems, validateEvidence("supporting", answer.SupportingEvidence)...)
	problems = append(problems, validateEvidence("contradicting", answer.ContradictingEvidence)...)
	if answer.RequestedExpansion != nil {
		ask := answer.RequestedExpansion
		if strings.TrimSpace(ask.TargetNodeID) == "" {
			problems = append(problems, "requested_expansion.target_node_id is required")
		}
		if strings.TrimSpace(ask.Purpose) == "" {
			problems = append(problems, "requested_expansion.purpose is required")
		}
		if strings.TrimSpace(ask.ExpectedGain) == "" {
			problems = append(problems, "requested_expansion.expected_gain is required: an expansion without an expected gain is a request to spend budget for nothing")
		}
		for name, value := range map[string]string{"purpose": ask.Purpose, "expected_gain": ask.ExpectedGain, "estimated_cost": ask.EstimatedCost} {
			if len(value) > MaxExpansionText {
				problems = append(problems, fmt.Sprintf("requested_expansion.%s exceeds %d characters", name, MaxExpansionText))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidAnswer, strings.Join(problems, "; "))
	}
	return nil
}

// validateEvidence rejects a citation that cannot be checked: it must carry either
// a resolved reference or a file and line, and a quote stays bounded.
func validateEvidence(label string, items []AnswerEvidence) []string {
	var problems []string
	for i, item := range items {
		where := fmt.Sprintf("%s_evidence[%d]", label, i)
		if strings.TrimSpace(item.Kind) == "" {
			problems = append(problems, where+".kind is required")
		}
		if strings.TrimSpace(item.Ref) == "" && (strings.TrimSpace(item.File) == "" || item.Line <= 0) {
			problems = append(problems, where+" must carry a ref or a file and line: an unverifiable citation is not evidence")
		}
		if len(item.Quote) > MaxQuoteChars {
			problems = append(problems, fmt.Sprintf("%s.quote exceeds %d characters", where, MaxQuoteChars))
		}
	}
	return problems
}

// ValidateToolRequest checks a request against the run's exploration policy. It is
// the only gate between an agent and a graph query, and it fails closed.
func ValidateToolRequest(req ToolRequest, policy ExplorationPolicy, used int) error {
	if strings.TrimSpace(req.CallID) == "" {
		return fmt.Errorf("%w: call_id is required", ErrUnsupportedTool)
	}
	if strings.TrimSpace(req.Tool) == "" {
		return fmt.Errorf("%w: tool is required", ErrUnsupportedTool)
	}
	if !policy.Allows(req.Tool) {
		return fmt.Errorf("%w: %q is not in the allowlist %v", ErrUnsupportedTool, req.Tool, policy.AllowedTools)
	}
	if policy.MaxToolCalls > 0 && used >= policy.MaxToolCalls {
		return fmt.Errorf("%w: %d of %d tool calls used", ErrBudgetExhausted, used, policy.MaxToolCalls)
	}
	if len(req.Args) > MaxToolArgs {
		return fmt.Errorf("%w: %d arguments, at most %d are accepted", ErrInvalidAnswer, len(req.Args), MaxToolArgs)
	}
	for key, value := range req.Args {
		if len(value) > MaxToolArgChars {
			return fmt.Errorf("%w: argument %q exceeds %d characters", ErrInvalidAnswer, key, MaxToolArgChars)
		}
	}
	return nil
}

// TruncateToolResult caps what an agent can pull into its context in one call.
func TruncateToolResult(result string) (string, bool) {
	if len(result) <= MaxToolResultChars {
		return result, false
	}
	return result[:MaxToolResultChars], true
}

// ExpandPolicy decides an expansion request (implementation guide §9.3). The
// orchestrator may approve, shrink, defer or reject — and the agent has no way to
// bypass the answer, because the approved policy is what the next exchange is
// validated against.
type ExpandPolicy struct {
	// MaxHopsPerExpansion caps how much room one approval may grant.
	MaxHopsPerExpansion int
	// MaxExpansionsPerRun caps how many requests a run may make.
	MaxExpansionsPerRun int
	// MaxToolCallsPerExpansion caps the added tool budget of one approval.
	MaxToolCallsPerExpansion int
	// AllowedTools is the closure of the allowlist: an expansion may never widen it.
	AllowedTools []string
}

// DefaultExpandPolicy returns the documented behaviour: a small grant, a bounded
// number of grants, and no way to widen the tool allowlist.
func DefaultExpandPolicy(allowed []string) ExpandPolicy {
	sorted := append([]string(nil), allowed...)
	sort.Strings(sorted)
	return ExpandPolicy{
		MaxHopsPerExpansion:      1,
		MaxExpansionsPerRun:      3,
		MaxToolCallsPerExpansion: 5,
		AllowedTools:             sorted,
	}
}

// ExpansionDecision is the orchestrator's answer to an expansion request.
type ExpansionDecision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	// GrantedHops and GrantedToolCalls are what the policy actually allowed, which
	// may be less than what was asked for.
	GrantedHops      int      `json:"granted_hops"`
	GrantedToolCalls int      `json:"granted_tool_calls"`
	GrantedTools     []string `json:"granted_tools"`
}

// DecideExpansion applies the policy. It never rejects for being inconvenient: a
// request is refused when the run has spent its requests, when the tool is outside
// the allowlist, or when the run is already at its exploration ceiling.
func DecideExpansion(ask ExpansionAsk, policy ExpandPolicy, current ExplorationPolicy, usedExpansions int, activeBranches int) ExpansionDecision {
	decide := func(decision, reason string, hops, calls int, tools []string) ExpansionDecision {
		return ExpansionDecision{Decision: decision, Reason: reason, GrantedHops: hops, GrantedToolCalls: calls, GrantedTools: tools}
	}
	if policy.MaxExpansionsPerRun > 0 && usedExpansions >= policy.MaxExpansionsPerRun {
		return decide(ExpansionRejected, fmt.Sprintf("the run has used %d of %d expansion requests", usedExpansions, policy.MaxExpansionsPerRun), 0, 0, nil)
	}
	if current.MaxBranches > 0 && activeBranches >= current.MaxBranches {
		return decide(ExpansionDeferred, fmt.Sprintf("the run already holds %d of %d active branches", activeBranches, current.MaxBranches), 0, 0, nil)
	}
	hops := ask.Hops
	if hops <= 0 {
		hops = 1
	}
	if policy.MaxHopsPerExpansion > 0 && hops > policy.MaxHopsPerExpansion {
		hops = policy.MaxHopsPerExpansion
		return decide(ExpansionShrunk, fmt.Sprintf("granted %d hop(s) instead of %d", hops, ask.Hops), hops, 0, policy.AllowedTools)
	}
	calls := ask.ToolCalls
	if calls <= 0 {
		calls = policy.MaxToolCallsPerExpansion
	}
	if policy.MaxToolCallsPerExpansion > 0 && calls > policy.MaxToolCallsPerExpansion {
		calls = policy.MaxToolCallsPerExpansion
		return decide(ExpansionShrunk, fmt.Sprintf("granted %d tool call(s) instead of %d", calls, ask.ToolCalls), hops, calls, policy.AllowedTools)
	}
	return decide(ExpansionApproved, "within the policy", hops, calls, policy.AllowedTools)
}

// ApplyExpansion folds a decision into the run's policy. It never widens the tool
// allowlist: an expansion buys room, not permissions.
func ApplyExpansion(policy ExplorationPolicy, decision ExpansionDecision) ExplorationPolicy {
	if decision.GrantedHops > 0 {
		policy.MaxHops += decision.GrantedHops
	}
	if decision.GrantedToolCalls > 0 {
		policy.MaxToolCalls += decision.GrantedToolCalls
	}
	return policy
}

// RepeatTracker stops a run that keeps producing the same answer.
//
// The failure mode is real: an adapter that did not receive new evidence tends to
// restate its first answer, and paying for that until the token budget runs out is
// the most expensive way to learn nothing.
type RepeatTracker struct {
	seen    map[string]int
	maxSame int
}

// NewRepeatTracker builds a tracker; maxSame <= 0 disables it.
func NewRepeatTracker(maxSame int) *RepeatTracker {
	return &RepeatTracker{seen: map[string]int{}, maxSame: maxSame}
}

// Observe records an answer digest and reports whether the run should stop.
func (t *RepeatTracker) Observe(statement string, evidenceCount int) (bool, int) {
	if t == nil || t.maxSame <= 0 {
		return false, 0
	}
	key := Digest(statement) + fmt.Sprintf("/%d", evidenceCount)
	t.seen[key]++
	count := t.seen[key]
	return count > t.maxSame, count
}
