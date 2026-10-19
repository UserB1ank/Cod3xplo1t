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
	ErrInvalidTask     = errors.New("agent: invalid task")
	ErrInvalidAnswer   = errors.New("agent: invalid answer")
	ErrUnsupportedTool = errors.New("agent: tool is not allowed for this run")
	ErrBudgetExhausted = errors.New("agent: budget exhausted")
	// ErrInvalidCheckpoint is a pause document a reader cannot trust.
	ErrInvalidCheckpoint = errors.New("agent: invalid checkpoint")
	// ErrRunNotPaused refuses a resume of an attempt that is not paused.
	ErrRunNotPaused = errors.New("agent: the run is not paused")
	// ErrCheckpointUnavailable refuses a resume whose checkpoint is missing.
	ErrCheckpointUnavailable = errors.New("agent: the checkpoint is unavailable")
	// ErrCheckpointStale refuses a resume whose fixed inputs are gone.
	ErrCheckpointStale = errors.New("agent: the checkpoint's fixed inputs are no longer available")
	// ErrCheckpointUnsupported refuses resume for an adapter that cannot carry one.
	ErrCheckpointUnsupported = errors.New("agent: this runtime cannot resume a checkpoint")
	// ErrRuntimeUnavailable is a task's selected runtime missing from the
	// deployment catalog. It must not fall back to another adapter.
	ErrRuntimeUnavailable = errors.New("agent: the requested runtime is not available")
	// ErrTurnDenied is what an adapter returns when the host refused a permit,
	// a correction or an answer. The host already set the run's stop reason; the
	// adapter must not invent one.
	ErrTurnDenied       = errors.New("agent: the orchestrator denied the turn")
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
	MaxStatementChars = 2000
	MaxNotesChars     = 1000
	MaxEvidenceItems  = 20
	MaxQuoteChars     = 500
	MaxNextAction     = 500
	MaxExpansionText  = 500
	// MaxToolArgBytes bounds one argument object before any tool sees it. The
	// per-field limits live in each tool's schema, which the host validates.
	MaxToolArgBytes    = 32000
	MaxToolResultChars = 20000
	// MaxObligationReason bounds the justification attached to one verdict. The
	// checklist is a decision record, not a reasoning transcript.
	MaxObligationReason = 400
)

// ValidateTask rejects a task the orchestrator should never have built.
func ValidateTask(task Task) error {
	var problems []string
	switch task.SchemaVersion {
	case SchemaVersion:
		// Version 1 predates the checklist and stays valid.
	case SchemaVersionObligations:
		problems = append(problems, validateObligationChecklist(task.Obligations)...)
	default:
		problems = append(problems, fmt.Sprintf("schema_version is %d, want %d or %d",
			task.SchemaVersion, SchemaVersion, SchemaVersionObligations))
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
	wantedVersion := SchemaVersion
	if task.SchemaVersion == SchemaVersionObligations {
		wantedVersion = SchemaVersionObligations
	}
	if answer.SchemaVersion != wantedVersion {
		problems = append(problems, fmt.Sprintf("schema_version is %d, want %d for a version %d task",
			answer.SchemaVersion, wantedVersion, task.SchemaVersion))
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
	if len(task.Obligations) > 0 {
		problems = append(problems, validateObligationVerdicts(answer.Obligations, task.Obligations, answer.Hypothesis.Status)...)
	}
	// Schema 2 conclusions must say what would refute them. A hypothesis without
	// a falsifier is an assertion, not an audited claim.
	if task.SchemaVersion == SchemaVersionObligations &&
		(answer.Hypothesis.Status == HypothesisCandidate || answer.Hypothesis.Status == HypothesisRefuted) {
		if answer.Falsifier == nil {
			problems = append(problems, "a candidate or refuted answer needs a falsifier: what observation would refute the claim")
		} else {
			if strings.TrimSpace(answer.Falsifier.Claim) == "" {
				problems = append(problems, "falsifier.claim is required")
			}
			if len(answer.Falsifier.Claim) > MaxStatementChars {
				problems = append(problems, fmt.Sprintf("falsifier.claim exceeds %d characters", MaxStatementChars))
			}
			if answer.Falsifier.Checked && len(answer.Falsifier.How) == 0 {
				problems = append(problems, "falsifier.checked=true needs at least one how reference")
			}
			if len(answer.Falsifier.How) > MaxEvidenceItems {
				problems = append(problems, fmt.Sprintf("falsifier.how is limited to %d references", MaxEvidenceItems))
			}
			for _, how := range answer.Falsifier.How {
				if len(strings.TrimSpace(how)) == 0 || len(how) > 200 {
					problems = append(problems, "falsifier.how entries must be non-empty and at most 200 characters")
				}
			}
		}
	}
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

// validateObligationChecklist checks the host-derived checklist: one obligation
// per kind, unique ids, and a subject and question that name what is being asked.
func validateObligationChecklist(obligations []Obligation) []string {
	var problems []string
	kinds := AllObligationKinds()
	if len(obligations) != len(kinds) {
		problems = append(problems, fmt.Sprintf("obligations holds %d entries, want one per kind (%d)",
			len(obligations), len(kinds)))
	}
	seenKind := make(map[string]bool, len(obligations))
	seenID := make(map[string]bool, len(obligations))
	for i, obligation := range obligations {
		where := fmt.Sprintf("obligations[%d]", i)
		switch {
		case !ValidObligationKind(obligation.Kind):
			problems = append(problems, fmt.Sprintf("%s.kind %q is not a known obligation kind", where, obligation.Kind))
		case seenKind[obligation.Kind]:
			problems = append(problems, fmt.Sprintf("%s.kind %q appears more than once", where, obligation.Kind))
		}
		seenKind[obligation.Kind] = true
		switch {
		case strings.TrimSpace(obligation.ID) == "":
			problems = append(problems, where+".id is required")
		case seenID[obligation.ID]:
			problems = append(problems, fmt.Sprintf("%s.id %q appears more than once", where, obligation.ID))
		}
		seenID[obligation.ID] = true
		if strings.TrimSpace(obligation.Subject) == "" {
			problems = append(problems, where+".subject is required")
		}
		if strings.TrimSpace(obligation.Question) == "" {
			problems = append(problems, where+".question is required")
		}
	}
	for _, kind := range kinds {
		if !seenKind[kind] {
			problems = append(problems, "obligations is missing the "+kind+" question")
		}
	}
	return problems
}

// validateObligationVerdicts checks that an answer closes the checklist it was
// given. An unknown verdict is allowed only with a blocker, and only when the
// hypothesis is inconclusive: a conclusive claim over an open question is exactly
// the premature answer the checklist exists to prevent.
func validateObligationVerdicts(verdicts []ObligationVerdict, obligations []Obligation, status string) []string {
	var problems []string
	expected := make(map[string]bool, len(obligations))
	for _, obligation := range obligations {
		expected[obligation.Kind] = true
	}
	seen := make(map[string]bool, len(verdicts))
	for i, verdict := range verdicts {
		where := fmt.Sprintf("obligations[%d]", i)
		if !ValidObligationKind(verdict.Kind) {
			problems = append(problems, fmt.Sprintf("%s.kind %q is not a known obligation kind", where, verdict.Kind))
			continue
		}
		if !expected[verdict.Kind] {
			problems = append(problems, fmt.Sprintf("%s answers %q, which this task does not ask", where, verdict.Kind))
			continue
		}
		if seen[verdict.Kind] {
			problems = append(problems, fmt.Sprintf("%s.kind %q appears more than once", where, verdict.Kind))
			continue
		}
		seen[verdict.Kind] = true
		switch verdict.Verdict {
		case VerdictMet, VerdictNotMet:
			if verdict.Blocker != "" {
				problems = append(problems, fmt.Sprintf("%s is closed and must not name a blocker", where))
			}
		case VerdictUnknown:
			if !ValidBlocker(verdict.Blocker) {
				problems = append(problems, fmt.Sprintf("%s is unknown and must name a blocker (%s)",
					where, strings.Join(AllBlockers(), ", ")))
			}
		default:
			problems = append(problems, fmt.Sprintf("%s.verdict %q is not one of %s, %s, %s",
				where, verdict.Verdict, VerdictMet, VerdictNotMet, VerdictUnknown))
		}
		if len(verdict.Reason) > MaxObligationReason {
			problems = append(problems, fmt.Sprintf("%s.reason exceeds %d characters", where, MaxObligationReason))
		}
	}
	for _, obligation := range obligations {
		if !seen[obligation.Kind] {
			problems = append(problems, "the answer closes no verdict for "+obligation.Kind)
		}
	}
	if status != HypothesisInconclusive {
		for _, verdict := range verdicts {
			if verdict.Verdict == VerdictUnknown {
				problems = append(problems, fmt.Sprintf(
					"obligation %s is still open (%s); only an inconclusive hypothesis may leave it open",
					verdict.Kind, verdict.Blocker))
			}
		}
	}
	return problems
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
	if len(req.Args) > MaxToolArgBytes {
		return fmt.Errorf("%w: arguments exceed %d bytes", ErrInvalidAnswer, MaxToolArgBytes)
	}
	return nil
}

// toolResultTooLarge is what an oversized result becomes. Cutting a result at a
// byte offset can slice a JSON document in half, and a half document is worse than
// no document: the model cannot tell truncated data from malformed data. The
// replacement is a complete, parseable error that names the fix.
const toolResultTooLarge = `{"error":"result_too_large","hint":"narrow the query: lower limit, max_nodes or max_paths"}`

// TruncateToolResult caps what an agent can pull into its context in one call.
// The second return value reports that the cap was hit, so the run's metrics and
// the event log can state it; the replacement is always valid JSON.
func TruncateToolResult(result string) (string, bool) {
	if len(result) <= MaxToolResultChars {
		return result, false
	}
	return toolResultTooLarge, true
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
