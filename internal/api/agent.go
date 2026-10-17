package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// The agent surface looks like the audit surface on purpose: a run is started by
// a POST that reads like the request, and every read is a bounded page with the
// same cursor convention. The one rule that is specific to it: the HTTP status
// describes the request, while the run's own status describes the run. A run that
// ended FAILED was still started successfully, so the POST answers 200 with that
// run in the body instead of turning the adapter's outcome into a transport error.

// defaultAgentPageSize bounds a run or hypothesis page when the caller names no
// limit. It is smaller than the audit page because a run document carries a whole
// task.
const defaultAgentPageSize = 100

// maxAgentPageSize bounds every agent page. A run event log can hold hundreds of
// entries for one run, and an unbounded answer would be the largest response the
// API serves.
const maxAgentPageSize = 500

// maxRunsPerRequest bounds one POST .../runs call. The cap is a request bound, not
// a policy: it keeps a single HTTP call from turning into an unbounded batch. A
// caller that wants more asks again, and each run still has to be claimed.
const maxRunsPerRequest = 10

// WithAgent attaches the P5 orchestrator, which enables the run and hypothesis
// routes. Without it those routes answer 501, because a deployment that cannot
// run an agent must not look like one whose runs are missing.
func WithAgent(runner *agent.Runner) Option { return func(s *Server) { s.Agent = runner } }

// agentUnavailable mirrors auditUnavailable: a server without the orchestrator
// says "not configured" rather than answering as if a run had vanished.
func (s *Server) agentUnavailable(w http.ResponseWriter) bool {
	if s.Agent == nil || s.Agent.Store == nil {
		writeError(w, http.StatusNotImplemented, "agent_unavailable",
			errors.New("this server was started without the agent runtime; start it with --agent-runtime scripted or cli"))
		return true
	}
	return false
}

// --- POST /api/audits/{id}/runs ---------------------------------------------

// explorationPolicyRequest is the wire form of an exploration policy. Every field
// is a pointer so "not sent" is distinguishable from "sent as zero": the request
// tightens the configured policy, it never silently replaces it (and zero is a
// real ceiling for expansions and the token budget).
type explorationPolicyRequest struct {
	MaxHops        *int     `json:"max_hops"`
	MaxBranches    *int     `json:"max_branches"`
	MaxToolCalls   *int     `json:"max_tool_calls"`
	MaxExpansions  *int     `json:"max_expansions"`
	TimeoutSeconds *int     `json:"timeout_seconds"`
	TokenBudget    *int     `json:"token_budget"`
	AllowedTools   []string `json:"allowed_tools"`
}

// startRunsRequest is the body of both run routes.
type startRunsRequest struct {
	MaxRuns int                      `json:"max_runs"`
	Policy  explorationPolicyRequest `json:"policy"`
}

// runBatchResponse is the answer to a run request. StopReason is the last run's
// reason, so a caller that asked for a batch can see why the batch ended.
type runBatchResponse struct {
	Runs       []agent.Run `json:"runs"`
	Count      int         `json:"count"`
	StopReason string      `json:"stop_reason,omitempty"`
}

// handleAuditRuns answers POST /api/audits/{id}/runs: run up to max_runs paths of
// an audit's queue.
//
// The route is audit-scoped because the decision is: which path runs next is a
// property of the audit's whole queue and its active-lease ceiling, not of one
// row. See handlePathRuns for the path-scoped spelling.
func (s *Server) handleAuditRuns(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	if s.auditUnavailable(w) {
		return
	}
	auditID := r.PathValue("id")
	if _, err := s.Audit.Audit(auditID); err != nil {
		writeAuditError(w, err, auditID)
		return
	}
	s.startRuns(w, r, auditID)
}

// handlePathRuns answers POST /api/paths/{id}/runs, which is the same operation
// reached through a path: the path only identifies the audit whose queue is run.
// It is kept because an operator that holds a path id should not have to look up
// its audit first, but it is not the canonical spelling — the path that runs may
// differ from the id in the URL, exactly as with POST /api/paths/{id}/claim.
func (s *Server) handlePathRuns(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	current, _, err := s.Audit.Path(id)
	if err != nil {
		writeAuditError(w, err, id)
		return
	}
	s.startRuns(w, r, current.AuditID)
}

// startRuns validates the request, narrows the runner's policy, and runs the
// batch. Both run routes share it so they cannot drift.
func (s *Server) startRuns(w http.ResponseWriter, r *http.Request, auditID string) {
	var req startRunsRequest
	if !s.decode(w, r, &req) {
		return
	}
	maxRuns := req.MaxRuns
	if maxRuns <= 0 {
		maxRuns = 1
	}
	if maxRuns > maxRunsPerRequest {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Errorf("max_runs %d exceeds the %d run(s) one request may start", maxRuns, maxRunsPerRequest))
		return
	}
	runner, err := s.narrowedRunner(req.Policy)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	runs, err := runner.RunAudit(r.Context(), auditID, maxRuns)
	if err != nil {
		writeAgentError(w, err, auditID)
		return
	}
	// An empty queue is a 404, not an empty batch: the caller asked for work and
	// there was none in the audit.
	if len(runs) == 0 {
		writeError(w, http.StatusNotFound, "not_found",
			fmt.Errorf("audit %s has no queued path to run", auditID))
		return
	}
	resp := runBatchResponse{Runs: runs, Count: len(runs), StopReason: runs[len(runs)-1].StopReason}
	writeJSON(w, http.StatusOK, resp)
}

// narrowedRunner applies a request policy on top of the configured one and
// returns a runner bound to it.
//
// The configured policy is a ceiling, not a default that a request may exceed: a
// caller may spend less of the agent's budget but never more, and the allowlist is
// the configured one intersected with what the request asked for. A request that
// names a tool the registry does not hold is refused outright — advertising a tool
// the gate would refuse teaches the agent to waste its budget on refusals.
func (s *Server) narrowedRunner(req explorationPolicyRequest) (*agent.Runner, error) {
	base := s.Agent.Policy.Normalize()
	effective := base
	if err := s.checkAllowedTools(req.AllowedTools, base.AllowedTools); err != nil {
		return nil, err
	}
	if req.AllowedTools != nil {
		effective.AllowedTools = intersectSorted(req.AllowedTools, base.AllowedTools)
	}
	effective.MaxHops = narrowerLimit(req.MaxHops, base.MaxHops)
	effective.MaxBranches = narrowerLimit(req.MaxBranches, base.MaxBranches)
	effective.MaxToolCalls = narrowerLimit(req.MaxToolCalls, base.MaxToolCalls)
	effective.MaxExpansions = narrowerLimit(req.MaxExpansions, base.MaxExpansions)
	effective.TimeoutSeconds = narrowerLimit(req.TimeoutSeconds, base.TimeoutSeconds)
	effective.TokenBudget = narrowerLimit(req.TokenBudget, base.TokenBudget)

	clone := *s.Agent
	clone.Policy = effective
	return &clone, nil
}

// checkAllowedTools rejects a request that names a tool the registry cannot
// execute, and one that asks for a tool the configured policy does not allow.
func (s *Server) checkAllowedTools(requested, base []string) error {
	if requested == nil {
		return nil
	}
	names := map[string]bool{}
	if s.Agent.Registry != nil {
		for _, name := range s.Agent.Registry.Names() {
			names[name] = true
		}
	}
	baseAllowed := map[string]bool{}
	for _, name := range base {
		baseAllowed[name] = true
	}
	unknown := make([]string, 0, len(requested))
	for _, name := range requested {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !names[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("unknown tool(s) %s; this deployment allows %s",
			strings.Join(unknown, ", "), strings.Join(sortedNames(names), ", "))
	}
	for _, name := range requested {
		name = strings.TrimSpace(name)
		if name != "" && !baseAllowed[name] {
			return fmt.Errorf("tool %q is not in the configured allowlist %s", name, strings.Join(base, ", "))
		}
	}
	return nil
}

// narrowerLimit keeps a request from widening a configured limit. A nil request
// field leaves the configured value alone; an explicit value is capped at it,
// which is the same intersection the allowlist gets.
func narrowerLimit(requested *int, base int) int {
	if requested == nil {
		return base
	}
	value := *requested
	if value < 0 {
		value = 0
	}
	if base > 0 && value > base {
		return base
	}
	return value
}

// intersectSorted returns the entries of wanted that are also in allowed, sorted
// and deduplicated, so the policy handed to the runner is canonical.
func intersectSorted(wanted, allowed []string) []string {
	permitted := map[string]bool{}
	for _, name := range allowed {
		permitted[strings.TrimSpace(name)] = true
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(wanted))
	for _, name := range wanted {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || !permitted[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func sortedNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// --- reads ------------------------------------------------------------------

// handleListRuns answers GET /api/runs.
func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	q := r.URL.Query()
	statuses, err := parseRunStatuses(q.Get("status"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	limit, offset, err := agentPage(q.Get("limit"), q.Get("offset"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	runs, total, err := s.Agent.Store.ListRuns(agent.RunQuery{
		PathID:     strings.TrimSpace(q.Get("path_id")),
		AuditID:    strings.TrimSpace(q.Get("audit_id")),
		SnapshotID: strings.TrimSpace(q.Get("snapshot_id")),
		Status:     statuses,
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil {
		writeAgentError(w, err, "")
		return
	}
	if runs == nil {
		runs = []agent.Run{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs, "total": total})
}

// handleGetRun answers GET /api/runs/{id}. The run document carries its task, so
// a reviewer can see what the agent was asked before judging what it answered.
func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	run, err := s.Agent.Store.GetRun(id)
	if err != nil {
		writeAgentError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// runEventPage is a bounded page of one run's exchange log, with the same
// resumable cursor convention as the audit event page.
type runEventPage struct {
	RunID        string        `json:"run_id"`
	Events       []agent.Event `json:"events"`
	Total        int           `json:"total"`
	NextAfterSeq int64         `json:"next_after_seq"`
}

// handleRunEvents answers GET /api/runs/{id}/events.
func (s *Server) handleRunEvents(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	if _, err := s.Agent.Store.GetRun(id); err != nil {
		writeAgentError(w, err, id)
		return
	}
	q := r.URL.Query()
	afterSeq := int64(0)
	if raw := strings.TrimSpace(q.Get("after_seq")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			writeError(w, http.StatusBadRequest, "invalid_request",
				fmt.Errorf("after_seq must be a non-negative integer (got %q)", raw))
			return
		}
		afterSeq = value
	}
	limit, err := agentLimit(q.Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	events, err := s.Agent.Store.ListRunEvents(agent.EventQuery{
		RunID:    id,
		Types:    commaList(q.Get("type")),
		AfterSeq: afterSeq,
		Limit:    limit,
	})
	if err != nil {
		writeAgentError(w, err, id)
		return
	}
	if events == nil {
		events = []agent.Event{}
	}
	next := afterSeq
	for _, event := range events {
		if event.Seq > next {
			next = event.Seq
		}
	}
	writeJSON(w, http.StatusOK, runEventPage{RunID: id, Events: events, Total: len(events), NextAfterSeq: next})
}

// handlePathHypotheses answers GET /api/paths/{id}/hypotheses, which is the same
// listing scoped to one path. The path must exist: an empty page for a typo is
// indistinguishable from a path whose run has not finished.
func (s *Server) handlePathHypotheses(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	if _, _, err := s.Audit.Path(id); err != nil {
		writeAuditError(w, err, id)
		return
	}
	s.listHypotheses(w, r, agent.HypothesisQuery{PathID: id})
}

// handleListHypotheses answers GET /api/hypotheses.
func (s *Server) handleListHypotheses(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	q := r.URL.Query()
	s.listHypotheses(w, r, agent.HypothesisQuery{
		AuditID:    strings.TrimSpace(q.Get("audit_id")),
		PathID:     strings.TrimSpace(q.Get("path_id")),
		SnapshotID: strings.TrimSpace(q.Get("snapshot_id")),
	})
}

// listHypotheses applies the shared filters, so the path-scoped and global
// listings cannot answer different questions.
func (s *Server) listHypotheses(w http.ResponseWriter, r *http.Request, q agent.HypothesisQuery) {
	params := r.URL.Query()
	statuses, err := parseHypothesisStatuses(params.Get("status"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	candidatesOnly, err := parseBool(params.Get("finding_candidates"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Errorf("finding_candidates: %w", err))
		return
	}
	limit, offset, err := agentPage(params.Get("limit"), params.Get("offset"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	q.Status = statuses
	q.FindingCandidatesOnly = candidatesOnly
	q.Limit = limit
	q.Offset = offset
	hypotheses, total, err := s.Agent.Store.ListHypotheses(q)
	if err != nil {
		writeAgentError(w, err, q.PathID)
		return
	}
	if hypotheses == nil {
		hypotheses = []agent.Hypothesis{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hypotheses": hypotheses, "total": total})
}

// handleGetHypothesis answers GET /api/hypotheses/{id}.
func (s *Server) handleGetHypothesis(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	hypothesis, err := s.Agent.Store.GetHypothesis(id)
	if err != nil {
		writeAgentError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, hypothesis)
}

// --- helpers ----------------------------------------------------------------

// writeAgentError maps the agent runtime's sentinels onto the API's vocabulary.
// The codes stay distinct on purpose: "the run is gone" (not_found) is a different
// operator action from "your run ended" (which is a 200 with the run's status) and
// from "you cannot spend that" (budget_exceeded).
func writeAgentError(w http.ResponseWriter, err error, id string) {
	switch {
	case errors.Is(err, llm.ErrNotConfigured):
		writeError(w, http.StatusServiceUnavailable, "llm_not_configured", err)
	case err == nil:
		return
	case errors.Is(err, agent.ErrNotFound),
		errors.Is(err, agent.ErrRunNotFound),
		errors.Is(err, path.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err)
	case errors.Is(err, agent.ErrInvalidArgument),
		errors.Is(err, agent.ErrInvalidTask),
		errors.Is(err, agent.ErrInvalidAnswer),
		errors.Is(err, agent.ErrUnsupportedTool),
		errors.Is(err, agent.ErrExpansionRefused):
		writeError(w, http.StatusBadRequest, "invalid_request", err)
	case errors.Is(err, path.ErrBudgetExceeded), errors.Is(err, agent.ErrBudgetExhausted):
		writeError(w, http.StatusConflict, "budget_exceeded", err)
	case errors.Is(err, agent.ErrConflict), errors.Is(err, path.ErrConflict):
		writeError(w, http.StatusConflict, "version_conflict", err)
	case errors.Is(err, path.ErrNoASG):
		writeError(w, http.StatusConflict, "asg_missing", fmt.Errorf(
			"snapshot %s has no attack surface; build it first with POST /api/snapshots/%s/asg: %w",
			id, id, err))
	default:
		writeAuditError(w, err, id)
	}
}

// parseRunStatuses validates the run status filter, so a typo is a 400 instead of
// an empty page.
func parseRunStatuses(value string) ([]agent.RunStatus, error) {
	parts := commaList(value)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]agent.RunStatus, 0, len(parts))
	for _, part := range parts {
		status := agent.RunStatus(part)
		if !agent.ValidRunStatus(status) {
			return nil, fmt.Errorf("unknown status %q; valid statuses are %s",
				part, strings.Join(runStatusNames(), ", "))
		}
		out = append(out, status)
	}
	return out, nil
}

// parseHypothesisStatuses validates the hypothesis status filter.
func parseHypothesisStatuses(value string) ([]string, error) {
	parts := commaList(value)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case agent.HypothesisCandidate, agent.HypothesisConfirmed,
			agent.HypothesisRefuted, agent.HypothesisInconclusive:
			out = append(out, part)
		default:
			return nil, fmt.Errorf("unknown hypothesis status %q; valid statuses are %s",
				part, strings.Join(hypothesisStatusNames(), ", "))
		}
	}
	return out, nil
}

// parseBool reads a boolean query parameter. A typo is refused rather than
// silently treated as false, because "finding_candidates=false" and
// "finding_candidates=ture" would otherwise look the same.
func parseBool(value string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("must be a boolean (got %q)", value)
	}
	return parsed, nil
}

// agentLimit bounds a page size on the agent surface.
func agentLimit(raw string) (int, error) {
	limit, err := agentQueryInt(raw, defaultAgentPageSize)
	if err != nil {
		return 0, err
	}
	if limit <= 0 {
		return defaultAgentPageSize, nil
	}
	if limit > maxAgentPageSize {
		return maxAgentPageSize, nil
	}
	return limit, nil
}

// agentPage parses a limit and an offset together.
func agentPage(limitRaw, offsetRaw string) (int, int, error) {
	limit, err := agentLimit(limitRaw)
	if err != nil {
		return 0, 0, err
	}
	offset, err := agentQueryInt(offsetRaw, 0)
	if err != nil {
		return 0, 0, err
	}
	if offset < 0 {
		return 0, 0, fmt.Errorf("offset must not be negative (got %d)", offset)
	}
	return limit, offset, nil
}

// agentQueryInt parses an integer parameter, refusing a bad value instead of
// falling back to the default the way queryInt does: on a paginated agent list a
// silent fallback would answer a different question than the one asked.
func agentQueryInt(value string, fallback int) (int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("must be an integer (got %q)", value)
	}
	return parsed, nil
}

func runStatusNames() []string {
	statuses := agent.AllRunStatuses()
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}

func hypothesisStatusNames() []string {
	return []string{agent.HypothesisCandidate, agent.HypothesisConfirmed,
		agent.HypothesisRefuted, agent.HypothesisInconclusive}
}
