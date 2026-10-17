package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// The verification surface turns a hypothesis into a finding.
//
// Two rules shape it, and both are visible in the handler bodies:
//
//   - the HTTP status describes the request, while the run's own status and
//     outcome describe the verification. A run that ended BLOCKED was still
//     started successfully, so the POST answers 200 with that run in the body;
//   - an approval is an explicit write, never an inference. `approved_by` is
//     recorded on the run, and a plan that needs approval without it is refused
//     with 409 before anything is stored.

// defaultVerificationPageSize bounds a verification page when the caller names no
// limit. It is smaller than the audit page because a run document carries its whole
// plan.
const defaultVerificationPageSize = 100

// maxVerificationPageSize bounds every verification page.
const maxVerificationPageSize = 500

// maxFindingsPerReport bounds how many findings one report renders. A report is a
// document a human reads; an unbounded one would be the largest response the API
// serves.
const maxFindingsPerReport = 500

// WithVerifier attaches the P6 verification engine, which enables the
// verification, finding and report routes. Without it those routes answer 501,
// because a deployment that cannot verify anything must not look like one whose
// verifications are missing.
func WithVerifier(v *verify.Verifier) Option { return func(s *Server) { s.Verifier = v } }

// WithVerifyPlanner attaches the planner that turns a hypothesis into a finding
// and a plan. Without it the write routes answer 501.
func WithVerifyPlanner(p *graph.VerifyPlanner) Option {
	return func(s *Server) { s.VerifyPlanner = p }
}

// verificationUnavailable mirrors agentUnavailable: a server without the
// verification layer says "not configured" rather than answering as if a record
// had vanished.
func (s *Server) verificationUnavailable(w http.ResponseWriter) bool {
	if s.Verifier == nil || s.VerifyPlanner == nil {
		writeError(w, http.StatusNotImplemented, "verification_unavailable",
			errors.New("this server was started without the verification layer; start it with --verify-executor scripted, cli or unsupported"))
		return true
	}
	return false
}

// --- POST /api/hypotheses/{id}/finding --------------------------------------

// handleEnsureFinding answers POST /api/hypotheses/{id}/finding: derive the
// finding for a hypothesis and store its citations as evidence.
//
// It is idempotent by construction — the finding is keyed by hypothesis id and the
// evidence is content-addressed — so a retry (or a second caller) converges on the
// same document instead of duplicating anything. It is nevertheless wrapped in
// withIdempotency, so a retry with the same key replays the first response exactly.
func (s *Server) handleEnsureFinding(w http.ResponseWriter, r *http.Request) {
	if s.verificationUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	finding, err := s.VerifyPlanner.EnsureFinding(r.Context(), id)
	if err != nil {
		writeVerifyError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, finding)
}

// --- POST /api/hypotheses/{id}/verifications --------------------------------

// verificationRequest is the body of the verification POST.
//
// Plan is optional: when it is absent the server builds one from the hypothesis and
// the scope with the planner, so a caller cannot smuggle an unvalidated plan in.
// A caller that supplies its own plan still goes through verify.Prepare and the
// scope/approval gate.
type verificationRequest struct {
	Approved    bool               `json:"approved"`
	ApprovedBy  string             `json:"approved_by"`
	Scope       verify.Scope       `json:"scope"`
	Environment verify.Environment `json:"environment"`
	Plan        *verify.Plan       `json:"plan,omitempty"`
}

// handleCreateVerification answers POST /api/hypotheses/{id}/verifications.
func (s *Server) handleCreateVerification(w http.ResponseWriter, r *http.Request) {
	if s.verificationUnavailable(w) {
		return
	}
	hypothesisID := r.PathValue("id")
	var req verificationRequest
	if !s.decode(w, r, &req) {
		return
	}
	// A plan that wants egress the scope withholds is an authorization decision,
	// not a malformed plan: answering 409 scope_denied tells the operator what to
	// change. It is checked here as well as by verify.Authorize because
	// verify.Prepare rejects the same combination as an invalid plan, and a caller
	// should not have to read "invalid plan" to learn they were refused.
	if err := requestScopeViolation(req); err != nil {
		writeVerifyError(w, err, hypothesisID)
		return
	}
	prepared, err := s.prepareVerification(r, hypothesisID, req)
	if err != nil {
		writeVerifyError(w, err, hypothesisID)
		return
	}
	// The authorisation gate runs before the verifier sees the plan, so a plan that
	// needs an approval it does not have — or that wants network access the scope
	// withholds — is refused without writing a run.
	if err := verify.Authorize(prepared, req.Approved, req.ApprovedBy); err != nil {
		writeVerifyError(w, err, hypothesisID)
		return
	}
	owner := ""
	if principal, ok := PrincipalFrom(r.Context()); ok {
		owner = principal.Name
	}
	run, err := s.Verifier.Verify(r.Context(), verify.VerifyRequest{
		Plan:       prepared.Plan,
		Approved:   req.Approved,
		ApprovedBy: strings.TrimSpace(req.ApprovedBy),
		Owner:      owner,
	})
	if err != nil {
		writeVerifyError(w, err, hypothesisID)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// prepareVerification either builds a plan from the hypothesis and the request's
// scope, or validates the plan the caller supplied. Either way it returns a
// *Prepared: the handler never executes an unvalidated plan.
func (s *Server) prepareVerification(r *http.Request, hypothesisID string, req verificationRequest) (*verify.Prepared, error) {
	if req.Plan == nil {
		return s.VerifyPlanner.BuildPlan(r.Context(), hypothesisID, req.Scope, req.Environment)
	}
	prepared, err := verify.Prepare(*req.Plan)
	if err != nil {
		return nil, err
	}
	// A caller-supplied plan must still describe this hypothesis: a plan for
	// another claim would attach the verdict to the wrong finding.
	if strings.TrimSpace(prepared.Plan.HypothesisID) != strings.TrimSpace(hypothesisID) {
		return nil, fmt.Errorf("%w: the plan is for hypothesis %s, not %s",
			verify.ErrInvalidPlan, prepared.Plan.HypothesisID, hypothesisID)
	}
	return prepared, nil
}

// requestScopeViolation reports whether a request asks an environment for egress
// the scope does not authorize. It is the API's own check so the answer is
// scope_denied rather than invalid_request, and it covers both the built and the
// caller-supplied plan.
func requestScopeViolation(req verificationRequest) error {
	if req.Plan != nil {
		return planScopeViolation(req.Plan.Environment, req.Plan.Scope)
	}
	return planScopeViolation(req.Environment, req.Scope)
}

// planScopeViolation states the conflict in the terms verify.Authorize would use.
func planScopeViolation(env verify.Environment, scope verify.Scope) error {
	normalized := env.Normalize()
	if normalized.Network != verify.NetworkNone && !scope.AllowNetwork {
		return fmt.Errorf("%w: the environment asks for %s network access and the scope allows none",
			verify.ErrScopeDenied, normalized.Network)
	}
	return nil
}

// --- reads ------------------------------------------------------------------

// handleListVerifications answers GET /api/verifications.
func (s *Server) handleListVerifications(w http.ResponseWriter, r *http.Request) {
	if s.verificationUnavailable(w) {
		return
	}
	q := r.URL.Query()
	statuses, err := parseVerificationStatuses(q.Get("status"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	outcomes, err := parseOutcomes(q.Get("outcome"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	limit, offset, err := verificationPage(q.Get("limit"), q.Get("offset"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	runs, total, err := s.Verifier.ListRuns(verify.RunQuery{
		HypothesisID: strings.TrimSpace(q.Get("hypothesis_id")),
		FindingID:    strings.TrimSpace(q.Get("finding_id")),
		PathID:       strings.TrimSpace(q.Get("path_id")),
		AuditID:      strings.TrimSpace(q.Get("audit_id")),
		SnapshotID:   strings.TrimSpace(q.Get("snapshot_id")),
		Status:       statuses,
		Outcome:      outcomes,
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		writeVerifyError(w, err, "")
		return
	}
	if runs == nil {
		runs = []verify.Run{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"verifications": runs, "total": total})
}

// handleGetVerification answers GET /api/verifications/{id}. The document carries
// the plan, the environment digest, the approval record, the outcome, the reason
// (in stop_reason/error/reproduction) and the evidence ids.
func (s *Server) handleGetVerification(w http.ResponseWriter, r *http.Request) {
	if s.verificationUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	run, err := s.Verifier.GetRun(id)
	if err != nil {
		writeVerifyError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// handleVerificationEvidence answers GET /api/verifications/{id}/evidence: the
// immutable, already-redacted objects one run produced.
func (s *Server) handleVerificationEvidence(w http.ResponseWriter, r *http.Request) {
	if s.verificationUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	if _, err := s.Verifier.GetRun(id); err != nil {
		writeVerifyError(w, err, id)
		return
	}
	limit, offset, err := verificationPage(r.URL.Query().Get("limit"), r.URL.Query().Get("offset"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	kinds, err := parseEvidenceKinds(r.URL.Query().Get("kind"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	items, total, err := s.Verifier.ListEvidence(verify.EvidenceQuery{
		VerificationRunID: id,
		Kinds:             kinds,
		Limit:             limit,
		Offset:            offset,
	})
	if err != nil {
		writeVerifyError(w, err, id)
		return
	}
	if items == nil {
		items = []verify.Evidence{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"verification_id": id, "evidence": items, "total": total})
}

// --- findings ---------------------------------------------------------------

// handleListFindings answers GET /api/findings.
func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	if s.verificationUnavailable(w) {
		return
	}
	q := r.URL.Query()
	statuses, err := parseFindingStatuses(q.Get("status"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	conclusive, err := parseBool(q.Get("conclusive"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", fmt.Errorf("conclusive: %w", err))
		return
	}
	candidates, err := parseBool(q.Get("candidates"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", fmt.Errorf("candidates: %w", err))
		return
	}
	if conclusive && candidates {
		writeError(w, http.StatusBadRequest, "invalid_request",
			errors.New("conclusive=true and candidates=true select disjoint sets; ask for one of them"))
		return
	}
	limit, offset, err := verificationPage(q.Get("limit"), q.Get("offset"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	findings, total, err := s.Verifier.ListFindings(verify.FindingQuery{
		AuditID:        strings.TrimSpace(q.Get("audit_id")),
		SnapshotID:     strings.TrimSpace(q.Get("snapshot_id")),
		PathID:         strings.TrimSpace(q.Get("path_id")),
		Status:         statuses,
		ConclusiveOnly: conclusive,
		CandidatesOnly: candidates,
		Limit:          limit,
		Offset:         offset,
	})
	if err != nil {
		writeVerifyError(w, err, "")
		return
	}
	if findings == nil {
		findings = []verify.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings, "total": total})
}

// findingEvidence groups one finding's referenced evidence into the three lists
// the finding keeps apart. The lists stay apart because a contradiction is the
// interesting part and "we could not tell" is not "we disproved it".
type findingEvidence struct {
	Supporting    []verify.Evidence `json:"supporting"`
	Contradicting []verify.Evidence `json:"contradicting"`
	Inconclusive  []verify.Evidence `json:"inconclusive"`
}

// findingDetail is the answer of GET /api/findings/{id}.
type findingDetail struct {
	Finding       verify.Finding  `json:"finding"`
	Evidence      findingEvidence `json:"evidence"`
	Verifications []verify.Run    `json:"verifications"`
}

// handleGetFinding answers GET /api/findings/{id} with the finding, its evidence
// grouped by what it does to the claim, and every verification run recorded for it.
func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	if s.verificationUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	finding, err := s.Verifier.GetFinding(id)
	if err != nil {
		writeVerifyError(w, err, id)
		return
	}
	grouped, err := s.groupFindingEvidence(finding)
	if err != nil {
		writeVerifyError(w, err, id)
		return
	}
	runs, _, err := s.Verifier.ListRuns(verify.RunQuery{FindingID: id, Limit: maxVerificationPageSize})
	if err != nil {
		writeVerifyError(w, err, id)
		return
	}
	if runs == nil {
		runs = []verify.Run{}
	}
	writeJSON(w, http.StatusOK, findingDetail{Finding: *finding, Evidence: grouped, Verifications: runs})
}

// groupFindingEvidence resolves the finding's three id lists into objects. A
// referenced object that cannot be read is reported rather than invented: it is
// dropped from the list, and the id lists on the finding remain the authority.
func (s *Server) groupFindingEvidence(finding *verify.Finding) (findingEvidence, error) {
	group := func(ids []string) ([]verify.Evidence, error) {
		out := make([]verify.Evidence, 0, len(ids))
		for _, evidenceID := range ids {
			item, err := s.Store.GetEvidence(evidenceID)
			if err != nil {
				if isVerificationNotFound(err) {
					continue
				}
				return nil, err
			}
			out = append(out, *item)
		}
		return out, nil
	}
	supporting, err := group(finding.Supporting)
	if err != nil {
		return findingEvidence{}, err
	}
	contradicting, err := group(finding.Contradicting)
	if err != nil {
		return findingEvidence{}, err
	}
	inconclusive, err := group(finding.Inconclusive)
	if err != nil {
		return findingEvidence{}, err
	}
	return findingEvidence{Supporting: supporting, Contradicting: contradicting, Inconclusive: inconclusive}, nil
}

// handleGetEvidence answers GET /api/evidence/{id}. The content returned is the
// stored content, which is already redacted: verification stores no unredacted
// bytes, so there is no unredacted form to leak.
func (s *Server) handleGetEvidence(w http.ResponseWriter, r *http.Request) {
	if s.verificationUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	item, err := s.Verifier.GetEvidence(id)
	if err != nil {
		writeVerifyError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// --- reports ----------------------------------------------------------------

// reportFormats maps a request's format onto the media type the answer carries.
var reportFormats = map[string]string{
	"md":    "text/markdown",
	"json":  "application/json",
	"sarif": "application/sarif+json",
}

// handleAuditReport answers GET /api/audits/{id}/report: render every finding of
// an audit, with its evidence, in one of the three report formats.
func (s *Server) handleAuditReport(w http.ResponseWriter, r *http.Request) {
	if s.verificationUnavailable(w) {
		return
	}
	auditID := r.PathValue("id")
	q := r.URL.Query()
	format, contentType, err := reportFormat(q.Get("format"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	includeCandidates, err := parseBool(q.Get("include_candidates"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", fmt.Errorf("include_candidates: %w", err))
		return
	}
	// An unknown audit is a 404, not an empty report: an empty report and a typo
	// would otherwise read the same.
	if s.Audit != nil {
		if _, err := s.Audit.Audit(auditID); err != nil {
			writeAuditError(w, err, auditID)
			return
		}
	}
	findings, _, err := s.Verifier.ListFindings(verify.FindingQuery{
		AuditID: auditID,
		Limit:   maxFindingsPerReport,
	})
	if err != nil {
		writeVerifyError(w, err, auditID)
		return
	}
	// Every finding's evidence is resolved, including a candidate's: RenderReport
	// decides which findings the report shows, and a candidate it drops must not
	// leave its evidence dangling in the map.
	evidence := map[string][]verify.Evidence{}
	snapshotID := ""
	for _, finding := range findings {
		grouped, err := s.groupFindingEvidence(&finding)
		if err != nil {
			writeVerifyError(w, err, finding.ID)
			return
		}
		evidence[finding.ID] = append(append(append(
			[]verify.Evidence{}, grouped.Supporting...), grouped.Contradicting...), grouped.Inconclusive...)
		if snapshotID == "" {
			snapshotID = finding.SnapshotID
		} else if finding.SnapshotID != snapshotID {
			// A report over one audit may still span snapshots; naming one would be
			// a lie, so the field stays empty.
			snapshotID = ""
		}
	}
	opts := verify.ReportOptions{
		Format: format, AuditID: auditID, SnapshotID: snapshotID,
		IncludeCandidates: includeCandidates,
		MaxFindings:       maxFindingsPerReport,
	}
	// RenderReport restates the caveats; a report that hid them would undo the
	// package.
	body, err := verify.RenderReport(findings, evidence, opts)
	if err != nil {
		writeVerifyError(w, err, auditID)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// reportFormat validates the format parameter and returns the canonical format and
// its media type. "markdown" is accepted as a spelling of "md"; anything else is a
// 400 rather than a silently rendered Markdown report.
func reportFormat(raw string) (string, string, error) {
	format := strings.ToLower(strings.TrimSpace(raw))
	if format == "" {
		format = "md"
	}
	if format == "markdown" {
		format = "md"
	}
	contentType, ok := reportFormats[format]
	if !ok {
		return "", "", fmt.Errorf("unknown report format %q; valid formats are %s",
			raw, strings.Join(reportFormatNames(), ", "))
	}
	return format, contentType, nil
}

// --- helpers ----------------------------------------------------------------

// writeVerifyError maps the verification layer's sentinels onto the API's
// vocabulary. The codes stay distinct on purpose: a missing approval is an
// operator gate (409 approval_required), a denied scope is an authorization
// decision (409 scope_denied), and an invalid plan is a builder or client bug
// (400 invalid_request).
func writeVerifyError(w http.ResponseWriter, err error, id string) {
	switch {
	case err == nil:
		return
	case errors.Is(err, verify.ErrNotFound), errors.Is(err, agent.ErrNotFound), errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err)
	case errors.Is(err, verify.ErrApprovalRequired):
		writeError(w, http.StatusConflict, "approval_required", err)
	case errors.Is(err, verify.ErrScopeDenied):
		writeError(w, http.StatusConflict, "scope_denied", err)
	case errors.Is(err, verify.ErrInvalidPlan), errors.Is(err, verify.ErrInvalidResult), errors.Is(err, verify.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, "invalid_request", err)
	case errors.Is(err, verify.ErrConflict):
		writeError(w, http.StatusConflict, "version_conflict", err)
	case errors.Is(err, verify.ErrUnsupportedStep):
		writeError(w, http.StatusConflict, "unsupported_step", err)
	default:
		writeAuditError(w, err, id)
	}
}

// isVerificationNotFound reports whether an error means a verification record is
// absent.
func isVerificationNotFound(err error) bool {
	return errors.Is(err, verify.ErrNotFound) || errors.Is(err, storage.ErrNotFound)
}

// verificationPage parses a limit and an offset, refusing a bad value instead of
// falling back to a default the way the graph handlers do: on a paginated list a
// silent fallback answers a different question than the one asked.
func verificationPage(limitRaw, offsetRaw string) (int, int, error) {
	limit, err := verificationLimit(limitRaw)
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

// verificationLimit bounds a page size on the verification surface.
func verificationLimit(raw string) (int, error) {
	limit, err := agentQueryInt(raw, defaultVerificationPageSize)
	if err != nil {
		return 0, err
	}
	if limit <= 0 {
		return defaultVerificationPageSize, nil
	}
	if limit > maxVerificationPageSize {
		return maxVerificationPageSize, nil
	}
	return limit, nil
}

// parseVerificationStatuses validates the run status filter.
func parseVerificationStatuses(value string) ([]verify.VerificationStatus, error) {
	parts := commaList(value)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]verify.VerificationStatus, 0, len(parts))
	for _, part := range parts {
		status := verify.VerificationStatus(part)
		if !verify.ValidVerificationStatus(status) {
			return nil, fmt.Errorf("unknown verification status %q; valid statuses are %s",
				part, strings.Join(verificationStatusNames(), ", "))
		}
		out = append(out, status)
	}
	return out, nil
}

// parseOutcomes validates the outcome filter.
func parseOutcomes(value string) ([]verify.Outcome, error) {
	parts := commaList(value)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]verify.Outcome, 0, len(parts))
	for _, part := range parts {
		outcome := verify.Outcome(part)
		if !verify.ValidOutcome(outcome) {
			return nil, fmt.Errorf("unknown outcome %q; valid outcomes are %s",
				part, strings.Join(outcomeNames(), ", "))
		}
		out = append(out, outcome)
	}
	return out, nil
}

// parseFindingStatuses validates the finding status filter.
func parseFindingStatuses(value string) ([]verify.FindingStatus, error) {
	parts := commaList(value)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]verify.FindingStatus, 0, len(parts))
	for _, part := range parts {
		status := verify.FindingStatus(part)
		if !verify.ValidFindingStatus(status) {
			return nil, fmt.Errorf("unknown finding status %q; valid statuses are %s",
				part, strings.Join(findingStatusNames(), ", "))
		}
		out = append(out, status)
	}
	return out, nil
}

// parseEvidenceKinds reads a comma-separated kind filter. An unknown kind is
// refused rather than dropped, because a silently dropped filter would answer a
// broader question than the one asked.
func parseEvidenceKinds(value string) ([]verify.EvidenceKind, error) {
	parts := commaList(value)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]verify.EvidenceKind, 0, len(parts))
	for _, part := range parts {
		kind := verify.EvidenceKind(part)
		if !verify.ValidEvidenceKind(kind) {
			return nil, fmt.Errorf("unknown evidence kind %q; valid kinds are %s",
				part, strings.Join(evidenceKindNames(), ", "))
		}
		out = append(out, kind)
	}
	return out, nil
}

func evidenceKindNames() []string {
	kinds := verify.AllEvidenceKinds()
	out := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, string(kind))
	}
	return out
}

func verificationStatusNames() []string {
	statuses := verify.AllVerificationStatuses()
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}

func outcomeNames() []string {
	return []string{
		string(verify.OutcomeConfirmed), string(verify.OutcomeRefuted),
		string(verify.OutcomeInconclusive), string(verify.OutcomeBlocked),
	}
}

func findingStatusNames() []string {
	statuses := verify.AllFindingStatuses()
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}

func reportFormatNames() []string {
	return []string{"md", "json", "sarif"}
}
