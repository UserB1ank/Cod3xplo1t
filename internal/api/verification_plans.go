package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func (s *Server) planRepository() (verify.PlanRepository, bool) {
	repo, ok := s.Store.(verify.PlanRepository)
	return repo, ok
}

func newPlanID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "plan-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return "plan-" + hex.EncodeToString(raw)
}

func writePlanError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, verify.ErrPlanInvalid):
		writeError(w, http.StatusBadRequest, "invalid_plan", err)
	case errors.Is(err, verify.ErrPlanNotFound):
		writeError(w, http.StatusNotFound, "plan_not_found", err)
	case errors.Is(err, verify.ErrPlanConflict):
		writeError(w, http.StatusPreconditionFailed, "plan_conflict", err)
	case errors.Is(err, verify.ErrPlanStale):
		writeError(w, http.StatusConflict, "plan_stale", err)
	case errors.Is(err, verify.ErrPlanExpired):
		writeError(w, http.StatusConflict, "plan_approval_expired", err)
	case errors.Is(err, verify.ErrPlanExpanded):
		writeError(w, http.StatusForbidden, "plan_permissions_expanded", err)
	case errors.Is(err, verify.ErrPlanNotApproved):
		writeError(w, http.StatusConflict, "plan_not_approved", err)
	default:
		writeStorageError(w, err)
	}
}

func (s *Server) handleCreateVerificationPlan(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.planRepository()
	if !ok {
		writeError(w, http.StatusNotImplemented, "plans_unavailable", errors.New("the verification plan store is unavailable"))
		return
	}
	projectID := r.PathValue("id")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 512<<10))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	plan, err := verify.DecodeExecutionPlan(raw)
	if err != nil {
		writePlanError(w, err)
		return
	}
	plan.ID, plan.ProjectID = newPlanID(), projectID
	plan.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	plan.Digest = plan.DigestOf()
	if err := verify.ValidateExecutionPlan(plan); err != nil {
		writePlanError(w, err)
		return
	}
	record, err := verify.NewPlanRecord(plan, time.Now().UTC())
	if err != nil {
		writePlanError(w, err)
		return
	}
	created, err := repo.PutPlan(r.Context(), record, 0)
	if err != nil {
		writePlanError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(created.Version, 10)+`"`)
	writeJSON(w, http.StatusCreated, map[string]any{"plan": created})
}

func (s *Server) handleListVerificationPlans(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.planRepository()
	if !ok {
		writeError(w, http.StatusNotImplemented, "plans_unavailable", errors.New("the verification plan store is unavailable"))
		return
	}
	projectID := r.PathValue("id")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	limit, offset := pageLimit(r.URL.Query().Get("limit")), 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", errors.New("invalid offset"))
			return
		}
		offset = parsed
	}
	rows, total, err := repo.ListPlans(r.Context(), projectID, strings.TrimSpace(r.URL.Query().Get("state")), limit, offset)
	if err != nil {
		writePlanError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plans": rows, "total": total})
}

func (s *Server) handleGetVerificationPlan(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.planRepository()
	if !ok {
		writeError(w, http.StatusNotImplemented, "plans_unavailable", errors.New("the verification plan store is unavailable"))
		return
	}
	record, err := repo.GetPlan(r.Context(), r.PathValue("id"), r.PathValue("planID"))
	if err != nil {
		writePlanError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(record.Version, 10)+`"`)
	writeJSON(w, http.StatusOK, map[string]any{"plan": record})
}

func (s *Server) handleDecideVerificationPlan(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.planRepository()
	if !ok {
		writeError(w, http.StatusNotImplemented, "plans_unavailable", errors.New("the verification plan store is unavailable"))
		return
	}
	version, err := strconv.ParseInt(strings.Trim(r.Header.Get("If-Match"), `"`), 10, 64)
	if err != nil || version <= 0 {
		writeError(w, http.StatusPreconditionRequired, "version_required", errors.New("read the current plan version first"))
		return
	}
	var body struct {
		Decision    verify.PlanState `json:"decision"`
		Permissions []string         `json:"permissions"`
		Reason      string           `json:"reason"`
		ExpiresAt   string           `json:"expires_at"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	record, err := repo.GetPlan(r.Context(), r.PathValue("id"), r.PathValue("planID"))
	if err != nil {
		writePlanError(w, err)
		return
	}
	if record.Version != version {
		writeError(w, http.StatusPreconditionFailed, "plan_conflict", verify.ErrPlanConflict)
		return
	}
	principal, _ := PrincipalFrom(r.Context())
	approval := verify.PlanApproval{
		PlanID: record.Plan.ID, PlanDigest: record.Plan.DigestOf(), Decision: body.Decision,
		Actor: principal.Name, ActorRole: roleName(principal.Capabilities), Permissions: body.Permissions,
		Reason: body.Reason, DecidedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: body.ExpiresAt,
	}
	approval.Digest = approval.DigestOf()
	_, state, err := verify.ApplyApproval(record.Plan, approval, time.Now().UTC())
	if err != nil {
		writePlanError(w, err)
		return
	}
	record.State = state
	record.Approval = &approval
	updated, err := repo.PutPlan(r.Context(), record, version)
	if err != nil {
		writePlanError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(updated.Version, 10)+`"`)
	writeJSON(w, http.StatusOK, map[string]any{"plan": updated})
}

func roleName(capabilities Capability) string {
	switch {
	case capabilities&CapAdmin != 0:
		return "admin"
	case capabilities&CapWrite != 0:
		return "writer"
	default:
		return "reader"
	}
}
