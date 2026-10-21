package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
	"github.com/open-mcp-ai/Codexploit/internal/verify/container"
)

// ContainerVerification is the real backend that executes an approved v2 plan.
// Source resolves the frozen snapshot to a read-only host directory; it is a
// callback so the API does not grow a second snapshot store.
type ContainerVerification struct {
	Provider verify.EnvironmentProvider
	Leases   verify.EnvironmentLeaseStore
	Owner    string
	Source   func(ctx context.Context, projectID, snapshotID string) (verify.EnvironmentSource, error)
}

// WithContainerVerification enables POST .../verification-plans/{planID}/execute.
// Without it the endpoint answers 501 rather than pretending an environment exists.
func WithContainerVerification(config *ContainerVerification) Option {
	return func(s *Server) { s.containerVerification = config }
}

func (s *Server) executeUnavailable(w http.ResponseWriter) bool {
	if s.Verifier == nil || s.containerVerification == nil || s.containerVerification.Source == nil {
		writeError(w, http.StatusNotImplemented, "container_verification_unavailable",
			errors.New("this server was started without a container verification backend; start it with --verify-executor container"))
		return true
	}
	return false
}

type executePlanRequest struct {
	// Attempt distinguishes a new run after a lost or blocked attempt. The default
	// is 1; a retry must say 2, 3, ... so it cannot replay the earlier verdict.
	Attempt int `json:"attempt"`
}

func (s *Server) handleExecuteVerificationPlan(w http.ResponseWriter, r *http.Request) {
	if s.executeUnavailable(w) {
		return
	}
	repo, ok := s.planRepository()
	if !ok {
		writeError(w, http.StatusNotImplemented, "plans_unavailable", errors.New("the verification plan store is unavailable"))
		return
	}
	projectID, planID := r.PathValue("id"), r.PathValue("planID")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	record, err := repo.GetPlan(r.Context(), projectID, planID)
	if err != nil {
		writePlanError(w, err)
		return
	}
	if record.State != verify.PlanApproved || record.Approval == nil {
		writePlanError(w, verify.ErrPlanNotApproved)
		return
	}
	if err := verify.ValidateExecutionPlan(record.Plan); err != nil {
		writePlanError(w, err)
		return
	}
	if err := verify.ValidateApproval(record.Plan, *record.Approval, time.Now().UTC()); err != nil {
		writePlanError(w, err)
		return
	}
	var body executePlanRequest
	if !s.decode(w, r, &body) {
		return
	}
	attempt := body.Attempt
	if attempt <= 0 {
		attempt = 1
	}
	if attempt > 20 {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("attempt must be between 1 and 20"))
		return
	}
	source, err := s.containerVerification.Source(r.Context(), projectID, record.Plan.SnapshotID)
	if err != nil {
		writeError(w, http.StatusConflict, "environment_source_unavailable", err)
		return
	}
	source.SnapshotID = record.Plan.SnapshotID
	source.ReadOnly = true

	owner := strings.TrimSpace(s.containerVerification.Owner)
	if principal, ok := PrincipalFrom(r.Context()); ok && strings.TrimSpace(principal.Name) != "" {
		if owner != "" {
			owner += "/"
		}
		owner += principal.Name
	}
	executor, err := container.NewExecutor(s.containerVerification.Provider, container.ExecutorConfig{
		Plan: record.Plan, Approval: *record.Approval, Source: source,
		Leases: s.containerVerification.Leases, Owner: owner,
	})
	if err != nil {
		writeError(w, http.StatusConflict, "container_verification_unavailable", err)
		return
	}
	run, err := s.Verifier.VerifyWith(r.Context(), verify.VerifyRequest{
		Plan: verify.LegacyPlanAttempt(record.Plan, attempt), Approved: true,
		ApprovedBy: record.Approval.Actor, Owner: owner,
	}, executor)
	if err != nil {
		writeVerifyError(w, err, record.Plan.HypothesisID)
		return
	}
	lease, leaseErr := s.containerVerification.Leases.GetEnvironmentLease(r.Context(), record.Plan.ID)
	response := map[string]any{"run": run, "attempt": attempt}
	if leaseErr == nil {
		response["environment"] = lease
	}
	writeJSON(w, http.StatusOK, response)
}
