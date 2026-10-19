package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	audit "github.com/open-mcp-ai/Codexploit/internal/path"
)

// projectAudit resolves the audit in the path and proves it belongs to the
// project's snapshots.
func (s *Server) projectAudit(w http.ResponseWriter, r *http.Request) (*audit.Audit, bool) {
	if s.auditUnavailable(w) {
		return nil, false
	}
	if _, err := s.Store.GetProject(r.Context(), r.PathValue("projectID")); err != nil {
		writeStorageError(w, err)
		return nil, false
	}
	task, err := s.Audit.Audit(r.PathValue("taskID"))
	if err != nil {
		writeAuditError(w, err, "")
		return nil, false
	}
	snapshots, err := s.Store.ListSnapshots(r.Context(), r.PathValue("projectID"))
	if err != nil {
		writeStorageError(w, err)
		return nil, false
	}
	for _, snapshot := range snapshots {
		if snapshot.SnapshotID == task.SnapshotID {
			return task, true
		}
	}
	writeError(w, http.StatusNotFound, "not_found", errors.New("task does not belong to this project"))
	return nil, false
}

// handleTaskBudget answers GET /api/v1/projects/{projectID}/tasks/{taskID}/budget.
func (s *Server) handleTaskBudget(w http.ResponseWriter, r *http.Request) {
	task, ok := s.projectAudit(w, r)
	if !ok || s.agentUnavailable(w) {
		return
	}
	budget, err := s.Agent.Store.GetAuditBudget(task.ID)
	if err != nil {
		writeAgentError(w, err, task.ID)
		return
	}
	grants, err := s.Agent.Store.ListBudgetGrants(task.ID)
	if err != nil {
		writeAgentError(w, err, task.ID)
		return
	}
	if grants == nil {
		grants = []agent.BudgetGrant{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "budget": budget, "grants": grants})
}

// handleGrantBudget answers POST .../budget/grants. Only a writer may add tokens,
// the reason is required, and the ledger version is the CAS that rejects a stale
// approval.
func (s *Server) handleGrantBudget(w http.ResponseWriter, r *http.Request) {
	task, ok := s.projectAudit(w, r)
	if !ok || s.agentUnavailable(w) {
		return
	}
	var request struct {
		Tokens          int    `json:"tokens"`
		Reason          string `json:"reason"`
		Decision        string `json:"decision"`
		ExpectedVersion int64  `json:"expected_version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err)
		return
	}
	if strings.TrimSpace(request.Reason) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("a grant needs a reason"))
		return
	}
	principal, _ := PrincipalFrom(r.Context())
	now := time.Now().UTC().Format(time.RFC3339)
	grant := agent.BudgetGrant{
		ID: fmt.Sprintf("grant-%d", time.Now().UnixNano()), AuditID: task.ID,
		Tokens: request.Tokens, Reason: strings.TrimSpace(request.Reason),
		RequestedBy: principal.Name, Decision: request.Decision, DecidedBy: principal.Name,
		CreatedAt: now, DecidedAt: now,
	}
	if grant.Decision == "" {
		grant.Decision = agent.GrantApproved
	}
	budget, err := s.Agent.Store.GrantAuditTokens(grant, request.ExpectedVersion)
	if err != nil {
		switch {
		case errors.Is(err, agent.ErrConflict):
			writeError(w, http.StatusPreconditionFailed, "version_conflict", err)
		case errors.Is(err, agent.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, "invalid_request", err)
		default:
			writeAgentError(w, err, task.ID)
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"api_version": "codexploit/v1", "budget": budget, "grant": grant})
}
