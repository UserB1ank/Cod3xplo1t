package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

func (s *Server) handleSupervisorBudget(w http.ResponseWriter, r *http.Request) {
	if !s.supervisorAvailable(w) {
		return
	}
	sessionID := r.PathValue("sessionID")
	budget, grants, err := s.Supervisor.Budget(r.Context(), r.PathValue("projectID"), sessionID)
	if err != nil {
		writeSupervisorError(w, err)
		return
	}
	if grants == nil {
		grants = []agent.BudgetGrant{}
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(budget.Version, 10)+`"`)
	writeJSON(w, http.StatusOK, map[string]any{
		"api_version": "codexploit/v1", "session_id": sessionID,
		"budget": budget, "grants": grants,
	})
}

func (s *Server) handleSupervisorBudgetGrant(w http.ResponseWriter, r *http.Request) {
	if !s.supervisorAvailable(w) {
		return
	}
	var req struct {
		Tokens          int    `json:"tokens"`
		Reason          string `json:"reason"`
		Decision        string `json:"decision"`
		ExpectedVersion int64  `json:"expected_version"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err)
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("a budget decision needs a reason"))
		return
	}
	if req.ExpectedVersion <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("expected_version is required"))
		return
	}
	if req.Decision == "" {
		req.Decision = agent.GrantApproved
	}
	principal, _ := PrincipalFrom(r.Context())
	now := time.Now().UTC().Format(time.RFC3339)
	grant := agent.BudgetGrant{
		ID: fmt.Sprintf("grant-%d", time.Now().UnixNano()), RunID: r.URL.Query().Get("run_id"),
		Tokens: req.Tokens, Reason: req.Reason, RequestedBy: principal.Name,
		Decision: req.Decision, DecidedBy: principal.Name, CreatedAt: now, DecidedAt: now,
	}
	budget, stored, err := s.Supervisor.GrantBudget(
		r.Context(), r.PathValue("projectID"), r.PathValue("sessionID"), grant, req.ExpectedVersion,
	)
	if err != nil {
		switch {
		case errors.Is(err, agent.ErrConflict):
			writeError(w, http.StatusPreconditionFailed, "version_conflict", err)
		case errors.Is(err, agent.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, "invalid_request", err)
		default:
			writeSupervisorError(w, err)
		}
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(budget.Version, 10)+`"`)
	_, grants, _ := s.Supervisor.Budget(r.Context(), r.PathValue("projectID"), r.PathValue("sessionID"))
	if grants == nil {
		grants = []agent.BudgetGrant{}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"api_version": "codexploit/v1", "session_id": r.PathValue("sessionID"),
		"budget": budget, "grants": grants, "grant": stored,
	})
}
