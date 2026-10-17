package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func WithWorkflowCompiler(c *workflow.Compiler) Option {
	return func(s *Server) { s.WorkflowCompiler = c }
}
func WithWorkflows(c *workflow.Catalog) Option { return func(s *Server) { s.Workflows = c } }
func writeWorkflowError(w http.ResponseWriter, err error) {
	var validation *workflow.ValidationError
	if errors.As(err, &validation) {
		writeWorkflowJSON(w, 422, map[string]any{"api_version": "codexploit/v1", "error": "Workflow compilation failed", "code": "workflow_invalid", "diagnostics": validation.Diagnostics})
		return
	}
	switch {
	case errors.Is(err, workflow.ErrInvalid):
		writeError(w, 400, "invalid_workflow", err)
	case errors.Is(err, workflow.ErrConflict):
		writeError(w, 409, "workflow_conflict", err)
	case errors.Is(err, workflow.ErrNotFound):
		writeError(w, 404, "workflow_not_found", err)
	default:
		writeError(w, 503, "workflows_unavailable", errors.New("workflow service is unavailable"))
	}
}
func (s *Server) workflowAvailable(w http.ResponseWriter) bool {
	if s.Workflows == nil {
		writeError(w, 501, "workflows_unavailable", errors.New("workflow service is unavailable"))
		return false
	}
	return true
}
func (s *Server) handleSaveWorkflow(w http.ResponseWriter, r *http.Request) {
	if !s.workflowAvailable(w) {
		return
	}
	var req struct {
		APIVersion   string          `json:"api_version"`
		Spec         json.RawMessage `json:"spec"`
		ExpectedHead string          `json:"expected_head"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.APIVersion != "codexploit/v1" {
		writeWorkflowError(w, workflow.ErrInvalid)
		return
	}
	row, err := s.Workflows.Save(r.Context(), r.PathValue("projectID"), req.Spec, req.ExpectedHead)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeWorkflowJSON(w, 201, map[string]any{"api_version": "codexploit/v1", "workflow": row})
}
func (s *Server) handleGetWorkflow(w http.ResponseWriter, r *http.Request) {
	if !s.workflowAvailable(w) {
		return
	}
	row, err := s.Workflows.Get(r.Context(), r.PathValue("projectID"), r.PathValue("workflowID"), r.PathValue("version"))
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+row.Digest+`"`)
	if strings.HasSuffix(r.URL.Path, "/export") {
		w.Header().Set("Content-Disposition", `attachment; filename="workflow.json"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		writeJSON(w, 200, row.Spec)
		return
	}
	writeWorkflowJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "workflow": row})
}

func (s *Server) handleCompileWorkflow(w http.ResponseWriter, r *http.Request) {
	if s.WorkflowCompiler == nil {
		writeWorkflowError(w, errors.New("unavailable"))
		return
	}
	var req workflow.CompileRequest
	if !s.decode(w, r, &req) {
		return
	}
	plan, err := s.WorkflowCompiler.Compile(r.Context(), r.PathValue("projectID"), r.PathValue("workflowID"), r.PathValue("version"), req)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeWorkflowJSON(w, 201, map[string]any{"api_version": "codexploit/v1", "plan": plan})
}
func (s *Server) handleGetWorkflowPlan(w http.ResponseWriter, r *http.Request) {
	if s.WorkflowCompiler == nil {
		writeWorkflowError(w, errors.New("unavailable"))
		return
	}
	plan, err := s.WorkflowCompiler.Get(r.Context(), r.PathValue("projectID"), r.PathValue("planID"))
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+plan.Digest+`"`)
	writeWorkflowJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "plan": plan})
}

func (s *Server) handleListWorkflows(w http.ResponseWriter, r *http.Request) {
	if !s.workflowAvailable(w) {
		return
	}
	limit := 50
	if value := r.URL.Query().Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			writeWorkflowError(w, workflow.ErrInvalid)
			return
		}
		limit = n
	}
	rows, err := s.Workflows.List(r.Context(), r.PathValue("projectID"), r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	next := ""
	if len(rows) == limit {
		last := rows[len(rows)-1]
		next = last.Spec.ID + "@" + last.Spec.Version
	}
	writeWorkflowJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "workflows": rows, "next_cursor": next})
}
func (s *Server) handleValidateWorkflow(w http.ResponseWriter, r *http.Request) {
	if s.WorkflowCompiler == nil {
		writeWorkflowError(w, errors.New("unavailable"))
		return
	}
	if _, err := s.Store.GetProject(r.Context(), r.PathValue("projectID")); err != nil {
		writeWorkflowError(w, workflow.ErrNotFound)
		return
	}
	var req struct {
		APIVersion string          `json:"api_version"`
		Spec       json.RawMessage `json:"spec"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.APIVersion != "codexploit/v1" {
		writeWorkflowError(w, workflow.ErrInvalid)
		return
	}
	result, err := s.WorkflowCompiler.Validate(r.Context(), req.Spec)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeWorkflowJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "valid": result.Valid, "diagnostics": result.Diagnostics, "nodes": result.Nodes})
}
