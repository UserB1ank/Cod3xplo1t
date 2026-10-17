package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func WithWorkflowRunner(r *workflow.Runner) Option { return func(s *Server) { s.WorkflowRunner = r } }

// handleWorkflowControl applies one operator control to a run. Every control is
// idempotent for the state it targets, so a retried request is safe.
func (s *Server) handleWorkflowControl(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.WorkflowRunner == nil {
			writeWorkflowError(w, errors.New("unavailable"))
			return
		}
		project, id := r.PathValue("projectID"), r.PathValue("runID")
		status := http.StatusOK
		var run workflow.Run
		var err error
		switch kind {
		case "pause":
			run, err = s.WorkflowRunner.Pause(r.Context(), project, id)
		case "resume":
			run, err = s.WorkflowRunner.Resume(r.Context(), project, id)
		case "cancel":
			run, err = s.WorkflowRunner.Cancel(r.Context(), project, id)
		case "retry":
			status = http.StatusCreated
			run, err = s.WorkflowRunner.Retry(r.Context(), project, id)
		}
		if err != nil {
			writeWorkflowError(w, err)
			return
		}
		writeWorkflowRunJSON(w, status, map[string]any{"api_version": "codexploit/v1", "run": run})
	}
}
func (s *Server) handleGetWorkflowRun(w http.ResponseWriter, r *http.Request) {
	if s.WorkflowRunner == nil {
		writeWorkflowError(w, errors.New("unavailable"))
		return
	}
	run, err := s.WorkflowRunner.Get(r.Context(), r.PathValue("projectID"), r.PathValue("runID"))
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	writeWorkflowRunJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "run": run})
}
func (s *Server) handleWorkflowRunEvents(w http.ResponseWriter, r *http.Request) {
	if s.WorkflowRunner == nil {
		writeWorkflowError(w, errors.New("unavailable"))
		return
	}
	after := int64(0)
	limit := 100
	if raw := r.URL.Query().Get("after_seq"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeWorkflowError(w, workflow.ErrInvalid)
			return
		}
		after = n
	}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeWorkflowError(w, workflow.ErrInvalid)
			return
		}
		limit = n
	}
	events, err := s.WorkflowRunner.Events(r.Context(), r.PathValue("projectID"), r.PathValue("runID"), after, limit)
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	next := after
	if len(events) > 0 {
		next = events[len(events)-1].Seq
	}
	writeWorkflowRunJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "events": events, "next_seq": next})
}
