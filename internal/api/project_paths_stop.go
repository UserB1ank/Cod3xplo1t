package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/lifecycle"
)

var projectPathStopSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	raw, err := contracts.Files.ReadFile("project-path-stop.schema.json")
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return schema.Resolve(nil)
})

func writePathStopResult(w http.ResponseWriter, result lifecycle.PathStopResult) {
	schema, err := projectPathStopSchema()
	raw, marshalErr := json.Marshal(result)
	var value any
	if err != nil || marshalErr != nil || json.Unmarshal(raw, &value) != nil || schema.Validate(value) != nil {
		writeError(w, 500, "contract_violation", errors.New("path stop result does not satisfy its public contract"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) projectPathControls() lifecycle.ProjectPaths {
	control := lifecycle.ProjectPaths{Store: s.Store, Paths: s.Audit}
	if s.Agent != nil {
		control.CancelLocalPath = s.Agent.CancelPath
	}
	if s.WorkflowRunner != nil {
		control.CancelWorkflow = func(ctx context.Context, projectID, runID string) error {
			_, err := s.WorkflowRunner.Cancel(ctx, projectID, runID)
			return err
		}
	}
	return control
}
func (s *Server) handleStopProjectPaths(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	var body struct{}
	if !s.decode(w, r, &body) {
		return
	}
	result, err := s.projectPathControls().Stop(r.Context(), r.PathValue("projectID"), principalName(r))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if err := s.syncProjectAnalysisControl(r.Context(), r.PathValue("projectID")); err != nil {
		writeStorageError(w, err)
		return
	}
	writePathStopResult(w, result)
}
func (s *Server) handleProjectPathStopStatus(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	if err := s.syncProjectAnalysisControl(r.Context(), r.PathValue("projectID")); err != nil {
		writeStorageError(w, err)
		return
	}
	result, err := s.projectPathControls().Status(r.Context(), r.PathValue("projectID"))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writePathStopResult(w, result)
}

func (s *Server) syncProjectAnalysisControl(ctx context.Context, projectID string) error {
	run, active, err := s.Store.ActiveAnalysisRun(ctx, projectID)
	if err != nil || !active {
		return err
	}
	_, err = s.syncAnalysisRun(ctx, run)
	return err
}
