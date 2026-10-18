package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/knowledge"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
	"github.com/open-mcp-ai/Codexploit/internal/reporting"
)

var reportRuntimeSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	load := func(name string) (*jsonschema.Schema, error) {
		raw, err := contracts.Files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var schema jsonschema.Schema
		if err := json.Unmarshal(raw, &schema); err != nil {
			return nil, err
		}
		return &schema, nil
	}
	schema, err := load("report-runtime.schema.json")
	if err != nil {
		return nil, err
	}
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
		if uri.Scheme != "https" || uri.Host != "codexploit.invalid" || path.Dir(uri.Path) != "/contracts/v1" {
			return nil, plugin.ErrInvalid
		}
		return load(path.Base(uri.Path))
	}})
})

func writeReportJSON(w http.ResponseWriter, status int, document any) {
	schema, err := reportRuntimeSchema()
	if err != nil {
		writeError(w, 500, "contract_unavailable", err)
		return
	}
	raw, err := json.Marshal(document)
	var value any
	if err != nil || json.Unmarshal(raw, &value) != nil || schema.Validate(value) != nil {
		writeError(w, 500, "contract_violation", errors.New("report response does not satisfy the public contract"))
		return
	}
	writeJSON(w, status, document)
}

func (s *Server) reportService(w http.ResponseWriter) *reporting.Service {
	store, ok := s.Store.(reporting.Store)
	if !ok || s.Plugins == nil || s.Knowledge == nil || s.Artifacts == nil {
		writeError(w, 501, "reports_unavailable", errors.New("report services are unavailable"))
		return nil
	}
	return &reporting.Service{Store: store, Knowledge: s.Knowledge, Artifacts: s.Artifacts, Host: s.Plugins}
}

func writeReportError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, reporting.ErrMissingEvidence):
		writeError(w, 409, "report_evidence_missing", err)
	case errors.Is(err, reporting.ErrChanged):
		writeError(w, 409, "report_input_changed", err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, 408, "report_interrupted", errors.New("report capture interrupted"))
	case errors.Is(err, knowledge.ErrViewSuperseded), errors.Is(err, knowledge.ErrNotFound), errors.Is(err, knowledge.ErrInvalid):
		writeKnowledgeError(w, err)
	case errors.Is(err, publication.ErrNotFound):
		writePublicationError(w, err)
	case errors.Is(err, artifact.ErrBudget):
		writeError(w, 413, "report_budget", plugin.ErrBudget)
	default:
		writePluginError(w, err)
	}
}

func (s *Server) handleCreateReport(w http.ResponseWriter, r *http.Request) {
	service := s.reportService(w)
	if service == nil {
		return
	}
	var request reporting.Request
	if !s.decode(w, r, &request) {
		return
	}
	inv, err := service.Create(r.Context(), r.PathValue("projectID"), request)
	if err != nil {
		writeReportError(w, err)
		return
	}
	w.Header().Set("ETag", invocationETag(inv))
	writeReportJSON(w, 202, map[string]any{"api_version": "codexploit/v1", "report": inv})
}

func (s *Server) reportScope(w http.ResponseWriter, r *http.Request) (artifact.Scope, bool) {
	service := s.reportService(w)
	if service == nil {
		return artifact.Scope{}, false
	}
	snapshotID := r.URL.Query().Get("snapshot_id")
	if snapshotID == "" {
		writePluginError(w, plugin.ErrInvalid)
		return artifact.Scope{}, false
	}
	scope, err := service.Store.ArtifactScope(r.Context(), r.PathValue("projectID"), snapshotID)
	if err != nil {
		writePluginError(w, plugin.ErrNotFound)
		return artifact.Scope{}, false
	}
	return scope, true
}

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.reportScope(w, r)
	if !ok {
		return
	}
	inv, err := s.Plugins.GetStatus(r.Context(), scope, r.PathValue("reportID"))
	if err != nil {
		writeReportError(w, err)
		return
	}
	if inv.Request.PluginID != reporting.PluginID {
		writePluginError(w, plugin.ErrNotFound)
		return
	}
	w.Header().Set("ETag", invocationETag(inv))
	writeReportJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "report": inv})
}

func (s *Server) handleListReports(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.reportScope(w, r)
	if !ok {
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writePluginError(w, plugin.ErrInvalid)
			return
		}
		limit = n
	}
	items, err := s.Plugins.List(r.Context(), scope, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeReportError(w, err)
		return
	}
	result := []plugin.Invocation{}
	for _, inv := range items {
		if inv.Request.PluginID != reporting.PluginID {
			continue
		}
		var config reporting.Settings
		if json.Unmarshal(inv.Request.Config, &config) != nil {
			writePluginError(w, plugin.ErrInvalid)
			return
		}
		if task := r.URL.Query().Get("task_id"); task != "" && task != config.TaskID {
			continue
		}
		result = append(result, inv)
	}
	next := ""
	if len(items) == limit {
		next = items[len(items)-1].ID
	}
	writeReportJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "reports": result, "next_cursor": next})
}
