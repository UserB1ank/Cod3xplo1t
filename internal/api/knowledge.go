package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"

	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/knowledge"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// knowledgeViewSchema validates the open-view response against the public
// contract, so a field added here cannot drift from the published schema.
var knowledgeViewSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	raw, err := contracts.Files.ReadFile("view.schema.json")
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return schema.Resolve(nil)
})

func writeKnowledgeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, knowledge.ErrNotFound):
		writeError(w, http.StatusNotFound, "knowledge_not_found", knowledge.ErrNotFound)
	case errors.Is(err, knowledge.ErrNoGraph):
		writeError(w, http.StatusConflict, "knowledge_unavailable", knowledge.ErrNoGraph)
	case errors.Is(err, knowledge.ErrLayerUnavailable):
		writeError(w, http.StatusConflict, "layer_unavailable", knowledge.ErrLayerUnavailable)
	case errors.Is(err, knowledge.ErrViewSuperseded):
		writeError(w, http.StatusConflict, "view_superseded", knowledge.ErrViewSuperseded)
	case errors.Is(err, knowledge.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_request", knowledge.ErrInvalid)
	default:
		writeError(w, http.StatusServiceUnavailable, "knowledge_unavailable", errors.New("knowledge queries are unavailable"))
	}
}

func (s *Server) knowledgeReader(w http.ResponseWriter) (*knowledge.Reader, bool) {
	if s.Knowledge == nil {
		writeError(w, http.StatusNotImplemented, "knowledge_unavailable", errors.New("knowledge queries are unavailable"))
		return nil, false
	}
	return s.Knowledge, true
}

// knowledgeScope resolves the project-scoped view id to its snapshot scope.
func (s *Server) knowledgeScope(w http.ResponseWriter, r *http.Request) (knowledge.Scope, bool) {
	reader, ok := s.knowledgeReader(w)
	if !ok {
		return knowledge.Scope{}, false
	}
	scope, err := reader.ScopeOf(r.Context(), r.PathValue("projectID"), r.PathValue("viewID"))
	if err != nil {
		writeKnowledgeError(w, err)
		return knowledge.Scope{}, false
	}
	return scope, true
}

// handleOpenKnowledgeView pins one snapshot's layer versions.
func (s *Server) handleOpenKnowledgeView(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.knowledgeReader(w)
	if !ok {
		return
	}
	var request struct {
		APIVersion string   `json:"api_version"`
		SnapshotID string   `json:"snapshot_id"`
		Layers     []string `json:"layers"`
	}
	if !s.decode(w, r, &request) {
		return
	}
	if request.APIVersion != "codexploit/v1" || request.SnapshotID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("codexploit/v1 and a snapshot_id are required"))
		return
	}
	view, err := reader.OpenView(r.Context(), knowledge.Scope{ProjectID: r.PathValue("projectID"), SnapshotID: request.SnapshotID}, request.Layers)
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	document := map[string]any{"api_version": "codexploit/v1", "view": view}
	schema, err := knowledgeViewSchema()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "contract_unavailable", err)
		return
	}
	raw, err := json.Marshal(document)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	if err := schema.Validate(value); err != nil {
		writeError(w, http.StatusInternalServerError, "contract_violation", err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

// knowledgePageLimit parses an optional positive integer query parameter.
func knowledgePageLimit(w http.ResponseWriter, r *http.Request, name string, fallback int) (int, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, true
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New(name+" must be a non-negative integer"))
		return 0, false
	}
	return value, true
}

func (s *Server) handleKnowledgeSymbols(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.knowledgeReader(w)
	if !ok {
		return
	}
	scope, ok := s.knowledgeScope(w, r)
	if !ok {
		return
	}
	limit, ok := knowledgePageLimit(w, r, "limit", 50)
	if !ok {
		return
	}
	page, err := reader.Symbols(r.Context(), scope, r.PathValue("viewID"), knowledge.SymbolQuery{
		Query:  r.URL.Query().Get("q"),
		Kinds:  r.URL.Query()["kind"],
		Cursor: r.URL.Query().Get("cursor"),
		Limit:  limit,
	})
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	symbols := page.Symbols
	if symbols == nil {
		symbols = []scg.Symbol{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_version": "codexploit/v1",
		"symbols":     symbols,
		"next_cursor": page.NextCursor,
		"meta":        page.Meta,
	})
}

func (s *Server) handleKnowledgeNeighborhood(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.knowledgeReader(w)
	if !ok {
		return
	}
	scope, ok := s.knowledgeScope(w, r)
	if !ok {
		return
	}
	depth, ok := knowledgePageLimit(w, r, "depth", 0)
	if !ok {
		return
	}
	maxNodes, ok := knowledgePageLimit(w, r, "max_nodes", 0)
	if !ok {
		return
	}
	page, err := reader.Neighborhood(r.Context(), scope, r.PathValue("viewID"), knowledge.NeighborhoodQuery{
		SymbolID:  r.URL.Query().Get("symbol_id"),
		Direction: r.URL.Query().Get("direction"),
		Depth:     depth,
		MaxNodes:  maxNodes,
	})
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "neighborhood": page.Neighborhood, "meta": page.Meta})
}

func (s *Server) handleKnowledgeNodes(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.knowledgeReader(w)
	if !ok {
		return
	}
	scope, ok := s.knowledgeScope(w, r)
	if !ok {
		return
	}
	limit, ok := knowledgePageLimit(w, r, "limit", 50)
	if !ok {
		return
	}
	page, err := reader.Nodes(r.Context(), scope, r.PathValue("viewID"), knowledge.NodeQuery{
		Kinds:   r.URL.Query()["kind"],
		Subject: r.URL.Query().Get("subject"),
		Cursor:  r.URL.Query().Get("cursor"),
		Limit:   limit,
	})
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	nodes := page.Nodes
	if nodes == nil {
		nodes = []asg.Node{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "nodes": nodes, "next_cursor": page.NextCursor, "meta": page.Meta})
}

func (s *Server) handleKnowledgePaths(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.knowledgeReader(w)
	if !ok {
		return
	}
	scope, ok := s.knowledgeScope(w, r)
	if !ok {
		return
	}
	limit, ok := knowledgePageLimit(w, r, "limit", 50)
	if !ok {
		return
	}
	page, err := reader.Paths(r.Context(), scope, r.PathValue("viewID"), knowledge.PathQuery{
		AuditID:      r.URL.Query().Get("audit_id"),
		EntryNodeID:  r.URL.Query().Get("entry_node_id"),
		TargetNodeID: r.URL.Query().Get("target_node_id"),
		Cursor:       r.URL.Query().Get("cursor"),
		Limit:        limit,
	})
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	paths := page.Paths
	if paths == nil {
		paths = []path.Path{}
	}
	audits := page.Audits
	if audits == nil {
		audits = []knowledge.AuditRef{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "paths": paths, "audits": audits, "next_cursor": page.NextCursor, "meta": page.Meta})
}

func (s *Server) handleKnowledgeSlice(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.knowledgeReader(w)
	if !ok {
		return
	}
	scope, ok := s.knowledgeScope(w, r)
	if !ok {
		return
	}
	maxLines, ok := knowledgePageLimit(w, r, "max_lines", 0)
	if !ok {
		return
	}
	maxSections, ok := knowledgePageLimit(w, r, "max_sections", 0)
	if !ok {
		return
	}
	contextLines, ok := knowledgePageLimit(w, r, "context_lines", 0)
	if !ok {
		return
	}
	page, err := reader.CodeSlice(r.Context(), scope, r.PathValue("viewID"), knowledge.SliceQuery{
		SymbolID:     r.URL.Query().Get("symbol_id"),
		MaxLines:     maxLines,
		MaxSections:  maxSections,
		ContextLines: contextLines,
	})
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "slice": page.Slice, "meta": page.Meta})
}

func (s *Server) handleKnowledgeProvenance(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.knowledgeReader(w)
	if !ok {
		return
	}
	scope, ok := s.knowledgeScope(w, r)
	if !ok {
		return
	}
	provenance, err := reader.Provenance(r.Context(), scope, r.PathValue("viewID"), r.URL.Query().Get("fact_id"))
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "provenance": provenance})
}
