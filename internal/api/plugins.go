package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func writePluginError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, artifact.ErrIntegrity), errors.Is(err, artifact.ErrNotFound), errors.Is(err, artifact.ErrInvalid):
		writeArtifactError(w, err)
	case errors.Is(err, plugin.ErrInvalid):
		writeError(w, 400, "invalid_request", plugin.ErrInvalid)
	case errors.Is(err, plugin.ErrConflict):
		writeError(w, 409, "plugin_conflict", plugin.ErrConflict)
	case errors.Is(err, plugin.ErrNotFound):
		writeError(w, 404, "plugin_not_found", plugin.ErrNotFound)
	case errors.Is(err, plugin.ErrUnsupported):
		writeError(w, 409, "plugin_unsupported", plugin.ErrUnsupported)
	case errors.Is(err, plugin.ErrBudget):
		writeError(w, 413, "plugin_budget", plugin.ErrBudget)
	default:
		writeError(w, 503, "plugins_unavailable", errors.New("plugin service is unavailable"))
	}
}

func (s *Server) handleRegisterPlugin(w http.ResponseWriter, r *http.Request) {
	if s.PluginCatalog == nil {
		writeError(w, 501, "plugins_unavailable", errors.New("plugin catalog is unavailable"))
		return
	}
	var request struct {
		APIVersion    string          `json:"api_version"`
		Manifest      json.RawMessage `json:"manifest"`
		PackageDigest string          `json:"package_digest"`
		Source        string          `json:"source"`
	}
	if !s.decode(w, r, &request) {
		return
	}
	if request.APIVersion != "codexploit/v1" {
		writePluginError(w, plugin.ErrInvalid)
		return
	}
	record, err := s.PluginCatalog.Register(r.Context(), request.Manifest, request.PackageDigest, request.Source)
	if err != nil {
		writePluginError(w, err)
		return
	}
	writePluginJSON(w, 201, map[string]any{"api_version": "codexploit/v1", "plugin": record})
}

func WithPluginCatalog(c *plugin.Catalog) Option { return func(s *Server) { s.PluginCatalog = c } }

func (s *Server) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	if s.PluginCatalog == nil {
		writeError(w, 501, "plugins_unavailable", errors.New("plugin catalog is unavailable"))
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writeError(w, 400, "invalid_request", plugin.ErrInvalid)
			return
		}
		limit = n
	}
	rows, err := s.PluginCatalog.List(r.Context(), r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeError(w, 503, "plugins_unavailable", errors.New("plugin catalog is unavailable"))
		return
	}
	next := ""
	if len(rows) == limit {
		last := rows[len(rows)-1].Manifest
		next = last.ID + "@" + last.Version
	}
	writePluginJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "plugins": rows, "next_cursor": next})
}
