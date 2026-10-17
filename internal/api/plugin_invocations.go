package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func WithPlugins(h *plugin.Host) Option { return func(s *Server) { s.Plugins = h } }
func invocationETag(inv plugin.Invocation) string {
	return fmt.Sprintf(`"plugin-%s-v%d"`, inv.ID, inv.Version)
}
func (s *Server) invocationScope(w http.ResponseWriter, r *http.Request) (artifact.Scope, bool) {
	if s.Plugins == nil {
		writeError(w, 501, "plugins_unavailable", plugin.ErrUnsupported)
		return artifact.Scope{}, false
	}
	index, ok := s.Store.(artifact.Index)
	if !ok {
		writePluginError(w, plugin.ErrUnsupported)
		return artifact.Scope{}, false
	}
	scope, err := index.ArtifactScope(r.Context(), r.PathValue("projectID"), r.PathValue("snapshotID"))
	if err != nil {
		writePluginError(w, plugin.ErrNotFound)
		return artifact.Scope{}, false
	}
	return scope, true
}
func (s *Server) handleExecutePlugin(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.invocationScope(w, r)
	if !ok {
		return
	}
	var request plugin.Request
	if !s.decode(w, r, &request) {
		return
	}
	if request.Scope != scope {
		writePluginError(w, plugin.ErrNotFound)
		return
	}
	inv, err := s.Plugins.Execute(r.Context(), request)
	if err != nil {
		if errors.Is(err, artifact.ErrBudget) {
			writeError(w, 413, "plugin_budget", plugin.ErrBudget)
		} else {
			writePluginError(w, err)
		}
		return
	}
	w.Header().Set("ETag", invocationETag(inv))
	writePluginJSON(w, 202, map[string]any{"api_version": "codexploit/v1", "invocation": inv})
}
func (s *Server) handleGetInvocation(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.invocationScope(w, r)
	if !ok {
		return
	}
	inv, err := s.Plugins.GetStatus(r.Context(), scope, r.PathValue("invocationID"))
	if err != nil {
		writePluginError(w, err)
		return
	}
	w.Header().Set("ETag", invocationETag(inv))
	writePluginJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "invocation": inv})
}
func (s *Server) handleCancelInvocation(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.invocationScope(w, r)
	if !ok {
		return
	}
	inv, err := s.Plugins.GetStatus(r.Context(), scope, r.PathValue("invocationID"))
	if err != nil {
		writePluginError(w, err)
		return
	}
	if !requireEntityVersion(w, r, invocationETag(inv)) {
		return
	}
	inv, err = s.Plugins.Cancel(r.Context(), scope, inv.ID, inv.Version)
	if err != nil {
		if errors.Is(err, plugin.ErrConflict) {
			writeError(w, 412, "precondition_failed", plugin.ErrConflict)
			return
		}
		writePluginError(w, err)
		return
	}
	w.Header().Set("ETag", invocationETag(inv))
	writePluginJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "invocation": inv})
}
func (s *Server) handleListInvocations(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.invocationScope(w, r)
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
	rows, err := s.Plugins.List(r.Context(), scope, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writePluginError(w, err)
		return
	}
	next := ""
	if len(rows) == limit {
		next = rows[len(rows)-1].ID
	}
	writePluginJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "invocations": rows, "next_cursor": next})
}
