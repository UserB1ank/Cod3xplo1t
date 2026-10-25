package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

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
	var manifest plugin.Manifest
	if json.Unmarshal(request.Manifest, &manifest) != nil || manifest.APIVersion != "codexploit/v1" {
		writePluginError(w, plugin.ErrInvalid)
		return
	}
	if strings.HasPrefix(strings.TrimSpace(request.Source), "compiled ") {
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
	legacy := []plugin.Record{}
	for _, row := range rows {
		if row.Manifest.APIVersion != plugin.DefinitionVersion {
			legacy = append(legacy, row)
		}
	}
	writePluginJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "plugins": legacy, "next_cursor": next})
}

type pluginCapabilityView struct {
	Key            string                  `json:"key"`
	Label          string                  `json:"label"`
	Available      bool                    `json:"available"`
	Reason         string                  `json:"reason,omitempty"`
	ExecutionModel string                  `json:"execution_model"`
	Plugins        []pluginCapabilityEntry `json:"plugins"`
	Adapters       []capabilityAdapter     `json:"adapters"`
	Contracts      []plugin.Contract       `json:"contracts"`
}

type pluginCapabilityEntry struct {
	ID              string `json:"id"`
	Version         string `json:"version"`
	Name            string `json:"name"`
	Runtime         string `json:"runtime"`
	Source          string `json:"source"`
	Installed       bool   `json:"installed"`
	Executable      bool   `json:"executable"`
	AdapterKind     string `json:"adapter_kind"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	PackageVersion  string `json:"package_version"`
	Declared        bool   `json:"declared"`
	Measured        bool   `json:"measured"`
	Reason          string `json:"reason,omitempty"`
}

// handlePluginCapabilities answers GET /api/v1/plugins/capabilities. The plugin
// page uses it to show every pipeline stage, the plugins that declare it and
// whether this host can execute it; a stage without an adapter is explicit
// instead of silently absent.
func (s *Server) handlePluginCapabilities(w http.ResponseWriter, r *http.Request) {
	if s.PluginCatalog == nil {
		writeError(w, 501, "plugins_unavailable", errors.New("plugin catalog is unavailable"))
		return
	}
	rows, err := s.PluginCatalog.All(r.Context())
	if err != nil {
		writeError(w, 503, "plugins_unavailable", errors.New("plugin catalog is unavailable"))
		return
	}
	contracts := plugin.Contracts()
	views := make([]pluginCapabilityView, 0, len(plugin.Capabilities()))
	for _, capability := range plugin.Capabilities() {
		view := pluginCapabilityView{
			Key: capability.Key, Label: capability.Label,
			ExecutionModel: executionModel(capability.Key),
			Plugins:        []pluginCapabilityEntry{}, Adapters: []capabilityAdapter{}, Contracts: []plugin.Contract{},
		}
		for _, contract := range contracts {
			if contract.Capability == capability.Key {
				view.Contracts = append(view.Contracts, contract)
			}
		}
		view.Adapters = append(view.Adapters, s.nativeAdapters(capability.Key)...)
		for _, record := range rows {
			kind, ok := plugin.CapabilityForRecord(record)
			if !ok || string(kind) != capability.Key {
				continue
			}
			view.Plugins = append(view.Plugins, pluginCapabilityEntry{
				ID: record.Manifest.ID, Version: record.Manifest.Version, Name: record.Manifest.Name,
				Runtime: record.Manifest.Runtime.Kind, Source: record.Source, Installed: record.Installed,
				Executable: record.Executable, AdapterKind: adapterPluginRuntime,
				ProtocolVersion: record.ProtocolVersion, PackageVersion: record.Manifest.Version,
				Declared: true, Measured: record.Executable && (record.Installation == nil || record.Installation.Probe == "passed"), Reason: record.Reason,
			})
			view.Adapters = append(view.Adapters, pluginAdapter(record))
		}
		for _, adapter := range view.Adapters {
			if adapter.Measured {
				view.Available = true
			}
		}
		if !view.Available {
			view.Reason = capabilityReason(capability.Key, view.Adapters)
		}
		views = append(views, view)
	}
	writeCapabilityJSON(w, 200, map[string]any{
		"api_version":  "codexploit/v1",
		"capabilities": views,
		"protocols":    plugin.DomainProtocols(),
	})
}
