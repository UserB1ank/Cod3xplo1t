package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	v1 "github.com/open-mcp-ai/Codexploit/contracts/v1"
	v2 "github.com/open-mcp-ai/Codexploit/contracts/v2"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

var pluginV2ResponseSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	load := func(version, name string) (*jsonschema.Schema, error) {
		files := v2.Files
		if version == "v1" {
			files = v1.Files
		}
		raw, err := files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var schema jsonschema.Schema
		err = json.Unmarshal(raw, &schema)
		return &schema, err
	}
	schema, err := load("v2", "runtime.schema.json")
	if err != nil {
		return nil, err
	}
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
		if uri.Scheme != "https" || uri.Host != "codexploit.invalid" {
			return nil, plugin.ErrInvalid
		}
		dir := path.Dir(uri.Path)
		if dir != "/contracts/v1" && dir != "/contracts/v2" {
			return nil, plugin.ErrInvalid
		}
		return load(path.Base(dir), path.Base(uri.Path))
	}})
})

func writePluginV2JSON(w http.ResponseWriter, status int, document any) {
	schema, err := pluginV2ResponseSchema()
	if err != nil {
		writeError(w, 500, "contract_unavailable", errors.New("plugin contract unavailable"))
		return
	}
	raw, err := json.Marshal(document)
	if err != nil {
		writePluginError(w, err)
		return
	}
	var value any
	if json.Unmarshal(raw, &value) != nil || schema.Validate(value) != nil {
		writeError(w, 500, "contract_violation", errors.New("plugin response violates contract"))
		return
	}
	writeJSON(w, status, document)
}

func (s *Server) handlePluginStages(w http.ResponseWriter, r *http.Request) {
	writePluginV2JSON(w, 200, map[string]any{"api_version": "codexploit/v2", "stages": plugin.Stages(), "host": map[string]string{"os": runtime.GOOS, "arch": runtime.GOARCH}})
}

func (s *Server) handleRegisterPluginV2(w http.ResponseWriter, r *http.Request) {
	if s.PluginCatalog == nil {
		writePluginError(w, plugin.ErrUnsupported)
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
	var manifest plugin.Manifest
	if request.APIVersion != "codexploit/v2" || json.Unmarshal(request.Manifest, &manifest) != nil || manifest.APIVersion != plugin.DefinitionVersion || strings.HasPrefix(strings.TrimSpace(request.Source), "compiled ") {
		writePluginError(w, plugin.ErrInvalid)
		return
	}
	record, err := s.PluginCatalog.Register(r.Context(), request.Manifest, request.PackageDigest, request.Source)
	if err != nil {
		writePluginError(w, err)
		return
	}
	writePluginV2JSON(w, 201, map[string]any{"api_version": "codexploit/v2", "plugin": record})
}

func (s *Server) handleListPluginsV2(w http.ResponseWriter, r *http.Request) {
	if s.PluginCatalog == nil {
		writePluginError(w, plugin.ErrUnsupported)
		return
	}
	limit := 50
	if value := r.URL.Query().Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 100 {
			writePluginError(w, plugin.ErrInvalid)
			return
		}
		limit = n
	}
	rows, err := s.PluginCatalog.List(r.Context(), r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writePluginError(w, err)
		return
	}
	next := ""
	if len(rows) == limit {
		last := rows[len(rows)-1].Manifest
		next = last.ID + "@" + last.Version
	}
	writePluginV2JSON(w, 200, map[string]any{"api_version": "codexploit/v2", "plugins": rows, "next_cursor": next})
}

func (s *Server) handlePluginVersionsV2(w http.ResponseWriter, r *http.Request) {
	if s.PluginCatalog == nil {
		writePluginError(w, plugin.ErrUnsupported)
		return
	}
	rows, err := s.PluginCatalog.All(r.Context())
	if err != nil {
		writePluginError(w, err)
		return
	}
	versions := []plugin.Record{}
	for _, row := range rows {
		if row.Manifest.ID == r.PathValue("pluginID") {
			versions = append(versions, row)
		}
	}
	writePluginV2JSON(w, 200, map[string]any{"api_version": "codexploit/v2", "versions": versions})
}
