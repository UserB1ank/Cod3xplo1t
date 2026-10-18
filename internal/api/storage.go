package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

var storageStatusSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	raw, err := contracts.Files.ReadFile("storage-status.schema.json")
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return schema.Resolve(nil)
})

func (s *Server) handleStorageStatus(w http.ResponseWriter, r *http.Request) {
	status := storage.ProbeStatus(r.Context(), s.Store)
	schema, err := storageStatusSchema()
	raw, marshalErr := json.Marshal(status)
	var value any
	if err != nil || marshalErr != nil || json.Unmarshal(raw, &value) != nil || schema.Validate(value) != nil {
		writeError(w, 500, "contract_violation", errors.New("storage response does not satisfy the public contract"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	code := http.StatusOK
	if status.Readiness != "ready" {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, status)
}

// This is an allow-list for the limited catalog profile. Unknown and later
// capabilities fail before handlers (including idempotency claims) can run.
func (s *Server) guardStorage(next http.Handler) http.Handler {
	if !storage.CatalogOnly(s.Store) {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || catalogRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, 501, "storage_capability_unavailable", errors.New("this operation is not wired for the PostgreSQL catalog profile"))
	})
}

func catalogRoute(path string) bool {
	p := strings.Split(strings.Trim(path, "/"), "/")
	if len(p) < 2 || p[0] != "api" {
		return false
	}
	if p[1] == "me" {
		return len(p) == 2
	}
	if p[1] == "auth" {
		return true
	}
	if p[1] == "settings" {
		return len(p) >= 3 && p[2] == "llm"
	}
	if p[1] == "projects" {
		return len(p) <= 3 || (len(p) == 4 && p[3] == "snapshots")
	}
	if p[1] == "snapshots" {
		return len(p) <= 3 || (len(p) == 4 && p[3] == "manifest")
	}
	if p[1] != "v1" || len(p) < 3 {
		return false
	}
	if p[2] == "storage" {
		return len(p) == 4 && p[3] == "status"
	}
	if p[2] == "sources" {
		return len(p) == 5 && p[4] == "snapshots"
	}
	if p[2] != "projects" {
		return false
	}
	return len(p) == 3 || (len(p) == 5 && p[4] == "sources") || (len(p) >= 7 && len(p) <= 9 && p[4] == "snapshots" && p[6] == "artifacts" && (len(p) < 9 || p[8] == "content"))
}

func (s *Server) snapshotCapabilities(w http.ResponseWriter, request createSnapshotRequest) bool {
	if storage.CatalogOnly(s.Store) && (request.BuildGraph || request.BuildASG) {
		writeError(w, 501, "storage_capability_unavailable", errors.New("graph construction is not wired for the PostgreSQL catalog profile"))
		return false
	}
	return true
}
