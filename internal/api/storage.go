package api

import (
	"encoding/json"
	"errors"
	"net/http"
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
