package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
)

var workflowRunSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
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
	schema, err := load("workflow-run.schema.json")
	if err != nil {
		return nil, err
	}
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
		if uri.Scheme != "https" || uri.Host != "codexploit.invalid" || path.Dir(uri.Path) != "/contracts/v1" {
			return nil, fmt.Errorf("unregistered schema")
		}
		return load(path.Base(uri.Path))
	}})
})

func writeWorkflowRunJSON(w http.ResponseWriter, status int, document any) {
	schema, err := workflowRunSchema()
	if err != nil {
		writeError(w, 500, "contract_unavailable", fmt.Errorf("workflow contract is unavailable"))
		return
	}
	raw, err := json.Marshal(document)
	if err != nil {
		writeError(w, 500, "contract_violation", fmt.Errorf("workflow response cannot be encoded"))
		return
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		writeError(w, 500, "contract_violation", fmt.Errorf("workflow response cannot be decoded: %w", err))
		return
	}
	if err := schema.Validate(value); err != nil {
		writeError(w, 500, "contract_violation", fmt.Errorf("workflow response does not satisfy the public contract: %w", err))
		return
	}
	writeJSON(w, status, document)
}
