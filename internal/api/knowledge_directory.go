package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
)

var knowledgeDirectorySchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
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
	schema, err := load("knowledge-directory.schema.json")
	if err != nil {
		return nil, err
	}
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
		if uri.Scheme != "https" || uri.Host != "codexploit.invalid" || path.Dir(uri.Path) != "/contracts/v1" {
			return nil, errors.New("unregistered schema")
		}
		return load(path.Base(uri.Path))
	}})
})

func writeKnowledgeDirectory(w http.ResponseWriter, document any) {
	schema, err := knowledgeDirectorySchema()
	raw, marshalErr := json.Marshal(document)
	var value any
	if err != nil || marshalErr != nil || json.Unmarshal(raw, &value) != nil || schema.Validate(value) != nil {
		writeError(w, 500, "contract_violation", errors.New("knowledge directory does not satisfy its public contract"))
		return
	}
	writeJSON(w, 200, document)
}
