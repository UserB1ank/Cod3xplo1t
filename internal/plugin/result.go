package plugin

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"path"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

var discoverySchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
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
	schema, err := load("discovery.schema.json")
	if err != nil {
		return nil, err
	}
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
		if uri.Scheme != "https" || uri.Host != "codexploit.invalid" || path.Dir(uri.Path) != "/contracts/v1" {
			return nil, ErrInvalid
		}
		return load(path.Base(uri.Path))
	}})
})

func ValidateDiscovery(document DiscoveryDocument) error {
	schema, err := discoverySchema()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return err
	}
	var value any
	if json.Unmarshal(raw, &value) != nil || schema.Validate(value) != nil {
		return ErrInvalid
	}
	return nil
}

// Result reads the immutable normalized artifact; it never materializes a
// finding verdict. Failed/unsupported/cancelled calls have no consumable result.
func (h *Host) Result(ctx context.Context, scope artifact.Scope, id string, budget int64) (DiscoveryDocument, error) {
	inv, err := h.GetStatus(ctx, scope, id)
	if err != nil {
		return DiscoveryDocument{}, err
	}
	if inv.Status != "SUCCEEDED" && inv.Status != "PARTIAL" {
		return DiscoveryDocument{}, ErrConflict
	}
	for _, ref := range inv.Outputs {
		if ref.SchemaID == "codexploit/discovery/v1" {
			reader, _, err := h.deps.Artifacts.Open(ctx, scope, ref.ID, budget)
			if err != nil {
				return DiscoveryDocument{}, err
			}
			defer reader.Close()
			raw, err := io.ReadAll(io.LimitReader(reader, budget+1))
			if err != nil {
				return DiscoveryDocument{}, err
			}
			if int64(len(raw)) > budget {
				return DiscoveryDocument{}, ErrBudget
			}
			var document DiscoveryDocument
			if json.Unmarshal(raw, &document) != nil || ValidateDiscovery(document) != nil || document.Scope != scope || document.Producer != ref.Producer {
				return DiscoveryDocument{}, ErrInvalid
			}
			return document, nil
		}
	}
	return DiscoveryDocument{}, ErrNotFound
}
