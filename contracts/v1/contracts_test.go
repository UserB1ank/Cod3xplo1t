package contracts

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

func loadSchemas(t *testing.T) map[string]*jsonschema.Resolved {
	t.Helper()
	names, err := fs.Glob(Files, "*.schema.json")
	if err != nil || len(names) != 18 {
		t.Fatalf("schemas: %d %v", len(names), err)
	}
	byID := map[string]*jsonschema.Schema{}
	byName := map[string]*jsonschema.Schema{}
	for _, name := range names {
		raw, err := Files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var schema jsonschema.Schema
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, exists := byID[schema.ID]; exists {
			t.Fatal("duplicate schema id", schema.ID)
		}
		byID[schema.ID], byName[name] = &schema, &schema
	}
	result := map[string]*jsonschema.Resolved{}
	for name, schema := range byName {
		resolved, err := schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
			if schema := byID[uri.String()]; schema != nil {
				return schema, nil
			}
			return nil, fmt.Errorf("schema is not registered offline: %s", uri)
		}})
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		result[name] = resolved
	}
	return result
}

func fixture(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := Files.ReadFile("examples/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSchemasResolveOfflineAndCompleteExamplesValidate(t *testing.T) {
	t.Parallel()
	schemas := loadSchemas(t)
	var examples []struct {
		File   string `json:"file"`
		Schema string `json:"schema"`
	}
	raw, err := Files.ReadFile("examples.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &examples); err != nil {
		t.Fatal(err)
	}
	for _, example := range examples {
		t.Run(example.File, func(t *testing.T) {
			raw, err := Files.ReadFile(example.File)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			schema := schemas[example.Schema]
			if schema == nil {
				t.Fatal("missing schema", example.Schema)
			}
			if err := schema.Validate(value); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestContractsRejectInvalidExtensionsAndFalseClaims(t *testing.T) {
	t.Parallel()
	schemas := loadSchemas(t)
	tests := []struct {
		name, schema, fixture string
		mutate                func(map[string]any)
	}{
		{"unknown field", "plugin", "plugin", func(v map[string]any) { v["unexpected"] = true }},
		{"unknown protocol", "plugin", "plugin", func(v map[string]any) { v["api_version"] = "codexploit/v99" }},
		{"source writes", "plugin", "plugin", func(v map[string]any) { v["permissions"].(map[string]any)["source_write"] = true }},
		{"missing entrypoint", "plugin", "plugin", func(v map[string]any) { delete(v["runtime"].(map[string]any), "entrypoint") }},
		{"invalid grade", "finding", "finding", func(v map[string]any) { v["severity"] = "critical" }},
		{"path traversal", "source", "source-local", func(v map[string]any) { v["location"] = "/repos/../outside" }},
		{"credential URL", "source", "source-git", func(v map[string]any) { v["location"] = "https://example:fixture@forge.example.invalid/repo" }},
		{"folder with Git ref", "source", "source-local", func(v map[string]any) { v["ref"] = "main" }},
		{"excess timeout", "workflow", "workflow", func(v map[string]any) { v["nodes"].([]any)[0].(map[string]any)["timeout_seconds"] = float64(601) }},
		{"invalid port", "storage", "storage", func(v map[string]any) { v["metadata"].(map[string]any)["port"] = float64(65536) }},
		{"probability as fact confidence", "knowledge", "graph-batch", func(v map[string]any) { v["nodes"].([]any)[0].(map[string]any)["confidence"] = float64(.95) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := fixture(t, test.fixture)
			test.mutate(value)
			if err := schemas[test.schema+".schema.json"].Validate(value); err == nil {
				t.Fatal("invalid contract accepted")
			}
		})
	}
}
