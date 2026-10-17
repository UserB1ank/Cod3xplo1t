package workflow

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

func offlineSchema(raw json.RawMessage) (*jsonschema.Schema, *jsonschema.Resolved, error) {
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, nil, ErrInvalid
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{Loader: func(*url.URL) (*jsonschema.Schema, error) { return nil, ErrInvalid }})
	return &schema, resolved, err
}
func pointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

// schemaDiagnostics locates invalid fields without echoing user configuration values.
func schemaDiagnostics(schema *jsonschema.Schema, value any, path, code string, depth int) []Diagnostic {
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{Loader: func(*url.URL) (*jsonschema.Schema, error) { return nil, ErrInvalid }})
	if err == nil && resolved.Validate(value) == nil {
		return nil
	}
	result := []Diagnostic{}
	if depth < 16 {
		switch v := value.(type) {
		case map[string]any:
			for _, required := range schema.Required {
				if _, ok := v[required]; !ok {
					result = append(result, Diagnostic{path + "/" + pointer(required), code, "Required field is missing"})
				}
			}
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				sub := schema.Properties[key]
				if sub == nil {
					sub = schema.AdditionalProperties
				}
				if sub != nil {
					result = append(result, schemaDiagnostics(sub, v[key], path+"/"+pointer(key), code, depth+1)...)
				}
			}
		case []any:
			if schema.Items != nil {
				for i, item := range v {
					result = append(result, schemaDiagnostics(schema.Items, item, path+"/"+strconv.Itoa(i), code, depth+1)...)
				}
			}
		}
	}
	if len(result) == 0 {
		if path == "" {
			path = "/"
		}
		result = append(result, Diagnostic{path, code, "Value does not match the field schema"})
	}
	return result
}
