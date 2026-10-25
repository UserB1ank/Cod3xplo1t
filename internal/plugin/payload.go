package plugin

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/jsonschema-go/jsonschema"
	v1 "github.com/open-mcp-ai/Codexploit/contracts/v1"
	v2 "github.com/open-mcp-ai/Codexploit/contracts/v2"
)

// Standard stage artifacts contain host-authored identity and provenance. A
// black-box adapter returns only data; it cannot select a different scope or
// claim a different producer by embedding forged envelope fields.
func standardOutput(inv Invocation, out RawOutput, raw []byte, coverage StageCoverage, limitations []string) ([]byte, error) {
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	var value any
	if json.Unmarshal(canonical, &value) != nil {
		return nil, ErrInvalid
	}
	definitions := map[string]string{"codexploit/code-facts/v2": "CodeFacts", "codexploit/security-facts/v2": "SecurityFacts", "codexploit/discovery-paths/v2": "Paths", "codexploit/report-input/v1": "ReportInput", "codexploit/path-enhancement/v2": "Enhancement"}
	if name, ok := definitions[out.SchemaID]; ok {
		doc, err := v2.Files.ReadFile("stage-payload.schema.json")
		if err != nil {
			return nil, err
		}
		var schemaDocument map[string]any
		if json.Unmarshal(doc, &schemaDocument) != nil {
			return nil, ErrInvalid
		}
		schemaDocument["$ref"] = "#/$defs/" + name
		doc, _ = json.Marshal(schemaDocument)
		var schema jsonschema.Schema
		if json.Unmarshal(doc, &schema) != nil {
			return nil, ErrInvalid
		}
		resolved, err := schema.Resolve(nil)
		if err != nil {
			return nil, err
		}
		if resolved.Validate(value) != nil {
			return nil, ErrInvalid
		}
		if err := validatePayloadReferences(out.SchemaID, canonical); err != nil {
			return nil, err
		}
		if out.SchemaID == "codexploit/code-facts/v2" {
			canonical, err = normalizeCodeIDs(inv, canonical)
			if err != nil {
				return nil, err
			}
			if json.Unmarshal(canonical, &value) != nil {
				return nil, ErrInvalid
			}
		}
		document := map[string]any{"api_version": "codexploit/v2", "kind": out.Kind, "schema_id": out.SchemaID, "scope": inv.Request.Scope, "producer": map[string]any{"plugin_id": inv.Request.PluginID, "plugin_version": inv.Request.PluginVersion, "operation_id": inv.Request.OperationID, "output_port": out.Port, "package_digest": inv.Request.PackageDigest, "invocation_id": inv.ID, "config_digest": inv.ConfigDigest, "normalizer_digest": stageNormalizerDigest()}, "inputs": inv.Request.Inputs, "coverage": coverage, "limitations": limitations, "data": value}
		return json.Marshal(document)
	}
	files := map[string]string{"codexploit/scanner-alerts/v1": "scanner-alerts.schema.json", "codexploit/path-enhancement/v1": "path-enhancement.schema.json", "codexploit/discovery/v1": "discovery.schema.json", "codexploit/go-facts/v1": "go-facts.schema.json"}
	name, ok := files[out.SchemaID]
	if !ok {
		return nil, ErrUnsupported
	}
	rawSchema, err := v1.Files.ReadFile(name)
	if err != nil {
		return nil, ErrUnsupported
	}
	var schema jsonschema.Schema
	if json.Unmarshal(rawSchema, &schema) != nil {
		return nil, ErrInvalid
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
		if uri.Scheme != "https" || uri.Host != "codexploit.invalid" || !strings.HasPrefix(uri.Path, "/contracts/v1/") {
			return nil, ErrInvalid
		}
		path := strings.TrimPrefix(uri.Path, "/contracts/v1/")
		if strings.Contains(path, "/") {
			return nil, ErrInvalid
		}
		raw, err := v1.Files.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var s jsonschema.Schema
		err = json.Unmarshal(raw, &s)
		return &s, err
	}})
	if err != nil {
		return nil, err
	}
	if resolved.Validate(value) != nil {
		return nil, ErrInvalid
	}
	// Existing native formats own their scope fields; do not silently rewrite.
	if obj, ok := value.(map[string]any); ok {
		if scope, exists := obj["scope"]; exists {
			a, _ := json.Marshal(scope)
			b, _ := json.Marshal(inv.Request.Scope)
			if !bytes.Equal(a, b) {
				return nil, ErrInvalid
			}
		}
	}
	return raw, nil
}

func validatePayloadReferences(schema string, raw []byte) error {
	if schema != "codexploit/code-facts/v2" {
		return nil
	}
	var facts struct {
		Files []struct {
			ID   string `json:"file_id"`
			Path string `json:"path"`
		} `json:"files"`
		Symbols []struct {
			ID   string `json:"id"`
			File string `json:"file_id"`
		} `json:"symbols"`
		Calls []struct {
			ID         string  `json:"id"`
			Caller     *string `json:"caller_ref"`
			Callee     *string `json:"callee_ref"`
			Resolution string  `json:"resolution"`
		} `json:"calls"`
	}
	if json.Unmarshal(raw, &facts) != nil {
		return ErrInvalid
	}
	files, symbols, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, f := range facts.Files {
		if files[f.ID] || !safeSourcePath(f.Path) {
			return ErrInvalid
		}
		files[f.ID] = true
	}
	for _, s := range facts.Symbols {
		if !files[s.File] || symbols[s.ID] {
			return ErrInvalid
		}
		symbols[s.ID] = true
	}
	for _, c := range facts.Calls {
		if ids[c.ID] || (c.Resolution == "resolved" && (c.Caller == nil || c.Callee == nil)) || (c.Caller != nil && !symbols[*c.Caller]) || (c.Callee != nil && !symbols[*c.Callee]) {
			return ErrInvalid
		}
		ids[c.ID] = true
	}
	return nil
}
