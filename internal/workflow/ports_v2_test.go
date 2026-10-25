package workflow_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func TestCompilerUsesOperationPortContractsWithoutToolIdentity(t *testing.T) {
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest plugin.Manifest
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.ID = "vendor.independent-parser"
	record := plugin.Record{Manifest: manifest, Executable: true, Installed: true, PackageDigest: strings.Repeat("e", 64), ManifestDigest: strings.Repeat("f", 64)}
	c := workflow.Compiler{Plugins: staticCatalog{record: record}}
	spec := json.RawMessage(`{"api_version":"codexploit/v1","id":"external-parser","version":"1.0.0","name":"External parser","description":"Typed boundary","inputs":["source.snapshot"],"nodes":[{"id":"parse","plugin_id":"vendor.independent-parser","plugin_version":"0.1.0","operation_id":"execute","needs":[],"config":{},"timeout_seconds":60}]}`)
	result, err := c.Validate(t.Context(), spec)
	if err != nil || !result.Valid || len(result.Nodes) != 1 {
		t.Fatalf("typed operation: %+v %v", result, err)
	}
	if len(result.Nodes[0].Inputs) != 1 || result.Nodes[0].Inputs[0].SchemaID != "codexploit/source-tar/v1" {
		t.Fatalf("port not fixed: %+v", result.Nodes)
	}
}
