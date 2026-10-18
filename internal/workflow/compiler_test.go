package workflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func fixture() workflow.Spec {
	return workflow.Spec{APIVersion: "codexploit/v1", ID: "discovery", Version: "1.0.0", Name: "Discovery", Description: "Synthetic", Inputs: []string{"source.snapshot"}, Nodes: []workflow.Node{
		{ID: "paths", PluginID: "builtin.discovery-paths", PluginVersion: "1.1.0", Needs: []string{"semantic"}, Config: json.RawMessage(`{}`), TimeoutSeconds: 60},
		{ID: "semantic", PluginID: plugin.SemanticID, PluginVersion: "1.1.0", Needs: []string{"parse"}, Config: json.RawMessage(`{}`), TimeoutSeconds: 60},
		{ID: "parse", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, Needs: []string{}, Config: json.RawMessage(`{}`), TimeoutSeconds: 60},
	}}
}
func compiler(t *testing.T) *workflow.Compiler {
	t.Helper()
	rt, err := app.Build(context.Background(), app.Config{Workspace: t.TempDir(), DBPath: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	return rt.WorkflowCompiler
}
func TestCompilerPinsTopologicalNodesAndDirectTypedBindings(t *testing.T) {
	c := compiler(t)
	raw, _ := json.Marshal(fixture())
	result, err := c.Validate(context.Background(), raw)
	if err != nil || !result.Valid {
		t.Fatalf("valid DAG: %+v %v", result, err)
	}
	if len(result.Nodes) != 3 || result.Nodes[0].ID != "parse" || result.Nodes[1].ID != "semantic" || result.Nodes[2].ID != "paths" {
		t.Fatalf("order: %+v", result.Nodes)
	}
	semantic := result.Nodes[1]
	if semantic.Inputs[0].Kind != "source.snapshot" || semantic.Inputs[0].From != "root" || semantic.Inputs[1].Kind != "code.facts" || semantic.Inputs[1].From != "parse" {
		t.Fatalf("typed sources: %+v", semantic.Inputs)
	}
	if len(semantic.Plugin.PackageDigest) != 64 || len(semantic.Plugin.ManifestDigest) != 64 || len(semantic.ConfigDigest) != 64 {
		t.Fatalf("unpinned plugin: %+v", semantic)
	}
}

func TestCompilerReportsFieldErrorsBeforeProducingExecutableNodes(t *testing.T) {
	c := compiler(t)
	cases := []struct {
		name, code, path string
		change           func(*workflow.Spec)
	}{
		{"cycle", "cycle", "/nodes/2/needs", func(s *workflow.Spec) { s.Nodes[2].Needs = []string{"paths"} }},
		{"missing dependency", "missing_dependency", "/nodes/1/needs/0", func(s *workflow.Spec) { s.Nodes[1].Needs = []string{"absent"} }},
		{"transitive input", "missing_input", "/nodes/0/needs", func(s *workflow.Spec) { s.Nodes[0].Needs = []string{"parse"} }},
		{"ambiguous root and dependency", "ambiguous_input", "/nodes/1/needs", func(s *workflow.Spec) { s.Inputs = append(s.Inputs, "code.facts") }},
		{"ambiguous dependency outputs", "ambiguous_input", "/nodes/0/needs", func(s *workflow.Spec) {
			other := s.Nodes[1]
			other.ID = "other"
			s.Nodes = append(s.Nodes, other)
			s.Nodes[0].Needs = []string{"semantic", "other"}
		}},
		{"missing plugin", "plugin_missing", "/nodes/0/plugin_version", func(s *workflow.Spec) { s.Nodes[0].PluginVersion = "9.0.0" }},
		{"duplicate node", "duplicate_node", "/nodes/2/id", func(s *workflow.Spec) { s.Nodes[2].ID = "semantic" }},
		{"bad parameter", "config_schema", "/nodes/2/config/include_comments", func(s *workflow.Spec) { s.Nodes[2].Config = json.RawMessage(`{"include_comments":"yes"}`) }},
		{"timeout policy", "timeout_policy", "/nodes/2/timeout_seconds", func(s *workflow.Spec) { s.Nodes[2].TimeoutSeconds = 121 }},
		{"schema timeout", "schema", "/nodes/2/timeout_seconds", func(s *workflow.Spec) { s.Nodes[2].TimeoutSeconds = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture()
			tc.change(&s)
			raw, _ := json.Marshal(s)
			result, err := c.Validate(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}
			if result.Valid || len(result.Nodes) != 0 {
				t.Fatalf("invalid workflow has executable nodes: %+v", result)
			}
			found := false
			for _, d := range result.Diagnostics {
				if d.Code == tc.code && d.Path == tc.path {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing %s at %s: %+v", tc.code, tc.path, result.Diagnostics)
			}
		})
	}
}

func TestCompilerRejectsCancelledValidationAndUnavailableAdapters(t *testing.T) {
	c := compiler(t)
	raw, _ := json.Marshal(fixture())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Validate(ctx, raw); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled validation: %v", err)
	}
	catalog := c.Plugins.(*plugin.Catalog)
	manifest := json.RawMessage(`{"api_version":"codexploit/v1","id":"external.scanner","version":"1.0.0","name":"Synthetic scanner","description":"Not installed","kind":"analyzer","languages":["Go"],"runtime":{"kind":"container","entrypoint":"scanner"},"consumes":["source.snapshot"],"produces":["scanner.alerts"],"permissions":{"network":"none","source_write":false},"config_schema":{"type":"object","additionalProperties":false}}`)
	if _, err := catalog.Register(context.Background(), manifest, strings.Repeat("a", 64), "synthetic fixture"); err != nil {
		t.Fatal(err)
	}
	s := fixture()
	s.Nodes = []workflow.Node{{ID: "scan", PluginID: "external.scanner", PluginVersion: "1.0.0", Needs: []string{}, Config: json.RawMessage(`{}`), TimeoutSeconds: 60}}
	raw, _ = json.Marshal(s)
	result, err := c.Validate(context.Background(), raw)
	if err != nil || result.Valid || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "plugin_unavailable" || result.Diagnostics[0].Path != "/nodes/0/plugin_version" {
		t.Fatalf("unavailable adapter: %+v %v", result, err)
	}
}

func TestCompilerDistinguishesRootInputsFromANodeNamedRoot(t *testing.T) {
	c := compiler(t)
	spec := fixture()
	spec.Nodes[2].ID = "root"
	spec.Nodes[1].Needs = []string{"root"}
	raw, _ := json.Marshal(spec)
	result, err := c.Validate(context.Background(), raw)
	if err != nil || !result.Valid {
		t.Fatalf("node named root: %+v %v", result, err)
	}
	inputs := result.Nodes[1].Inputs
	if inputs[0].Source != "root" || inputs[1].Source != "node" || inputs[1].From != "root" {
		t.Fatalf("root identity collision: %+v", inputs)
	}
}
