package api

import (
	"encoding/json"

	"github.com/open-mcp-ai/Codexploit/internal/analysisengine"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

// Historical plans remain executable and readable after changing the formal
// default. This provider exists only in tests; deployments have one default.
type legacyAnalysisFixture struct{}

func (legacyAnalysisFixture) Workflow() workflow.Spec {
	empty := json.RawMessage(`{}`)
	return workflow.Spec{APIVersion: "codexploit/v1", ID: workflow.DefaultAnalysisWorkflowID, Version: "1.0.0", Name: "Legacy pinned analysis", Description: "Historical Go workflow compatibility fixture", Inputs: []string{"source.snapshot"}, Nodes: []workflow.Node{
		{ID: "parse", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, Needs: []string{}, Config: empty, TimeoutSeconds: 60},
		{ID: "semantic", PluginID: plugin.SemanticID, PluginVersion: "1.2.0", Needs: []string{"parse"}, Config: empty, TimeoutSeconds: 60},
		{ID: "paths", PluginID: "builtin.discovery-paths", PluginVersion: "1.2.0", Needs: []string{"semantic"}, Config: empty, TimeoutSeconds: 60},
		{ID: "enhance", PluginID: "builtin.path-enhancer", PluginVersion: "1.0.0", Needs: []string{"paths"}, Config: empty, TimeoutSeconds: 60},
	}}
}
func (legacyAnalysisFixture) Project(analysisengine.Bundle) (*plugin.NativeReport, error) {
	return nil, plugin.ErrUnsupported
}
func useLegacyAnalysisFixture(env *testEnv) { env.server.AnalysisEngine = legacyAnalysisFixture{} }
