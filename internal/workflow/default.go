package workflow

import (
	"encoding/json"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

// The default analysis is a fixed, project-scoped workflow. Its identity and
// version are stored in every analysis plan, so a later default cannot rewrite
// an existing run's meaning.
const (
	DefaultAnalysisWorkflowID      = "codexploit.default-analysis"
	DefaultAnalysisWorkflowVersion = "1.0.0"
)

// DefaultAnalysisSpec returns the four deterministic stages that do not require
// a model. The plugin runner appends the fixed $publish and $analyze nodes; the
// one-click service explicitly disables candidate analysis unless an operator
// asked for Agent assistance.
func DefaultAnalysisSpec() Spec {
	empty := json.RawMessage(`{}`)
	return Spec{
		APIVersion:  "codexploit/v1",
		ID:          DefaultAnalysisWorkflowID,
		Version:     DefaultAnalysisWorkflowVersion,
		Name:        "Default four-stage analysis",
		Description: "Code graph, security semantics, candidate paths, deterministic path enhancement.",
		Inputs:      []string{"source.snapshot"},
		Nodes: []Node{
			{ID: "parse", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, Needs: []string{}, Config: empty, TimeoutSeconds: 60},
			{ID: "semantic", PluginID: plugin.SemanticID, PluginVersion: "1.2.0", Needs: []string{"parse"}, Config: empty, TimeoutSeconds: 60},
			{ID: "paths", PluginID: "builtin.discovery-paths", PluginVersion: "1.2.0", Needs: []string{"semantic"}, Config: empty, TimeoutSeconds: 60},
			{ID: "enhance", PluginID: "builtin.path-enhancer", PluginVersion: "1.0.0", Needs: []string{"paths"}, Config: empty, TimeoutSeconds: 60},
		},
	}
}
