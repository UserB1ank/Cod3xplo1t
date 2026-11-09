package workflow

import (
	"encoding/json"
)

// The default analysis is a fixed, project-scoped workflow. Its identity and
// version are stored in every analysis plan, so a later default cannot rewrite
// an existing run's meaning.
const (
	DefaultAnalysisWorkflowID      = "codexploit.default-analysis"
	DefaultAnalysisWorkflowVersion = "2.2.2"
	DefaultEngineID                = "joern"
	DefaultEnginePluginID          = "codexploit.joern"
	DefaultEnginePluginVersion     = "2.3.4"
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
		Name:        "Joern graph and taint analysis",
		Description: "One pinned Joern engine: CPG, taint queries, candidate paths and deterministic ranking.",
		Inputs:      []string{"source.snapshot"},
		Nodes: []Node{
			{ID: "parse", PluginID: DefaultEnginePluginID, PluginVersion: DefaultEnginePluginVersion, OperationID: "parse", Needs: []string{}, Config: json.RawMessage(`{"frontend":"AUTO","heap_mib":4096}`), TimeoutSeconds: 900},
			{ID: "semantic", PluginID: DefaultEnginePluginID, PluginVersion: DefaultEnginePluginVersion, OperationID: "taint", Needs: []string{"parse"}, Config: json.RawMessage(`{"max_flows":100,"max_call_depth":4,"heap_mib":4096}`), TimeoutSeconds: 900},
			{ID: "paths", PluginID: DefaultEnginePluginID, PluginVersion: DefaultEnginePluginVersion, OperationID: "paths", Needs: []string{"parse", "semantic"}, Config: empty, TimeoutSeconds: 60},
			{ID: "enhance", PluginID: DefaultEnginePluginID, PluginVersion: DefaultEnginePluginVersion, OperationID: "enhance", Needs: []string{"paths"}, Config: empty, TimeoutSeconds: 60},
		},
	}
}
