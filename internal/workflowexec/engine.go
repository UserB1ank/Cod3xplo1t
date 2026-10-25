package workflowexec

import (
	"context"
	"encoding/json"
	"io"

	"github.com/open-mcp-ai/Codexploit/internal/analysisengine"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

// Restore only one engine's complete immutable chain. Independent scanner
// observations may coexist in the publication but cannot supply graph stages.
func (e *Effects) restoreEngine(ctx context.Context, run workflow.Run, plan workflow.Plan) error {
	provider := e.Engine
	if provider == nil {
		provider = analysisengine.Default()
	}
	spec := provider.Workflow()
	if len(spec.Nodes) == 0 {
		return workflow.ErrInvalid
	}
	pluginID := spec.Nodes[0].PluginID
	stages := map[string]string{}
	for _, node := range plan.Nodes {
		if node.Operation != nil {
			stages[node.ID] = node.Operation.Stage
		}
	}
	var b analysisengine.Bundle
	b.BuiltAt = run.CreatedAt
	found := map[string]bool{}
	for _, node := range run.Nodes {
		if node.Kind != "plugin" || (node.Status != "SUCCEEDED" && node.Status != "PARTIAL") {
			continue
		}
		for _, ref := range node.Outputs {
			if ref.Producer.PluginID != pluginID {
				continue
			}
			var key string
			switch ref.SchemaID {
			case "codexploit/code-facts/v2":
				key = "code"
			case "codexploit/security-facts/v2":
				key = "security"
			case "codexploit/discovery-paths/v2":
				if stages[node.NodeID] == "path.generate" {
					key = "generated"
				} else if stages[node.NodeID] == "path.enhance" && (plan.PathSourceNodeID == "" || plan.PathSourceNodeID == node.NodeID) {
					key = "selected"
				}
			case "codexploit/path-enhancement/v2":
				if plan.PathSourceNodeID == "" || plan.PathSourceNodeID == node.NodeID {
					key = "selection"
				}
			}
			if key == "" {
				continue
			}
			if found[key] {
				return workflow.ErrInvalid
			}
			found[key] = true
			reader, _, err := e.Artifacts.Open(ctx, run.Scope, ref.ID, 64<<20)
			if err != nil {
				return err
			}
			raw, err := io.ReadAll(io.LimitReader(reader, (64<<20)+1))
			closeErr := reader.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if len(raw) > 64<<20 {
				return plugin.ErrBudget
			}
			var doc plugin.StageDocument
			if json.Unmarshal(raw, &doc) != nil || doc.Scope != run.Scope || doc.Producer != ref.Producer || doc.Kind != ref.Kind || doc.SchemaID != ref.SchemaID {
				return workflow.ErrInvalid
			}
			input := analysisengine.Input{Ref: ref, Document: doc}
			switch key {
			case "code":
				b.Code = input
			case "security":
				b.Security = input
			case "generated":
				b.Generated = input
			case "selected":
				b.Selected = input
			case "selection":
				b.Selection = &input
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	// A parse-only custom workflow can publish facts without claiming a complete
	// review index. A chain containing paths must be complete and engine coherent.
	if !found["generated"] && !found["selected"] {
		return nil
	}
	if !found["code"] || !found["security"] || !found["generated"] {
		return workflow.ErrInvalid
	}
	if !found["selected"] {
		b.Selected = b.Generated
	}
	native, err := provider.Project(b)
	if err != nil {
		return err
	}
	e.native = native
	e.pathReports = []pathReport{{native, b.Selected.Ref.ID}}
	e.projected = true
	return nil
}
