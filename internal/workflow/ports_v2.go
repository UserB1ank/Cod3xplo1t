package workflow

import (
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func (c *Compiler) compileOperationInputs(spec Spec, node Node, op plugin.Operation, records map[string]plugin.Record, operations map[string]plugin.Operation, position int) ([]Binding, []Diagnostic) {
	bindings := []Binding{}
	diagnostics := []Diagnostic{}
	add := func(code, message string) {
		diagnostics = append(diagnostics, Diagnostic{fmt.Sprintf("/nodes/%d/input_bindings", position), code, message})
	}
	for name := range node.InputBindings {
		known := false
		for _, p := range op.Inputs {
			if p.Name == name {
				known = true
			}
		}
		if !known {
			add("unknown_port", "Input binding names an undeclared port")
		}
	}
	for _, port := range op.Inputs {
		sources := []Binding{}
		for _, root := range spec.Inputs {
			if root == port.Kind {
				sources = append(sources, Binding{Source: "root", From: "root", Kind: port.Kind, SchemaID: port.SchemaID})
			}
		}
		for _, need := range node.Needs {
			if upstream, ok := operations[need]; ok {
				for _, out := range upstream.Outputs {
					if out.Kind == port.Kind && out.SchemaID == port.SchemaID {
						sources = append(sources, Binding{Source: "node", From: need, OutputPort: out.Name, Kind: port.Kind, SchemaID: port.SchemaID})
					}
				}
			} else {
				record := records[need]
				for _, kind := range record.Manifest.Produces {
					if kind == port.Kind && legacyOutputSchema(record, kind) == port.SchemaID {
						sources = append(sources, Binding{Source: "node", From: need, Kind: port.Kind, SchemaID: port.SchemaID})
					}
				}
			}
		}
		if selected, ok := node.InputBindings[port.Name]; ok {
			filtered := []Binding{}
			for _, source := range sources {
				if source.Source == selected.Source && source.From == selected.From && (selected.Port == "" || source.OutputPort == selected.Port) {
					filtered = append(filtered, source)
				}
			}
			sources = filtered
		}
		if len(sources) == 0 {
			if port.Required {
				add("missing_input", "No compatible source for port "+port.Name)
			}
			continue
		}
		if len(sources) != 1 {
			add("ambiguous_input", "Select an explicit node and output port for "+port.Name)
			continue
		}
		binding := sources[0]
		binding.Port = port.Name
		binding.Cardinality = port.Cardinality
		binding.Optional = !port.Required
		bindings = append(bindings, binding)
	}
	return bindings, diagnostics
}

// Legacy schemas are compatibility metadata, never a reason to require a
// particular tool ID for a v2 port. New operations carry their exact schemas.
func legacyOutputSchema(record plugin.Record, kind string) string {
	switch kind {
	case "code.ast":
		return "codexploit/go-ast/v1"
	case "code.facts":
		return "codexploit/go-facts/v1"
	case "security.facts", "discovery.paths":
		return "codexploit/discovery/v1"
	case "scanner.alerts":
		return "codexploit/scanner-alerts/v1"
	case "report.document":
		if record.Manifest.Kind == "reporter" {
			return "codexploit/report/v1"
		}
		return "codexploit/builtin-native/v1"
	}
	return ""
}
