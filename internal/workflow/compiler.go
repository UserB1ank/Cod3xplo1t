package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

type Diagnostic struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Binding struct {
	Port           string `json:"port,omitempty"`
	OutputPort     string `json:"output_port,omitempty"`
	Cardinality    string `json:"cardinality,omitempty"`
	Optional       bool   `json:"optional,omitempty"`
	Source         string `json:"source"`
	Kind           string `json:"kind"`
	From           string `json:"from"`
	SchemaID       string `json:"schema_id"`
	ProducerPlugin string `json:"producer_plugin,omitempty"`
}
type CompiledNode struct {
	BoundInputPorts []string          `json:"-"`
	Operation       *plugin.Operation `json:"operation,omitempty"`
	Node
	Plugin       plugin.Record `json:"plugin"`
	ConfigDigest string        `json:"config_digest"`
	Inputs       []Binding     `json:"inputs"`
	Outputs      []string      `json:"outputs"`
}
type Validation struct {
	Valid       bool           `json:"valid"`
	Diagnostics []Diagnostic   `json:"diagnostics"`
	Nodes       []CompiledNode `json:"nodes"`
	// PathSourceNodeID names the one node whose discovery.paths output is the
	// authoritative candidate set for $publish/$analyze. It is set only when an
	// enhancement node consumes and produces discovery.paths; old plans leave it
	// empty and keep their previous behavior.
	PathSourceNodeID string `json:"path_source_node_id,omitempty"`
}
type PluginCatalog interface {
	Get(context.Context, string, string) (plugin.Record, error)
}
type AdapterInputs struct {
	Schemas   []string
	Producers []string
}

type Compiler struct {
	AdapterInputs map[string]AdapterInputs
	Plugins       PluginCatalog
	Workflows     *Catalog
	Plans         PlanRepository
	Artifacts     artifact.Store
	Scopes        Scopes
	Knowledge     Knowledge
}

func (c *Compiler) Validate(ctx context.Context, raw json.RawMessage) (Validation, error) {
	if err := ctx.Err(); err != nil {
		return Validation{}, err
	}
	result := Validation{Diagnostics: []Diagnostic{}, Nodes: []CompiledNode{}}
	add := func(path, code, message string) {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{path, code, message})
	}
	spec, err := Parse(raw)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			schemaRaw, _ := contracts.Files.ReadFile("workflow.schema.json")
			schema, _, schemaErr := offlineSchema(schemaRaw)
			var value any
			if schemaErr == nil && len(raw) <= 256<<10 && json.Unmarshal(raw, &value) == nil {
				result.Diagnostics = schemaDiagnostics(schema, value, "", "schema", 0)
			} else {
				add("/", "schema", "Invalid JSON or definition exceeds 256 KiB")
			}
			return result, nil
		}
		return result, err
	}
	positions := map[string]int{}
	records := map[string]plugin.Record{}
	operations := map[string]plugin.Operation{}
	for i, node := range spec.Nodes {
		if _, exists := positions[node.ID]; exists {
			add(fmt.Sprintf("/nodes/%d/id", i), "duplicate_node", "Node ID must be unique")
			continue
		}
		positions[node.ID] = i
		record, err := c.Plugins.Get(ctx, node.PluginID, node.PluginVersion)
		if err != nil {
			if !errors.Is(err, plugin.ErrNotFound) {
				return result, err
			}
			add(fmt.Sprintf("/nodes/%d/plugin_version", i), "plugin_missing", "Plugin version is not registered")
			continue
		}
		if !record.Executable {
			add(fmt.Sprintf("/nodes/%d/plugin_version", i), "plugin_unavailable", "Plugin package has no installed execution adapter")
		}
		if record.Manifest.APIVersion == plugin.DefinitionVersion {
			if node.TimeoutSeconds > 3600 {
				add(fmt.Sprintf("/nodes/%d/timeout_seconds", i), "timeout_policy", "Stage operations permit at most 3600 seconds")
			}
			op, opErr := record.Manifest.Operation(node.OperationID)
			if opErr != nil {
				add(fmt.Sprintf("/nodes/%d/operation_id", i), "operation", "Select an operation declared by this plugin")
				continue
			}
			if err := plugin.ValidateDefinition(record.Manifest); err != nil {
				add(fmt.Sprintf("/nodes/%d/plugin_version", i), "capability", "Invalid stage or port contract")
				continue
			}
			if op.Profile != "native" && op.Profile != "standard" {
				add(fmt.Sprintf("/nodes/%d/operation_id", i), "operation", "Unknown operation profile")
				continue
			}
			_, resolved, configErr := offlineSchema(op.ConfigSchema)
			var config any
			if configErr != nil || json.Unmarshal(node.Config, &config) != nil || resolved.Validate(config) != nil {
				add(fmt.Sprintf("/nodes/%d/config", i), "config_schema", "Configuration does not match the operation schema")
			}
			operations[node.ID] = op
			records[node.ID] = record
			continue
		}
		if node.TimeoutSeconds > 120 {
			add(fmt.Sprintf("/nodes/%d/timeout_seconds", i), "timeout_policy", "Legacy adapters permit at most 120 seconds per node")
		}
		if node.OperationID != "" || len(node.InputBindings) > 0 {
			add(fmt.Sprintf("/nodes/%d/operation_id", i), "operation", "Legacy nodes do not expose named operations")
		}
		_, kindKnown := plugin.CapabilityForManifestKind(record.Manifest.Kind)
		primary, capabilityKnown := plugin.CapabilityForRecord(record)
		if !kindKnown || !capabilityKnown {
			add(fmt.Sprintf("/nodes/%d/plugin_version", i), "capability", "Plugin manifest declares an unknown capability")
			capabilityKnown = false
		}
		producedPrimary := false
		for _, kind := range append(append([]string{}, record.Manifest.Consumes...), record.Manifest.Produces...) {
			contract, ok := plugin.LookupContract(kind)
			if !ok {
				add(fmt.Sprintf("/nodes/%d/needs", i), "unknown_contract", "Unknown artifact contract "+kind)
				continue
			}
			if capabilityKnown && contract.Capability == string(primary) {
				for _, produced := range record.Manifest.Produces {
					if produced == kind {
						producedPrimary = true
					}
				}
			}
		}
		if capabilityKnown && !producedPrimary {
			add(fmt.Sprintf("/nodes/%d/plugin_version", i), "capability", "Plugin does not produce an artifact of its declared capability")
		}
		schema, resolved, err := offlineSchema(record.Manifest.ConfigSchema)
		if err != nil {
			add(fmt.Sprintf("/nodes/%d/config", i), "config_schema", "Plugin parameter schema cannot be resolved offline")
		} else {
			var config any
			_ = json.Unmarshal(node.Config, &config)
			if resolved.Validate(config) != nil {
				result.Diagnostics = append(result.Diagnostics, schemaDiagnostics(schema, config, fmt.Sprintf("/nodes/%d/config", i), "config_schema", 0)...)
			}
		}
		records[node.ID] = record
	}
	visited := map[string]int{}
	order := []string{}
	var visit func(string)
	visit = func(id string) {
		if visited[id] == 2 {
			return
		}
		i, ok := positions[id]
		if !ok {
			return
		}
		if visited[id] == 1 {
			add(fmt.Sprintf("/nodes/%d/needs", i), "cycle", "Dependencies contain a cycle")
			return
		}
		visited[id] = 1
		for j, need := range spec.Nodes[i].Needs {
			if _, ok := positions[need]; !ok {
				add(fmt.Sprintf("/nodes/%d/needs/%d", i, j), "missing_dependency", "Dependency node does not exist")
				continue
			}
			visit(need)
		}
		visited[id] = 2
		order = append(order, id)
	}
	ids := make([]string, 0, len(positions))
	for id := range positions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		visit(id)
	}
	for _, id := range order {
		i := positions[id]
		node := spec.Nodes[i]
		record, ok := records[id]
		if !ok || !record.Executable {
			continue
		}
		compiled := CompiledNode{Node: node, Plugin: record, ConfigDigest: Digest(node.Config), Inputs: []Binding{}, Outputs: record.Manifest.Produces}
		if op, ok := operations[id]; ok {
			compiled.Operation = &op
			compiled.OperationID = op.ID
			compiled.Outputs = []string{}
			for _, out := range op.Outputs {
				compiled.Outputs = append(compiled.Outputs, out.Kind)
			}
			bindings, diagnostics := c.compileOperationInputs(spec, node, op, records, operations, i)
			compiled.Inputs = bindings
			result.Diagnostics = append(result.Diagnostics, diagnostics...)
			result.Nodes = append(result.Nodes, compiled)
			continue
		}
		for inputIndex, kind := range record.Manifest.Consumes {
			sources := []Binding{}
			for _, root := range spec.Inputs {
				if root == kind {
					sources = append(sources, Binding{Source: "root", From: "root"})
				}
			}
			for _, need := range node.Needs {
				for _, output := range records[need].Manifest.Produces {
					if output == kind {
						sources = append(sources, Binding{Source: "node", From: need})
					}
				}
			}
			switch len(sources) {
			case 0:
				add(fmt.Sprintf("/nodes/%d/needs", i), "missing_input", "No root or direct dependency produces "+kind)
			case 1:
				policy := c.AdapterInputs[node.PluginID+"@"+node.PluginVersion]
				if len(policy.Schemas) != len(record.Manifest.Consumes) {
					add(fmt.Sprintf("/nodes/%d/plugin_version", i), "plugin_unavailable", "Installed input contract is unavailable")
					continue
				}
				owner := ""
				if inputIndex < len(policy.Producers) {
					owner = policy.Producers[inputIndex]
				}
				if sources[0].Source != "root" && owner != "" && records[sources[0].From].Manifest.ID != owner {
					add(fmt.Sprintf("/nodes/%d/needs", i), "input_producer", "Direct dependency is incompatible with the installed input contract")
					continue
				}
				compiled.Inputs = append(compiled.Inputs, Binding{Source: sources[0].Source, Kind: kind, From: sources[0].From, SchemaID: policy.Schemas[inputIndex], ProducerPlugin: owner})
			default:
				add(fmt.Sprintf("/nodes/%d/needs", i), "ambiguous_input", "Multiple root or direct dependency producers for "+kind)
			}
		}
		result.Nodes = append(result.Nodes, compiled)
	}
	pathSources := []string{}
	for _, node := range result.Nodes {
		if node.Operation != nil {
			if node.Operation.Stage == "path.enhance" {
				pathSources = append(pathSources, node.ID)
			}
			continue
		}
		consumesPaths, producesPaths := false, false
		for _, kind := range node.Plugin.Manifest.Consumes {
			if kind == "discovery.paths" {
				consumesPaths = true
			}
		}
		for _, kind := range node.Plugin.Manifest.Produces {
			if kind == "discovery.paths" {
				producesPaths = true
			}
		}
		if consumesPaths && producesPaths {
			pathSources = append(pathSources, node.ID)
		}
	}
	switch len(pathSources) {
	case 0:
	case 1:
		result.PathSourceNodeID = pathSources[0]
	default:
		add("/nodes", "ambiguous_path_source", "More than one node consumes and produces discovery.paths; select one enhancement node")
	}
	result.Valid = len(result.Diagnostics) == 0
	if !result.Valid {
		result.Nodes = []CompiledNode{}
		result.PathSourceNodeID = ""
	}
	return result, nil
}
