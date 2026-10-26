package plugin

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v2"
)

const DefinitionVersion = "codexploit/plugin/v2"
const FileJobProtocol = "codexploit/file-job/v1"
const FileJobProtocolV2 = "codexploit/file-job/v2"
const ProcessProtocolV2 = "codexploit/process-plugin/v2"

type Port struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	SchemaID    string `json:"schema_id"`
	Cardinality string `json:"cardinality"`
	Required    bool   `json:"required"`
}

type Operation struct {
	ID           string          `json:"id"`
	Stage        string          `json:"stage"`
	Capability   Capability      `json:"capability"`
	Profile      string          `json:"profile"`
	Inputs       []Port          `json:"inputs"`
	Outputs      []Port          `json:"outputs"`
	ConfigSchema json.RawMessage `json:"config_schema"`
}

type Stage struct {
	Stage      string     `json:"stage"`
	Capability Capability `json:"capability"`
	Label      string     `json:"label"`
	Transport  string     `json:"transport"`
	Profile    string     `json:"profile"`
	Inputs     []Port     `json:"inputs"`
	Outputs    []Port     `json:"outputs"`
	InputData  []string   `json:"input_data"`
	OutputData []string   `json:"output_data"`
}

var stageRegistry = sync.OnceValues(func() ([]Stage, error) {
	raw, err := contracts.Files.ReadFile("stages.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Stages []Stage `json:"stages"`
	}
	err = json.Unmarshal(raw, &doc)
	return doc.Stages, err
})

func Stages() []Stage {
	rows, err := stageRegistry()
	if err != nil {
		return nil
	}
	raw, _ := json.Marshal(rows)
	var result []Stage
	_ = json.Unmarshal(raw, &result)
	return result
}

func resolveV2Schema(name string) (*jsonschema.Resolved, error) {
	raw, err := contracts.Files.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err = json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(*url.URL) (*jsonschema.Schema, error) { return nil, ErrInvalid }})
}

var definitionSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) { return resolveV2Schema("manifest.schema.json") })

func schemaForManifest(raw []byte) (*jsonschema.Resolved, error) {
	var header struct {
		APIVersion string `json:"api_version"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return nil, ErrInvalid
	}
	if header.APIVersion == DefinitionVersion {
		return definitionSchema()
	}
	return manifestSchema()
}

func ValidateDefinition(manifest Manifest) error {
	if manifest.APIVersion != DefinitionVersion {
		if _, err := resolveConfig(manifest.ConfigSchema); err != nil {
			return err
		}
		return ValidateManifestContracts(manifest)
	}
	stages, err := stageRegistry()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	toolIDs := map[string]bool{}
	for _, tool := range manifest.Tools {
		if toolIDs[tool.ID] || tool.Version == "latest" || tool.Version == "main" || tool.Version == "master" {
			return ErrInvalid
		}
		toolIDs[tool.ID] = true
		if _, err := safeEntrypoint(tool.Entrypoint); err != nil {
			return err
		}
	}
	for _, op := range manifest.Operations {
		if seen[op.ID] {
			return fmt.Errorf("%w: duplicate operation", ErrInvalid)
		}
		seen[op.ID] = true
		if _, err := resolveConfig(op.ConfigSchema); err != nil {
			return err
		}
		var stage *Stage
		for i := range stages {
			if stages[i].Stage == op.Stage {
				stage = &stages[i]
				break
			}
		}
		if stage == nil || op.Capability != stage.Capability {
			return fmt.Errorf("%w: stage capability mismatch", ErrInvalid)
		}
		for _, ports := range [][]Port{op.Inputs, op.Outputs} {
			names := map[string]bool{}
			for _, port := range ports {
				if names[port.Name] {
					return fmt.Errorf("%w: duplicate port", ErrInvalid)
				}
				names[port.Name] = true
				if !KnownPortContract(port) {
					return fmt.Errorf("%w: unknown port contract", ErrInvalid)
				}
			}
		}
		if op.Profile == "standard" {
			for i, wanted := range [][]Port{stage.Inputs, stage.Outputs} {
				actual := op.Inputs
				if i == 1 {
					actual = op.Outputs
				}
				for _, required := range wanted {
					found := false
					for _, p := range actual {
						if p.Kind == required.Kind && (p.SchemaID == required.SchemaID || (p.Kind == "source.snapshot" && p.SchemaID == "codexploit/source-directory/v1")) && p.Required {
							found = true
						}
					}
					if !found {
						return fmt.Errorf("%w: stage required port missing", ErrInvalid)
					}
				}
			}
		} else {
			if stage.Transport != "plugin_execute" {
				return ErrInvalid
			}
			for _, out := range op.Outputs {
				if out.Kind != "tool.native" {
					return ErrInvalid
				}
			}
		}
		if manifest.Runtime.Kind == "process" && stage.Transport != "plugin_execute" {
			return fmt.Errorf("%w: domain stage requires its domain adapter", ErrInvalid)
		}
		if manifest.Runtime.Kind != "process" && manifest.Runtime.Kind != stage.Transport {
			return ErrInvalid
		}
		if manifest.Permissions.TargetExecution != nil && *manifest.Permissions.TargetExecution && op.Stage != "environment" && op.Stage != "verification" {
			return ErrInvalid
		}
	}
	return nil
}

func KnownPortContract(port Port) bool {
	if port.Kind == "tool.native" {
		return port.SchemaID == "joern/cpg/v1" || port.SchemaID == "codexploit/native-bytes/v1"
	}
	if contract, ok := LookupContract(port.Kind); ok {
		for _, s := range contract.Schemas {
			if s == port.SchemaID {
				return true
			}
		}
	}
	rows, err := stageRegistry()
	if err != nil {
		return false
	}
	for _, stage := range rows {
		for _, ports := range [][]Port{stage.Inputs, stage.Outputs} {
			for _, p := range ports {
				if p.Kind == port.Kind && p.SchemaID == port.SchemaID {
					return true
				}
			}
		}
	}
	return false
}

func (m Manifest) Operation(id string) (Operation, error) {
	if id == "" && len(m.Operations) == 1 {
		return m.Operations[0], nil
	}
	for _, op := range m.Operations {
		if op.ID == id {
			return op, nil
		}
	}
	return Operation{}, ErrInvalid
}

// DefinitionStages is explicit for v2. Legacy IDs appear only in the migration
// compatibility layer; new plugins never infer their stage from a tool name.
func DefinitionStages(m Manifest) []string {
	stages := []string{}
	seen := map[string]bool{}
	if m.APIVersion == DefinitionVersion {
		for _, op := range m.Operations {
			if !seen[op.Stage] {
				stages = append(stages, op.Stage)
				seen[op.Stage] = true
			}
		}
		return stages
	}
	if m.ID == "builtin.path-enhancer" {
		return []string{"path.enhance"}
	}
	capability, ok := CapabilityForRecord(Record{Manifest: m})
	if !ok {
		return stages
	}
	stage := string(capability)
	if capability == CapabilityPath {
		stage = "path.generate"
	}
	return []string{stage}
}
