package plugin

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sync"

	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
)

// Capability is one reviewable stage of the pipeline. The manifest's kind names
// the plugin's primary capability; the artifact contracts below name the typed
// values it consumes and produces.
type Capability string

const (
	CapabilitySource       Capability = "source"
	CapabilityParse        Capability = "parse"
	CapabilitySemantic     Capability = "semantic"
	CapabilityScan         Capability = "scan"
	CapabilityPath         Capability = "path"
	CapabilityAgent        Capability = "agent"
	CapabilityEnvironment  Capability = "environment"
	CapabilityVerification Capability = "verification"
	CapabilityReport       Capability = "report"
)

var manifestCapabilities = map[string]Capability{
	"source":       CapabilitySource,
	"parser":       CapabilityParse,
	"analyzer":     CapabilitySemantic,
	"normalizer":   CapabilitySemantic,
	"graph":        CapabilityPath,
	"agent":        CapabilityAgent,
	"scanner":      CapabilityScan,
	"environment":  CapabilityEnvironment,
	"verification": CapabilityVerification,
	"reporter":     CapabilityReport,
}

// Contract declares one versioned artifact type. A kind may carry more than one
// schema version while old plans and records stay readable.
type Contract struct {
	Kind       string   `json:"kind"`
	Capability string   `json:"capability"`
	Schemas    []string `json:"schemas"`
}

type CapabilityInfo struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

type registry struct {
	Capabilities []CapabilityInfo
	Contracts    []Contract
	byKind       map[string]Contract
}

var contractRegistry = sync.OnceValues(func() (*registry, error) {
	raw, err := contracts.Files.ReadFile("artifact-contracts.json")
	if err != nil {
		return nil, ErrInvalid
	}
	var document struct {
		APIVersion   string           `json:"api_version"`
		Capabilities []CapabilityInfo `json:"capabilities"`
		Contracts    []Contract       `json:"contracts"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document.APIVersion != "codexploit/contracts/v1" {
		return nil, ErrInvalid
	}
	known := map[string]bool{}
	for _, capability := range document.Capabilities {
		if capability.Key == "" || capability.Label == "" || known[capability.Key] {
			return nil, ErrInvalid
		}
		known[capability.Key] = true
	}
	result := &registry{Capabilities: document.Capabilities, Contracts: document.Contracts, byKind: map[string]Contract{}}
	kindPattern := regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$`)
	schemaPattern := regexp.MustCompile(`^[a-z][a-z0-9-]*/[a-z][a-z0-9-]*/v[0-9]+$`)
	for _, contract := range document.Contracts {
		if !kindPattern.MatchString(contract.Kind) || !known[contract.Capability] || len(contract.Schemas) == 0 {
			return nil, ErrInvalid
		}
		for _, schema := range contract.Schemas {
			if !schemaPattern.MatchString(schema) {
				return nil, ErrInvalid
			}
		}
		if _, exists := result.byKind[contract.Kind]; exists {
			return nil, ErrInvalid
		}
		result.byKind[contract.Kind] = contract
	}
	return result, nil
})

// CapabilityForManifestKind maps a manifest kind to its capability. An unknown
// kind is rejected instead of being treated as an arbitrary executable plugin.
func CapabilityForManifestKind(kind string) (Capability, bool) {
	capability, ok := manifestCapabilities[kind]
	return capability, ok
}

// LookupContract resolves a declared artifact kind against the local registry.
// It never performs network resolution.
func LookupContract(kind string) (Contract, bool) {
	reg, err := contractRegistry()
	if err != nil {
		return Contract{}, false
	}
	contract, ok := reg.byKind[kind]
	return contract, ok
}

// Capabilities returns the ordered capability taxonomy for the catalog page.
func Capabilities() []CapabilityInfo {
	reg, err := contractRegistry()
	if err != nil {
		return nil
	}
	return append([]CapabilityInfo(nil), reg.Capabilities...)
}

// Contracts returns the registered artifact contracts.
func Contracts() []Contract {
	reg, err := contractRegistry()
	if err != nil {
		return nil
	}
	return append([]Contract(nil), reg.Contracts...)
}

// ValidateManifestContracts rejects unknown plugin capabilities and unknown
// artifact kinds at registration time. The check is local and deterministic.
func ValidateManifestContracts(manifest Manifest) error {
	if _, ok := CapabilityForManifestKind(manifest.Kind); !ok {
		return fmt.Errorf("%w: unknown plugin capability %q", ErrInvalid, manifest.Kind)
	}
	for _, kind := range append(append([]string{}, manifest.Consumes...), manifest.Produces...) {
		if _, ok := LookupContract(kind); !ok {
			return fmt.Errorf("%w: unknown artifact contract %q", ErrInvalid, kind)
		}
	}
	return nil
}
