package plugin

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
)

// DomainProtocol registers one versioned input/output type that is not a
// generic plugin Execute artifact. Agent runtimes, environment backends and
// verification executors have their own domain ports; this registry describes
// their envelopes without forcing them into the plugin call interface.
type DomainProtocol struct {
	Schema      string `json:"schema"`
	Capability  string `json:"capability"`
	Transport   string `json:"transport"`
	Direction   string `json:"direction"`
	File        string `json:"file"`
	Description string `json:"description"`
}

const (
	TransportPluginExecute        = "plugin_execute"
	TransportAgentRuntime         = "agent_runtime"
	TransportEnvironmentBackend   = "environment_backend"
	TransportVerificationExecutor = "verification_executor"
)

var domainProtocols = sync.OnceValues(loadDomainProtocols)

type domainRegistry struct {
	protocols []DomainProtocol
	bySchema  map[string]DomainProtocol
}

func loadDomainProtocols() (*domainRegistry, error) {
	raw, err := contracts.Files.ReadFile("domain-protocols.json")
	if err != nil {
		return nil, ErrInvalid
	}
	var document struct {
		APIVersion string           `json:"api_version"`
		Protocols  []DomainProtocol `json:"protocols"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document.APIVersion != "codexploit/contracts/v1" || len(document.Protocols) == 0 {
		return nil, ErrInvalid
	}
	registry := &domainRegistry{protocols: make([]DomainProtocol, 0, len(document.Protocols)), bySchema: map[string]DomainProtocol{}}
	for _, protocol := range document.Protocols {
		if _, exists := registry.bySchema[protocol.Schema]; exists {
			return nil, ErrInvalid
		}
		registry.protocols = append(registry.protocols, protocol)
		registry.bySchema[protocol.Schema] = protocol
	}
	return registry, nil
}

var (
	protocolSchemaPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*/[a-z][a-z0-9-]*/v[0-9]+$`)
	domainFilePattern     = regexp.MustCompile(`^[a-z][a-z0-9-]*\.schema\.json$`)
)

// validateDomainProtocols is called while the artifact contract registry is
// built. It proves that every domain schema is registered in both places, uses
// a controlled namespace, and resolves from an embedded local file without
// network access.
func validateDomainProtocols(registry *registry) error {
	if registry == nil {
		return ErrInvalid
	}
	document, err := domainProtocols()
	if err != nil {
		return err
	}
	capabilities := map[string]bool{}
	for _, capability := range registry.Capabilities {
		capabilities[capability.Key] = true
	}
	for _, protocol := range document.protocols {
		if !protocolSchemaPattern.MatchString(protocol.Schema) || !capabilities[protocol.Capability] {
			return ErrInvalid
		}
		switch protocol.Transport {
		case TransportPluginExecute, TransportAgentRuntime, TransportEnvironmentBackend, TransportVerificationExecutor:
		default:
			return ErrInvalid
		}
		switch protocol.Direction {
		case "input", "output", "bidirectional":
		default:
			return ErrInvalid
		}
		if path.Base(protocol.File) != protocol.File || !domainFilePattern.MatchString(protocol.File) {
			return ErrInvalid
		}
		contract, ok := registry.byKind[domainContractKind(protocol.Schema)]
		if !ok || !containsSchema(contract.Schemas, protocol.Schema) {
			return ErrInvalid
		}
		if _, err := localSchema(protocol.File); err != nil {
			return err
		}
	}
	return nil
}

// domainContractKind is intentionally explicit: the schema ID is not a kind, and
// guessing a kind from it would let a new file silently bind to the wrong
// capability contract. The mapping is reviewed with domain-protocols.json.
func domainContractKind(schema string) string {
	switch schema {
	case "codexploit/agent-task/v1":
		return "agent.task"
	case "codexploit/agent-answer/v1":
		return "agent.answer"
	case "codexploit/environment-request/v1":
		return "environment.request"
	case "codexploit/environment-receipt/v1":
		return "environment.receipt"
	case "codexploit/verification-plan/v1":
		return "verification.plan"
	case "codexploit/verification-evidence/v1":
		return "verification.evidence"
	case "codexploit/path-enhancement/v1":
		return "path.enhancement"
	default:
		return ""
	}
}

func containsSchema(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func localSchema(name string) (*jsonschema.Resolved, error) {
	if path.Base(name) != name || !strings.HasSuffix(name, ".schema.json") {
		return nil, ErrInvalid
	}
	raw, err := contracts.Files.ReadFile(name)
	if err != nil {
		return nil, ErrInvalid
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, ErrInvalid
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
		if uri == nil || uri.Scheme != "https" || uri.Host != "codexploit.invalid" || path.Dir(uri.Path) != "/contracts/v1" {
			return nil, ErrInvalid
		}
		loader := path.Base(uri.Path)
		if path.Base(loader) != loader {
			return nil, ErrInvalid
		}
		referenced, err := contracts.Files.ReadFile(loader)
		if err != nil {
			return nil, ErrInvalid
		}
		var value jsonschema.Schema
		if err := json.Unmarshal(referenced, &value); err != nil {
			return nil, ErrInvalid
		}
		return &value, nil
	}})
	if err != nil {
		return nil, fmt.Errorf("%w: domain schema %s: %v", ErrInvalid, name, err)
	}
	return resolved, nil
}

// DomainProtocols returns the validated domain protocol table. It is copied so a
// caller cannot mutate the registry used by validation.
func DomainProtocols() []DomainProtocol {
	if _, err := contractRegistry(); err != nil {
		return nil
	}
	document, err := domainProtocols()
	if err != nil {
		return nil
	}
	return append([]DomainProtocol(nil), document.protocols...)
}

// LookupDomainProtocol resolves a domain schema ID locally. Unknown IDs are
// rejected; no network resolution is attempted.
func LookupDomainProtocol(schema string) (DomainProtocol, bool) {
	if _, err := contractRegistry(); err != nil {
		return DomainProtocol{}, false
	}
	document, err := domainProtocols()
	if err != nil {
		return DomainProtocol{}, false
	}
	protocol, ok := document.bySchema[schema]
	return protocol, ok
}
