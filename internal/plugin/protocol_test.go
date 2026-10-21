package plugin_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestDomainProtocolRegistryIsLocalAndVersioned(t *testing.T) {
	protocols := plugin.DomainProtocols()
	if len(protocols) < 7 {
		t.Fatalf("domain protocols = %d", len(protocols))
	}
	for _, protocol := range protocols {
		contract, ok := plugin.LookupContract(pluginContractKindForTest(protocol.Schema))
		if !ok {
			t.Fatalf("protocol %s has no artifact contract", protocol.Schema)
		}
		found := false
		for _, schema := range contract.Schemas {
			if schema == protocol.Schema {
				found = true
			}
		}
		if !found || protocol.Transport == "" || protocol.Direction == "" || protocol.File == "" {
			t.Fatalf("incomplete protocol = %+v", protocol)
		}
	}
	if _, ok := plugin.LookupDomainProtocol("codexploit/unknown/v1"); ok {
		t.Fatal("unknown domain protocol was accepted")
	}
	if got, ok := plugin.LookupDomainProtocol("codexploit/agent-task/v1"); !ok || got.Transport != plugin.TransportAgentRuntime {
		t.Fatalf("agent task protocol = %+v %v", got, ok)
	}
}

func TestManifestCapabilityRequiresItsOwnProducedContract(t *testing.T) {
	manifest := plugin.Manifest{
		APIVersion: "codexploit/v1", ID: "fixture.scanner", Version: "1.0.0", Name: "Scanner", Kind: "scanner",
		Languages: []string{"Go"}, Consumes: []string{"source.snapshot"}, Produces: []string{"scanner.alerts"},
		ConfigSchema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	}
	if err := plugin.ValidateManifestContracts(manifest); err != nil {
		t.Fatalf("scanner manifest rejected: %v", err)
	}
	wrong := manifest
	wrong.Produces = []string{"code.facts"}
	if err := plugin.ValidateManifestContracts(wrong); !errors.Is(err, plugin.ErrInvalid) {
		t.Fatalf("capability mismatch = %v", err)
	}
	unknown := manifest
	unknown.Produces = []string{"secret.unknown"}
	if err := plugin.ValidateManifestContracts(unknown); !errors.Is(err, plugin.ErrInvalid) {
		t.Fatalf("unknown contract = %v", err)
	}
}

func TestCatalogExposesRuntimeProtocolAndRejectsMismatch(t *testing.T) {
	ctx := context.Background()
	catalog, err := plugin.NewCatalog(ctx, storage.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	builtin, err := catalog.Get(ctx, plugin.BuiltinID, plugin.BuiltinVersion)
	if err != nil || builtin.ProtocolVersion != "builtin/v1" {
		t.Fatalf("builtin protocol = %+v %v", builtin, err)
	}
	manifest := func(id, protocol string) json.RawMessage {
		body := `{"api_version":"codexploit/v1","id":"` + id + `","version":"1.0.0","name":"Protocol scanner","description":"Synthetic","kind":"scanner","languages":["Go"],"runtime":{"kind":"process","entrypoint":"scanner"`
		if protocol != "" {
			body += `,"protocol":"` + protocol + `"`
		}
		body += `},"consumes":["source.snapshot"],"produces":["scanner.alerts"],"permissions":{"network":"none","source_write":false},"config_schema":{"type":"object","additionalProperties":false}}`
		return json.RawMessage(body)
	}
	record, err := catalog.Register(ctx, manifest("fixture.protocol", "other/v1"), strings.Repeat("a", 64), "synthetic fixture")
	if err != nil {
		t.Fatal(err)
	}
	if record.ProtocolVersion != "ndjson-jsonrpc/v1" || record.Executable || !strings.Contains(record.Reason, "protocol") {
		t.Fatalf("mismatched protocol = %+v", record)
	}
	record, err = catalog.Register(ctx, manifest("fixture.protocol-default", ""), strings.Repeat("b", 64), "synthetic fixture")
	if err != nil {
		t.Fatal(err)
	}
	if record.ProtocolVersion != "ndjson-jsonrpc/v1" || record.Executable {
		t.Fatalf("uninstalled protocol = %+v", record)
	}
}

func pluginContractKindForTest(schema string) string {
	switch schema {
	case "codexploit/agent-task/v1", "codexploit/agent-answer/v1":
		if schema == "codexploit/agent-task/v1" {
			return "agent.task"
		}
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
