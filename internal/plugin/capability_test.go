package plugin

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestCapabilityRegistryCoversManifestContracts(t *testing.T) {
	if len(Capabilities()) != 9 {
		t.Fatalf("capabilities = %d", len(Capabilities()))
	}
	contract, ok := LookupContract("source.snapshot")
	if !ok || contract.Capability != string(CapabilitySource) || len(contract.Schemas) == 0 {
		t.Fatalf("source.snapshot contract = %+v", contract)
	}
	if _, ok := LookupContract("unknown.kind"); ok {
		t.Fatal("unknown contract was accepted")
	}
	if capability, ok := CapabilityForManifestKind("scanner"); !ok || capability != CapabilityScan {
		t.Fatalf("scanner capability = %s %v", capability, ok)
	}
	if _, ok := CapabilityForManifestKind("mystery"); ok {
		t.Fatal("unknown capability was accepted")
	}
}

func TestManifestContractValidationRejectsUnknownTypes(t *testing.T) {
	var builtin Manifest
	if err := json.Unmarshal(BuiltinManifest(), &builtin); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestContracts(builtin); err != nil {
		t.Fatalf("builtin manifest rejected: %v", err)
	}
	unknownType := builtin
	unknownType.Produces = append(append([]string{}, builtin.Produces...), "secret.unknown")
	if err := ValidateManifestContracts(unknownType); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown produce = %v", err)
	}
	unknownKind := builtin
	unknownKind.Kind = "mystery"
	if err := ValidateManifestContracts(unknownKind); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown kind = %v", err)
	}
}
