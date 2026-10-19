package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

const testSchema = `{"type":"object","properties":{"symbol_id":{"type":"string","maxLength":8},"limit":{"type":"integer","minimum":1,"maximum":10},"flag":{"type":"boolean"},"kind":{"type":"string","enum":["function","method"]}},"required":["symbol_id"],"additionalProperties":false}`

func TestToolSchemaParsesAndRejectsBrokenDocuments(t *testing.T) {
	if _, err := ParseToolSchema(json.RawMessage(testSchema)); err != nil {
		t.Fatalf("valid schema rejected: %v", err)
	}
	for name, broken := range map[string]string{
		"empty":            ``,
		"not object":       `{"type":"array"}`,
		"open additional":  `{"type":"object","properties":{},"additionalProperties":true}`,
		"unsupported type": `{"type":"object","properties":{"x":{"type":"number"}}}`,
		"required missing": `{"type":"object","properties":{},"required":["x"]}`,
		"bad enum":         `{"type":"object","properties":{"x":{"type":"integer","enum":["a"]}}}`,
	} {
		if _, err := ParseToolSchema(json.RawMessage(broken)); err == nil {
			t.Errorf("%s schema was accepted", name)
		}
	}
}

func TestToolSchemaValidatesNativeArguments(t *testing.T) {
	valid := map[string]string{
		`{"symbol_id":"sym-1"}`:                       "",
		`{"symbol_id":"sym-1","limit":5,"flag":true}`: "",
		`{"symbol_id":"sym-1","kind":"method"}`:       "",
	}
	for args, want := range valid {
		if err := ValidateToolArgs(json.RawMessage(testSchema), json.RawMessage(args)); err != nil {
			t.Errorf("%s: %v (want %q)", args, err, want)
		}
	}
	invalid := map[string]string{
		`{}`:                                   "is required",
		`{"symbol_id":"sym-1","extra":1}`:      "unknown argument",
		`{"symbol_id":1}`:                      "must be a string",
		`{"symbol_id":"sym-1","limit":"5"}`:    "must be an integer",
		`{"symbol_id":"sym-1","limit":5.5}`:    "must be an integer",
		`{"symbol_id":"sym-1","limit":0}`:      "below 1",
		`{"symbol_id":"sym-1","limit":11}`:     "above 10",
		`{"symbol_id":"sym-1","flag":"true"}`:  "must be a boolean",
		`{"symbol_id":"sym-1","kind":"class"}`: "not one of",
	}
	for args, want := range invalid {
		err := ValidateToolArgs(json.RawMessage(testSchema), json.RawMessage(args))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", args, err, want)
		}
	}
}

func TestLegacyToolArgsConvertsDeclaredFieldsOnly(t *testing.T) {
	raw, err := LegacyToolArgs(json.RawMessage(testSchema), map[string]string{
		"symbol_id": "sym-1", "limit": "5", "flag": "true", "kind": "function",
		"snapshot_id": "snap-other", // protocol-v1 scope field: dropped, not forwarded
	})
	if err != nil {
		t.Fatalf("legacy conversion: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["limit"] != float64(5) || fields["flag"] != true || fields["kind"] != "function" {
		t.Fatalf("legacy values did not keep their types: %s", raw)
	}
	if _, ok := fields["snapshot_id"]; ok {
		t.Fatalf("a v1 scope field was forwarded: %s", raw)
	}
	if _, err := LegacyToolArgs(json.RawMessage(testSchema), map[string]string{"symbol_id": "sym", "limit": "many"}); err == nil {
		t.Fatal("a non-integer legacy limit was accepted")
	}
	if _, err := LegacyToolArgs(json.RawMessage(testSchema), map[string]string{"symbol_id": "sym", "flag": "yes"}); err == nil {
		t.Fatal("a non-boolean legacy flag was accepted")
	}
}

func TestToolSchemaDigestPinsTheContract(t *testing.T) {
	a := []ToolDescriptor{{Name: "b", Version: "1", InputSchema: json.RawMessage(testSchema)}}
	b := []ToolDescriptor{{Name: "b", Version: "2", InputSchema: json.RawMessage(testSchema)}}
	digest := ToolSchemaDigest(a)
	if digest != ToolSchemaDigest(a) {
		t.Fatal("digest is not deterministic")
	}
	if ToolSchemaDigest(a) == ToolSchemaDigest(b) {
		t.Fatal("a version bump did not change the digest")
	}
	reordered := []ToolDescriptor{a[0], {Name: "a", Version: "1", InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)}}
	flipped := []ToolDescriptor{reordered[1], reordered[0]}
	if ToolSchemaDigest(reordered) != ToolSchemaDigest(flipped) {
		t.Fatal("digest depends on descriptor order")
	}
}
