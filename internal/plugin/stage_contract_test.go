package plugin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

func TestStageCoverageRejectsContradictoryCounters(t *testing.T) {
	n := func(v int64) *int64 { return &v }
	for _, c := range []StageCoverage{
		{Unit: "files", Seen: n(-1)},
		{Unit: "files", Seen: n(1), Analyzed: n(2)},
		{Unit: "files", Seen: n(2), Analyzed: n(2), Skipped: n(1), Failed: n(0)},
		{Unit: "files", Truncated: true},
	} {
		if validateStageCoverage("SUCCEEDED", c) == nil {
			t.Fatalf("accepted contradictory successful coverage: %+v", c)
		}
	}
	if err := validateStageCoverage("PARTIAL", StageCoverage{Unit: "files", Truncated: true, Reasons: []string{"budget"}}); err != nil {
		t.Fatal(err)
	}
}

func TestPathEnhancementPreservesInputAndPartitionsIDs(t *testing.T) {
	input := json.RawMessage(`{"paths":[{"id":"p","basis":"hypothesis","completeness":"partial","ordered_steps":[]}],"graph_pins":{"code":"c","security":"s"},"omitted":{"count":0,"reasons":[]}}`)
	retained := input
	enhancement := json.RawMessage(`{"source_path_artifact":"input-paths","selected":[{"path_id":"p","rank":1,"score":1,"features":{},"reason_codes":["test"]}],"filtered":[],"scoring_version":"v1","weights_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := validateEnhancement("input-paths", input, retained, enhancement); err != nil {
		t.Fatal(err)
	}
	forged := json.RawMessage(strings.Replace(string(retained), `"hypothesis"`, `"data_flow"`, 1))
	if validateEnhancement("input-paths", input, forged, enhancement) == nil {
		t.Fatal("accepted rewritten path")
	}
	missing := json.RawMessage(strings.Replace(string(enhancement), `"path_id":"p"`, `"path_id":"other"`, 1))
	if validateEnhancement("input-paths", input, retained, missing) == nil {
		t.Fatal("accepted incomplete partition")
	}
}

func TestSemanticAndPathReferencesMustBelongToFixedInputs(t *testing.T) {
	inv := Invocation{Request: Request{Inputs: []artifact.Ref{{ID: "code-input", SchemaID: "codexploit/code-facts/v2"}, {ID: "security-input", SchemaID: "codexploit/security-facts/v2"}}}}
	inputs := [][]byte{[]byte(`{"api_version":"codexploit/v2","data":{"symbols":[{"id":"caller"},{"id":"callee"}],"calls":[{"id":"call","caller_ref":"caller","callee_ref":"callee","resolution":"resolved"}]}}`), []byte(`{"api_version":"codexploit/v2","data":{"entries":[{"id":"entry"}],"sinks":[{"id":"sink"}],"controls":[],"relations":[]}}`)}
	semantic := []byte(`{"entries":[{"id":"entry","symbol_ref":"forged"}],"sinks":[],"controls":[],"relations":[]}`)
	if validateStageReferences(inv, inputs, "codexploit/security-facts/v2", semantic) == nil {
		t.Fatal("accepted foreign symbol")
	}
	paths := []byte(`{"paths":[{"id":"p","entry_ref":"entry","sink_ref":"sink","basis":"call_reachability","completeness":"complete","ordered_steps":[{"from_ref":"caller","to_ref":"callee","relation_ref":"call"}],"unresolved_segments":[]}],"graph_pins":{"code":"code-input","security":"security-input"}}`)
	if err := validateStageReferences(inv, inputs, "codexploit/discovery-paths/v2", paths); err != nil {
		t.Fatal(err)
	}
	if validateStageReferences(inv, inputs, "codexploit/discovery-paths/v2", []byte(strings.Replace(string(paths), "call_reachability", "data_flow", 1))) == nil {
		t.Fatal("call edge promoted to data flow")
	}
}

func TestReportDocumentValidatesActualFormat(t *testing.T) {
	if validateReport("application/json", []byte(`{"truncated":`)) == nil {
		t.Fatal("accepted broken JSON")
	}
	if validateReport("application/sarif+json", []byte(`{"version":"1.0","runs":[]}`)) == nil {
		t.Fatal("accepted incompatible SARIF")
	}
	if err := validateReport("text/markdown; charset=utf-8", []byte("# Fixed report\n")); err != nil {
		t.Fatal(err)
	}
}

func TestCodeNormalizationUsesStableHostIDs(t *testing.T) {
	inv := Invocation{Request: Request{Scope: artifact.Scope{SnapshotID: "fixed"}}}
	raw := []byte(`{"files":[{"file_id":"local-file","path":"main.go","language":"Go"}],"symbols":[{"id":"local-symbol","file_id":"local-file","qualified_name":"main.main","signature":"func main()","location":null}],"calls":[],"native_id_mappings":[]}`)
	a, err := normalizeCodeIDs(inv, raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := normalizeCodeIDs(inv, []byte(strings.ReplaceAll(string(raw), "local-", "other-")))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) || strings.Contains(string(a), "local-symbol") {
		t.Fatal("tool-local ID changed canonical identity")
	}
}
