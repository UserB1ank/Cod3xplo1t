package analysisengine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

// These are standard-contract fixtures, not a replacement for real Joern
// acceptance. They exercise the host projection and its provenance boundary.
func bundleFixture() Bundle {
	scope := artifact.Scope{ProjectID: "project", SnapshotID: "snapshot"}
	makeInput := func(id, operation, kind, schema, data string) Input {
		producer := artifact.Producer{PluginID: "codexploit.joern", PluginVersion: "2.1.0", PackageDigest: "package", InvocationID: "inv-" + operation, OperationID: operation, ConfigDigest: "config"}
		return Input{Ref: artifact.Ref{ID: id, Scope: scope, SHA256: id + "digest", Producer: producer, Kind: kind, SchemaID: schema}, Document: plugin.StageDocument{APIVersion: "codexploit/v2", Scope: scope, Producer: producer, Kind: kind, SchemaID: schema, Data: json.RawMessage(data)}}
	}
	code := makeInput("code", "parse", "code.facts", "codexploit/code-facts/v2", `{"files":[{"file_id":"file-a","path":"service.py","language":"Python","parse_status":"partial"}],"symbols":[{"id":"sym-entry","file_id":"file-a","name":"entry","qualified_name":"entry","kind":"function","location":{"file":"service.py","start_line":1}},{"id":"sym-sink","file_id":"file-a","name":"sink","qualified_name":"sink","kind":"function","location":{"file":"service.py","start_line":4}}],"calls":[],"native_id_mappings":[{"native_artifact_ref":"cpg-fixed","canonical_ref":"sym-entry"}]}`)
	sec := makeInput("security", "taint", "security.facts", "codexploit/security-facts/v2", `{"entries":[{"id":"entry-native","symbol_ref":"sym-entry","entry_kind":"test-rule","observed_or_inferred":"inferred","location":{"file":"service.py","start_line":1},"evidence_refs":["cpg-fixed"]}],"sinks":[{"id":"sink-native","symbol_ref":"sym-sink","operation_kind":"test-rule","location":{"file":"service.py","start_line":4},"evidence_refs":["cpg-fixed"]}],"relations":[{"id":"flow-native","from":"entry-native","to":"sink-native","kind":"taint_flow","observed_or_inferred":"observed","evidence_refs":["cpg-fixed"]}],"ruleset":{"digest":"rules-fixed"}}`)
	sec.Document.Inputs = []artifact.Ref{code.Ref}
	paths := makeInput("paths", "paths", "discovery.paths", "codexploit/discovery-paths/v2", `{"paths":[{"id":"path-native","entry_ref":"entry-native","sink_ref":"sink-native","basis":"data_flow","completeness":"partial","ordered_steps":[{"from_ref":"entry-native","to_ref":"sink-native","relation_ref":"flow-native"}],"evidence_refs":["flows-fixed"],"unresolved_segments":["source_trust_and_sanitizers_unassessed"],"limitations":[]}],"graph_pins":{"code":"code","security":"security"},"omitted":{"count":0,"reasons":[]}}`)
	paths.Document.Inputs = []artifact.Ref{code.Ref, sec.Ref, {ID: "flows-fixed", Scope: scope, Producer: sec.Ref.Producer}}
	return Bundle{Code: code, Security: sec, Generated: paths, Selected: paths, BuiltAt: "2026-10-23T00:00:00Z"}
}

func TestJoernProjectionCarriesUpstreamFlowTruncationIntoReview(t *testing.T) {
	b := bundleFixture()
	b.Security.Document.Coverage.Truncated = true
	b.Security.Document.Coverage.Reasons = []string{"flow_budget_exceeded"}
	b.Security.Document.Limitations = []string{"Flow enumeration reached max_flows; retained traces are not exhaustive."}
	got, err := (Joern{}).Project(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Paths.Coverage.Truncated || !strings.Contains(strings.Join(got.Paths.Coverage.TruncationReasons, ","), "flow_budget_exceeded") || !strings.Contains(strings.Join(got.Paths.Paths[0].Limitations, ","), "max_flows") {
		t.Fatalf("upstream coverage lost at review boundary: %+v", got.Paths)
	}
}

func TestJoernProjectionPreservesStaticEvidenceAndAgentReferences(t *testing.T) {
	b := bundleFixture()
	got, err := (Joern{}).Project(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Graph.Engine.Name != "codexploit.joern" || len(got.Graph.Symbols) != 2 || got.Graph.Coverage.FilesParsed != 1 || got.Graph.Coverage.FilesPartial != 1 || len(got.Paths.Paths) != 1 {
		t.Fatalf("projection: %+v", got)
	}
	p := got.Paths.Paths[0]
	if p.PathKind != "data_flow" || len(p.SCGRefs) != 2 || len(p.EvidenceRefs) == 0 || len(p.OpenQuestions) == 0 || len(p.Limitations) == 0 || p.Selection == nil {
		t.Fatalf("lost review evidence: %+v", p)
	}
	if got.Surface.Nodes[0].Evidence != asg.StatusInferred || len(got.Surface.Edges) != 1 || got.Surface.Edges[0].Detail["basis"] != "data_flow" {
		t.Fatal("projection promoted source trust or relabelled data flow")
	}
	if err := got.Surface.Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestJoernProjectionRejectsMixedEngineAndGraphPins(t *testing.T) {
	for _, mutate := range []func(*Bundle){
		func(b *Bundle) { b.Security.Document.Producer.PluginID = "other.engine" },
		func(b *Bundle) { b.Security.Document.Producer.PackageDigest = "other-release" },
		func(b *Bundle) {
			b.Selected.Document.Data = json.RawMessage(`{"paths":[],"graph_pins":{"code":"foreign-code","security":"security"}}`)
		},
		func(b *Bundle) { b.Security.Document.Inputs = nil },
	} {
		b := bundleFixture()
		mutate(&b)
		if _, err := (Joern{}).Project(b); err == nil {
			t.Fatal("accepted mixed lineage")
		}
	}
}

func TestJoernProjectionKeepsCatalogueSinksWithoutInventingFlows(t *testing.T) {
	b := bundleFixture()
	var security map[string]any
	if err := json.Unmarshal(b.Security.Document.Data, &security); err != nil {
		t.Fatal(err)
	}
	sinks := security["sinks"].([]any)
	security["sinks"] = append(sinks, map[string]any{
		"id": "sink-no-flow", "symbol_ref": "sym-sink", "operation_kind": "sink:deserialization",
		"observed_or_inferred": "inferred", "location": map[string]any{"file": "service.py", "start_line": 8},
		"evidence_refs": []string{"cpg-fixed"},
	})
	b.Security.Document.Data, _ = json.Marshal(security)
	got, err := (Joern{}).Project(b)
	if err != nil {
		t.Fatal(err)
	}
	sensitive := 0
	for _, node := range got.Surface.Nodes {
		if node.Kind == asg.NodeSensitiveOperation {
			sensitive++
		}
	}
	if sensitive != 2 || len(got.Surface.Edges) != 1 {
		t.Fatalf("zero-flow sink was dropped or given a fabricated edge: nodes=%d edges=%d", sensitive, len(got.Surface.Edges))
	}
}

func TestJoernProjectionCarriesCataloguePriorityIntoReviewOrdering(t *testing.T) {
	b := bundleFixture()
	var paths map[string]any
	if err := json.Unmarshal(b.Generated.Document.Data, &paths); err != nil {
		t.Fatal(err)
	}
	rows := paths["paths"].([]any)
	rows[0].(map[string]any)["priority_hint"] = 0.9
	b.Generated.Document.Data, _ = json.Marshal(paths)
	b.Selected = b.Generated
	got, err := (Joern{}).Project(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Paths.Paths) != 1 || got.Paths.Paths[0].Score.Priority <= 1 {
		t.Fatalf("catalogue priority did not affect review ordering: %+v", got.Paths.Paths)
	}
	if got.Paths.Paths[0].Features.Reasons["catalog_priority"] == "" || got.Paths.Paths[0].Score.Weights["catalog_priority"] != 0.5 {
		t.Fatalf("priority lineage is incomplete: %+v", got.Paths.Paths[0])
	}
}
