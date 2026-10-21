package builtinanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

func enhancementFixture() (plugin.Invocation, plugin.DiscoveryDocument, plugin.NativeReport) {
	scope := artifact.Scope{ProjectID: "proj-enhance", SnapshotID: "snap-enhance"}
	inv := plugin.Invocation{ID: "inv-enhance", Request: plugin.Request{
		APIVersion: "codexploit/v1", PluginID: "builtin.path-enhancer", PluginVersion: "1.0.0",
		Scope: scope, Config: json.RawMessage(`{"max_paths":2}`),
		Inputs: []artifact.Ref{
			{ID: "artifact-paths", Scope: scope, Kind: "discovery.paths", SchemaID: "codexploit/discovery/v1", Producer: artifact.Producer{PluginID: "builtin.discovery-paths", InvocationID: "inv-paths"}},
			{ID: "artifact-native", Scope: scope, Kind: "report.document", SchemaID: "codexploit/builtin-native/v1", Producer: artifact.Producer{PluginID: "builtin.discovery-paths", InvocationID: "inv-paths"}},
		},
	}}
	makePath := func(id, entry, target string, priority float64, status path.PathStatus) path.Path {
		return path.Path{
			ID: id, SnapshotID: scope.SnapshotID, SCGVersion: "g1", ASGVersion: "a1",
			EntryNodeID: entry, EntrySubject: "GET /" + entry, TargetNodeID: target, TargetSubject: "sink:sql_execution",
			PathKind: path.PathKindCallGraph, PathStatus: status, Status: path.StatusDiscovered,
			Score:       path.Score{Priority: priority, Risk: 0.8, Support: 0.7, Utility: 0.6, ScoreVersion: path.ScoreVersion, Weights: map[string]float64{"risk.exposure": 0.25, "priority.risk": 0.55}},
			Limitations: []string{"call reachability is not taint flow"},
		}
	}
	paths := []path.Path{
		makePath("p1", "entry-a", "sink-a", 90, path.PathStaticallySupported),
		makePath("p2", "entry-a", "sink-b", 50, path.PathStaticallySupported),
		makePath("p3", "entry-b", "sink-c", 20, path.PathStaticallySupported),
		makePath("p4", "entry-c", "sink-d", 95, path.PathUnresolved),
	}
	report := plugin.NativeReport{
		Format: "codexploit/paths-native/v1", Scope: scope,
		Graph:   &scg.Graph{SnapshotID: scope.SnapshotID, GraphVersion: "g1"},
		Surface: &asg.Document{SnapshotID: scope.SnapshotID, ASGVersion: "a1", SCGVersion: "g1"},
		Paths:   &path.GenerateResult{SnapshotID: scope.SnapshotID, SCGVersion: "g1", ASGVersion: "a1", Paths: paths},
	}
	discovery := plugin.DiscoveryDocument{APIVersion: "codexploit/v1", Kind: "discovery.paths", Scope: scope}
	for _, p := range paths {
		discovery.Paths = append(discovery.Paths, plugin.DiscoveryPath{ID: p.ID, Kind: "call_reachability", Completeness: "complete", EvidenceClass: string(p.PathStatus)})
	}
	return inv, discovery, report
}

func TestEnhancementSelectsAndExplainsWithoutChangingPathIdentity(t *testing.T) {
	inv, discovery, report := enhancementFixture()
	result, err := enhancePaths(context.Background(), inv, discovery, report)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths.Paths) != 2 {
		t.Fatalf("selected paths = %d, want 2", len(result.Paths.Paths))
	}
	if result.Paths.Paths[0].ID != "p1" || result.Paths.Paths[1].ID != "p2" {
		t.Fatalf("selected order = %s, %s", result.Paths.Paths[0].ID, result.Paths.Paths[1].ID)
	}
	if result.Paths.Paths[0].Score.ScoreVersion != path.ScoreVersion || result.Paths.Paths[0].Score.Priority <= 0 {
		t.Fatalf("enhancement did not score the path: %+v", result.Paths.Paths[0].Score)
	}
	for _, p := range result.Paths.Paths {
		if p.Selection == nil || p.Selection.Selection != "selected" || p.Selection.SourcePathID != p.ID || p.Selection.WeightsDigest == "" {
			t.Fatalf("selection missing from %+v", p)
		}
		if !strings.Contains(p.Selection.Reason, "scheduling") || !strings.Contains(p.Selection.Reason, "not a severity") {
			t.Fatalf("selection overclaims: %q", p.Selection.Reason)
		}
	}
	if result.Enhancement == nil || len(result.Enhancement.Selected) != 2 || len(result.Enhancement.Filtered) != 2 {
		t.Fatalf("enhancement summary = %+v", result.Enhancement)
	}
	for _, selected := range result.Enhancement.Selected {
		if selected.Selection.Reason == "" || !strings.Contains(selected.Selection.Reason, "scheduling") {
			t.Fatalf("selected summary has no explanation: %+v", selected)
		}
	}
	codes := map[string]string{}
	for _, filtered := range result.Enhancement.Filtered {
		codes[filtered.PathID] = filtered.Selection.FilterCode
	}
	if codes["p3"] != "path_budget" || codes["p4"] != "path_budget" {
		t.Fatalf("filter codes = %+v", codes)
	}
	for _, note := range result.Limitations {
		if strings.Contains(note, "proof that a path is safe") {
			return
		}
	}
	t.Fatalf("missing filter disclaimer: %+v", result.Limitations)
}

func TestEnhancementRejectsMismatchedInputsAndExplorationWhenDisabled(t *testing.T) {
	inv, discovery, report := enhancementFixture()
	discovery.Paths = discovery.Paths[:3]
	if _, err := enhancePaths(context.Background(), inv, discovery, report); !errors.Is(err, plugin.ErrInvalid) {
		t.Fatalf("mismatched inputs = %v", err)
	}
	inv, discovery, report = enhancementFixture()
	inv.Request.Config = json.RawMessage(`{"max_paths":2,"min_priority":0,"keep_exploration":false}`)
	result, err := enhancePaths(context.Background(), inv, discovery, report)
	if err != nil {
		t.Fatal(err)
	}
	for _, filtered := range result.Enhancement.Filtered {
		if filtered.PathID == "p4" && filtered.Selection.FilterCode == "exploration_disabled" {
			return
		}
	}
	t.Fatalf("exploration filter missing: %+v", result.Enhancement.Filtered)
}

func TestEnhancementScoresUnscoredUpstreamPathsDeterministically(t *testing.T) {
	inv, discovery, report := enhancementFixture()
	for i := range report.Paths.Paths {
		report.Paths.Paths[i].Score = path.Score{}
		report.Paths.Paths[i].Features = path.Features{}
	}
	first, err := enhancePaths(context.Background(), inv, discovery, report)
	if err != nil {
		t.Fatal(err)
	}
	second, err := enhancePaths(context.Background(), inv, discovery, report)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first.Enhancement)
	secondJSON, _ := json.Marshal(second.Enhancement)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("enhancement is not deterministic: %s / %s", firstJSON, secondJSON)
	}
	if first.Enhancement.ScoreVersion != path.ScoreVersion || first.Enhancement.WeightsDigest == "" {
		t.Fatalf("score provenance missing: %+v", first.Enhancement)
	}
	for _, selected := range first.Paths.Paths {
		if selected.Features.Reasons == nil || selected.Score.Weights == nil {
			t.Fatalf("scored path lost reasons/weights: %+v", selected)
		}
	}
}
