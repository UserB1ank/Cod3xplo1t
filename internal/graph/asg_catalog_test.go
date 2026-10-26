package graph_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestASGCatalogFiltersEntryPointsAndSinks(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	ctx := context.Background()

	httpEntries, err := fixture.asg.ListEntryPoints(ctx, agentSnapID, graph.ASGEntryPointQuery{
		Kind: asg.EntryHTTPRoute, Limit: 1,
	})
	if err != nil {
		t.Fatalf("ListEntryPoints(http): %v", err)
	}
	if httpEntries.Total < 2 || len(httpEntries.EntryPoints) != 1 {
		t.Fatalf("HTTP entry page = %d/%d, want a bounded page from at least two routes", len(httpEntries.EntryPoints), httpEntries.Total)
	}
	if !strings.HasPrefix(httpEntries.EntryPoints[0].Subject, asg.EntryHTTPRoute+":") {
		t.Errorf("kind filter leaked %q", httpEntries.EntryPoints[0].Subject)
	}
	if httpEntries.EntryPoints[0].Evidence == "" || httpEntries.EntryPoints[0].File == "" {
		t.Errorf("entry loses evidence or location: %+v", httpEntries.EntryPoints[0])
	}

	processEntries, err := fixture.asg.ListEntryPoints(ctx, agentSnapID, graph.ASGEntryPointQuery{
		Boundary: asg.BoundaryProcess, Limit: 20,
	})
	if err != nil {
		t.Fatalf("ListEntryPoints(process): %v", err)
	}
	if processEntries.Total == 0 {
		t.Fatal("CLI fixture produced no process-boundary entry")
	}
	for _, node := range processEntries.EntryPoints {
		if node.Detail["boundary"] != asg.BoundaryProcess {
			t.Errorf("boundary filter leaked %+v", node)
		}
	}

	processSinks, err := fixture.asg.ListSinks(ctx, agentSnapID, graph.ASGSinkQuery{
		Category: asg.SinkProcess, File: "web/server.go", Limit: 20,
	})
	if err != nil {
		t.Fatalf("ListSinks(process): %v", err)
	}
	if processSinks.Total == 0 || len(processSinks.Sinks) == 0 {
		t.Fatal("process sink fixture produced no sink")
	}
	for _, node := range processSinks.Sinks {
		if node.Subject != "sink:"+asg.SinkProcess || node.File != "web/server.go" || node.Evidence == "" {
			t.Errorf("sink filter leaked or lost evidence: %+v", node)
		}
	}

	if _, err := fixture.asg.ListEntryPoints(ctx, agentSnapID, graph.ASGEntryPointQuery{Kind: "wormhole"}); !errors.Is(err, graph.ErrInvalidArgument) {
		t.Errorf("unknown entry kind error = %v, want ErrInvalidArgument", err)
	}
	if _, err := fixture.asg.ListSinks(ctx, agentSnapID, graph.ASGSinkQuery{Category: "everything"}); !errors.Is(err, graph.ErrInvalidArgument) {
		t.Errorf("unknown sink category error = %v, want ErrInvalidArgument", err)
	}
}

func TestASGNodeViewStatesEvidenceLimits(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	ctx := context.Background()

	sinks, err := fixture.asg.ListSinks(ctx, agentSnapID, graph.ASGSinkQuery{Category: asg.SinkProcess})
	if err != nil || len(sinks.Sinks) == 0 {
		t.Fatalf("ListSinks: %v, %+v", err, sinks)
	}
	view, err := fixture.asg.Node(ctx, agentSnapID, sinks.Sinks[0].ID)
	if err != nil {
		t.Fatalf("Node: %v", err)
	}
	if len(view.DerivedFrom) == 0 {
		t.Error("node view has no resolved source evidence")
	}
	joined := strings.Join(view.Limitations, " ")
	if !strings.Contains(joined, "effectiveness") || !strings.Contains(joined, "not proof") {
		t.Errorf("node limitations do not distinguish presence from effectiveness or vulnerability: %v", view.Limitations)
	}
}

func TestASGSinkCatalogueFiltersPinnedRuleAndRiskPartition(t *testing.T) {
	t.Parallel()
	const snapshotID = "snap-sink-catalogue"
	makeSink := func(subject, discriminator string, detail map[string]string, generator string) asg.Node {
		return asg.Node{
			ID:         asg.NodeID(snapshotID, asg.NodeSensitiveOperation, subject, discriminator),
			SnapshotID: snapshotID, Kind: asg.NodeSensitiveOperation, Subject: subject,
			Label: subject, Detail: detail, Evidence: asg.StatusInferred,
			Confidence: scg.Inferred, Generator: generator, File: "src/Handler.java",
			Line: 10, SCGRefs: []string{"cs-" + discriminator},
		}
	}
	doc := &asg.Document{
		SchemaVersion: asg.SchemaVersion, SnapshotID: snapshotID,
		ASGVersion: "asg-catalogue", SCGVersion: "scg-catalogue",
		Engine:      asg.Engine{Name: "fixture", Version: "1"},
		RulesetHash: "rules", Nodes: []asg.Node{
			makeSink("sink:process_execution", "runtime", map[string]string{
				"sink_kind": asg.SinkProcess, "catalog_id": "java.process.runtime-exec",
				"catalog_version": "1.0.0", "catalog_digest": "catalog-digest",
				"method_full_name":    "java.lang.Runtime.exec:java.lang.Process(java.lang.String)",
				"dangerous_arguments": "[0]", "priority": "0.98", "has_flow": "false",
			}, "catalog:process_execution"),
			makeSink("sink:deserialization", "object", map[string]string{
				"sink_kind": asg.SinkDeserialization, "catalog_id": "java.deserialization.object-input",
				"catalog_version": "1.0.0", "catalog_digest": "catalog-digest",
				"method_full_name":    "java.io.ObjectInputStream.readObject:java.lang.Object()",
				"dangerous_arguments": "[]", "priority": "0.90", "has_flow": "true",
			}, "catalog:deserialization"),
			makeSink("sink:process_execution", "fallback", map[string]string{
				"sink_kind": asg.SinkProcess,
			}, "rule.sink"),
		},
		Limitations: []string{"static candidates only"},
	}
	store := storage.NewMemory()
	if err := store.ReplaceASG(t.Context(), snapshotID, doc); err != nil {
		t.Fatal(err)
	}
	service := graph.NewASGService(store, nil)

	noFlow := false
	highRisk, err := service.ListSinks(t.Context(), snapshotID, graph.ASGSinkQuery{
		Category: asg.SinkProcess, Partition: graph.ASGSinkPartitionHighRisk,
		RuleID: "java.process.runtime-exec", ReceiverType: "java.lang.Runtime",
		HasFlow: &noFlow,
	})
	if err != nil {
		t.Fatalf("ListSinks(high risk): %v", err)
	}
	if highRisk.Total != 1 || len(highRisk.Sinks) != 1 ||
		highRisk.Sinks[0].Detail["catalog_id"] != "java.process.runtime-exec" {
		t.Fatalf("high-risk rule page = %+v", highRisk)
	}
	if highRisk.Partitions.HighRisk != 2 || highRisk.Partitions.Unclassified != 1 {
		t.Fatalf("risk partition counts = %+v", highRisk.Partitions)
	}

	unclassified, err := service.ListSinks(t.Context(), snapshotID, graph.ASGSinkQuery{
		Partition: graph.ASGSinkPartitionUnclassified,
	})
	if err != nil {
		t.Fatalf("ListSinks(unclassified): %v", err)
	}
	if unclassified.Total != 1 || len(unclassified.Sinks) != 1 ||
		unclassified.Sinks[0].Generator != "rule.sink" {
		t.Fatalf("unclassified page = %+v", unclassified)
	}
}

func TestRepoMapIsCompactAndUsesRealCounts(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	repo, err := fixture.asg.RepoMap(context.Background(), agentSnapID)
	if err != nil {
		t.Fatalf("RepoMap: %v", err)
	}
	raw, err := json.Marshal(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 2000 {
		t.Fatalf("repo_map = %d bytes, want <= 2000 (approximately 500 tokens): %s", len(raw), raw)
	}
	if len(repo.Modules) == 0 || repo.EntryPointTotal == 0 || repo.SinkTotal == 0 {
		t.Fatalf("repo map is missing real distributions: %+v", repo)
	}
	if repo.EntryPointsByBoundary[asg.BoundaryNetwork] == 0 || repo.SinksByCategory[asg.SinkProcess] == 0 {
		t.Errorf("repo map distributions are empty: %+v", repo)
	}
	if repo.Coverage.CallSitesSeen == 0 {
		t.Errorf("repo map does not state call-site coverage: %+v", repo.Coverage)
	}
}
