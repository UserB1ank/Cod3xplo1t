package storage

import (
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"testing"
)

func TestPostgresGraphLayerReplacementRollsBackAsAUnit(t *testing.T) {
	store, _ := postgresKnowledgeStores(t)
	graph := &scg.Graph{SnapshotID: "snapshot-engine", GraphVersion: "graph-old", Engine: scg.Engine{Name: "legacy", Version: "1"}}
	surface := &asg.Document{SnapshotID: graph.SnapshotID, SCGVersion: graph.GraphVersion, ASGVersion: "asg-old", Nodes: []asg.Node{}, Edges: []asg.Edge{}}
	if err := store.ReplaceGraphLayers(t.Context(), graph.SnapshotID, graph, surface); err != nil {
		t.Fatal(err)
	}
	next := *graph
	next.GraphVersion = "graph-new"
	bad := *surface
	bad.SCGVersion = next.GraphVersion
	bad.ASGVersion = "asg-new"
	// A duplicate ASG id fails after graph replacement has already run inside
	// the transaction. Neither layer may advance when the transaction rolls back.
	node := asg.Node{ID: "asgn-duplicate", SnapshotID: graph.SnapshotID, Kind: asg.NodeEntryPoint, Subject: "entry", SCGRefs: []string{"sym-entry"}}
	bad.Nodes = []asg.Node{node, node}
	if err := store.ReplaceGraphLayers(t.Context(), graph.SnapshotID, &next, &bad); err == nil {
		t.Fatal("accepted duplicate semantic nodes")
	}
	got, err := store.GraphSummary(t.Context(), graph.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.ASGSummary(t.Context(), graph.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if got.GraphVersion != "graph-old" || a.ASGVersion != "asg-old" {
		t.Fatal("failed engine replacement left mixed versions")
	}
	bad.Nodes = []asg.Node{}
	if err := store.ReplaceGraphLayers(t.Context(), graph.SnapshotID, &next, &bad); err != nil {
		t.Fatal(err)
	}
	got, _ = store.GraphSummary(t.Context(), graph.SnapshotID)
	a, _ = store.ASGSummary(t.Context(), graph.SnapshotID)
	if got.GraphVersion != a.SCGVersion || a.ASGVersion != "asg-new" {
		t.Fatal("new engine layers were not replaced together")
	}
}
