package mcp_test

import (
	"context"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	internalmcp "github.com/open-mcp-ai/Codexploit/internal/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestProjectMCPExposesScopedASGCatalogue(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemory()
	if _, err := store.CreateProject(ctx, storage.Project{ID: "project", Name: "fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutSnapshot(ctx, "project", &repository.Snapshot{SnapshotID: testSnapshotID}); err != nil {
		t.Fatal(err)
	}
	entry := asg.Node{
		ID:         asg.NodeID(testSnapshotID, asg.NodeEntryPoint, "http_route:GET /users", "cs-entry"),
		SnapshotID: testSnapshotID, Kind: asg.NodeEntryPoint, Subject: "http_route:GET /users",
		Label: "GET /users", Detail: map[string]string{"entry_kind": asg.EntryHTTPRoute, "boundary": asg.BoundaryNetwork},
		Evidence: asg.StatusObserved, Confidence: scg.Observed, Generator: "entrypoint/framework",
		File: "main.go", Line: 8, SCGRefs: []string{"cs-entry"},
	}
	sink := asg.Node{
		ID:         asg.NodeID(testSnapshotID, asg.NodeSensitiveOperation, "sink:deserialization", "cs-sink"),
		SnapshotID: testSnapshotID, Kind: asg.NodeSensitiveOperation, Subject: "sink:deserialization",
		Label: "deserialization", Detail: map[string]string{
			"sink_kind": asg.SinkDeserialization, "catalog_id": "java.deserialization.object-input",
			"catalog_version": "1.0.0", "catalog_digest": "catalog-digest",
			"method_full_name": "java.io.ObjectInputStream.readObject:java.lang.Object()",
			"priority":         "0.98", "has_flow": "false",
		},
		Evidence: asg.StatusInferred, Confidence: scg.Inferred, Generator: "sink/deserialization",
		File: "main.go", Line: 12, SCGRefs: []string{"cs-sink"},
	}
	doc := &asg.Document{
		SchemaVersion: asg.SchemaVersion, SnapshotID: testSnapshotID, ASGVersion: "asg-fixture",
		SCGVersion: "scg-fixture", Engine: asg.Engine{Name: "rules", Version: "1"},
		RulesetHash: "rules", Nodes: []asg.Node{entry, sink},
		Limitations: []string{"static candidates only"},
	}
	if err := store.ReplaceASG(ctx, testSnapshotID, doc); err != nil {
		t.Fatal(err)
	}
	svc := graph.NewService(store, nil)
	client, err := internalmcp.NewProjectClient(ctx, svc, store, "project", testSnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	entries := callOK(t, client, "list_entry_points", map[string]any{
		"snapshot_id": testSnapshotID, "boundary": "network",
	})
	if entries["total"] != float64(1) {
		t.Fatalf("entry catalogue = %+v", entries)
	}
	sinks := callOK(t, client, "list_sinks", map[string]any{
		"snapshot_id": testSnapshotID, "category": "deserialization",
	})
	if sinks["total"] != float64(1) {
		t.Fatalf("sink catalogue = %+v", sinks)
	}
	rows, _ := sinks["sinks"].([]any)
	detail, _ := rows[0].(map[string]any)["detail"].(map[string]any)
	if len(rows) != 1 || detail["priority"] != "0.98" || detail["has_flow"] != "false" {
		t.Fatalf("sink catalogue lost high-risk metadata: %+v", sinks)
	}
	filtered := callOK(t, client, "list_sinks", map[string]any{
		"snapshot_id": testSnapshotID, "partition": "high_risk",
		"rule_id":       "java.deserialization.object-input",
		"receiver_type": "java.io.ObjectInputStream", "has_flow": false,
	})
	filteredRows, _ := filtered["sinks"].([]any)
	partitions, _ := filtered["partitions"].(map[string]any)
	if filtered["total"] != float64(1) || len(filteredRows) != 1 ||
		partitions["high_risk"] != float64(1) || partitions["unclassified"] != float64(0) {
		t.Fatalf("filtered sink catalogue = %+v", filtered)
	}
	node := callOK(t, client, "get_asg_node", map[string]any{
		"snapshot_id": testSnapshotID, "node_id": sink.ID,
	})
	if node["node"] == nil || node["limitations"] == nil {
		t.Fatalf("ASG node lost evidence limits: %+v", node)
	}
	if got := callErr(t, client, "list_sinks", map[string]any{
		"snapshot_id": testSnapshotID, "category": "everything",
	}); got == "" {
		t.Fatal("unknown sink category was not rejected")
	}
	if got := callErr(t, client, "list_entry_points", map[string]any{
		"snapshot_id": testSnapshotID, "kind": "cli_command", "boundary": "network",
	}); got == "" {
		t.Fatal("contradictory entry kind and boundary were accepted")
	}
	if got := callErr(t, client, "repo_map", map[string]any{
		"snapshot_id": testSnapshotID, "cpgql": "arbitrary query",
	}); got == "" {
		t.Fatal("unknown repo_map parameter was accepted")
	}
}
