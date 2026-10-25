package storage

import (
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"testing"
)

func TestReplaceGraphLayersRejectsMixedPinsAndKeepsPriorView(t *testing.T) {
	store := NewMemory()
	g := graphFixture(t)
	surface := &asg.Document{SnapshotID: g.SnapshotID, SCGVersion: g.GraphVersion, ASGVersion: "asg-old"}
	if err := store.ReplaceGraphLayers(t.Context(), g.SnapshotID, g, surface); err != nil {
		t.Fatal(err)
	}
	next := *g
	next.GraphVersion = "graph-new"
	if err := store.ReplaceGraphLayers(t.Context(), g.SnapshotID, &next, surface); err == nil {
		t.Fatal("mixed graph versions accepted")
	}
	got, err := store.GraphSummary(t.Context(), g.SnapshotID)
	if err != nil || got.GraphVersion != g.GraphVersion {
		t.Fatal("failed replacement advanced graph")
	}
	surface.SCGVersion = next.GraphVersion
	surface.ASGVersion = "asg-new"
	if err := store.ReplaceGraphLayers(t.Context(), g.SnapshotID, &next, surface); err != nil {
		t.Fatal(err)
	}
	got, _ = store.GraphSummary(t.Context(), g.SnapshotID)
	a, _ := store.ASGSummary(t.Context(), g.SnapshotID)
	if got.GraphVersion != a.SCGVersion || a.ASGVersion != "asg-new" {
		t.Fatal("engine replacement mixed graph layers")
	}
}
