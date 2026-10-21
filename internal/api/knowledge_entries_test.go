package api

import (
	"net/http"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
)

func TestKnowledgeEntryDirectorySearchAndBoundedNeighborhood(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if captured.status != http.StatusCreated {
		t.Fatalf("capture: %d %s", captured.status, captured.body)
	}
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	base := "/api/v1/projects/" + project.Project.ID + "/knowledge/views"
	opened := do(t, env.ts, http.MethodPost, base, map[string]any{
		"api_version": "codexploit/v1", "snapshot_id": snapshot.Snapshot.SnapshotID,
		"layers": []string{"scg", "asg", "paths"},
	}, nil)
	if opened.status != http.StatusOK {
		t.Fatalf("open view: %d %s", opened.status, opened.body)
	}
	var view knowledgeViewResponse
	opened.decode(t, &view)
	viewBase := base + "/" + view.View.ID
	entries := do(t, env.ts, http.MethodGet, viewBase+"/nodes?kind=EntryPoint&q=users&limit=10", nil, nil)
	if entries.status != http.StatusOK {
		t.Fatalf("entry search: %d %s", entries.status, entries.body)
	}
	var page struct {
		Nodes []asg.Node    `json:"nodes"`
		Meta  knowledgeMeta `json:"meta"`
	}
	entries.decode(t, &page)
	if len(page.Nodes) == 0 || page.Nodes[0].Kind != asg.NodeEntryPoint || page.Meta.SnapshotID != snapshot.Snapshot.SnapshotID {
		t.Fatalf("entry directory = %+v", page)
	}
	entryID := page.Nodes[0].ID
	neighborhood := do(t, env.ts, http.MethodGet, viewBase+"/asg-neighborhood?node_id="+entryID+"&depth=2&max_nodes=20", nil, nil)
	if neighborhood.status != http.StatusOK {
		t.Fatalf("neighborhood: %d %s", neighborhood.status, neighborhood.body)
	}
	var result struct {
		Neighborhood struct {
			Root            asg.Node      `json:"root"`
			Nodes           []asg.Node    `json:"nodes"`
			Edges           []asg.Edge    `json:"edges"`
			UnresolvedEdges int           `json:"unresolved_edges"`
			Meta            knowledgeMeta `json:"meta"`
			Limitations     []string      `json:"limitations"`
		} `json:"neighborhood"`
	}
	neighborhood.decode(t, &result)
	if result.Neighborhood.Root.ID != entryID || len(result.Neighborhood.Nodes) < 2 || len(result.Neighborhood.Edges) == 0 || result.Neighborhood.Meta.SnapshotID != snapshot.Snapshot.SnapshotID {
		t.Fatalf("local graph = %+v", result.Neighborhood)
	}
	for _, edge := range result.Neighborhood.Edges {
		if edge.Kind == asg.EdgeDerivedFrom {
			t.Fatalf("provenance edge leaked into the local graph: %+v", edge)
		}
	}
	if len(result.Neighborhood.Limitations) == 0 {
		t.Fatal("local graph did not state its reachability limits")
	}
	missing := do(t, env.ts, http.MethodGet, viewBase+"/asg-neighborhood?node_id=asg-missing", nil, nil)
	if missing.status != http.StatusNotFound {
		t.Fatalf("missing node = %d %s", missing.status, missing.body)
	}
}
