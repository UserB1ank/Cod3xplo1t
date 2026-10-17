package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/knowledge"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

type knowledgeViewResponse struct {
	APIVersion string `json:"api_version"`
	View       struct {
		ID       string                         `json:"view_id"`
		Revision string                         `json:"revision"`
		Scope    knowledge.Scope                `json:"scope"`
		Layers   map[string]knowledge.LayerInfo `json:"layers"`
		Coverage scg.Coverage                   `json:"coverage"`
	} `json:"view"`
}

type knowledgeMeta struct {
	ViewID     string            `json:"view_id"`
	Revision   string            `json:"revision"`
	Layer      string            `json:"layer"`
	Versions   map[string]string `json:"versions"`
	Total      int               `json:"total"`
	Truncated  bool              `json:"truncated"`
	SnapshotID string            `json:"snapshot_id"`
}

func TestKnowledgeAPIExploresAFixedSnapshot(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	capture := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if capture.status != http.StatusCreated {
		t.Fatalf("capture: %d %s", capture.status, capture.body)
	}
	var snapshot snapshotResponse
	capture.decode(t, &snapshot)
	snapshotID := snapshot.Snapshot.SnapshotID
	// Two independent tasks that share one snapshot: they must read one knowledge.
	taskID := func(name string) string {
		created := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/tasks",
			map[string]any{"name": name, "objective": "review the fixture", "snapshot_id": snapshotID}, nil)
		if created.status != http.StatusCreated {
			t.Fatalf("create task %s: %d %s", name, created.status, created.body)
		}
		var out struct {
			Task struct {
				ID string `json:"audit_id"`
			} `json:"task"`
		}
		created.decode(t, &out)
		return out.Task.ID
	}
	auditA := taskID("shared task one")
	taskID("shared task two")

	base := "/api/v1/projects/" + project.Project.ID + "/knowledge/views"
	opened := do(t, env.ts, http.MethodPost, base, map[string]any{
		"api_version": "codexploit/v1",
		"snapshot_id": snapshotID,
		"layers":      []string{"scg", "asg", "paths"},
	}, nil)
	if opened.status != http.StatusOK {
		t.Fatalf("open view: %d %s", opened.status, opened.body)
	}
	var view knowledgeViewResponse
	opened.decode(t, &view)
	if view.APIVersion != "codexploit/v1" || view.View.ID == "" || view.View.Revision == "" {
		t.Fatalf("view envelope: %s", opened.body)
	}
	if view.View.Scope.ProjectID != project.Project.ID || view.View.Scope.SnapshotID != snapshotID {
		t.Fatalf("view scope: %+v", view.View.Scope)
	}
	for _, layer := range []string{knowledge.LayerSCG, knowledge.LayerASG, knowledge.LayerPaths} {
		if view.View.Layers[layer].Status != knowledge.StatusAvailable {
			t.Fatalf("layer %s = %+v", layer, view.View.Layers[layer])
		}
	}
	if view.View.Layers[knowledge.LayerPaths].Tasks != 2 {
		t.Fatalf("paths layer did not count both tasks: %+v", view.View.Layers[knowledge.LayerPaths])
	}

	viewBase := base + "/" + view.View.ID
	symbols := do(t, env.ts, http.MethodGet, viewBase+"/symbols?q=a&limit=3", nil, nil)
	if symbols.status != http.StatusOK {
		t.Fatalf("symbols: %d %s", symbols.status, symbols.body)
	}
	var symbolPage struct {
		Symbols    []scg.Symbol  `json:"symbols"`
		NextCursor string        `json:"next_cursor"`
		Meta       knowledgeMeta `json:"meta"`
	}
	symbols.decode(t, &symbolPage)
	if len(symbolPage.Symbols) == 0 || symbolPage.Meta.Versions[knowledge.LayerSCG] != view.View.Layers[knowledge.LayerSCG].Version {
		t.Fatalf("symbols page: %s", symbols.body)
	}
	symbolID := symbolPage.Symbols[0].ID

	slice := do(t, env.ts, http.MethodGet, viewBase+"/code-slice?symbol_id="+url.QueryEscape(symbolID)+"&max_lines=40", nil, nil)
	if slice.status != http.StatusOK {
		t.Fatalf("code slice: %d %s", slice.status, slice.body)
	}
	var slicePage struct {
		Slice struct {
			Sections []struct {
				Lines []string `json:"lines"`
			} `json:"sections"`
		} `json:"slice"`
		Meta knowledgeMeta `json:"meta"`
	}
	slice.decode(t, &slicePage)
	if len(slicePage.Slice.Sections) == 0 || len(slicePage.Slice.Sections[0].Lines) == 0 {
		t.Fatalf("slice has no source: %s", slice.body)
	}

	neighborhood := do(t, env.ts, http.MethodGet, viewBase+"/neighborhood?symbol_id="+url.QueryEscape(symbolID)+"&direction=callers", nil, nil)
	if neighborhood.status != http.StatusOK || !containsString(neighborhood.body, `"neighborhood"`) {
		t.Fatalf("neighborhood: %d %s", neighborhood.status, neighborhood.body)
	}

	nodes := do(t, env.ts, http.MethodGet, viewBase+"/nodes?limit=5", nil, nil)
	if nodes.status != http.StatusOK {
		t.Fatalf("nodes: %d %s", nodes.status, nodes.body)
	}
	var nodePage struct {
		Nodes []asg.Node    `json:"nodes"`
		Meta  knowledgeMeta `json:"meta"`
	}
	nodes.decode(t, &nodePage)
	if len(nodePage.Nodes) == 0 || nodePage.Meta.Layer != knowledge.LayerASG {
		t.Fatalf("asg nodes: %s", nodes.body)
	}

	paths := do(t, env.ts, http.MethodGet, viewBase+"/paths?limit=5", nil, nil)
	if paths.status != http.StatusOK {
		t.Fatalf("paths: %d %s", paths.status, paths.body)
	}
	var pathPage struct {
		Paths  []path.Path          `json:"paths"`
		Audits []knowledge.AuditRef `json:"audits"`
		Meta   knowledgeMeta        `json:"meta"`
	}
	paths.decode(t, &pathPage)
	if len(pathPage.Paths) == 0 || len(pathPage.Audits) != 2 {
		t.Fatalf("paths page: %s", paths.body)
	}
	if pathPage.Meta.Versions[knowledge.LayerSCG] != view.View.Layers[knowledge.LayerSCG].Version {
		t.Fatalf("paths lost the pin: %s", paths.body)
	}

	provenance := do(t, env.ts, http.MethodGet, viewBase+"/provenance?fact_id="+url.QueryEscape(symbolID), nil, nil)
	if provenance.status != http.StatusOK {
		t.Fatalf("provenance: %d %s", provenance.status, provenance.body)
	}
	var prov struct {
		Provenance knowledge.Provenance `json:"provenance"`
	}
	provenance.decode(t, &prov)
	if prov.Provenance.Kind != "symbol" || prov.Provenance.Producer.PluginID != "builtin.scg" || len(prov.Provenance.Tasks) != 2 {
		t.Fatalf("provenance: %s", provenance.body)
	}
	if auditA == "" || !containsString(provenance.body, auditA) {
		t.Fatalf("provenance tasks = %+v, want %s", prov.Provenance.Tasks, auditA)
	}

	// The same view answered for the same pin, so two tasks read one knowledge.
	reopened := do(t, env.ts, http.MethodPost, base, map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshotID, "layers": []string{"scg", "asg", "paths"}}, nil)
	var second knowledgeViewResponse
	reopened.decode(t, &second)
	if second.View.ID != view.View.ID || second.View.Revision != view.View.Revision {
		t.Fatalf("the same snapshot produced two views: %s vs %s", view.View.ID, second.View.ID)
	}

	// Project isolation: another project cannot address this view.
	other := createProject(t, env.ts, asgFixtureSource(t))
	foreign := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+other.Project.ID+"/knowledge/views/"+view.View.ID+"/symbols", nil, nil)
	if foreign.status != http.StatusNotFound {
		t.Fatalf("foreign project view: %d %s", foreign.status, foreign.body)
	}
	if r := doAs(t, env.ts, "", http.MethodPost, base, map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshotID}, nil); r.status != http.StatusUnauthorized {
		t.Fatalf("anonymous open: %d", r.status)
	}
	if r := doAs(t, env.ts, readerSecret, http.MethodPost, base, map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshotID}, nil); r.status != http.StatusOK {
		t.Fatalf("reader open: %d %s", r.status, r.body)
	}
	if r := do(t, env.ts, http.MethodPost, base, map[string]any{"api_version": "codexploit/v2", "snapshot_id": snapshotID}, nil); r.status != http.StatusBadRequest {
		t.Fatalf("bad api_version: %d", r.status)
	}

	// Rebuilding the graph supersedes the open view instead of changing it. The
	// pin records built_at at RFC3339 second precision, so the rebuild must land
	// in a later second; the reader's fixed-clock test covers the same rule.
	time.Sleep(1100 * time.Millisecond)
	if r := do(t, env.ts, http.MethodPost, "/api/snapshots/"+snapshotID+"/graph", map[string]any{"force": true}, nil); r.status != http.StatusCreated && r.status != http.StatusOK {
		t.Fatalf("rebuild graph: %d %s", r.status, r.body)
	}
	if r := do(t, env.ts, http.MethodGet, viewBase+"/symbols", nil, nil); r.status != http.StatusConflict || !containsString(r.body, "view_superseded") {
		t.Fatalf("stale view: %d %s", r.status, r.body)
	}

	// The legacy graph routes keep their old shape.
	legacy := do(t, env.ts, http.MethodGet, "/api/snapshots/"+snapshotID+"/symbols?limit=1", nil, nil)
	if legacy.status != http.StatusOK {
		t.Fatalf("legacy symbols: %d %s", legacy.status, legacy.body)
	}
}

func TestKnowledgeAPIMakesMissingLayersExplicit(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	capture := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true}, nil)
	if capture.status != http.StatusCreated {
		t.Fatalf("capture: %d %s", capture.status, capture.body)
	}
	var snapshot snapshotResponse
	capture.decode(t, &snapshot)
	base := "/api/v1/projects/" + project.Project.ID + "/knowledge/views"
	opened := do(t, env.ts, http.MethodPost, base, map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshot.Snapshot.SnapshotID}, nil)
	if opened.status != http.StatusOK {
		t.Fatalf("open view: %d %s", opened.status, opened.body)
	}
	var view knowledgeViewResponse
	opened.decode(t, &view)
	if view.View.Layers[knowledge.LayerASG].Status != knowledge.StatusNotBuilt {
		t.Fatalf("asg layer without a surface = %+v", view.View.Layers[knowledge.LayerASG])
	}
	if r := do(t, env.ts, http.MethodGet, base+"/"+view.View.ID+"/nodes", nil, nil); r.status != http.StatusConflict || !containsString(r.body, "layer_unavailable") {
		t.Fatalf("unbuilt asg answered: %d %s", r.status, r.body)
	}

	// A snapshot without any graph has no view to open.
	empty := createProject(t, env.ts, asgFixtureSource(t))
	plain := do(t, env.ts, http.MethodPost, "/api/projects/"+empty.Project.ID+"/snapshots", map[string]any{}, nil)
	var plainSnapshot snapshotResponse
	plain.decode(t, &plainSnapshot)
	if r := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+empty.Project.ID+"/knowledge/views",
		map[string]any{"api_version": "codexploit/v1", "snapshot_id": plainSnapshot.Snapshot.SnapshotID}, nil); r.status != http.StatusConflict || !containsString(r.body, "knowledge_unavailable") {
		t.Fatalf("graphless view: %d %s", r.status, r.body)
	}
}

func containsString(body []byte, want string) bool {
	return strings.Contains(string(body), want)
}
