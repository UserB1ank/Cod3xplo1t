package knowledge_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/knowledge"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

const (
	projectAlpha = "proj-alpha"
	projectBeta  = "proj-beta"
	snapshotOne  = "snap-11111111111111111111111111111111"
	snapshotTwo  = "snap-22222222222222222222222222222222"
)

var fixtureFiles = map[string]string{
	"go.mod": "module example.invalid/svc\n\ngo 1.24\n",
	"main.go": `package main

import "example.invalid/svc/internal/flow"

func main() {
	flow.Start()
}
`,
	"internal/flow/flow.go": `package flow

// Start drives the fixture chain.
func Start() { step() }

func step() { leaf() }

func leaf() { println("done") }
`,
	"internal/flow/query.go": `package flow

import "database/sql"

// Query runs the fixture sink.
func Query(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = " + id)
}
`,
}

// resolver serves the temp tree of each fixture snapshot.
type resolver map[string]string

func (r resolver) Load(id string) (*repository.Snapshot, error) {
	dir, ok := r[id]
	if !ok {
		return nil, repository.ErrSnapshotNotFound
	}
	return &repository.Snapshot{SnapshotID: id, Dir: dir}, nil
}

type fixture struct {
	reader  *knowledge.Reader
	store   *storage.Memory
	service *graph.Service
	graphs  map[string]*scg.Graph
	dirs    resolver
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	store := storage.NewMemory()
	for _, project := range []string{projectAlpha, projectBeta} {
		if err := store.PutProject(ctx, storage.Project{ID: project}); err != nil {
			t.Fatal(err)
		}
	}
	dirs := resolver{}
	graphs := map[string]*scg.Graph{}
	for snapshotID, project := range map[string]string{snapshotOne: projectAlpha, snapshotTwo: projectBeta} {
		dir := t.TempDir()
		tree := filepath.Join(dir, repository.TreeDirName)
		for rel, content := range fixtureFiles {
			target := filepath.Join(tree, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.PutSnapshot(ctx, project, &repository.Snapshot{SnapshotID: snapshotID}); err != nil {
			t.Fatal(err)
		}
		built, err := scg.NewBuilder(gofrontend.New()).BuildTree(ctx, snapshotID, tree)
		if err != nil {
			t.Fatalf("build %s: %v", snapshotID, err)
		}
		if err := store.ReplaceGraph(ctx, snapshotID, built); err != nil {
			t.Fatal(err)
		}
		dirs[snapshotID] = dir
		graphs[snapshotID] = built
	}
	service := graph.NewService(store, dirs)
	doc, err := asg.NewBuilder(service).Build(ctx, snapshotTwo)
	if err != nil {
		t.Fatalf("build asg: %v", err)
	}
	if err := store.ReplaceASG(ctx, snapshotTwo, doc); err != nil {
		t.Fatalf("store asg: %v", err)
	}
	reader := knowledge.New(knowledge.Deps{
		Store:     store,
		Graph:     service,
		ASG:       graph.NewASGService(store, service),
		Queue:     path.NewService(store, nil),
		Artifacts: store,
	})
	return &fixture{reader: reader, store: store, service: service, graphs: graphs, dirs: dirs}
}

func TestOpenViewPinsTheSnapshotAndReportsEachLayer(t *testing.T) {
	env := newFixture(t)
	ctx := context.Background()
	scope := knowledge.Scope{ProjectID: projectAlpha, SnapshotID: snapshotOne}

	view, err := env.reader.OpenView(ctx, scope, nil)
	if err != nil {
		t.Fatalf("OpenView: %v", err)
	}
	if view.Scope != scope {
		t.Fatalf("view scope = %+v, want %+v", view.Scope, scope)
	}
	if view.ID == "" || view.Revision == "" {
		t.Fatalf("view has no identity: %+v", view)
	}
	scgLayer := view.Layers[knowledge.LayerSCG]
	if scgLayer.Status != knowledge.StatusAvailable || scgLayer.Version != env.graphs[snapshotOne].GraphVersion {
		t.Fatalf("scg layer = %+v, want %s", scgLayer, env.graphs[snapshotOne].GraphVersion)
	}
	if asgLayer := view.Layers[knowledge.LayerASG]; asgLayer.Status != knowledge.StatusNotBuilt {
		t.Fatalf("asg layer without an attack surface = %+v", asgLayer)
	}
	if pathsLayer := view.Layers[knowledge.LayerPaths]; pathsLayer.Status != knowledge.StatusAvailable {
		t.Fatalf("paths layer = %+v", pathsLayer)
	}
	if view.Coverage.FilesInSnapshot == 0 || len(view.Limitations) == 0 {
		t.Fatalf("view carries no coverage statement: %+v", view)
	}

	again, err := env.reader.OpenView(ctx, scope, nil)
	if err != nil {
		t.Fatalf("OpenView again: %v", err)
	}
	if again.ID != view.ID || again.Revision != view.Revision {
		t.Fatalf("the same scope opened two views: %s/%s vs %s/%s", view.ID, view.Revision, again.ID, again.Revision)
	}

	// The snapshot belongs to another project: the scope is refused, not served.
	foreign := knowledge.Scope{ProjectID: projectBeta, SnapshotID: snapshotOne}
	if _, err := env.reader.OpenView(ctx, foreign, nil); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("foreign project scope: %v", err)
	}
	if _, err := env.reader.OpenView(ctx, knowledge.Scope{ProjectID: projectAlpha, SnapshotID: "snap-missing"}, nil); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("unknown snapshot: %v", err)
	}

	// A different snapshot is a different, independently pinned view.
	other, err := env.reader.OpenView(ctx, knowledge.Scope{ProjectID: projectBeta, SnapshotID: snapshotTwo}, nil)
	if err != nil {
		t.Fatalf("OpenView second snapshot: %v", err)
	}
	if other.ID == view.ID {
		t.Fatal("two snapshots share one view id")
	}
	if other.Layers[knowledge.LayerSCG].Version == scgLayer.Version {
		t.Fatal("two snapshots share one graph version")
	}
}

func TestSymbolsReadsThePinnedGraphWithCursorPagination(t *testing.T) {
	env := newFixture(t)
	ctx := context.Background()
	scope := knowledge.Scope{ProjectID: projectAlpha, SnapshotID: snapshotOne}
	view, err := env.reader.OpenView(ctx, scope, []string{knowledge.LayerSCG})
	if err != nil {
		t.Fatalf("OpenView: %v", err)
	}

	first, err := env.reader.Symbols(ctx, scope, view.ID, knowledge.SymbolQuery{Query: "a", Limit: 2})
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	if len(first.Symbols) == 0 || first.Symbols[0].SnapshotID != snapshotOne {
		t.Fatalf("symbols do not belong to the pinned snapshot: %+v", first.Symbols)
	}
	if first.Meta.Versions[knowledge.LayerSCG] != view.Layers[knowledge.LayerSCG].Version {
		t.Fatalf("query version = %v, want the pinned %s", first.Meta.Versions, view.Layers[knowledge.LayerSCG].Version)
	}
	if first.Meta.Total < 2 || first.NextCursor == "" {
		t.Fatalf("page did not report more results: total=%d cursor=%q", first.Meta.Total, first.NextCursor)
	}

	second, err := env.reader.Symbols(ctx, scope, view.ID, knowledge.SymbolQuery{Query: "flow", Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatalf("Symbols second page: %v", err)
	}
	for _, symbol := range second.Symbols {
		for _, prior := range first.Symbols {
			if symbol.ID == prior.ID {
				t.Fatalf("pagination repeated %s", symbol.ID)
			}
		}
	}

	if _, err := env.reader.Symbols(ctx, scope, view.ID, knowledge.SymbolQuery{Cursor: "not-a-cursor"}); !errors.Is(err, knowledge.ErrInvalid) {
		t.Fatalf("malformed cursor: %v", err)
	}
	if _, err := env.reader.Paths(ctx, scope, view.ID, knowledge.PathQuery{}); !errors.Is(err, knowledge.ErrLayerUnavailable) {
		t.Fatalf("unpinned paths layer answered: %v", err)
	}
	foreign := knowledge.Scope{ProjectID: projectBeta, SnapshotID: snapshotTwo}
	if _, err := env.reader.Symbols(ctx, foreign, view.ID, knowledge.SymbolQuery{}); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("foreign view id: %v", err)
	}
	if _, err := env.reader.Symbols(ctx, scope, "view-tampered", knowledge.SymbolQuery{}); !errors.Is(err, knowledge.ErrInvalid) {
		t.Fatalf("tampered view id: %v", err)
	}
}

func TestNeighborhoodAndSliceStayInsideThePinnedSnapshot(t *testing.T) {
	env := newFixture(t)
	ctx := context.Background()
	scope := knowledge.Scope{ProjectID: projectAlpha, SnapshotID: snapshotOne}
	view, err := env.reader.OpenView(ctx, scope, []string{knowledge.LayerSCG})
	if err != nil {
		t.Fatalf("OpenView: %v", err)
	}
	found, err := env.reader.Symbols(ctx, scope, view.ID, knowledge.SymbolQuery{Query: "step"})
	if err != nil || len(found.Symbols) != 1 {
		t.Fatalf("symbols: %+v %v", found, err)
	}
	step := found.Symbols[0]

	callers, err := env.reader.Neighborhood(ctx, scope, view.ID, knowledge.NeighborhoodQuery{SymbolID: step.ID, Direction: "callers", Depth: 1, MaxNodes: 20})
	if err != nil {
		t.Fatalf("callers: %v", err)
	}
	if callers.Neighborhood.Root.ID != step.ID || callers.Neighborhood.Direction != "callers" {
		t.Fatalf("neighbourhood root/direction: %+v", callers.Neighborhood)
	}
	if !hasNeighbor(callers.Neighborhood.Nodes, "Start") {
		t.Fatalf("step has no caller Start: %+v", callers.Neighborhood.Nodes)
	}
	if callers.Meta.Versions[knowledge.LayerSCG] == "" || callers.Meta.SnapshotID != snapshotOne {
		t.Fatalf("neighbourhood meta lost the pin: %+v", callers.Meta)
	}

	callees, err := env.reader.Neighborhood(ctx, scope, view.ID, knowledge.NeighborhoodQuery{SymbolID: step.ID, Direction: "callees", Depth: 1, MaxNodes: 20})
	if err != nil || !hasNeighbor(callees.Neighborhood.Nodes, "leaf") {
		t.Fatalf("callees: %+v %v", callees, err)
	}

	slice, err := env.reader.CodeSlice(ctx, scope, view.ID, knowledge.SliceQuery{SymbolID: step.ID, MaxLines: 40})
	if err != nil {
		t.Fatalf("slice: %v", err)
	}
	if len(slice.Slice.Sections) == 0 || !strings.Contains(strings.Join(slice.Slice.Sections[0].Lines, "\n"), "func step()") {
		t.Fatalf("slice has no source: %+v", slice.Slice.Sections)
	}
	wide, err := env.reader.Symbols(ctx, scope, view.ID, knowledge.SymbolQuery{Query: "main"})
	if err != nil || len(wide.Symbols) != 1 {
		t.Fatalf("main symbol: %+v %v", wide, err)
	}
	tiny, err := env.reader.CodeSlice(ctx, scope, view.ID, knowledge.SliceQuery{SymbolID: wide.Symbols[0].ID, MaxLines: 1})
	if err != nil {
		t.Fatalf("bounded slice: %v", err)
	}
	if len(tiny.Slice.Sections) == 0 || !tiny.Slice.Sections[0].Truncated {
		t.Fatalf("a one-line budget did not report truncation: %+v", tiny.Slice.Sections)
	}

	if _, err := env.reader.Neighborhood(ctx, scope, view.ID, knowledge.NeighborhoodQuery{SymbolID: "sym-missing"}); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("unknown symbol neighbourhood: %v", err)
	}
	if _, err := env.reader.Neighborhood(ctx, scope, view.ID, knowledge.NeighborhoodQuery{SymbolID: step.ID, Direction: "sideways"}); !errors.Is(err, knowledge.ErrInvalid) {
		t.Fatalf("unknown direction: %v", err)
	}
}

func hasNeighbor(nodes []graph.NeighborhoodNode, name string) bool {
	for _, node := range nodes {
		if node.Symbol.Name == name {
			return true
		}
	}
	return false
}

func seedAudit(t *testing.T, store *storage.Memory, audit path.Audit, rows []path.Path) {
	t.Helper()
	if err := store.CreateAudit(audit); err != nil {
		t.Fatalf("seed audit %s: %v", audit.ID, err)
	}
	if len(rows) == 0 {
		return
	}
	if err := store.ReplacePaths(audit.ID, rows); err != nil {
		t.Fatalf("seed paths %s: %v", audit.ID, err)
	}
}

func TestPathsArePinnedToTheSnapshotAndItsLayerVersions(t *testing.T) {
	env := newFixture(t)
	ctx := context.Background()
	scope := knowledge.Scope{ProjectID: projectAlpha, SnapshotID: snapshotOne}
	version := env.graphs[snapshotOne].GraphVersion
	seedAudit(t, env.store, path.Audit{ID: "aud-pinned", Name: "pinned task", SnapshotID: snapshotOne, SCGVersion: version, Status: string(path.StatusQueued), PathCount: 2}, []path.Path{
		{ID: "path-one", AuditID: "aud-pinned", SnapshotID: snapshotOne, SCGVersion: version, Status: path.StatusQueued, Signature: "sig-one"},
		{ID: "path-two", AuditID: "aud-pinned", SnapshotID: snapshotOne, SCGVersion: version, Status: path.StatusQueued, Signature: "sig-two"},
	})
	seedAudit(t, env.store, path.Audit{ID: "aud-stale", Name: "stale task", SnapshotID: snapshotOne, SCGVersion: "graph-stale", Status: string(path.StatusQueued), PathCount: 1}, []path.Path{
		{ID: "path-stale", AuditID: "aud-stale", SnapshotID: snapshotOne, SCGVersion: "graph-stale", Status: path.StatusQueued, Signature: "sig-stale"},
	})
	seedAudit(t, env.store, path.Audit{ID: "aud-other", Name: "other snapshot", SnapshotID: snapshotTwo, SCGVersion: env.graphs[snapshotTwo].GraphVersion, Status: string(path.StatusQueued), PathCount: 1}, []path.Path{
		{ID: "path-other", AuditID: "aud-other", SnapshotID: snapshotTwo, SCGVersion: env.graphs[snapshotTwo].GraphVersion, Status: path.StatusQueued, Signature: "sig-other"},
	})

	view, err := env.reader.OpenView(ctx, scope, []string{knowledge.LayerSCG, knowledge.LayerPaths})
	if err != nil {
		t.Fatalf("OpenView: %v", err)
	}
	if got := view.Layers[knowledge.LayerPaths].Tasks; got != 1 {
		t.Fatalf("paths layer tasks = %d, want only the pinned audit", got)
	}
	page, err := env.reader.Paths(ctx, scope, view.ID, knowledge.PathQuery{Limit: 10})
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	if len(page.Paths) != 2 {
		t.Fatalf("paths = %+v, want the two pinned rows", page.Paths)
	}
	for _, row := range page.Paths {
		if row.ID == "path-stale" || row.ID == "path-other" {
			t.Fatalf("stale or foreign path leaked: %s", row.ID)
		}
	}
	if len(page.Audits) != 1 || page.Audits[0].ID != "aud-pinned" {
		t.Fatalf("audits = %+v, want only the pinned task", page.Audits)
	}
	if page.Meta.Omitted != 1 || !page.Meta.Truncated || page.Meta.TruncationReason != "stale_layer_version" {
		t.Fatalf("stale rows were not reported: %+v", page.Meta)
	}
	if page.Meta.Versions[knowledge.LayerSCG] != version || page.Meta.SnapshotID != snapshotOne {
		t.Fatalf("paths meta lost the pin: %+v", page.Meta)
	}

	// A task of another snapshot cannot be requested through this view.
	foreign, err := env.reader.Paths(ctx, scope, view.ID, knowledge.PathQuery{AuditID: "aud-other"})
	if err != nil || len(foreign.Paths) != 0 {
		t.Fatalf("foreign audit paths: %+v %v", foreign, err)
	}
}

func TestProvenanceResolvesSymbolsNodesAndSharingTasks(t *testing.T) {
	env := newFixture(t)
	ctx := context.Background()
	scopeOne := knowledge.Scope{ProjectID: projectAlpha, SnapshotID: snapshotOne}
	seedAudit(t, env.store, path.Audit{ID: "aud-shared", Name: "shared task", SnapshotID: snapshotOne, SCGVersion: env.graphs[snapshotOne].GraphVersion, Status: string(path.StatusQueued), PathCount: 1}, nil)
	view, err := env.reader.OpenView(ctx, scopeOne, []string{knowledge.LayerSCG, knowledge.LayerPaths})
	if err != nil {
		t.Fatalf("OpenView: %v", err)
	}
	found, err := env.reader.Symbols(ctx, scopeOne, view.ID, knowledge.SymbolQuery{Query: "step"})
	if err != nil || len(found.Symbols) != 1 {
		t.Fatalf("symbols: %+v %v", found, err)
	}
	prov, err := env.reader.Provenance(ctx, scopeOne, view.ID, found.Symbols[0].ID)
	if err != nil {
		t.Fatalf("Provenance: %v", err)
	}
	if prov.Kind != "symbol" || prov.Producer.PluginID != "builtin.scg" || prov.Producer.ConfigDigest != env.graphs[snapshotOne].GraphVersion {
		t.Fatalf("symbol provenance: %+v", prov)
	}
	if prov.Location == nil || prov.Location.File != "internal/flow/flow.go" || prov.Location.StartLine == 0 {
		t.Fatalf("symbol location: %+v", prov.Location)
	}
	if len(prov.Tasks) != 1 || prov.Tasks[0].ID != "aud-shared" {
		t.Fatalf("sharing tasks: %+v", prov.Tasks)
	}
	if prov.Versions[knowledge.LayerSCG] == "" {
		t.Fatalf("provenance lost the pin: %+v", prov.Versions)
	}
	if _, err := env.reader.Provenance(ctx, scopeOne, view.ID, "sym-missing"); !errors.Is(err, knowledge.ErrNotFound) {
		t.Fatalf("unknown fact: %v", err)
	}

	scopeTwo := knowledge.Scope{ProjectID: projectBeta, SnapshotID: snapshotTwo}
	viewTwo, err := env.reader.OpenView(ctx, scopeTwo, []string{knowledge.LayerSCG, knowledge.LayerASG})
	if err != nil {
		t.Fatalf("OpenView asg: %v", err)
	}
	nodes, err := env.reader.Nodes(ctx, scopeTwo, viewTwo.ID, knowledge.NodeQuery{Kinds: []string{"SensitiveOperation"}})
	if err != nil || len(nodes.Nodes) == 0 {
		t.Fatalf("asg nodes: %+v %v", nodes, err)
	}
	nodeProv, err := env.reader.Provenance(ctx, scopeTwo, viewTwo.ID, nodes.Nodes[0].ID)
	if err != nil {
		t.Fatalf("node provenance: %v", err)
	}
	if nodeProv.Kind != "asg_node" || nodeProv.Node == nil || nodeProv.Node.Node.ID != nodes.Nodes[0].ID || nodeProv.Producer.PluginID != "builtin.asg" {
		t.Fatalf("node provenance: %+v", nodeProv)
	}
	if _, err := env.reader.Nodes(ctx, scopeOne, view.ID, knowledge.NodeQuery{}); !errors.Is(err, knowledge.ErrLayerUnavailable) {
		t.Fatalf("asg query on an scg-only view: %v", err)
	}
}

func TestARebuiltGraphSupersedesAnOpenView(t *testing.T) {
	env := newFixture(t)
	ctx := context.Background()
	scope := knowledge.Scope{ProjectID: projectAlpha, SnapshotID: snapshotOne}
	view, err := env.reader.OpenView(ctx, scope, []string{knowledge.LayerSCG})
	if err != nil {
		t.Fatalf("OpenView: %v", err)
	}
	tree := filepath.Join(env.dirs[snapshotOne], repository.TreeDirName)
	if err := os.WriteFile(filepath.Join(tree, "extra.go"), []byte("package main\n\nfunc extra() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	builder := scg.NewBuilder(gofrontend.New())
	// The pin records the build timestamp, so the rebuild must carry a distinct
	// one; a fixed clock keeps the test independent of the wall clock.
	builder.Now = func() time.Time { return time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC) }
	rebuilt, err := builder.BuildTree(ctx, snapshotOne, tree)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if err := env.store.ReplaceGraph(ctx, snapshotOne, rebuilt); err != nil {
		t.Fatalf("replace graph: %v", err)
	}
	if _, err := env.reader.Symbols(ctx, scope, view.ID, knowledge.SymbolQuery{}); !errors.Is(err, knowledge.ErrViewSuperseded) {
		t.Fatalf("stale view answered after a rebuild: %v", err)
	}
	fresh, err := env.reader.OpenView(ctx, scope, []string{knowledge.LayerSCG})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if fresh.Revision == view.Revision {
		t.Fatal("rebuilt snapshot kept the old revision")
	}
	if _, err := env.reader.Symbols(ctx, scope, fresh.ID, knowledge.SymbolQuery{}); err != nil {
		t.Fatalf("fresh view: %v", err)
	}
}
