package graph_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

const snapID = "snap-0123456789abcdef0123456789abcdef"

var fixtureFiles = map[string]string{
	"go.mod": "module example.invalid/chain\n\ngo 1.24\n",
	"main.go": `package main

import "example.invalid/chain/internal/flow"

func main() {
	flow.Step1()
	flow.External()
}
`,
	"internal/flow/flow.go": `package flow

import "fmt"

type Doer interface {
	Do()
}

func Step1() { Step2() }

func Step2() {
	Step3()
}

func Step3() {}

func External() { fmt.Println("outside") }

func ViaInterface(d Doer) { d.Do() }
`,
}

// resolver serves a snapshot record whose tree lives in a temp directory.
type resolver struct {
	dir string
}

func (r resolver) Load(id string) (*repository.Snapshot, error) {
	if id != snapID {
		return nil, repository.ErrSnapshotNotFound
	}
	return &repository.Snapshot{SnapshotID: id, Dir: r.dir}, nil
}

// newFixture builds the graph of the fixture repository and stores it.
func newFixture(t *testing.T) (*graph.Service, *scg.Graph) {
	t.Helper()
	dir := t.TempDir()
	tree := filepath.Join(dir, repository.TreeDirName)
	for rel, content := range fixtureFiles {
		p := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	builder := scg.NewBuilder(gofrontend.New())
	g, err := builder.BuildTree(context.Background(), snapID, tree)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	store := storage.NewMemory()
	if err := store.ReplaceGraph(context.Background(), snapID, g); err != nil {
		t.Fatalf("ReplaceGraph: %v", err)
	}
	return graph.NewService(store, resolver{dir: dir}), g
}

func symbolID(t *testing.T, g *scg.Graph, qualified string) string {
	t.Helper()
	for _, s := range g.Symbols {
		if s.QualifiedName == qualified {
			return s.ID
		}
	}
	t.Fatalf("symbol %q not found", qualified)
	return ""
}

func TestModulesFilesAndSymbols(t *testing.T) {
	t.Parallel()
	svc, g := newFixture(t)
	ctx := context.Background()

	mods, err := svc.Modules(ctx, snapID, graph.Options{})
	if err != nil {
		t.Fatalf("Modules: %v", err)
	}
	if len(mods.Modules) != 1 || mods.Modules[0].Name != "example.invalid/chain" {
		t.Fatalf("modules = %+v", mods.Modules)
	}
	if mods.Meta.SnapshotID != snapID || mods.Meta.GraphVersion == "" {
		t.Errorf("modules meta lost provenance: %+v", mods.Meta)
	}

	files, meta, err := svc.Files(ctx, snapID, "", graph.Options{})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(files) != len(fixtureFiles) {
		t.Errorf("files = %d, want %d", len(files), len(fixtureFiles))
	}
	if meta.Query != "files" {
		t.Errorf("meta query = %q", meta.Query)
	}

	page, err := svc.Symbols(ctx, snapID, graph.SymbolQuery{Options: graph.Options{Limit: 2}})
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	if len(page.Symbols) != 2 || page.Total != len(g.Symbols) {
		t.Fatalf("page = %d of %d symbols, want 2 of %d", len(page.Symbols), page.Total, len(g.Symbols))
	}
	if !page.Meta.Truncated || page.Meta.TruncationReason == "" {
		t.Errorf("a partial page must say so: %+v", page.Meta)
	}

	// The second identical query is served from the cache but keeps its meaning.
	again, err := svc.Symbols(ctx, snapID, graph.SymbolQuery{Options: graph.Options{Limit: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if !again.Meta.CacheHit {
		t.Error("repeat query was not served from the cache")
	}
	if again.Total != page.Total || len(again.Symbols) != len(page.Symbols) {
		t.Errorf("cached answer differs: %+v vs %+v", again, page)
	}
	other, err := svc.Symbols(ctx, snapID, graph.SymbolQuery{NameContains: "Step", Options: graph.Options{Limit: 100}})
	if err != nil {
		t.Fatal(err)
	}
	if other.Meta.CacheHit {
		t.Error("a different query reused a cache entry")
	}
	if other.Total != 3 {
		t.Errorf("name filter returned %d symbols, want 3", other.Total)
	}

	sym, meta, err := svc.Symbol(ctx, snapID, "example.invalid/chain/internal/flow.Step2", graph.Options{})
	if err != nil {
		t.Fatalf("Symbol by qualified name: %v", err)
	}
	if sym.Name != "Step2" || meta.SnapshotID != snapID {
		t.Errorf("symbol = %+v meta = %+v", sym, meta)
	}
	if _, _, err := svc.Symbol(ctx, snapID, "does.not.exist", graph.Options{}); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown symbol error = %v", err)
	}
}

func TestNeighborhoodTraversal(t *testing.T) {
	t.Parallel()
	svc, g := newFixture(t)
	ctx := context.Background()
	mainID := symbolID(t, g, "example.invalid/chain.main")
	step3 := symbolID(t, g, "example.invalid/chain/internal/flow.Step3")

	direct, err := svc.Callees(ctx, snapID, mainID, graph.Options{MaxDepth: 1})
	if err != nil {
		t.Fatalf("Callees: %v", err)
	}
	if len(direct.Nodes) != 2 {
		t.Fatalf("depth 1 callees = %v, want Step1 and External", names(direct))
	}
	if direct.Meta.DepthReached != 1 {
		t.Errorf("unexpected meta: %+v", direct.Meta)
	}
	// The answer is complete for the requested depth, but more graph exists: that
	// is reported without calling it truncation.
	if direct.Meta.Truncated {
		t.Errorf("a complete depth-1 answer was marked truncated: %+v", direct.Meta)
	}
	if !direct.Meta.MoreBeyondDepth {
		t.Errorf("deeper neighbours were not reported: %+v", direct.Meta)
	}

	deep, err := svc.Callees(ctx, snapID, mainID, graph.Options{MaxDepth: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !containsSymbol(deep, step3) {
		t.Errorf("depth 3 did not reach Step3: %v", names(deep))
	}
	if deep.Meta.DepthReached != 3 {
		t.Errorf("depth reached = %d, want 3", deep.Meta.DepthReached)
	}

	// Callers walk in the other direction.
	callers, err := svc.Callers(ctx, snapID, step3, graph.Options{MaxDepth: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !containsSymbol(callers, mainID) {
		t.Errorf("callers of Step3 did not reach main: %v", names(callers))
	}

	// A node budget returns a partial answer with a reason.
	budgeted, err := svc.Callees(ctx, snapID, mainID, graph.Options{MaxDepth: 3, MaxNodes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !budgeted.Meta.Truncated || budgeted.Meta.TruncationReason == "" {
		t.Errorf("node budget did not report truncation: %+v", budgeted.Meta)
	}
	if strings.Contains(budgeted.Meta.TruncationReason, "depth budget") {
		t.Errorf("expected a node budget reason, got %q", budgeted.Meta.TruncationReason)
	}

	// Unresolved calls inside visited symbols travel with the answer.
	externalID := symbolID(t, g, "example.invalid/chain/internal/flow.External")
	external, err := svc.Callees(ctx, snapID, externalID, graph.Options{MaxDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(external.Unresolved) == 0 {
		t.Fatal("the fmt.Println call site should be reported as unresolved")
	}
	if !strings.Contains(strings.Join(external.Limitations, "\n"), "could not be resolved") {
		t.Errorf("unresolved calls are not stated as a limitation: %v", external.Limitations)
	}

	// A cancelled context must fail the query rather than return a partial answer
	// that looks authoritative.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.Callees(ctx2(cancelled), snapID, mainID, graph.Options{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled query error = %v, want context.Canceled", err)
	}
	if _, err := svc.Callees(ctx, "snap-missing", mainID, graph.Options{}); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown snapshot error = %v", err)
	}
}

func TestCallPaths(t *testing.T) {
	t.Parallel()
	svc, g := newFixture(t)
	ctx := context.Background()
	mainID := symbolID(t, g, "example.invalid/chain.main")
	step3 := symbolID(t, g, "example.invalid/chain/internal/flow.Step3")

	paths, err := svc.CallPaths(ctx, snapID, graph.PathRequest{Source: mainID, Sink: step3})
	if err != nil {
		t.Fatalf("CallPaths: %v", err)
	}
	if len(paths.Paths) != 1 {
		t.Fatalf("paths = %d, want 1: %+v", len(paths.Paths), paths.Paths)
	}
	path := paths.Paths[0]
	if len(path.SymbolIDs) != 4 || path.Length != 3 {
		t.Errorf("path = %v (length %d), want main -> Step1 -> Step2 -> Step3", namesOf(path.Symbols), path.Length)
	}
	if path.Symbols[len(path.Symbols)-1].ID != step3 {
		t.Errorf("path does not end at the sink: %v", namesOf(path.Symbols))
	}
	if len(path.EdgeIDs) != 3 {
		t.Errorf("path has %d edge ids, want 3", len(path.EdgeIDs))
	}
	if !strings.Contains(strings.Join(paths.Limitations, "\n"), "not a dataflow fact") {
		t.Errorf("path semantics are not stated: %v", paths.Limitations)
	}

	// No route in the other direction: Step3 cannot reach main.
	none, err := svc.CallPaths(ctx, snapID, graph.PathRequest{Source: step3, Sink: mainID})
	if err != nil {
		t.Fatal(err)
	}
	if len(none.Paths) != 0 {
		t.Errorf("unexpected reverse path: %+v", none.Paths)
	}
	if !strings.Contains(strings.Join(none.Limitations, "\n"), "no call path") {
		t.Errorf("absent paths are not explained: %v", none.Limitations)
	}

	// A depth budget smaller than the route reports truncation.
	shallow, err := svc.CallPaths(ctx, snapID, graph.PathRequest{Source: mainID, Sink: step3, Options: graph.Options{MaxDepth: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if len(shallow.Paths) != 0 || !shallow.Meta.Truncated {
		t.Errorf("shallow search = %d paths, truncated=%v", len(shallow.Paths), shallow.Meta.Truncated)
	}
	if !strings.Contains(shallow.Meta.TruncationReason, "depth budget") {
		t.Errorf("reason = %q", shallow.Meta.TruncationReason)
	}

	// A source that is its own sink is a zero-length path, not an error.
	self, err := svc.CallPaths(ctx, snapID, graph.PathRequest{Source: mainID, Sink: mainID})
	if err != nil || len(self.Paths) != 1 {
		t.Errorf("self path = %+v, %v", self.Paths, err)
	}
	if _, err := svc.CallPaths(ctx, snapID, graph.PathRequest{Source: "", Sink: step3}); !errors.Is(err, graph.ErrInvalidArgument) {
		t.Errorf("missing source error = %v", err)
	}
}

func TestSlice(t *testing.T) {
	t.Parallel()
	svc, g := newFixture(t)
	ctx := context.Background()
	step2 := symbolID(t, g, "example.invalid/chain/internal/flow.Step2")

	slice, err := svc.Slice(ctx, snapID, graph.SliceRequest{SymbolID: step2})
	if err != nil {
		t.Fatalf("Slice: %v", err)
	}
	if len(slice.Sections) != 1 {
		t.Fatalf("sections = %d, want 1: %+v", len(slice.Sections), slice.Sections)
	}
	body := strings.Join(slice.Sections[0].Lines, "\n")
	if !strings.Contains(body, "func Step2()") || !strings.Contains(body, "Step3()") {
		t.Errorf("unexpected declaration slice:\n%s", body)
	}
	if slice.Sections[0].Symbol != "example.invalid/chain/internal/flow.Step2" {
		t.Errorf("section lost its symbol: %+v", slice.Sections[0])
	}

	withCallers, err := svc.Slice(ctx, snapID, graph.SliceRequest{SymbolID: step2, Include: "callers"})
	if err != nil {
		t.Fatal(err)
	}
	if len(withCallers.Sections) < 2 {
		t.Fatalf("caller sections missing: %+v", withCallers.Sections)
	}
	found := false
	for _, s := range withCallers.Sections {
		if s.Reason == graph.SectionCaller && strings.Contains(strings.Join(s.Lines, "\n"), "Step2()") {
			found = true
		}
	}
	if !found {
		t.Errorf("no caller call-site section: %+v", withCallers.Sections)
	}

	withCalls, err := svc.Slice(ctx, snapID, graph.SliceRequest{SymbolID: step2, Include: "calls"})
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, s := range withCalls.Sections {
		if s.Reason == graph.SectionCall && strings.Contains(strings.Join(s.Lines, "\n"), "Step3()") {
			found = true
		}
	}
	if !found {
		t.Errorf("no in-symbol call section: %+v", withCalls.Sections)
	}

	// A line budget cuts the section and says so.
	truncated, err := svc.Slice(ctx, snapID, graph.SliceRequest{SymbolID: step2, MaxLines: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !truncated.Sections[0].Truncated || len(truncated.Sections[0].Lines) != 1 {
		t.Errorf("line budget not applied: %+v", truncated.Sections[0])
	}

	// File selector.
	fileSlice, err := svc.Slice(ctx, snapID, graph.SliceRequest{File: "main.go", StartLine: 1, EndLine: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(fileSlice.Sections) != 1 || len(fileSlice.Sections[0].Lines) != 3 {
		t.Errorf("file slice = %+v", fileSlice.Sections)
	}

	if _, err := svc.Slice(ctx, snapID, graph.SliceRequest{}); !errors.Is(err, graph.ErrInvalidArgument) {
		t.Errorf("empty slice request error = %v", err)
	}
	if _, err := svc.Slice(ctx, snapID, graph.SliceRequest{File: "../../etc/passwd"}); err == nil {
		t.Error("a path outside the snapshot was accepted")
	}
	// A snapshot whose tree is gone cannot be sliced.
	orphan := graph.NewService(storage.NewMemory(), resolver{dir: filepath.Join(t.TempDir(), "missing")})
	if _, err := orphan.Slice(ctx, snapID, graph.SliceRequest{File: "main.go"}); !errors.Is(err, graph.ErrTreeUnavailable) {
		t.Errorf("missing tree error = %v", err)
	}
}

func TestMissingGraphIsAnError(t *testing.T) {
	t.Parallel()
	svc, _ := newFixture(t)
	ctx := context.Background()
	const missing = "snap-fedcba9876543210fedcba9876543210"

	if _, err := svc.Summary(ctx, missing); !errors.Is(err, graph.ErrNoGraph) {
		t.Errorf("Summary error = %v, want ErrNoGraph", err)
	}
	if _, err := svc.Modules(ctx, missing, graph.Options{}); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Modules error = %v", err)
	}
	if _, err := svc.Callees(ctx, missing, "sym-whatever", graph.Options{}); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Callees error = %v", err)
	}
	if _, err := svc.Symbols(ctx, missing, graph.SymbolQuery{}); !errors.Is(err, graph.ErrNoGraph) {
		t.Errorf("Symbols error = %v, want ErrNoGraph", err)
	}
}

func TestUnresolvedCallsAreQueryable(t *testing.T) {
	t.Parallel()
	svc, g := newFixture(t)
	ctx := context.Background()
	externalID := symbolID(t, g, "example.invalid/chain/internal/flow.External")

	sites, meta, err := svc.UnresolvedCalls(ctx, snapID, externalID, graph.Options{})
	if err != nil {
		t.Fatalf("UnresolvedCalls: %v", err)
	}
	if len(sites) == 0 {
		t.Fatal("expected an unresolved call site")
	}
	for _, cs := range sites {
		if cs.Resolution.IsResolved() {
			t.Errorf("resolved call site reported as unresolved: %+v", cs)
		}
	}
	if meta.Query != "unresolved_calls" || meta.SnapshotID != snapID {
		t.Errorf("meta = %+v", meta)
	}
}

// ctx2 returns a context that is already cancelled, for cancellation tests.
func ctx2(c context.Context) context.Context { return c }

func names(n *graph.Neighborhood) []string {
	out := make([]string, 0, len(n.Nodes))
	for _, node := range n.Nodes {
		out = append(out, node.Symbol.QualifiedName)
	}
	return out
}

func namesOf(syms []scg.Symbol) []string {
	out := make([]string, 0, len(syms))
	for _, s := range syms {
		out = append(out, s.QualifiedName)
	}
	return out
}

func containsSymbol(n *graph.Neighborhood, id string) bool {
	for _, node := range n.Nodes {
		if node.Symbol.ID == id {
			return true
		}
	}
	return false
}
