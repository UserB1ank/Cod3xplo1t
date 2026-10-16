package scg_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
)

// goFixtureFiles is a small but realistic Go repository: one root module, one
// nested module, a struct type with methods, an interface, a function-typed
// package variable, a constructor whose result type must be inferred, and a
// non-source file.
var goFixtureFiles = map[string]string{
	"go.mod": "module example.invalid/app\n\ngo 1.24\n",
	"main.go": `package main

import (
	"fmt"

	"example.invalid/app/internal/store"
)

func main() {
	s := store.New()
	s.Save("users")
	helper()
	store.PackageValue("x")
	store.Callback("y")
	var saver store.Saver = s
	store.Use(saver)
	fmt.Println(len("hi"))
}

func helper() { fmt.Println("hi") }
`,
	"internal/store/store.go": `package store

type Store struct{ name string }

func New() *Store { return &Store{name: "s"} }

func (s *Store) Save(name string) { write(name) }

func (s *Store) String() string { return s.name }

func write(name string) { _ = name }

func PackageValue(v string) { _ = v }

var Callback = func(v string) { write(v) }
`,
	"internal/store/iface.go": `package store

type Saver interface {
	Save(string)
}

func Use(s Saver) { s.Save("via-interface") }
`,
	"internal/store/chain.go": `package store

type Repo struct{ store *Store }

func Open() *Repo { return &Repo{store: New()} }

func (r *Repo) Persist(name string) { r.store.Save(name) }

func (r *Repo) PersistAll(names []string) {
	for _, n := range names {
		r.Persist(n)
	}
	_ = len(names)
}
`,
	"internal/other/other.go": `package other

import "example.invalid/app/internal/store"

func Touch() {
	r := store.Open()
	r.Persist("from-other")
}
`,
	"README.md":    "# fixture\n",
	"tools/go.mod": "module example.invalid/tools\n\ngo 1.24\n",
	"tools/tool.go": `package main

import "example.invalid/app/internal/store"

func main() {
	s := store.New()
	s.Save("from-tools")
}
`,
}

const testSnapshotID = "snap-0123456789abcdef0123456789abcdef"

func goFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range goFixtureFiles {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// countFixtureFiles counts fixture entries below a module root.
func countFixtureFiles(root string) int {
	n := 0
	for rel := range goFixtureFiles {
		if root == "." || rel == root || strings.HasPrefix(rel, root+"/") {
			n++
		}
	}
	return n
}

func buildFixture(t *testing.T, tree string) *scg.Graph {
	t.Helper()
	b := scg.NewBuilder(gofrontend.New())
	g, err := b.BuildTree(context.Background(), testSnapshotID, tree)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	return g
}

func symbolByQualified(t *testing.T, g *scg.Graph, qualified string) scg.Symbol {
	t.Helper()
	for _, s := range g.Symbols {
		if s.QualifiedName == qualified {
			return s
		}
	}
	t.Fatalf("symbol %q not found; symbols: %v", qualified, qualifiedNames(g))
	return scg.Symbol{}
}

// callSiteAt finds a call site by the file it appears in and the callee it
// names. A callee can be called from several files with different certainty, so
// the file is part of the identity of the assertion.
func callSiteAt(t *testing.T, g *scg.Graph, file, callee string) scg.CallSite {
	t.Helper()
	for _, cs := range g.CallSites {
		if cs.CalleeQualified == callee && cs.File == file {
			return cs
		}
	}
	t.Fatalf("no call site %s -> %q; callees: %v", file, callee, calleeNames(g))
	return scg.CallSite{}
}

func calleeNames(g *scg.Graph) []string {
	out := make([]string, 0, len(g.CallSites))
	for _, cs := range g.CallSites {
		if cs.CalleeQualified != "" {
			out = append(out, cs.CalleeQualified)
		}
	}
	return out
}

func qualifiedNames(g *scg.Graph) []string {
	out := make([]string, 0, len(g.Symbols))
	for _, s := range g.Symbols {
		out = append(out, s.QualifiedName)
	}
	return out
}

func TestBuildDiscoversModulesAndSymbols(t *testing.T) {
	t.Parallel()
	g := buildFixture(t, goFixture(t))

	if g.SnapshotID != testSnapshotID {
		t.Errorf("snapshot id = %q", g.SnapshotID)
	}
	if !strings.HasPrefix(g.GraphVersion, "graph-") {
		t.Errorf("graph version = %q", g.GraphVersion)
	}
	if len(g.Modules) != 2 {
		t.Fatalf("modules = %d, want 2 (root and tools): %+v", len(g.Modules), g.Modules)
	}
	byName := map[string]scg.Module{}
	for _, mod := range g.Modules {
		byName[mod.Name] = mod
	}
	root, ok := byName["example.invalid/app"]
	if !ok {
		t.Fatalf("root module not found: %+v", g.Modules)
	}
	if root.Path != "." || root.Files != countFixtureFiles(".")-countFixtureFiles("tools") {
		t.Errorf("root module = %+v", root)
	}
	if root.Language != "Go" {
		t.Errorf("root module language = %q", root.Language)
	}
	tools, ok := byName["example.invalid/tools"]
	if !ok {
		t.Fatalf("nested module not found: %+v", g.Modules)
	}
	if tools.Path != "tools" || tools.Files != 2 {
		t.Errorf("nested module = %+v", tools)
	}

	want := []string{
		"example.invalid/app.main",
		"example.invalid/app.helper",
		"example.invalid/app/internal/store.New",
		"example.invalid/app/internal/store.Open",
		"example.invalid/app/internal/store.Store.Save",
		"example.invalid/app/internal/store.Store.String",
		"example.invalid/app/internal/store.write",
		"example.invalid/app/internal/store.PackageValue",
		"example.invalid/app/internal/store.Callback",
		"example.invalid/app/internal/store.Store",
		"example.invalid/app/internal/store.Saver",
		"example.invalid/app/internal/store.Use",
		"example.invalid/app/internal/store.Repo.Persist",
		"example.invalid/app/internal/store.Repo.PersistAll",
		"example.invalid/tools.main",
	}
	have := map[string]bool{}
	for _, s := range g.Symbols {
		have[s.QualifiedName] = true
		if s.ID == "" || s.SnapshotID != testSnapshotID || s.FileID == "" || s.ModuleID == "" {
			t.Errorf("symbol without identity: %+v", s)
		}
	}
	for _, q := range want {
		if !have[q] {
			t.Errorf("symbol %q missing", q)
		}
	}
	save := symbolByQualified(t, g, "example.invalid/app/internal/store.Store.Save")
	if save.Kind != scg.KindMethod || save.Receiver != "Store" || !save.Exported {
		t.Errorf("unexpected Save symbol: %+v", save)
	}
	if save.Signature == "" {
		t.Error("method signature was not recorded")
	}
	if got := symbolByQualified(t, g, "example.invalid/app/internal/store.Saver"); got.Kind != scg.KindInterface {
		t.Errorf("Saver kind = %q, want interface", got.Kind)
	}
	if got := symbolByQualified(t, g, "example.invalid/app/internal/store.New"); got.ResultType != "Store" {
		t.Errorf("New result type = %q, want Store", got.ResultType)
	}
	if got := symbolByQualified(t, g, "example.invalid/app/internal/store.Callback"); got.Kind != scg.KindVar {
		t.Errorf("Callback kind = %q, want var", got.Kind)
	}
	if len(g.Files) != len(goFixtureFiles) {
		t.Errorf("files = %d, want %d", len(g.Files), len(goFixtureFiles))
	}
}

func TestBuildResolvesCallsAndMarksUnresolved(t *testing.T) {
	t.Parallel()
	g := buildFixture(t, goFixture(t))

	cases := []struct {
		file       string
		callee     string
		resolution scg.Resolution
		confidence scg.Confidence
	}{
		{"main.go", "example.invalid/app.helper", scg.Resolved, scg.Observed},
		{"main.go", "example.invalid/app/internal/store.New", scg.Resolved, scg.Observed},
		{"main.go", "example.invalid/app/internal/store.Store.Save", scg.ResolvedBestEffort, scg.Inferred},
		{"main.go", "example.invalid/app/internal/store.Use", scg.Resolved, scg.Observed},
		{"main.go", "builtin:len", scg.Builtin, scg.Observed},
		{"main.go", "fmt.Println", scg.External, scg.Unresolved},
		{"main.go", "example.invalid/app/internal/store.Callback", scg.Dynamic, scg.Unresolved},
		{"internal/store/iface.go", "example.invalid/app/internal/store.Saver.Save", scg.Dynamic, scg.Unresolved},
		{"internal/store/chain.go", "example.invalid/app/internal/store.Repo.Persist", scg.Resolved, scg.Observed},
		{"internal/other/other.go", "example.invalid/app/internal/store.Repo.Persist", scg.ResolvedBestEffort, scg.Inferred},
		{"tools/tool.go", "example.invalid/app/internal/store.Store.Save", scg.ResolvedBestEffort, scg.Inferred},
	}
	for _, tc := range cases {
		cs := callSiteAt(t, g, tc.file, tc.callee)
		if cs.Resolution != tc.resolution || cs.Confidence != tc.confidence {
			t.Errorf("%s %s: resolution=%s confidence=%s, want %s/%s (%s)",
				tc.file, tc.callee, cs.Resolution, cs.Confidence, tc.resolution, tc.confidence, cs.Detail)
		}
		if cs.CallerSymbolID == "" {
			t.Errorf("%s %s: call site has no caller symbol", tc.file, tc.callee)
		}
		if cs.Analyzer == "" || cs.AnalyzerVersion == "" || cs.Line == 0 {
			t.Errorf("%s %s: call site lacks provenance: %+v", tc.file, tc.callee, cs)
		}
	}
	if g.Resolution.Total() != len(g.CallSites) {
		t.Errorf("resolution counters (%d) do not match call sites (%d)", g.Resolution.Total(), len(g.CallSites))
	}
	for _, count := range []int{g.Resolution.Resolved, g.Resolution.ResolvedBestEffort, g.Resolution.External, g.Resolution.Dynamic, g.Resolution.Builtin} {
		if count == 0 {
			t.Errorf("unexpected resolution mix: %+v", g.Resolution)
		}
	}
}

func TestBuildEdgesCarryProvenance(t *testing.T) {
	t.Parallel()
	g := buildFixture(t, goFixture(t))

	counts := map[scg.EdgeKind]int{}
	seen := map[string]bool{}
	importTargets := map[string]bool{}
	_ = importTargets
	for _, e := range g.Edges {
		if seen[e.ID] {
			t.Fatalf("duplicate edge id %s", e.ID)
		}
		seen[e.ID] = true
		counts[e.Kind]++
		switch e.Kind {
		case scg.EdgeCalls:
			if e.Analyzer == "" || e.AnalyzerVersion == "" || e.SourceLocation.File == "" || e.SourceLocation.Line == 0 {
				t.Errorf("CALLS edge without provenance: %+v", e)
			}
			if e.CallSiteID == "" {
				t.Errorf("CALLS edge without a call site: %+v", e)
			}
		case scg.EdgeImports:
			if e.Detail["import_path"] == "" || e.Detail["count"] == "" {
				t.Errorf("IMPORTS edge without an import path or count: %+v", e)
			}
			importTargets[e.To] = true
		}
	}
	if counts[scg.EdgeCalls] == 0 || counts[scg.EdgeImports] == 0 || counts[scg.EdgeContains] == 0 {
		t.Fatalf("missing edge kinds: %+v", counts)
	}
	moduleID := map[string]string{}
	for _, mod := range g.Modules {
		moduleID[mod.Path] = mod.ID
	}
	// The nested tools module imports the root module's store package.
	importPairs := map[string]bool{}
	for _, e := range g.Edges {
		if e.Kind == scg.EdgeImports {
			importPairs[e.From+"->"+e.To] = true
		}
	}
	wantPair := moduleID["tools"] + "->" + moduleID["."]
	if !importPairs[wantPair] {
		t.Errorf("missing IMPORTS edge tools -> root: %v", importPairs)
	}
	summary := g.Summarize()
	if summary.EdgesByKind["CALLS"] != counts[scg.EdgeCalls] || summary.Edges != len(g.Edges) {
		t.Errorf("summary disagrees with the graph: %+v", summary)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	t.Parallel()
	tree := goFixture(t)
	b := scg.NewBuilder(gofrontend.New())
	first, err := b.BuildTree(context.Background(), testSnapshotID, tree)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.BuildTree(context.Background(), testSnapshotID, tree)
	if err != nil {
		t.Fatal(err)
	}
	first.BuiltAt, second.BuiltAt = "", ""
	first.BuildDurationMS, second.BuildDurationMS = 0, 0
	a, err := first.JSON()
	if err != nil {
		t.Fatal(err)
	}
	c, err := second.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(c) {
		t.Error("graph builds are not deterministic")
	}
	other, err := b.BuildTree(context.Background(), "snap-fedcba9876543210fedcba9876543210", tree)
	if err != nil {
		t.Fatal(err)
	}
	if other.GraphVersion == first.GraphVersion {
		t.Error("graph version ignores the snapshot id")
	}
	if len(other.Symbols) != len(first.Symbols) || other.Symbols[0].ID == first.Symbols[0].ID {
		t.Error("symbol ids are not snapshot-scoped")
	}
	empty := scg.NewBuilder()
	noFrontends, err := empty.BuildTree(context.Background(), testSnapshotID, tree)
	if err != nil {
		t.Fatal(err)
	}
	if noFrontends.GraphVersion == first.GraphVersion {
		t.Error("graph version ignores the frontend set")
	}
}

func TestBuildReportsCoverageAndLimitations(t *testing.T) {
	t.Parallel()
	tree := goFixture(t)
	if err := os.WriteFile(filepath.Join(tree, "app.py"), []byte("print('hi')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := buildFixture(t, tree)

	joined := strings.Join(g.Limitations, "\n")
	for _, want := range []string{"without a registered frontend", "unresolved call", "static approximations", "FLOWS_TO", "not source code"} {
		if !strings.Contains(joined, want) {
			t.Errorf("limitations do not mention %q:\n%s", want, joined)
		}
	}
	if g.Coverage.FilesInSnapshot != len(goFixtureFiles)+1 {
		t.Errorf("files in snapshot = %d, want %d", g.Coverage.FilesInSnapshot, len(goFixtureFiles)+1)
	}
	if g.Coverage.FilesUnsupported != 1 {
		t.Errorf("unsupported files = %d, want 1 (app.py)", g.Coverage.FilesUnsupported)
	}
	if g.Coverage.FilesNotSource != 3 {
		t.Errorf("not-source files = %d, want 3 (README.md and two go.mod)", g.Coverage.FilesNotSource)
	}
	// Every Go file of the fixture parses.
	if g.Coverage.FilesParsed != len(goFixtureFiles)-3 {
		t.Errorf("parsed files = %d, want %d", g.Coverage.FilesParsed, len(goFixtureFiles)-3)
	}
	status := map[string]string{}
	for _, f := range g.Files {
		status[f.Path] = f.ParseStatus
	}
	if status["app.py"] != scg.ParseUnsupported {
		t.Errorf("app.py status = %q, want %q", status["app.py"], scg.ParseUnsupported)
	}
	if status["README.md"] != scg.ParseNotSource {
		t.Errorf("README.md status = %q, want %q", status["README.md"], scg.ParseNotSource)
	}
	if status["main.go"] != scg.ParseOK {
		t.Errorf("main.go status = %q, want ok", status["main.go"])
	}
}

func TestBuildRespectsLimits(t *testing.T) {
	t.Parallel()
	tree := goFixture(t)

	b := scg.NewBuilder(gofrontend.New())
	b.Limits.MaxFileBytes = 40
	g, err := b.BuildTree(context.Background(), testSnapshotID, tree)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if g.Coverage.FilesTooLarge == 0 {
		t.Error("oversized files were not counted")
	}
	if !strings.Contains(strings.Join(g.Limitations, "\n"), "per-file size limit") {
		t.Error("size limit is not stated as a limitation")
	}

	b2 := scg.NewBuilder(gofrontend.New())
	b2.Limits.MaxSymbols = 1
	g2, err := b2.BuildTree(context.Background(), testSnapshotID, tree)
	if err != nil {
		t.Fatal(err)
	}
	if g2.Coverage.SymbolsSkipped == 0 {
		t.Error("symbol budget did not stop any file")
	}
	if !strings.Contains(strings.Join(g2.Limitations, "\n"), "symbol budget") {
		t.Errorf("symbol budget is not stated: %v", g2.Limitations)
	}

	b3 := scg.NewBuilder(gofrontend.New())
	b3.Limits.MaxEdges = 2
	g3, err := b3.BuildTree(context.Background(), testSnapshotID, tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(g3.Edges) != 2 {
		t.Errorf("edge budget not enforced: %d edges", len(g3.Edges))
	}
	if !strings.Contains(strings.Join(g3.Limitations, "\n"), "edge budget") {
		t.Errorf("edge budget is not stated: %v", g3.Limitations)
	}
}

func TestMalformedFileIsRecordedNotDropped(t *testing.T) {
	t.Parallel()
	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "go.mod"), []byte("module example.invalid/broken\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "broken.go"), []byte("package broken\n\nfunc Unclosed( {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := buildFixture(t, tree)
	if len(g.Files) != 2 {
		t.Fatalf("files = %d, want 2", len(g.Files))
	}
	var broken scg.File
	for _, f := range g.Files {
		if f.Path == "broken.go" {
			broken = f
		}
	}
	if broken.ParseStatus == scg.ParseOK {
		t.Errorf("malformed file reported as ok: %+v", broken)
	}
	if broken.ParseError == "" {
		t.Error("malformed file has no error text")
	}
	if g.Coverage.FilesPartial+g.Coverage.FilesUnparsed == 0 {
		t.Error("parse failure is not reflected in coverage")
	}
	if !strings.Contains(strings.Join(g.Limitations, "\n"), "could not be parsed") {
		t.Errorf("parse failure is not stated as a limitation: %v", g.Limitations)
	}
}

func TestSymbolIDsAreStableWithinASnapshot(t *testing.T) {
	t.Parallel()
	tree := goFixture(t)
	g := buildFixture(t, tree)
	before := symbolByQualified(t, g, "example.invalid/app/internal/store.write")

	path := filepath.Join(tree, "internal/store/store.go")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(content), "func write(name string) { _ = name }",
		"func write(name string) {\n\t_ = name\n\t_ = len(name)\n}", 1)
	if edited == string(content) {
		t.Fatal("fixture edit did not apply")
	}
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	g2 := buildFixture(t, tree)
	after := symbolByQualified(t, g2, "example.invalid/app/internal/store.write")
	if before.ID != after.ID {
		t.Errorf("symbol id changed after a body edit: %s -> %s", before.ID, after.ID)
	}
	if after.EndLine == before.EndLine {
		t.Error("the edit did not change the recorded end line")
	}
	if scg.SymbolID(g.SnapshotID, "Go", before.File, before.QualifiedName, "func()", scg.Location{File: before.File, Line: before.StartLine}) == before.ID {
		t.Error("signature does not participate in the symbol id")
	}
	if scg.SymbolID("snap-fedcba9876543210fedcba9876543210", "Go", before.File, before.QualifiedName, before.Signature, scg.Location{File: before.File, Line: before.StartLine}) == before.ID {
		t.Error("snapshot id does not participate in the symbol id")
	}
}

func TestCallSitesCarryArgumentFacts(t *testing.T) {
	t.Parallel()
	tree := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.invalid/routes\n\ngo 1.24\n",
		"main.go": `package main

import "example.invalid/routes/web"

func main() { web.Run() }
`,
		"web/server.go": `package web

import "net/http"

func Run() {
	mux := http.NewServeMux()
	mux.HandleFunc("/users/:id", showUser)
	http.ListenAndServe(":8080", mux)
}

func showUser(w http.ResponseWriter, r *http.Request) { _ = w; _ = r }
`,
	}
	for rel, content := range files {
		p := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g := buildFixture(t, tree)

	var route scg.CallSite
	for _, cs := range g.CallSites {
		if cs.CalleeText == "mux.HandleFunc" {
			route = cs
		}
	}
	if route.ID == "" {
		t.Fatalf("route registration was not recorded: %v", calleeNames(g))
	}
	if len(route.Args) != 2 {
		t.Fatalf("route call has %d argument facts, want 2: %+v", len(route.Args), route.Args)
	}
	path := route.Args[0]
	if path.Kind != scg.ArgStringLiteral || path.StringValue != "/users/:id" {
		t.Errorf("route path argument = %+v", path)
	}
	handler := route.Args[1]
	if handler.Kind != scg.ArgSymbolRef || handler.SymbolID == "" {
		t.Fatalf("handler argument was not resolved to a symbol: %+v", handler)
	}
	if handler.SymbolQualified != "example.invalid/routes/web.showUser" {
		t.Errorf("handler qualified name = %q", handler.SymbolQualified)
	}
	// The receiver came from a constructor in another package, so no receiver
	// type could be inferred, but its provenance is recorded.
	if route.ReceiverFrom != "" && !strings.Contains(route.ReceiverFrom, "NewServeMux") {
		t.Errorf("receiver provenance = %q", route.ReceiverFrom)
	}
	// A non-literal, non-symbol argument keeps its text without claiming a target.
	var listen scg.CallSite
	for _, cs := range g.CallSites {
		if cs.CalleeText == "http.ListenAndServe" {
			listen = cs
		}
	}
	if listen.ID == "" {
		t.Fatal("external call was not recorded")
	}
	if len(listen.Args) == 0 || listen.Args[0].Kind != scg.ArgStringLiteral || listen.Args[0].StringValue != ":8080" {
		t.Errorf("listen address argument = %+v", listen.Args)
	}
}
