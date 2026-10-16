package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/open-mcp-ai/Codexploit/internal/graph"
	internalmcp "github.com/open-mcp-ai/Codexploit/internal/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

const testSnapshotID = "snap-0123456789abcdef0123456789abcdef"

// fixtureFiles is a small but realistic Go module: main calls a constructor and
// a method, and the method calls a package-level function, which gives the
// tests a two-hop call path.
var fixtureFiles = map[string]string{
	"go.mod": "module example.invalid/svc\n\ngo 1.24\n",
	"main.go": `package main

import "example.invalid/svc/internal/db"

func main() { db.Connect().Query("select 1") }
`,
	"internal/db/db.go": `package db

type DB struct{}

func Connect() *DB { return &DB{} }

func (d *DB) Query(sql string) { log(sql) }

func log(sql string) { _ = sql }
`,
}

// treeResolver stands in for repository.Manager: a code slice only needs the
// snapshot directory, whose frozen tree lives in the repository.TreeDirName
// sub-directory.
type treeResolver struct{ dir string }

func (r treeResolver) Load(string) (*repository.Snapshot, error) {
	return &repository.Snapshot{Dir: r.dir}, nil
}

// newClient builds a snapshot-free graph from a temporary Go fixture, stores it
// in memory and connects an in-process MCP client to the server.
func newClient(t *testing.T) (*mcp.ClientSession, *scg.Graph) {
	t.Helper()
	root := t.TempDir()
	tree := filepath.Join(root, repository.TreeDirName)
	for rel, content := range fixtureFiles {
		path := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	g, err := scg.NewBuilder(gofrontend.New()).BuildTree(ctx, testSnapshotID, tree)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	store := storage.NewMemory()
	if err := store.ReplaceGraph(ctx, testSnapshotID, g); err != nil {
		t.Fatalf("ReplaceGraph: %v", err)
	}

	svc := graph.NewService(store, treeResolver{dir: root})
	srv := internalmcp.NewServer(svc, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "codexploit-test", Version: "0.0.0"}, nil).
		Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, g
}

// callOK calls a tool and fails the test on a tool error, returning its
// structured content.
func callOK(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("%s: tool error: %s", name, textOf(t, res))
	}
	out, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("%s: structured content is %T, want a JSON object", name, res.StructuredContent)
	}
	return out
}

// callErr calls a tool that must fail as a tool error and returns the message
// the agent would see.
func callErr(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: got a protocol error %v, want a tool error", name, err)
	}
	if !res.IsError {
		t.Fatalf("%s: got a success result, want an error", name)
	}
	return textOf(t, res)
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func metaOf(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	meta, ok := out["meta"].(map[string]any)
	if !ok {
		t.Fatalf("result carries no provenance block, got keys %v", keysOf(out))
	}
	return meta
}

// assertProvenance checks the part of the provenance contract every tool shares.
func assertProvenance(t *testing.T, out map[string]any) {
	t.Helper()
	meta := metaOf(t, out)
	if got := meta["snapshot_id"]; got != testSnapshotID {
		t.Errorf("meta.snapshot_id = %v, want %s", got, testSnapshotID)
	}
	budget, ok := meta["budget"].(map[string]any)
	if !ok {
		t.Fatalf("meta.budget is %T, want an object", meta["budget"])
	}
	for _, field := range []string{"max_depth", "max_nodes", "max_edges", "limit", "offset", "timeout"} {
		if _, ok := budget[field]; !ok {
			t.Errorf("meta.budget has no %q, so the result does not state its budget", field)
		}
	}
	if meta["query"] == nil {
		t.Error("meta.query is missing")
	}
}

// assertJSONTextIsComplete pins the text channel to the same payload as the
// structured channel: a client that only reads content text must still see the
// provenance block, so replacing it with a prose summary would be a regression.
func assertJSONTextIsComplete(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(textOf(t, res)), &payload); err != nil {
		t.Fatalf("%s: text content is not the JSON payload: %v", name, err)
	}
	meta, ok := payload["meta"].(map[string]any)
	if !ok || meta["snapshot_id"] != testSnapshotID {
		t.Fatalf("%s: text content lost the provenance block: %v", name, payload["meta"])
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func symbolByName(t *testing.T, g *scg.Graph, name string) scg.Symbol {
	t.Helper()
	for _, s := range g.Symbols {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("fixture has no symbol named %q", name)
	return scg.Symbol{}
}

func nodeNames(t *testing.T, out map[string]any) []string {
	t.Helper()
	raw, ok := out["nodes"].([]any)
	if !ok {
		t.Fatalf("neighbourhood has no nodes array, got keys %v", keysOf(out))
	}
	names := make([]string, 0, len(raw))
	for _, n := range raw {
		node, _ := n.(map[string]any)
		sym, _ := node["symbol"].(map[string]any)
		name, _ := sym["name"].(string)
		names = append(names, name)
	}
	return names
}

func TestToolSurfaceIsReadOnly(t *testing.T) {
	cs, _ := newClient(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	want := []string{
		"find_call_paths", "get_callees", "get_callers", "get_code_slice", "get_symbol",
		"graph_summary", "list_modules", "list_symbols", "list_unresolved_calls",
	}
	got := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		got = append(got, tool.Name)
		schema, ok := tool.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("%s: input schema is %T, want a JSON object", tool.Name, tool.InputSchema)
		}
		required, _ := schema["required"].([]any)
		if !slices.Contains(required, any("snapshot_id")) {
			t.Errorf("%s: snapshot_id is not a required argument", tool.Name)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: not advertised as read-only", tool.Name)
		}
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Fatalf("tools = %v, want exactly %v", got, want)
	}
}

func TestListSymbolsIsBoundedAndCarriesProvenance(t *testing.T) {
	cs, _ := newClient(t)
	out := callOK(t, cs, "list_symbols", map[string]any{
		"snapshot_id": testSnapshotID,
		"kind":        "function",
		"limit":       1,
	})
	symbols, ok := out["symbols"].([]any)
	if !ok || len(symbols) != 1 {
		t.Fatalf("symbols = %v, want exactly the one requested", out["symbols"])
	}
	total, _ := out["total"].(float64)
	if total <= 1 {
		t.Fatalf("total = %v, want more matches than the page holds", total)
	}
	assertProvenance(t, out)
	meta := metaOf(t, out)
	if meta["truncated"] != true {
		t.Errorf("meta.truncated = %v, want true for a partial page", meta["truncated"])
	}
	budget := meta["budget"].(map[string]any)
	if budget["limit"] != float64(1) {
		t.Errorf("meta.budget.limit = %v, want the caller's 1", budget["limit"])
	}
	assertJSONTextIsComplete(t, cs, "list_symbols", map[string]any{
		"snapshot_id": testSnapshotID,
		"limit":       1,
	})
}

func TestCallersCalleesAndCallPaths(t *testing.T) {
	cs, g := newClient(t)
	query := symbolByName(t, g, "Query")
	callers := callOK(t, cs, "get_callers", map[string]any{
		"snapshot_id": testSnapshotID,
		"symbol_id":   symbolByName(t, g, "log").ID,
		"max_depth":   1,
	})
	if !slices.Contains(nodeNames(t, callers), "Query") {
		t.Errorf("callers of log = %v, want Query", nodeNames(t, callers))
	}
	assertProvenance(t, callers)

	callees := callOK(t, cs, "get_callees", map[string]any{
		"snapshot_id": testSnapshotID,
		"symbol_id":   query.ID,
		"max_depth":   1,
	})
	if !slices.Contains(nodeNames(t, callees), "log") {
		t.Errorf("callees of Query = %v, want log", nodeNames(t, callees))
	}
	assertProvenance(t, callees)

	paths := callOK(t, cs, "find_call_paths", map[string]any{
		"snapshot_id":      testSnapshotID,
		"source_symbol_id": symbolByName(t, g, "main").ID,
		"sink_symbol_id":   symbolByName(t, g, "log").ID,
		"max_paths":        2,
	})
	found, _ := paths["paths"].([]any)
	if len(found) == 0 {
		t.Fatalf("no call path from main to log, want at least one")
	}
	assertProvenance(t, paths)
}

func TestCodeSliceReadsTheFrozenTree(t *testing.T) {
	cs, g := newClient(t)
	out := callOK(t, cs, "get_code_slice", map[string]any{
		"snapshot_id": testSnapshotID,
		"symbol_id":   symbolByName(t, g, "Query").ID,
		"max_lines":   10,
	})
	sections, ok := out["sections"].([]any)
	if !ok || len(sections) == 0 {
		t.Fatalf("sections = %v, want the declaration of Query", out["sections"])
	}
	first := sections[0].(map[string]any)
	if lines, _ := first["lines"].([]any); len(lines) == 0 {
		t.Errorf("first section has no lines: %v", first)
	}
	assertProvenance(t, out)
}

func TestCodeSliceRefusesPathsOutsideTheSnapshot(t *testing.T) {
	cs, _ := newClient(t)
	msg := callErr(t, cs, "get_code_slice", map[string]any{
		"snapshot_id": testSnapshotID,
		"file":        "../../etc/passwd",
	})
	if !strings.Contains(msg, internalmcp.CodeInvalidArgument) {
		t.Errorf("error %q does not carry %q", msg, internalmcp.CodeInvalidArgument)
	}
}

func TestGraphSummaryCarriesProvenance(t *testing.T) {
	cs, _ := newClient(t)
	out := callOK(t, cs, "graph_summary", map[string]any{"snapshot_id": testSnapshotID})
	summary, ok := out["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary is %T, want an object", out["summary"])
	}
	if symbols, _ := summary["symbols"].(float64); symbols == 0 {
		t.Errorf("summary reports no symbols: %v", summary)
	}
	assertProvenance(t, out)
}

func TestUnresolvedCallsAlwaysAnswer(t *testing.T) {
	cs, _ := newClient(t)
	out := callOK(t, cs, "list_unresolved_calls", map[string]any{
		"snapshot_id": testSnapshotID,
		"limit":       5,
	})
	if _, ok := out["unresolved_call_sites"].([]any); !ok {
		t.Fatalf("unresolved_call_sites is %T, want an array", out["unresolved_call_sites"])
	}
	assertProvenance(t, out)
}

func TestUnknownSnapshotIsNotFound(t *testing.T) {
	cs, _ := newClient(t)
	for _, tool := range []string{"list_symbols", "graph_summary", "list_modules"} {
		msg := callErr(t, cs, tool, map[string]any{"snapshot_id": "snap-ffffffffffffffffffffffffffffffff"})
		if !strings.Contains(msg, internalmcp.CodeNotFound) {
			t.Errorf("%s: error %q does not carry %q", tool, msg, internalmcp.CodeNotFound)
		}
	}
}

func TestUnknownSymbolIsNotFound(t *testing.T) {
	cs, _ := newClient(t)
	for _, tool := range []string{"get_symbol", "get_callers", "get_callees"} {
		msg := callErr(t, cs, tool, map[string]any{
			"snapshot_id": testSnapshotID,
			"symbol_id":   "sym-does-not-exist",
		})
		if !strings.Contains(msg, internalmcp.CodeNotFound) {
			t.Errorf("%s: error %q does not carry %q", tool, msg, internalmcp.CodeNotFound)
		}
	}
}

func TestMissingOrEmptySnapshotIDIsRejected(t *testing.T) {
	cs, _ := newClient(t)
	if msg := callErr(t, cs, "list_modules", map[string]any{}); !strings.Contains(msg, "snapshot_id") {
		t.Errorf("missing snapshot_id: error %q does not mention the argument", msg)
	}
	if msg := callErr(t, cs, "graph_summary", map[string]any{"snapshot_id": "  "}); !strings.Contains(msg, internalmcp.CodeInvalidArgument) {
		t.Errorf("blank snapshot_id: error %q does not carry %q", msg, internalmcp.CodeInvalidArgument)
	}
}

func TestUnknownKindAndIncludeAreRejected(t *testing.T) {
	cs, _ := newClient(t)
	msg := callErr(t, cs, "list_symbols", map[string]any{
		"snapshot_id": testSnapshotID,
		"kind":        "not-a-kind",
	})
	if !strings.Contains(msg, internalmcp.CodeInvalidArgument) {
		t.Errorf("kind: error %q does not carry %q", msg, internalmcp.CodeInvalidArgument)
	}
	msg = callErr(t, cs, "get_code_slice", map[string]any{
		"snapshot_id": testSnapshotID,
		"symbol_id":   "any",
		"include":     "everything",
	})
	if !strings.Contains(msg, internalmcp.CodeInvalidArgument) {
		t.Errorf("include: error %q does not carry %q", msg, internalmcp.CodeInvalidArgument)
	}
}
