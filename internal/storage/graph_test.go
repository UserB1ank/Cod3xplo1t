package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
)

const graphSnapshotID = "snap-0123456789abcdef0123456789abcdef"

// graphFixtureTree writes a tiny Go repository and returns its tree directory.
func graphFixtureTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
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
	for rel, content := range files {
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

func graphFixture(t *testing.T) *scg.Graph {
	t.Helper()
	b := scg.NewBuilder(gofrontend.New())
	g, err := b.BuildTree(context.Background(), graphSnapshotID, graphFixtureTree(t))
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	return g
}

// fullStore opens each store implementation that can persist graphs.
func fullStores(t *testing.T) []struct {
	name  string
	store FullStore
} {
	t.Helper()
	out := []struct {
		name  string
		store FullStore
	}{{"memory", NewMemory()}}
	for _, f := range storeFactories() {
		if f.name != "sqlite" {
			continue
		}
		store, ok := f.open(t).(FullStore)
		if !ok {
			t.Fatalf("%s does not implement FullStore", f.name)
		}
		out = append(out, struct {
			name  string
			store FullStore
		}{f.name, store})
	}
	return out
}

func TestGraphRoundTrip(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			g := graphFixture(t)
			if err := tc.store.ReplaceGraph(ctx, graphSnapshotID, g); err != nil {
				t.Fatalf("ReplaceGraph: %v", err)
			}

			summary, err := tc.store.GraphSummary(ctx, graphSnapshotID)
			if err != nil {
				t.Fatalf("GraphSummary: %v", err)
			}
			if summary.Symbols != len(g.Symbols) || summary.Edges != len(g.Edges) || summary.CallSites != len(g.CallSites) {
				t.Fatalf("summary %+v does not match the graph (%d symbols, %d edges, %d call sites)",
					summary, len(g.Symbols), len(g.Edges), len(g.CallSites))
			}
			if summary.GraphVersion != g.GraphVersion || summary.Engine != g.Engine {
				t.Errorf("summary lost the graph identity: %+v", summary)
			}
			if summary.Resolution.Total() != len(g.CallSites) {
				t.Errorf("resolution counters were not persisted: %+v", summary.Resolution)
			}
			if len(summary.Limitations) == 0 {
				t.Error("limitations were not persisted")
			}
			if summary.EdgesByKind["CALLS"] == 0 {
				t.Errorf("edge kinds were not persisted: %+v", summary.EdgesByKind)
			}

			mods, err := tc.store.ListModules(ctx, graphSnapshotID)
			if err != nil || len(mods) == 0 {
				t.Fatalf("ListModules = %v, %v", mods, err)
			}
			mod, err := tc.store.GetModule(ctx, graphSnapshotID, mods[0].ID)
			if err != nil || mod.ID != mods[0].ID {
				t.Fatalf("GetModule = %+v, %v", mod, err)
			}

			files, err := tc.store.ListFiles(ctx, graphSnapshotID, "")
			if err != nil || len(files) != len(g.Files) {
				t.Fatalf("ListFiles = %d files, %v", len(files), err)
			}
			if _, err := tc.store.GetFile(ctx, graphSnapshotID, files[0].Path); err != nil {
				t.Fatalf("GetFile by path: %v", err)
			}

			all, total, err := tc.store.ListSymbols(ctx, SymbolQuery{SnapshotID: graphSnapshotID, Limit: 1000})
			if err != nil {
				t.Fatalf("ListSymbols: %v", err)
			}
			if total != len(g.Symbols) || len(all) != len(g.Symbols) {
				t.Fatalf("ListSymbols returned %d/%d, want %d", len(all), total, len(g.Symbols))
			}
			var method scg.Symbol
			for _, s := range all {
				if s.Kind == scg.KindMethod {
					method = s
				}
			}
			if method.ID == "" {
				t.Fatal("fixture has no method symbol")
			}
			byID, err := tc.store.GetSymbol(ctx, graphSnapshotID, method.ID)
			if err != nil || byID.QualifiedName != method.QualifiedName {
				t.Fatalf("GetSymbol by id = %+v, %v", byID, err)
			}
			byName, err := tc.store.GetSymbol(ctx, graphSnapshotID, method.QualifiedName)
			if err != nil || byName.ID != method.ID {
				t.Fatalf("GetSymbol by qualified name = %+v, %v", byName, err)
			}
			filtered, filteredTotal, err := tc.store.ListSymbols(ctx, SymbolQuery{
				SnapshotID:   graphSnapshotID,
				Kinds:        []scg.SymbolKind{scg.KindMethod},
				NameContains: "Query",
			})
			if err != nil {
				t.Fatalf("filtered ListSymbols: %v", err)
			}
			if filteredTotal != 1 || len(filtered) != 1 || filtered[0].ID != method.ID {
				t.Fatalf("kind/name filter returned %+v (%d total)", filtered, filteredTotal)
			}
			paged, pageTotal, err := tc.store.ListSymbols(ctx, SymbolQuery{SnapshotID: graphSnapshotID, Limit: 1})
			if err != nil || len(paged) != 1 || pageTotal != len(g.Symbols) {
				t.Fatalf("paging returned %d symbols, total %d, err %v", len(paged), pageTotal, err)
			}

			sites, siteTotal, err := tc.store.ListCallSites(ctx, CallSiteQuery{SnapshotID: graphSnapshotID, Limit: 1000})
			if err != nil || siteTotal != len(g.CallSites) {
				t.Fatalf("ListCallSites = %d/%d, %v", len(sites), siteTotal, err)
			}
			unresolved, _, err := tc.store.ListCallSites(ctx, CallSiteQuery{
				SnapshotID: graphSnapshotID,
				Resolution: []scg.Resolution{scg.External, scg.Dynamic, scg.Ambiguous},
			})
			if err != nil {
				t.Fatalf("unresolved ListCallSites: %v", err)
			}
			for _, cs := range unresolved {
				if cs.Resolution.IsResolved() {
					t.Errorf("resolution filter leaked a resolved call site: %+v", cs)
				}
			}
			byCaller, _, err := tc.store.ListCallSites(ctx, CallSiteQuery{SnapshotID: graphSnapshotID, CallerSymbolID: method.ID})
			if err != nil || len(byCaller) == 0 {
				t.Fatalf("call sites of %s = %v, %v", method.QualifiedName, byCaller, err)
			}

			callsFrom, err := tc.store.EdgesFrom(ctx, graphSnapshotID, []string{method.ID}, []scg.EdgeKind{scg.EdgeCalls})
			if err != nil || len(callsFrom) == 0 {
				t.Fatalf("EdgesFrom = %v, %v", callsFrom, err)
			}
			for _, e := range callsFrom {
				if e.Kind != scg.EdgeCalls || e.From != method.ID {
					t.Errorf("EdgesFrom returned an unexpected edge: %+v", e)
				}
				if e.Analyzer == "" || e.AnalyzerVersion == "" {
					t.Errorf("edge lost its provenance: %+v", e)
				}
			}
			callsTo, err := tc.store.EdgesTo(ctx, graphSnapshotID, []string{method.ID}, []scg.EdgeKind{scg.EdgeCalls})
			if err != nil || len(callsTo) == 0 {
				t.Fatalf("EdgesTo = %v, %v", callsTo, err)
			}
			for _, e := range callsTo {
				if e.To != method.ID {
					t.Errorf("EdgesTo returned an unexpected edge: %+v", e)
				}
			}

			if err := tc.store.DeleteGraph(ctx, graphSnapshotID); err != nil {
				t.Fatalf("DeleteGraph: %v", err)
			}
			if _, err := tc.store.GraphSummary(ctx, graphSnapshotID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("GraphSummary after delete = %v, want ErrNotFound", err)
			}
			if _, _, err := tc.store.ListSymbols(ctx, SymbolQuery{SnapshotID: graphSnapshotID}); !errors.Is(err, ErrNotFound) {
				t.Fatalf("ListSymbols after delete = %v, want ErrNotFound", err)
			}
			if err := tc.store.DeleteGraph(ctx, "snap-fedcba9876543210fedcba9876543210"); err != nil {
				t.Errorf("DeleteGraph on a missing snapshot should be a no-op: %v", err)
			}
		})
	}
}

func TestReplaceGraphIsIdempotentAndValidated(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			g := graphFixture(t)
			for i := 0; i < 3; i++ {
				if err := tc.store.ReplaceGraph(ctx, graphSnapshotID, g); err != nil {
					t.Fatalf("ReplaceGraph run %d: %v", i, err)
				}
			}
			summary, err := tc.store.GraphSummary(ctx, graphSnapshotID)
			if err != nil {
				t.Fatal(err)
			}
			if summary.Symbols != len(g.Symbols) || summary.Edges != len(g.Edges) {
				t.Fatalf("rebuild duplicated rows: %+v", summary)
			}
			if err := tc.store.ReplaceGraph(ctx, graphSnapshotID, nil); !errors.Is(err, ErrConflict) {
				t.Errorf("ReplaceGraph(nil) = %v, want ErrConflict", err)
			}
			other := *g
			other.SnapshotID = "snap-fedcba9876543210fedcba9876543210"
			if err := tc.store.ReplaceGraph(ctx, graphSnapshotID, &other); !errors.Is(err, ErrConflict) {
				t.Errorf("ReplaceGraph with a mismatched snapshot = %v, want ErrConflict", err)
			}
		})
	}
}

func TestGraphReadsAreScopedToASnapshot(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			g := graphFixture(t)
			otherID := "snap-fedcba9876543210fedcba9876543210"
			if err := tc.store.ReplaceGraph(ctx, graphSnapshotID, g); err != nil {
				t.Fatal(err)
			}
			// A second snapshot gets its own ids: rebuilding with the builder is
			// the only way to produce a consistent graph for another snapshot.
			builder := scg.NewBuilder(gofrontend.New())
			other, err := builder.BuildTree(ctx, otherID, graphFixtureTree(t))
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.store.ReplaceGraph(ctx, otherID, other); err != nil {
				t.Fatal(err)
			}
			syms, total, err := tc.store.ListSymbols(ctx, SymbolQuery{SnapshotID: otherID, Limit: 1000})
			if err != nil {
				t.Fatal(err)
			}
			if total != len(g.Symbols) {
				t.Fatalf("second snapshot has %d symbols, want %d", total, len(g.Symbols))
			}
			for _, s := range syms {
				if s.SnapshotID != otherID {
					t.Errorf("symbol from another snapshot leaked: %+v", s)
				}
			}
			if _, err := tc.store.GetSymbol(ctx, otherID, g.Symbols[0].ID); !errors.Is(err, ErrNotFound) {
				t.Errorf("symbol id from another snapshot was readable: %v", err)
			}
			mixed := *other
			mixed.Symbols = append(append([]scg.Symbol{}, other.Symbols...), g.Symbols[0])
			if err := tc.store.ReplaceGraph(ctx, otherID, &mixed); !errors.Is(err, ErrConflict) {
				t.Errorf("ReplaceGraph accepted a graph with foreign elements: %v", err)
			}
			if err := tc.store.DeleteGraph(ctx, otherID); err != nil {
				t.Fatal(err)
			}
			if _, err := tc.store.GraphSummary(ctx, graphSnapshotID); err != nil {
				t.Errorf("deleting one graph removed another: %v", err)
			}
		})
	}
}

func TestMemoryDeleteSnapshotRemovesItsGraph(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemory()
	if err := m.PutProject(ctx, testProject("proj-1")); err != nil {
		t.Fatal(err)
	}
	if err := m.PutSnapshot(ctx, "proj-1", testSnapshot(snapID)); err != nil {
		t.Fatal(err)
	}
	g := graphFixture(t)
	scoped := *g
	scoped.SnapshotID = snapID
	if err := m.ReplaceGraph(ctx, snapID, &scoped); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteSnapshot(ctx, snapID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GraphSummary(ctx, snapID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("graph survived its snapshot: %v", err)
	}
}
