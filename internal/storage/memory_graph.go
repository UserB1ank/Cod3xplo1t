package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// memoryGraph holds the SCG of one snapshot.
type memoryGraph struct {
	graph *scg.Graph
}

// ReplaceGraph implements GraphStore.
func (m *Memory) ReplaceGraph(_ context.Context, snapshotID string, g *scg.Graph) error {
	if err := validateGraph(snapshotID, g); err != nil {
		return err
	}
	// Store a deep copy so a caller cannot mutate stored facts afterwards.
	doc, err := json.Marshal(g)
	if err != nil {
		return err
	}
	var copyGraph scg.Graph
	if err := json.Unmarshal(doc, &copyGraph); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.graphs[snapshotID] = &memoryGraph{graph: &copyGraph}
	return nil
}

// DeleteGraph implements GraphStore.
func (m *Memory) DeleteGraph(_ context.Context, snapshotID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.graphs, snapshotID)
	return nil
}

// GraphSummary implements GraphStore.
func (m *Memory) GraphSummary(_ context.Context, snapshotID string) (*scg.Summary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.graphs[snapshotID]
	if !ok {
		return nil, fmt.Errorf("%w: graph for snapshot %s", ErrNotFound, snapshotID)
	}
	return rec.graph.Summarize(), nil
}

// ListModules implements GraphStore.
func (m *Memory) ListModules(_ context.Context, snapshotID string) ([]scg.Module, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.graphs[snapshotID]
	if !ok {
		return nil, fmt.Errorf("%w: graph for snapshot %s", ErrNotFound, snapshotID)
	}
	out := append([]scg.Module(nil), rec.graph.Modules...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// GetModule implements GraphStore.
func (m *Memory) GetModule(_ context.Context, snapshotID, moduleID string) (scg.Module, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.graphs[snapshotID]
	if !ok {
		return scg.Module{}, fmt.Errorf("%w: graph for snapshot %s", ErrNotFound, snapshotID)
	}
	for _, mod := range rec.graph.Modules {
		if mod.ID == moduleID {
			return mod, nil
		}
	}
	return scg.Module{}, fmt.Errorf("%w: module %s", ErrNotFound, moduleID)
}

// ListFiles implements GraphStore.
func (m *Memory) ListFiles(_ context.Context, snapshotID, moduleID string) ([]scg.File, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.graphs[snapshotID]
	if !ok {
		return nil, fmt.Errorf("%w: graph for snapshot %s", ErrNotFound, snapshotID)
	}
	var out []scg.File
	for _, f := range rec.graph.Files {
		if moduleID != "" && f.ModuleID != moduleID {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// GetFile implements GraphStore.
func (m *Memory) GetFile(_ context.Context, snapshotID, fileID string) (scg.File, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.graphs[snapshotID]
	if !ok {
		return scg.File{}, fmt.Errorf("%w: graph for snapshot %s", ErrNotFound, snapshotID)
	}
	for _, f := range rec.graph.Files {
		if f.ID == fileID || f.Path == fileID {
			return f, nil
		}
	}
	return scg.File{}, fmt.Errorf("%w: file %s", ErrNotFound, fileID)
}

// ListSymbols implements GraphStore.
func (m *Memory) ListSymbols(_ context.Context, q SymbolQuery) ([]scg.Symbol, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.graphs[q.SnapshotID]
	if !ok {
		return nil, 0, fmt.Errorf("%w: graph for snapshot %s", ErrNotFound, q.SnapshotID)
	}
	kinds := map[scg.SymbolKind]bool{}
	for _, k := range q.Kinds {
		kinds[k] = true
	}
	var all []scg.Symbol
	for _, s := range rec.graph.Symbols {
		if q.ModuleID != "" && s.ModuleID != q.ModuleID {
			continue
		}
		if q.FileID != "" && s.FileID != q.FileID {
			continue
		}
		if len(kinds) > 0 && !kinds[s.Kind] {
			continue
		}
		if q.NameContains != "" && !strings.Contains(s.Name, q.NameContains) {
			continue
		}
		if q.QualifiedName != "" && s.QualifiedName != q.QualifiedName {
			continue
		}
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].QualifiedName != all[j].QualifiedName {
			return all[i].QualifiedName < all[j].QualifiedName
		}
		return all[i].ID < all[j].ID
	})
	total := len(all)
	return page(all, q.Offset, normaliseLimit(q.Limit, 100, 1000)), total, nil
}

// GetSymbol implements GraphStore.
func (m *Memory) GetSymbol(_ context.Context, snapshotID, symbolID string) (scg.Symbol, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.graphs[snapshotID]
	if !ok {
		return scg.Symbol{}, fmt.Errorf("%w: graph for snapshot %s", ErrNotFound, snapshotID)
	}
	for _, s := range rec.graph.Symbols {
		if s.ID == symbolID || s.QualifiedName == symbolID {
			return s, nil
		}
	}
	return scg.Symbol{}, fmt.Errorf("%w: symbol %s", ErrNotFound, symbolID)
}

// ListCallSites implements GraphStore.
func (m *Memory) ListCallSites(_ context.Context, q CallSiteQuery) ([]scg.CallSite, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.graphs[q.SnapshotID]
	if !ok {
		return nil, 0, fmt.Errorf("%w: graph for snapshot %s", ErrNotFound, q.SnapshotID)
	}
	resolutions := map[scg.Resolution]bool{}
	for _, r := range q.Resolution {
		resolutions[r] = true
	}
	callers := map[string]bool{}
	for _, id := range q.CallerIn {
		callers[id] = true
	}
	var all []scg.CallSite
	for _, cs := range rec.graph.CallSites {
		if q.CallerSymbolID != "" && cs.CallerSymbolID != q.CallerSymbolID {
			continue
		}
		if len(callers) > 0 && !callers[cs.CallerSymbolID] {
			continue
		}
		if q.FileID != "" && cs.FileID != q.FileID {
			continue
		}
		if q.CalleeSymbolID != "" && cs.CalleeSymbolID != q.CalleeSymbolID {
			continue
		}
		if len(resolutions) > 0 && !resolutions[cs.Resolution] {
			continue
		}
		all = append(all, cs)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].File != all[j].File {
			return all[i].File < all[j].File
		}
		if all[i].Line != all[j].Line {
			return all[i].Line < all[j].Line
		}
		return all[i].ID < all[j].ID
	})
	total := len(all)
	return page(all, q.Offset, normaliseLimit(q.Limit, 100, 1000)), total, nil
}

// EdgesFrom implements GraphStore.
func (m *Memory) EdgesFrom(_ context.Context, snapshotID string, from []string, kinds []scg.EdgeKind) ([]scg.Edge, error) {
	return m.edges(snapshotID, from, kinds, false)
}

// EdgesTo implements GraphStore.
func (m *Memory) EdgesTo(_ context.Context, snapshotID string, to []string, kinds []scg.EdgeKind) ([]scg.Edge, error) {
	return m.edges(snapshotID, to, kinds, true)
}

func (m *Memory) edges(snapshotID string, ids []string, kinds []scg.EdgeKind, incoming bool) ([]scg.Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.graphs[snapshotID]
	if !ok {
		return nil, fmt.Errorf("%w: graph for snapshot %s", ErrNotFound, snapshotID)
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	kindSet := map[scg.EdgeKind]bool{}
	for _, k := range kinds {
		kindSet[k] = true
	}
	var out []scg.Edge
	for _, e := range rec.graph.Edges {
		key := e.From
		if incoming {
			key = e.To
		}
		if len(want) > 0 && !want[key] {
			continue
		}
		if len(kindSet) > 0 && !kindSet[e.Kind] {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// page slices a result set.
func page[T any](all []T, offset, limit int) []T {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(all) {
		return []T{}
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end]
}
