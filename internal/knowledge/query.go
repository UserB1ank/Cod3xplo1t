package knowledge

import (
	"context"
	"errors"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// mapError turns a store miss into the package's not-found answer so callers
// never have to know which layer answered.
func mapError(err error) error {
	if errors.Is(err, storage.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// Meta travels with every answer. It restates the pin, the budget outcome and
// the coverage statement so a page can never look complete when it is not.
type Meta struct {
	SnapshotID string `json:"snapshot_id"`
	ViewID     string `json:"view_id"`
	Revision   string `json:"revision"`
	Layer      string `json:"layer"`
	// Versions repeats the pinned layer versions actually used.
	Versions map[string]string `json:"versions"`
	Total    int               `json:"total"`
	// Truncated reports that a budget, not the caller's page size, cut the
	// answer short. TruncationReason says which budget.
	Truncated        bool         `json:"truncated"`
	TruncationReason string       `json:"truncation_reason,omitempty"`
	Omitted          int          `json:"omitted,omitempty"`
	Coverage         scg.Coverage `json:"coverage"`
	Limitations      []string     `json:"limitations,omitempty"`
	CacheHit         bool         `json:"cache_hit,omitempty"`
	ElapsedMS        int64        `json:"elapsed_ms,omitempty"`
}

// SymbolQuery filters the code-graph symbol list.
type SymbolQuery struct {
	Query  string
	Kinds  []string
	Cursor string
	Limit  int
}

// SymbolPage is one page of symbols pinned to a view.
type SymbolPage struct {
	Symbols    []scg.Symbol `json:"symbols"`
	NextCursor string       `json:"next_cursor,omitempty"`
	Meta       Meta         `json:"meta"`
}

// NeighborhoodQuery walks the call graph around one symbol.
type NeighborhoodQuery struct {
	SymbolID  string
	Direction string // "callers" or "callees"; empty means callers
	Depth     int
	MaxNodes  int
}

// NeighborhoodPage is the call graph around one symbol.
type NeighborhoodPage struct {
	Neighborhood *graph.Neighborhood `json:"neighborhood"`
	Meta         Meta                `json:"meta"`
}

// SliceQuery reads source lines around a symbol.
type SliceQuery struct {
	SymbolID     string
	MaxLines     int
	MaxSections  int
	ContextLines int
}

// SlicePage is a bounded code slice.
type SlicePage struct {
	Slice *graph.CodeSlice `json:"slice"`
	Meta  Meta             `json:"meta"`
}

// PathQuery filters the path layer. Every path is pinned to the view's snapshot
// and layer versions.
type PathQuery struct {
	AuditID      string
	EntryNodeID  string
	TargetNodeID string
	Cursor       string
	Limit        int
}

// AuditRef identifies a task that shares the view's snapshot.
type AuditRef struct {
	ID     string `json:"audit_id"`
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
	Paths  int    `json:"paths"`
}

// PathPage is one page of pinned AuditPaths plus the tasks that own them.
type PathPage struct {
	Paths      []path.Path `json:"paths"`
	Audits     []AuditRef  `json:"audits"`
	NextCursor string      `json:"next_cursor,omitempty"`
	Meta       Meta        `json:"meta"`
}

func metaFor(view *View, layer string, total int) Meta {
	versions := map[string]string{LayerSCG: view.Layers[LayerSCG].Version}
	if info, ok := view.Layers[LayerASG]; ok && info.Version != "" {
		versions[LayerASG] = info.Version
	}
	return Meta{
		SnapshotID:  view.Scope.SnapshotID,
		ViewID:      view.ID,
		Revision:    view.Revision,
		Layer:       layer,
		Versions:    versions,
		Total:       total,
		Coverage:    view.Coverage,
		Limitations: view.Limitations,
	}
}

// Symbols lists the code graph's symbols, newest pin first.
func (r *Reader) Symbols(ctx context.Context, scope Scope, viewID string, q SymbolQuery) (*SymbolPage, error) {
	view, _, err := r.loadView(ctx, scope, viewID)
	if err != nil {
		return nil, err
	}
	if err := requireLayer(view, LayerSCG); err != nil {
		return nil, err
	}
	offset, err := decodeCursor(q.Cursor)
	if err != nil {
		return nil, err
	}
	limit := clampLimit(q.Limit)
	kinds := make([]scg.SymbolKind, 0, len(q.Kinds))
	for _, kind := range q.Kinds {
		kinds = append(kinds, scg.SymbolKind(kind))
	}
	page, err := r.Graph.Symbols(ctx, scope.SnapshotID, graph.SymbolQuery{
		NameContains: q.Query,
		Kinds:        kinds,
		Options:      graph.Options{Limit: limit, Offset: offset},
	})
	if err != nil {
		return nil, mapError(err)
	}
	meta := metaFor(view, LayerSCG, page.Total)
	meta.Truncated = page.Meta.Truncated
	meta.TruncationReason = page.Meta.TruncationReason
	meta.CacheHit = page.Meta.CacheHit
	meta.ElapsedMS = page.Meta.ElapsedMS
	next := ""
	if offset+len(page.Symbols) < page.Total {
		next = encodeCursor(offset + len(page.Symbols))
	}
	return &SymbolPage{Symbols: page.Symbols, NextCursor: next, Meta: meta}, nil
}

// Neighborhood walks the call graph around a symbol within a bounded budget.
func (r *Reader) Neighborhood(ctx context.Context, scope Scope, viewID string, q NeighborhoodQuery) (*NeighborhoodPage, error) {
	view, _, err := r.loadView(ctx, scope, viewID)
	if err != nil {
		return nil, err
	}
	if err := requireLayer(view, LayerSCG); err != nil {
		return nil, err
	}
	if q.SymbolID == "" {
		return nil, ErrInvalid
	}
	options := graph.Options{MaxDepth: q.Depth, MaxNodes: q.MaxNodes}
	var neighborhood *graph.Neighborhood
	switch q.Direction {
	case "", "callers":
		neighborhood, err = r.Graph.Callers(ctx, scope.SnapshotID, q.SymbolID, options)
	case "callees":
		neighborhood, err = r.Graph.Callees(ctx, scope.SnapshotID, q.SymbolID, options)
	default:
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, mapError(err)
	}
	meta := metaFor(view, LayerSCG, len(neighborhood.Nodes))
	meta.Truncated = neighborhood.Meta.Truncated
	meta.TruncationReason = neighborhood.Meta.TruncationReason
	meta.ElapsedMS = neighborhood.Meta.ElapsedMS
	if len(neighborhood.Limitations) > 0 {
		meta.Limitations = append(append([]string{}, meta.Limitations...), neighborhood.Limitations...)
	}
	return &NeighborhoodPage{Neighborhood: neighborhood, Meta: meta}, nil
}

// CodeSlice reads bounded source lines for a symbol and its direct context.
func (r *Reader) CodeSlice(ctx context.Context, scope Scope, viewID string, q SliceQuery) (*SlicePage, error) {
	view, _, err := r.loadView(ctx, scope, viewID)
	if err != nil {
		return nil, err
	}
	if err := requireLayer(view, LayerSCG); err != nil {
		return nil, err
	}
	if q.SymbolID == "" {
		return nil, ErrInvalid
	}
	slice, err := r.Graph.Slice(ctx, scope.SnapshotID, graph.SliceRequest{
		SymbolID:     q.SymbolID,
		MaxLines:     q.MaxLines,
		MaxSections:  q.MaxSections,
		ContextLines: q.ContextLines,
	})
	if err != nil {
		return nil, mapError(err)
	}
	meta := metaFor(view, LayerSCG, len(slice.Sections))
	meta.Truncated = slice.Meta.Truncated
	meta.TruncationReason = slice.Meta.TruncationReason
	meta.ElapsedMS = slice.Meta.ElapsedMS
	if len(slice.Limitations) > 0 {
		meta.Limitations = append(append([]string{}, meta.Limitations...), slice.Limitations...)
	}
	return &SlicePage{Slice: slice, Meta: meta}, nil
}

// Paths lists AuditPaths pinned to the view's snapshot and layer versions.
func (r *Reader) Paths(ctx context.Context, scope Scope, viewID string, q PathQuery) (*PathPage, error) {
	view, d, err := r.loadView(ctx, scope, viewID)
	if err != nil {
		return nil, err
	}
	if err := requireLayer(view, LayerPaths); err != nil {
		return nil, err
	}
	offset, err := decodeCursor(q.Cursor)
	if err != nil {
		return nil, err
	}
	limit := clampLimit(q.Limit)
	pinned, err := r.pinnedAudits(ctx, scope.SnapshotID, d)
	if err != nil {
		return nil, err
	}
	refs := make([]AuditRef, 0, len(pinned))
	for _, audit := range pinned {
		refs = append(refs, AuditRef{ID: audit.ID, Name: audit.Name, Status: audit.Status, Paths: audit.PathCount})
	}
	query := path.PathQuery{
		SnapshotID:   scope.SnapshotID,
		AuditID:      q.AuditID,
		EntryNodeID:  q.EntryNodeID,
		TargetNodeID: q.TargetNodeID,
		Limit:        limit,
		Offset:       offset,
	}
	if q.AuditID != "" {
		audit, ok := auditByID(pinned, q.AuditID)
		if !ok {
			return &PathPage{Paths: []path.Path{}, Audits: refs, Meta: metaFor(view, LayerPaths, 0)}, nil
		}
		query.SnapshotID = audit.SnapshotID
	}
	rows, total, err := r.Queue.Paths(query)
	if err != nil {
		return nil, err
	}
	kept := make([]path.Path, 0, len(rows))
	omitted := 0
	for _, row := range rows {
		if row.SnapshotID != scope.SnapshotID || row.SCGVersion != d.SCG || (d.ASG != "" && row.ASGVersion != d.ASG) {
			omitted++
			continue
		}
		kept = append(kept, row)
	}
	meta := metaFor(view, LayerPaths, total)
	meta.Omitted = omitted
	if omitted > 0 {
		meta.Truncated = true
		meta.TruncationReason = "stale_layer_version"
	}
	next := ""
	if offset+len(rows) < total {
		next = encodeCursor(offset + len(rows))
	}
	return &PathPage{Paths: kept, Audits: refs, NextCursor: next, Meta: meta}, nil
}

// pinnedAudits returns the audits whose layers match the view pin.
func (r *Reader) pinnedAudits(ctx context.Context, snapshotID string, d descriptor) ([]path.Audit, error) {
	audits, _, err := r.Queue.Audits(path.AuditQuery{SnapshotID: snapshotID, Limit: 1000})
	if err != nil {
		return nil, err
	}
	pinned := make([]path.Audit, 0, len(audits))
	for _, audit := range audits {
		if pinnedAudit(audit, d.SCG, d.ASG) {
			pinned = append(pinned, audit)
		}
	}
	return pinned, nil
}

func auditByID(audits []path.Audit, id string) (path.Audit, bool) {
	for _, audit := range audits {
		if audit.ID == id {
			return audit, true
		}
	}
	return path.Audit{}, false
}

// NodeQuery filters the attack-surface node list.
type NodeQuery struct {
	Kinds   []string
	Subject string
	Cursor  string
	Limit   int
}

// NodePage is one page of pinned attack-surface nodes.
type NodePage struct {
	Nodes      []asg.Node `json:"nodes"`
	NextCursor string     `json:"next_cursor,omitempty"`
	Meta       Meta       `json:"meta"`
}

// Nodes lists the attack surface of a view that pinned the ASG layer.
func (r *Reader) Nodes(ctx context.Context, scope Scope, viewID string, q NodeQuery) (*NodePage, error) {
	view, _, err := r.loadView(ctx, scope, viewID)
	if err != nil {
		return nil, err
	}
	if err := requireLayer(view, LayerASG); err != nil {
		return nil, err
	}
	offset, err := decodeCursor(q.Cursor)
	if err != nil {
		return nil, err
	}
	limit := clampLimit(q.Limit)
	kinds := make([]asg.NodeKind, 0, len(q.Kinds))
	for _, kind := range q.Kinds {
		kinds = append(kinds, asg.NodeKind(kind))
	}
	page, err := r.ASG.Nodes(ctx, scope.SnapshotID, graph.ASGNodeQuery{
		Kinds:   kinds,
		Subject: q.Subject,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		return nil, mapError(err)
	}
	meta := metaFor(view, LayerASG, page.Total)
	meta.Truncated = page.Meta.Truncated
	meta.TruncationReason = page.Meta.TruncationReason
	meta.ElapsedMS = page.Meta.ElapsedMS
	next := ""
	if offset+len(page.Nodes) < page.Total {
		next = encodeCursor(offset + len(page.Nodes))
	}
	return &NodePage{Nodes: page.Nodes, NextCursor: next, Meta: meta}, nil
}

// Producer names what generated a fact.
type Producer struct {
	PluginID      string `json:"plugin_id"`
	PluginVersion string `json:"plugin_version"`
	InvocationID  string `json:"invocation_id"`
	ConfigDigest  string `json:"config_digest"`
}

// Location is the code position a fact was derived from.
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// ArtifactRef is the raw content provenance points at.
type ArtifactRef struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	SchemaID string `json:"schema_id"`
}

// Provenance answers where a fact came from and which tasks share it.
type Provenance struct {
	FactID    string             `json:"fact_id"`
	Kind      string             `json:"kind"` // "symbol" or "asg_node"
	Scope     Scope              `json:"scope"`
	Versions  map[string]string  `json:"versions"`
	Producer  Producer           `json:"producer"`
	Location  *Location          `json:"location,omitempty"`
	Symbol    *scg.Symbol        `json:"symbol,omitempty"`
	Node      *graph.ASGNodeView `json:"node,omitempty"`
	Tasks     []AuditRef         `json:"tasks"`
	Artifacts []ArtifactRef      `json:"artifacts,omitempty"`
}

// Provenance resolves one fact id inside the view and reports its origin. The
// fact may be a code symbol or an attack-surface node; anything else is a
// not-found answer rather than an empty success.
func (r *Reader) Provenance(ctx context.Context, scope Scope, viewID, factID string) (*Provenance, error) {
	view, d, err := r.loadView(ctx, scope, viewID)
	if err != nil {
		return nil, err
	}
	if factID == "" {
		return nil, ErrInvalid
	}
	out := &Provenance{
		FactID:   factID,
		Scope:    scope,
		Versions: map[string]string{LayerSCG: d.SCG},
	}
	if d.ASG != "" {
		out.Versions[LayerASG] = d.ASG
	}
	if view.Has(LayerSCG) {
		symbol, meta, err := r.Graph.Symbol(ctx, scope.SnapshotID, factID, graph.Options{})
		switch {
		case err == nil:
			out.Kind = "symbol"
			out.Symbol = symbol
			out.Location = &Location{File: symbol.File, StartLine: symbol.StartLine, EndLine: symbol.EndLine}
			out.Producer = Producer{PluginID: "builtin.scg", PluginVersion: view.Engine.Version, InvocationID: "graph:" + d.SCG, ConfigDigest: d.SCG}
			_ = meta
		case errors.Is(mapError(err), ErrNotFound):
			// Not a symbol; try the attack surface below.
		default:
			return nil, mapError(err)
		}
	}
	if out.Kind == "" {
		if d.ASG == "" || r.ASG == nil {
			return nil, ErrNotFound
		}
		node, err := r.ASG.Node(ctx, scope.SnapshotID, factID)
		if err != nil {
			return nil, mapError(err)
		}
		out.Kind = "asg_node"
		out.Node = node
		out.Location = &Location{File: node.Node.File, StartLine: node.Node.Line, EndLine: node.Node.Line}
		out.Producer = Producer{PluginID: "builtin.asg", PluginVersion: node.Meta.ASGVersion, InvocationID: "asg:" + d.ASG, ConfigDigest: d.ASG}
	}
	out.Tasks = []AuditRef{}
	if view.Has(LayerPaths) && r.Queue != nil {
		pinned, err := r.pinnedAudits(ctx, scope.SnapshotID, d)
		if err != nil {
			return nil, err
		}
		for _, audit := range pinned {
			out.Tasks = append(out.Tasks, AuditRef{ID: audit.ID, Name: audit.Name, Status: audit.Status, Paths: audit.PathCount})
		}
	}
	if r.Artifacts != nil {
		if artifactScope, err := r.Artifacts.ArtifactScope(ctx, scope.ProjectID, scope.SnapshotID); err == nil {
			if refs, err := r.Artifacts.ListArtifacts(ctx, artifactScope, "", 10); err == nil {
				for _, ref := range refs {
					out.Artifacts = append(out.Artifacts, ArtifactRef{ID: ref.ID, Kind: ref.Kind, SHA256: ref.SHA256, Bytes: ref.Bytes, SchemaID: ref.SchemaID})
				}
			}
		}
	}
	return out, nil
}
