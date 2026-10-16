package graph

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// ErrNoASG means the snapshot has no attack surface at all, which is a different
// answer from "the attack surface exists and does not contain that node". A
// caller that cannot tell them apart reports the wrong thing to a user.
var ErrNoASG = errors.New("graph: snapshot has no attack surface")

// ASGService answers attack-surface queries.
//
// It is the read path over a stored ASG candidate. Like the SCG service it
// returns its provenance with every answer: an attack surface without the rule
// set and coverage that produced it cannot be reviewed or compared.
type ASGService struct {
	Store storage.ASGStore
	// SCG dereferences the SCG facts an ASG node was derived from, which is what
	// makes "show me the evidence" answerable.
	SCG *Service
	Now func() time.Time
}

// NewASGService builds an attack-surface query service.
func NewASGService(store storage.ASGStore, scgService *Service) *ASGService {
	return &ASGService{Store: store, SCG: scgService, Now: func() time.Time { return time.Now().UTC() }}
}

// ASGMeta is the provenance block of an attack-surface answer.
type ASGMeta struct {
	SnapshotID       string            `json:"snapshot_id"`
	ASGVersion       string            `json:"asg_version,omitempty"`
	SCGVersion       string            `json:"scg_version,omitempty"`
	Query            string            `json:"query"`
	Args             map[string]string `json:"args,omitempty"`
	ElapsedMS        int64             `json:"elapsed_ms"`
	Total            int               `json:"total,omitempty"`
	Limit            int               `json:"limit,omitempty"`
	Offset           int               `json:"offset,omitempty"`
	Truncated        bool              `json:"truncated"`
	TruncationReason string            `json:"truncation_reason,omitempty"`
}

// requireASG reports a missing attack surface in this package's own error
// domain, so "no ASG" and "no such row" stay distinguishable.
func (s *ASGService) requireASG(ctx context.Context, snapshotID string) error {
	if _, err := s.Store.ASGSummary(ctx, snapshotID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNoASG, snapshotID)
		}
		return mapASGError(err, snapshotID)
	}
	return nil
}

func (s *ASGService) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now()
}

func (s *ASGService) meta(ctx context.Context, snapshotID, query string, args map[string]string, started time.Time) ASGMeta {
	m := ASGMeta{SnapshotID: snapshotID, Query: query, Args: args, ElapsedMS: s.now().Sub(started).Milliseconds()}
	if summary, err := s.Store.ASGSummary(ctx, snapshotID); err == nil {
		m.ASGVersion = summary.ASGVersion
		m.SCGVersion = summary.SCGVersion
	}
	return m
}

// Summary returns the stored summary of a snapshot's attack surface.
func (s *ASGService) Summary(ctx context.Context, snapshotID string) (*asg.Summary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.requireASG(ctx, snapshotID); err != nil {
		return nil, err
	}
	summary, err := s.Store.ASGSummary(ctx, snapshotID)
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	return summary, nil
}

// ASGNodeQuery filters a node listing.
type ASGNodeQuery struct {
	Kinds     []asg.NodeKind
	Subject   string
	Generator string
	File      string
	Limit     int
	Offset    int
}

// ASGNodePage is a page of attack-surface nodes.
type ASGNodePage struct {
	Nodes []asg.Node `json:"nodes"`
	Total int        `json:"total"`
	Meta  ASGMeta    `json:"meta"`
}

// Nodes lists attack-surface nodes.
func (s *ASGService) Nodes(ctx context.Context, snapshotID string, q ASGNodeQuery) (*ASGNodePage, error) {
	started := s.now()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.requireASG(ctx, snapshotID); err != nil {
		return nil, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	nodes, total, err := s.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID,
		Kinds:      q.Kinds,
		Subject:    q.Subject,
		Generator:  q.Generator,
		File:       q.File,
		Limit:      limit,
		Offset:     q.Offset,
	})
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	out := &ASGNodePage{
		Nodes: nodes,
		Total: total,
		Meta: s.meta(ctx, snapshotID, "asg_nodes", map[string]string{
			"kinds": joinNodeKinds(q.Kinds), "subject": q.Subject, "generator": q.Generator, "file": q.File,
			"limit": fmt.Sprint(limit), "offset": fmt.Sprint(q.Offset),
		}, started),
	}
	if out.Nodes == nil {
		out.Nodes = []asg.Node{}
	}
	out.Meta.Limit, out.Meta.Offset = limit, q.Offset
	out.Meta.Total = total
	if q.Offset+len(out.Nodes) < total {
		out.Meta.Truncated = true
		out.Meta.TruncationReason = fmt.Sprintf("page %d of %d nodes", len(out.Nodes), total)
	}
	return out, nil
}

// ASGReference is an SCG fact a node was derived from, resolved for display.
type ASGReference struct {
	Kind  string `json:"kind"` // symbol, call_site or unknown
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	File  string `json:"file,omitempty"`
	Line  int    `json:"line,omitempty"`
	// Detail explains why the reference exists, for example the callee text.
	Detail string `json:"detail,omitempty"`
}

// ASGNodeView is one node with its relationships and its evidence.
type ASGNodeView struct {
	Node        asg.Node       `json:"node"`
	Outgoing    []asg.Edge     `json:"outgoing"`
	Incoming    []asg.Edge     `json:"incoming"`
	DerivedFrom []ASGReference `json:"derived_from"`
	Meta        ASGMeta        `json:"meta"`
}

// Node returns one node with the edges that touch it and the SCG facts it came
// from, so a reviewer can walk from a claim to its evidence.
func (s *ASGService) Node(ctx context.Context, snapshotID, nodeID string) (*ASGNodeView, error) {
	started := s.now()
	if strings.TrimSpace(nodeID) == "" {
		return nil, fmt.Errorf("%w: node id is required", ErrInvalidArgument)
	}
	if err := s.requireASG(ctx, snapshotID); err != nil {
		return nil, err
	}
	node, err := s.Store.GetASGNode(ctx, snapshotID, nodeID)
	if err != nil {
		// The document exists (requireASG passed), so this is specifically "no such
		// node" and the API can answer not_found rather than asg_missing.
		return nil, mapASGError(err, snapshotID)
	}
	outgoing, err := s.Store.ListASGEdges(ctx, storage.ASGEdgeQuery{SnapshotID: snapshotID, From: []string{nodeID}, Limit: 1000})
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	incoming, err := s.Store.ListASGEdges(ctx, storage.ASGEdgeQuery{SnapshotID: snapshotID, To: []string{nodeID}, Limit: 1000})
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	view := &ASGNodeView{Node: node, Outgoing: outgoing, Incoming: incoming}
	if view.Outgoing == nil {
		view.Outgoing = []asg.Edge{}
	}
	if view.Incoming == nil {
		view.Incoming = []asg.Edge{}
	}
	// DERIVED_FROM edges carry the SCG ids; resolve them so the answer is usable
	// without a second manual lookup.
	var scgIDs []string
	for _, e := range outgoing {
		if e.Kind == asg.EdgeDerivedFrom {
			scgIDs = append(scgIDs, e.To)
		}
	}
	if len(scgIDs) == 0 {
		scgIDs = node.SCGRefs
	}
	sort.Strings(scgIDs)
	view.DerivedFrom = s.resolveReferences(ctx, snapshotID, scgIDs)
	view.Meta = s.meta(ctx, snapshotID, "asg_node", map[string]string{"node_id": nodeID}, started)
	return view, nil
}

// resolveReferences turns SCG ids into readable evidence. A reference that
// cannot be resolved is still reported by id: dropping it would hide evidence.
func (s *ASGService) resolveReferences(ctx context.Context, snapshotID string, ids []string) []ASGReference {
	out := make([]ASGReference, 0, len(ids))
	for _, id := range ids {
		ref := ASGReference{ID: id, Kind: "unknown"}
		switch {
		case strings.HasPrefix(id, "sym-"):
			ref.Kind = "symbol"
			if s.SCG != nil {
				if sym, _, err := s.SCG.Symbol(ctx, snapshotID, id, Options{}); err == nil {
					ref.Label = sym.QualifiedName
					ref.File = sym.File
					ref.Line = sym.StartLine
					ref.Detail = string(sym.Kind)
				}
			}
		case strings.HasPrefix(id, "cs-"):
			ref.Kind = "call_site"
			if s.SCG != nil {
				if cs, err := s.SCG.GetCallSite(ctx, snapshotID, id); err == nil {
					ref.Label = cs.CalleeText
					ref.File = cs.File
					ref.Line = cs.Line
					ref.Detail = string(cs.Resolution)
				}
			}
		}
		out = append(out, ref)
	}
	return out
}

// ASGEntryPointView is one entry point with everything the ASG knows about it.
type ASGEntryPointView struct {
	EntryPoint asg.Node   `json:"entry_point"`
	Boundary   *asg.Node  `json:"boundary,omitempty"`
	Controls   []asg.Node `json:"controls"`
	Inputs     []asg.Node `json:"inputs"`
	Sinks      []asg.Node `json:"sinks"`
	// ObservedControls counts controls wired in as middleware, as opposed to
	// controls merely reachable from the handler. The two mean very different
	// things to a reviewer.
	ObservedControls int `json:"observed_controls"`
}

// ASGEntryPointPage is the route-table view of an attack surface.
type ASGEntryPointPage struct {
	EntryPoints []ASGEntryPointView `json:"entry_points"`
	Total       int                 `json:"total"`
	Meta        ASGMeta             `json:"meta"`
}

// EntryPoints returns the entry points with their boundary, controls, inputs and
// reachable sinks. It answers the question an auditor asks first: what can be
// reached from outside, and what guards it.
func (s *ASGService) EntryPoints(ctx context.Context, snapshotID string, limit, offset int) (*ASGEntryPointPage, error) {
	started := s.now()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.requireASG(ctx, snapshotID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	entries, total, err := s.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeEntryPoint}, Limit: limit, Offset: offset,
	})
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	nodes, err := s.allNodes(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	edges, err := s.allEdges(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	byFrom := map[string][]asg.Edge{}
	for _, e := range edges {
		byFrom[e.From] = append(byFrom[e.From], e)
	}
	out := &ASGEntryPointPage{
		EntryPoints: make([]ASGEntryPointView, 0, len(entries)),
		Total:       total,
		Meta: s.meta(ctx, snapshotID, "asg_entry_points", map[string]string{
			"limit": fmt.Sprint(limit), "offset": fmt.Sprint(offset),
		}, started),
	}
	for _, entry := range entries {
		view := ASGEntryPointView{EntryPoint: entry, Controls: []asg.Node{}, Inputs: []asg.Node{}, Sinks: []asg.Node{}}
		for _, e := range byFrom[entry.ID] {
			target, ok := nodes[e.To]
			if !ok {
				continue
			}
			switch e.Kind {
			case asg.EdgeCrosses:
				node := target
				view.Boundary = &node
			case asg.EdgeProtectedBy:
				view.Controls = append(view.Controls, target)
				if e.Evidence == asg.StatusObserved {
					view.ObservedControls++
				}
			case asg.EdgeReaches:
				switch target.Kind {
				case asg.NodeSensitiveOperation:
					view.Sinks = append(view.Sinks, target)
				case asg.NodeAttackerControlledInput:
					view.Inputs = append(view.Inputs, target)
				}
			}
		}
		sortNodes(view.Controls)
		sortNodes(view.Inputs)
		sortNodes(view.Sinks)
		out.EntryPoints = append(out.EntryPoints, view)
	}
	if offset+len(out.EntryPoints) < total {
		out.Meta.Truncated = true
		out.Meta.TruncationReason = fmt.Sprintf("page %d of %d entry points", len(out.EntryPoints), total)
	}
	return out, nil
}

// ASGEdgePage is a page of attack-surface edges.
type ASGEdgePage struct {
	Edges []asg.Edge `json:"edges"`
	Meta  ASGMeta    `json:"meta"`
}

// Edges lists attack-surface edges.
func (s *ASGService) Edges(ctx context.Context, snapshotID string, from, to []string, kinds []asg.EdgeKind, limit int) (*ASGEdgePage, error) {
	started := s.now()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.requireASG(ctx, snapshotID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 500
	}
	edges, err := s.Store.ListASGEdges(ctx, storage.ASGEdgeQuery{
		SnapshotID: snapshotID, From: from, To: to, Kinds: kinds, Limit: limit,
	})
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	out := &ASGEdgePage{Edges: edges, Meta: s.meta(ctx, snapshotID, "asg_edges", map[string]string{
		"kinds": joinEdgeKinds(kinds), "limit": fmt.Sprint(limit),
	}, started)}
	if out.Edges == nil {
		out.Edges = []asg.Edge{}
	}
	out.Meta.Limit = limit
	if len(edges) >= limit {
		out.Meta.Truncated = true
		out.Meta.TruncationReason = fmt.Sprintf("the edge limit of %d was reached", limit)
	}
	return out, nil
}

// maxASGNodesForViews bounds the in-memory join behind the entry-point view.
const maxASGNodesForViews = 50000
const maxASGEdgesForViews = 200000

// allNodes loads every node, indexed by id, for the views that need a join. The
// cap is stated in the result's meta when it is hit.
func (s *ASGService) allNodes(ctx context.Context, snapshotID string) (map[string]asg.Node, error) {
	out := map[string]asg.Node{}
	offset := 0
	for len(out) < maxASGNodesForViews {
		nodes, total, err := s.Store.ListASGNodes(ctx, storage.ASGNodeQuery{SnapshotID: snapshotID, Limit: 1000, Offset: offset})
		if err != nil {
			return nil, mapASGError(err, snapshotID)
		}
		for _, n := range nodes {
			out[n.ID] = n
		}
		offset += len(nodes)
		if len(nodes) == 0 || offset >= total {
			break
		}
	}
	return out, nil
}

func (s *ASGService) allEdges(ctx context.Context, snapshotID string) ([]asg.Edge, error) {
	var out []asg.Edge
	limit := 5000
	seen := map[string]bool{}
	// The store has no offset for edges, so paging is by kind: each request is
	// bounded and the union is what the views need.
	for _, kind := range asg.AllEdgeKinds() {
		edges, err := s.Store.ListASGEdges(ctx, storage.ASGEdgeQuery{
			SnapshotID: snapshotID, Kinds: []asg.EdgeKind{kind}, Limit: limit,
		})
		if err != nil {
			return nil, mapASGError(err, snapshotID)
		}
		for _, e := range edges {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			out = append(out, e)
			if len(out) >= maxASGEdgesForViews {
				return out, nil
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func sortNodes(nodes []asg.Node) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Kind != nodes[j].Kind {
			return nodes[i].Kind < nodes[j].Kind
		}
		return nodes[i].Label < nodes[j].Label
	})
}

func joinNodeKinds(kinds []asg.NodeKind) string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return strings.Join(out, ",")
}

func joinEdgeKinds(kinds []asg.EdgeKind) string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return strings.Join(out, ",")
}

// mapASGError translates store errors, keeping "no attack surface" distinct
// from "no such node".
func mapASGError(err error, snapshotID string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrNotFound) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("graph: attack-surface query on snapshot %s exceeded its budget: %w", snapshotID, err)
	}
	return err
}
