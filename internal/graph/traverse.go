package graph

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// Default path-search budgets. A call-path search is deliberately more
// expensive than a neighbourhood query but still bounded.
const (
	defaultPathDepth = 6
	defaultPathCount = 5
	defaultPathNodes = 5000
	defaultPathEdges = 20000
)

// NeighborhoodNode is one symbol reached by a traversal, with its distance from
// the root.
type NeighborhoodNode struct {
	Symbol   scg.Symbol `json:"symbol"`
	Distance int        `json:"distance"`
}

// Neighborhood is the result of a callers/callees traversal.
type Neighborhood struct {
	Root      scg.Symbol         `json:"root"`
	Direction string             `json:"direction"`
	Nodes     []NeighborhoodNode `json:"nodes"`
	Edges     []scg.Edge         `json:"edges"`
	// Unresolved lists call sites inside the visited symbols that have no edge.
	// They are the blind spots of this neighbourhood and travel with it.
	Unresolved []scg.CallSite `json:"unresolved_call_sites"`
	// Limitations restate the coverage statements that apply to this answer.
	Limitations []string `json:"limitations"`
	Meta        Meta     `json:"meta"`
}

// Callers returns the symbols that reach symbolID through CALLS edges, up to the
// requested depth.
func (s *Service) Callers(ctx context.Context, snapshotID, symbolID string, opt Options) (*Neighborhood, error) {
	return s.neighborhood(ctx, snapshotID, symbolID, opt, "callers")
}

// Callees returns the symbols reachable from symbolID through CALLS edges, up to
// the requested depth.
func (s *Service) Callees(ctx context.Context, snapshotID, symbolID string, opt Options) (*Neighborhood, error) {
	return s.neighborhood(ctx, snapshotID, symbolID, opt, "callees")
}

// neighborhood implements both traversals. It walks one level at a time so the
// store does the filtering and the service stays in control of the budget.
func (s *Service) neighborhood(ctx context.Context, snapshotID, symbolID string, opt Options, direction string) (*Neighborhood, error) {
	opt = opt.WithDefaults()
	started := s.now()
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if direction != "callers" && direction != "callees" {
		return nil, fmt.Errorf("%w: unknown direction %q", ErrInvalidArgument, direction)
	}
	if symbolID == "" {
		return nil, fmt.Errorf("%w: symbol id is required", ErrInvalidArgument)
	}
	root, err := s.Store.GetSymbol(ctx, snapshotID, symbolID)
	if err != nil {
		return nil, mapStoreError(err, snapshotID)
	}

	out := &Neighborhood{
		Root:        root,
		Direction:   direction,
		Nodes:       []NeighborhoodNode{},
		Edges:       []scg.Edge{},
		Unresolved:  []scg.CallSite{},
		Limitations: []string{},
	}
	visited := map[string]bool{root.ID: true}
	frontier := []string{root.ID}
	edgeSeen := map[string]bool{}
	nodes := map[string]scg.Symbol{root.ID: root}

	for depth := 1; depth <= opt.MaxDepth && len(frontier) > 0; depth++ {
		if err := ctx.Err(); err != nil {
			out.Meta.Truncated = true
			out.Meta.TruncationReason = "time budget exhausted"
			break
		}
		var edges []scg.Edge
		if direction == "callers" {
			edges, err = s.Store.EdgesTo(ctx, snapshotID, frontier, []scg.EdgeKind{scg.EdgeCalls})
		} else {
			edges, err = s.Store.EdgesFrom(ctx, snapshotID, frontier, []scg.EdgeKind{scg.EdgeCalls})
		}
		if err != nil {
			return nil, mapStoreError(err, snapshotID)
		}
		sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
		out.Meta.DepthReached = depth
		var next []string
		for _, e := range edges {
			if edgeSeen[e.ID] {
				continue
			}
			edgeSeen[e.ID] = true
			if out.Meta.EdgesVisited >= opt.MaxEdges {
				out.Meta.Truncated = true
				out.Meta.TruncationReason = fmt.Sprintf("edge budget of %d reached", opt.MaxEdges)
				break
			}
			out.Meta.EdgesVisited++
			out.Edges = append(out.Edges, e)
			neighbour := e.To
			if direction == "callers" {
				neighbour = e.From
			}
			if visited[neighbour] {
				continue
			}
			if len(visited) >= opt.MaxNodes {
				out.Meta.Truncated = true
				out.Meta.TruncationReason = fmt.Sprintf("node budget of %d reached", opt.MaxNodes)
				break
			}
			visited[neighbour] = true
			sym, serr := s.Store.GetSymbol(ctx, snapshotID, neighbour)
			if serr != nil {
				if errors.Is(serr, storage.ErrNotFound) {
					// A dangling edge is a bug worth reporting, not hiding.
					out.Limitations = append(out.Limitations,
						fmt.Sprintf("edge %s points at %s, which is not in the graph", e.ID, neighbour))
					continue
				}
				return nil, mapStoreError(serr, snapshotID)
			}
			nodes[neighbour] = sym
			out.Nodes = append(out.Nodes, NeighborhoodNode{Symbol: sym, Distance: depth})
			next = append(next, neighbour)
		}
		if out.Meta.Truncated {
			break
		}
		frontier = next
	}
	if !out.Meta.Truncated && len(frontier) > 0 && out.Meta.DepthReached >= opt.MaxDepth {
		out.Meta.MoreBeyondDepth = true
	}

	// Unresolved call sites attached to the visited symbols are this answer's
	// blind spots.
	sites, _, serr := s.Store.ListCallSites(ctx, storage.CallSiteQuery{
		SnapshotID: snapshotID,
		CallerIn:   keysOf(nodes),
		Resolution: []scg.Resolution{scg.Ambiguous, scg.Dynamic, scg.External, scg.Unsupported},
		Limit:      opt.Limit,
	})
	if serr != nil {
		return nil, mapStoreError(serr, snapshotID)
	}
	out.Unresolved = append(out.Unresolved, sites...)
	if len(out.Unresolved) > 0 {
		out.Limitations = append(out.Limitations, fmt.Sprintf(
			"%d call site(s) inside these symbols could not be resolved and are not represented as edges; the neighbourhood may be incomplete",
			len(out.Unresolved)))
	}
	sort.Slice(out.Nodes, func(i, j int) bool {
		if out.Nodes[i].Distance != out.Nodes[j].Distance {
			return out.Nodes[i].Distance < out.Nodes[j].Distance
		}
		return out.Nodes[i].Symbol.QualifiedName < out.Nodes[j].Symbol.QualifiedName
	})
	sort.Slice(out.Edges, func(i, j int) bool { return out.Edges[i].ID < out.Edges[j].ID })

	out.Meta.NodesVisited = len(visited)
	out.Meta = mergeMeta(out.Meta, s.meta(ctx, snapshotID, direction, map[string]string{
		"symbol_id": symbolID,
		"max_depth": fmt.Sprint(opt.MaxDepth),
		"max_nodes": fmt.Sprint(opt.MaxNodes),
		"max_edges": fmt.Sprint(opt.MaxEdges),
	}, opt, started))
	return out, nil
}

// CallPath is one route from the source symbol to the sink symbol.
type CallPath struct {
	// SymbolIDs is the node sequence, starting at the source and ending at the sink.
	SymbolIDs []string `json:"symbol_ids"`
	EdgeIDs   []string `json:"edge_ids"`
	// Symbols resolves SymbolIDs in the same order.
	Symbols []scg.Symbol `json:"symbols"`
	Length  int          `json:"length"`
}

// PathSet is the result of a bounded call-path search.
type PathSet struct {
	Source      scg.Symbol `json:"source"`
	Sink        scg.Symbol `json:"sink"`
	Paths       []CallPath `json:"paths"`
	Limitations []string   `json:"limitations"`
	Meta        Meta       `json:"meta"`
}

// PathRequest describes a call-path search.
type PathRequest struct {
	Source string
	Sink   string
	// MaxPaths caps how many routes are returned.
	MaxPaths int
	Options  Options
}

// CallPaths enumerates up to MaxPaths distinct simple routes from source to sink
// along CALLS edges.
//
// A call path is a reachability fact, not a dataflow fact: it shows that one
// function can reach another, never that attacker-controlled data flows between
// them. That distinction is stated in the result's limitations.
func (s *Service) CallPaths(ctx context.Context, snapshotID string, req PathRequest) (*PathSet, error) {
	opt := req.Options.WithDefaults()
	if opt.MaxDepth == defaultMaxDepth {
		opt.MaxDepth = defaultPathDepth
	}
	if opt.MaxNodes == defaultMaxNodes {
		opt.MaxNodes = defaultPathNodes
	}
	if opt.MaxEdges == defaultMaxEdges {
		opt.MaxEdges = defaultPathEdges
	}
	maxPaths := req.MaxPaths
	if maxPaths <= 0 {
		maxPaths = defaultPathCount
	}
	if maxPaths > 50 {
		maxPaths = 50
	}
	started := s.now()
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Source == "" || req.Sink == "" {
		return nil, fmt.Errorf("%w: source and sink symbol ids are required", ErrInvalidArgument)
	}

	source, err := s.Store.GetSymbol(ctx, snapshotID, req.Source)
	if err != nil {
		return nil, mapStoreError(err, snapshotID)
	}
	sink, err := s.Store.GetSymbol(ctx, snapshotID, req.Sink)
	if err != nil {
		return nil, mapStoreError(err, snapshotID)
	}

	out := &PathSet{Source: source, Sink: sink, Paths: []CallPath{}, Limitations: []string{
		"a call path is a reachability fact, not a dataflow fact: it does not show that attacker-controlled data reaches the sink",
	}}
	meta := Meta{}

	if source.ID == sink.ID {
		out.Paths = append(out.Paths, CallPath{SymbolIDs: []string{source.ID}, Symbols: []scg.Symbol{source}})
		out.Meta = s.meta(ctx, snapshotID, "call_paths", map[string]string{"source": req.Source, "sink": req.Sink}, opt, started)
		return out, nil
	}

	// Bounded depth-first enumeration of simple paths, with hard node, edge and
	// path budgets and a deterministic successor order.
	visited := map[string]bool{source.ID: true}
	symbols := map[string]scg.Symbol{source.ID: source, sink.ID: sink}
	var paths [][]string
	var edgeIDs [][]string
	truncated := false
	reason := ""
	edgesVisited := 0
	depthReached := 0

	var walk func(node string, chain []string, chainEdges []string)
	walk = func(node string, chain []string, chainEdges []string) {
		if len(paths) >= maxPaths || truncated {
			return
		}
		if ctx.Err() != nil {
			truncated = true
			reason = "time budget exhausted"
			return
		}
		if len(chain)-1 > depthReached {
			depthReached = len(chain) - 1
		}
		if len(chain)-1 >= opt.MaxDepth {
			if node != sink.ID {
				truncated = true
				reason = fmt.Sprintf("depth budget of %d reached", opt.MaxDepth)
			}
			return
		}
		edges, eerr := s.Store.EdgesFrom(ctx, snapshotID, []string{node}, []scg.EdgeKind{scg.EdgeCalls})
		if eerr != nil {
			truncated = true
			reason = "store error during traversal: " + eerr.Error()
			return
		}
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].To != edges[j].To {
				return edges[i].To < edges[j].To
			}
			return edges[i].ID < edges[j].ID
		})
		for _, e := range edges {
			if len(paths) >= maxPaths || truncated {
				return
			}
			if edgesVisited >= opt.MaxEdges {
				truncated = true
				reason = fmt.Sprintf("edge budget of %d reached", opt.MaxEdges)
				return
			}
			edgesVisited++
			if visited[e.To] {
				continue
			}
			if len(visited) >= opt.MaxNodes {
				truncated = true
				reason = fmt.Sprintf("node budget of %d reached", opt.MaxNodes)
				return
			}
			visited[e.To] = true
			nextChain := append(append([]string{}, chain...), e.To)
			nextEdges := append(append([]string{}, chainEdges...), e.ID)
			if e.To == sink.ID {
				paths = append(paths, nextChain)
				edgeIDs = append(edgeIDs, nextEdges)
			} else {
				walk(e.To, nextChain, nextEdges)
			}
			delete(visited, e.To)
		}
	}
	walk(source.ID, []string{source.ID}, nil)

	// Resolve the nodes of every path, shortest first then by node names, so the
	// output is deterministic.
	order := make([]int, len(paths))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := paths[order[i]], paths[order[j]]
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		return joinIDs(a) < joinIDs(b)
	})
	for _, idx := range order {
		chain := paths[idx]
		path := CallPath{SymbolIDs: chain, EdgeIDs: edgeIDs[idx], Length: len(chain) - 1}
		for _, id := range chain {
			sym, ok := symbols[id]
			if !ok {
				sym, err = s.Store.GetSymbol(ctx, snapshotID, id)
				if err != nil {
					return nil, mapStoreError(err, snapshotID)
				}
				symbols[id] = sym
			}
			path.Symbols = append(path.Symbols, sym)
		}
		out.Paths = append(out.Paths, path)
	}
	if len(out.Paths) == 0 {
		out.Limitations = append(out.Limitations,
			"no call path was found within the budgets; unresolved call sites elsewhere in the graph can also break a real path")
	}
	meta.NodesVisited = len(visited)
	meta.EdgesVisited = edgesVisited
	meta.DepthReached = depthReached
	meta.Truncated = truncated
	meta.TruncationReason = reason
	if !truncated && len(paths) >= maxPaths {
		meta.Truncated = true
		meta.TruncationReason = fmt.Sprintf("stopped after %d path(s)", maxPaths)
	}
	out.Meta = mergeMeta(meta, s.meta(ctx, snapshotID, "call_paths", map[string]string{
		"source":    req.Source,
		"sink":      req.Sink,
		"max_paths": fmt.Sprint(maxPaths),
		"max_depth": fmt.Sprint(opt.MaxDepth),
	}, opt, started))
	return out, nil
}

// mergeMeta keeps the traversal counters of dst and fills the provenance fields
// from src (snapshot, graph version, query, budget).
func mergeMeta(dst, src Meta) Meta {
	dst.SnapshotID = src.SnapshotID
	dst.GraphVersion = src.GraphVersion
	dst.Engine = src.Engine
	dst.Query = src.Query
	dst.Args = src.Args
	dst.Budget = src.Budget
	dst.ElapsedMS = src.ElapsedMS
	dst.CacheHit = src.CacheHit
	dst.MoreBeyondDepth = dst.MoreBeyondDepth || src.MoreBeyondDepth
	return dst
}

func keysOf(m map[string]scg.Symbol) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ">"
		}
		out += id
	}
	return out
}
