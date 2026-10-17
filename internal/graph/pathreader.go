package graph

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// PathFacts adapts the query layer to the path engine's readers.
//
// The engine consumes the same two graphs the ASG and SCG services expose, but
// through its own narrow interfaces: the attack surface as a whole document, and
// the call chains between symbols. Keeping the adaptation here means neither the
// engine nor the storage layer depends on the other's packages.

// PathFacts implements path.ASGReader and path.SCGReader.
type PathFacts struct {
	SCG   *Service
	ASG   *ASGService
	Store storage.ASGStore
	// MaxNodes and MaxEdges bound the document read; a truncated read is reported
	// to the engine instead of silently producing a smaller path set.
	MaxNodes int
	MaxEdges int
}

// NewPathFacts builds the adapter.
func NewPathFacts(scgService *Service, asgService *ASGService, store storage.ASGStore) *PathFacts {
	return &PathFacts{SCG: scgService, ASG: asgService, Store: store, MaxNodes: 50000, MaxEdges: 200000}
}

// ASGFacts loads the attack surface of a snapshot as facts the engine consumes.
func (p *PathFacts) ASGFacts(ctx context.Context, snapshotID string) (*path.ASGFacts, error) {
	if p.ASG == nil {
		return nil, fmt.Errorf("%w: the attack-surface service is not configured", path.ErrNoASG)
	}
	summary, err := p.ASG.Summary(ctx, snapshotID)
	if err != nil {
		if errors.Is(err, ErrNoASG) || errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", path.ErrNoASG, snapshotID)
		}
		return nil, err
	}
	facts := &path.ASGFacts{
		SnapshotID:  snapshotID,
		SCGVersion:  summary.SCGVersion,
		ASGVersion:  summary.ASGVersion,
		Nodes:       map[string]path.ASGNode{},
		Limitations: append([]string(nil), summary.Limitations...),
		Summary:     summary,
	}
	// The document is read whole because generation needs every relation edge; the
	// caps are the reader's, and hitting one is reported.
	nodes := 0
	offset := 0
	total := 0
	for nodes < p.MaxNodes {
		page, err := p.ASG.Nodes(ctx, snapshotID, ASGNodeQuery{Limit: 1000, Offset: offset})
		if err != nil {
			return nil, err
		}
		total = page.Total
		for _, node := range page.Nodes {
			facts.Nodes[node.ID] = path.ASGNode{
				ID: node.ID, Kind: string(node.Kind), Subject: node.Subject, Label: node.Label,
				Evidence: string(node.Evidence), Confidence: string(node.Confidence),
				File: node.File, Line: node.Line, Detail: node.Detail,
				SCGRefs: append([]string(nil), node.SCGRefs...),
			}
		}
		nodes += len(page.Nodes)
		offset += len(page.Nodes)
		if len(page.Nodes) == 0 || offset >= total {
			break
		}
	}
	if nodes >= p.MaxNodes {
		facts.Truncated = true
		facts.TruncationReasons = append(facts.TruncationReasons,
			fmt.Sprintf("the attack surface has more than %d nodes; generation saw only the first %d", p.MaxNodes, nodes))
	}
	for _, kind := range []asg.EdgeKind{asg.EdgeReaches, asg.EdgeCrosses, asg.EdgeProtectedBy, asg.EdgeMayAffect} {
		edges, err := p.Store.ListASGEdges(ctx, storage.ASGEdgeQuery{SnapshotID: snapshotID, Kinds: []asg.EdgeKind{kind}, Limit: p.MaxEdges})
		if err != nil {
			return nil, err
		}
		if len(edges) >= p.MaxEdges {
			facts.Truncated = true
			facts.TruncationReasons = append(facts.TruncationReasons,
				fmt.Sprintf("relation edges of kind %s were cut at %d", kind, p.MaxEdges))
		}
		for _, edge := range edges {
			facts.Edges = append(facts.Edges, path.ASGEdge{
				ID: edge.ID, From: edge.From, To: edge.To, Kind: string(edge.Kind),
				Evidence: string(edge.Evidence), Confidence: string(edge.Confidence),
				Detail: edge.Detail, SCGRefs: append([]string(nil), edge.SCGRefs...),
			})
		}
	}
	sort.Slice(facts.Edges, func(i, j int) bool { return facts.Edges[i].ID < facts.Edges[j].ID })
	return facts, nil
}

// Chains returns observed call chains between two symbols.
func (p *PathFacts) Chains(ctx context.Context, snapshotID, fromSymbolID, toSymbolID string, maxDepth, maxPaths int) ([]path.CallChain, error) {
	if p.SCG == nil {
		return nil, errors.New("graph: the source graph service is not configured")
	}
	if fromSymbolID == "" || toSymbolID == "" || fromSymbolID == toSymbolID {
		return nil, nil
	}
	if maxDepth <= 0 {
		maxDepth = path.DefaultBudget().MaxDepth
	}
	if maxPaths <= 0 {
		maxPaths = 1
	}
	set, err := p.SCG.CallPaths(ctx, snapshotID, PathRequest{
		Source: fromSymbolID, Sink: toSymbolID, MaxPaths: maxPaths,
		Options: Options{MaxDepth: maxDepth},
	})
	if err != nil {
		if errors.Is(err, ErrNoGraph) {
			return nil, fmt.Errorf("%w: %s", path.ErrNoASG, snapshotID)
		}
		// A missing path is not an error: it is the answer "no observed chain".
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if set == nil {
		return nil, nil
	}
	out := make([]path.CallChain, 0, len(set.Paths))
	for _, callPath := range set.Paths {
		chain := path.CallChain{Symbols: make([]path.SymbolFact, 0, len(callPath.Symbols))}
		for _, sym := range callPath.Symbols {
			chain.Symbols = append(chain.Symbols, path.SymbolFact{
				ID: sym.ID, QualifiedName: sym.QualifiedName, Kind: string(sym.Kind),
				File: sym.File, Line: sym.StartLine, ModuleID: sym.ModuleID, ResultType: sym.ResultType,
			})
		}
		symbolIDs := make([]string, 0, len(callPath.Symbols))
		for _, sym := range callPath.Symbols {
			symbolIDs = append(symbolIDs, sym.ID)
		}
		byID := map[string]scg.Edge{}
		if edges, err := p.SCG.Store.EdgesFrom(ctx, snapshotID, symbolIDs, []scg.EdgeKind{scg.EdgeCalls}); err == nil {
			for _, edge := range edges {
				byID[edge.ID] = edge
			}
		}
		for _, edgeID := range callPath.EdgeIDs {
			hop := path.CallHop{EdgeID: edgeID, Kind: string(scg.EdgeCalls)}
			if edge, ok := byID[edgeID]; ok {
				hop.From = edge.From
				hop.To = edge.To
				hop.Kind = string(edge.Kind)
				hop.Resolution = string(edge.Resolution)
			}
			chain.Hops = append(chain.Hops, hop)
		}
		// The hop endpoints come from the symbol sequence when the edge lookup did
		// not fill them, so a chain is always walkable.
		for i := range chain.Hops {
			if i < len(chain.Symbols)-1 {
				if chain.Hops[i].From == "" {
					chain.Hops[i].From = chain.Symbols[i].ID
				}
				if chain.Hops[i].To == "" {
					chain.Hops[i].To = chain.Symbols[i+1].ID
				}
				chain.Hops[i].ToQualified = chain.Symbols[i+1].QualifiedName
				chain.Hops[i].File = chain.Symbols[i+1].File
				chain.Hops[i].Line = chain.Symbols[i+1].Line
			}
		}
		out = append(out, chain)
	}
	return out, nil
}

// CallSiteCaller returns the symbol that contains a call site.
func (p *PathFacts) CallSiteCaller(ctx context.Context, snapshotID, callSiteID string) (path.SymbolFact, bool, error) {
	if p.SCG == nil {
		return path.SymbolFact{}, false, errors.New("graph: the source graph service is not configured")
	}
	callSite, err := p.SCG.GetCallSite(ctx, snapshotID, callSiteID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return path.SymbolFact{}, false, nil
		}
		return path.SymbolFact{}, false, err
	}
	if callSite.CallerSymbolID == "" {
		return path.SymbolFact{}, false, nil
	}
	return p.Symbol(ctx, snapshotID, callSite.CallerSymbolID)
}

// Symbol returns one symbol.
func (p *PathFacts) Symbol(ctx context.Context, snapshotID, symbolID string) (path.SymbolFact, bool, error) {
	if p.SCG == nil {
		return path.SymbolFact{}, false, errors.New("graph: the source graph service is not configured")
	}
	sym, _, err := p.SCG.Symbol(ctx, snapshotID, symbolID, Options{})
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return path.SymbolFact{}, false, nil
		}
		return path.SymbolFact{}, false, err
	}
	return path.SymbolFact{
		ID: sym.ID, QualifiedName: sym.QualifiedName, Kind: string(sym.Kind),
		File: sym.File, Line: sym.StartLine, ModuleID: sym.ModuleID, ResultType: sym.ResultType,
	}, true, nil
}
