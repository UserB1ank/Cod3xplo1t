package graph

import (
	"context"
	"errors"
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// The ASG extractor reads the SCG through a narrow interface declared in its own
// package. These five methods are the adapter: they exist so the query service
// can satisfy that interface without the attack-surface package depending on the
// query layer or on storage, which would make the dependency graph cyclic.
//
// They are deliberately unexported in spirit — no other caller should use them —
// but Go needs exported methods to satisfy an interface from another package.

// ReadSummary returns the stored summary of a snapshot's SCG.
//
// A missing graph is reported in the attack-surface package's own error domain:
// the extractor must be able to tell "there is nothing to derive" from a store
// failure, and it cannot import this package to find out.
func (s *Service) ReadSummary(ctx context.Context, snapshotID string) (*scg.Summary, error) {
	summary, err := s.Summary(ctx, snapshotID)
	if err != nil {
		if errors.Is(err, ErrNoGraph) {
			return nil, fmt.Errorf("%w: %s", asg.ErrNoSCG, snapshotID)
		}
		return nil, err
	}
	return summary, nil
}

// ReadFiles returns every file of a snapshot's SCG.
func (s *Service) ReadFiles(ctx context.Context, snapshotID string) ([]scg.File, error) {
	files, _, err := s.Files(ctx, snapshotID, "", Options{Limit: maxLimit})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// ReadSymbols pages through a snapshot's symbols.
func (s *Service) ReadSymbols(ctx context.Context, snapshotID string, offset, limit int) ([]scg.Symbol, int, error) {
	page, err := s.Symbols(ctx, snapshotID, SymbolQuery{Options: Options{Limit: limit, Offset: offset}})
	if err != nil {
		return nil, 0, err
	}
	return page.Symbols, page.Total, nil
}

// ReadCallSites pages through a snapshot's call sites, argument facts included.
func (s *Service) ReadCallSites(ctx context.Context, snapshotID string, offset, limit int) ([]scg.CallSite, int, error) {
	page, err := s.CallSites(ctx, snapshotID, CallSiteQuery{Options: Options{Limit: limit, Offset: offset}})
	if err != nil {
		return nil, 0, err
	}
	return page.CallSites, page.Total, nil
}

// ReadCallees returns the symbols a symbol can reach over CALLS edges within the
// given budgets, and whether a budget cut the walk short.
func (s *Service) ReadCallees(ctx context.Context, snapshotID, symbolID string, depth, maxNodes int) ([]scg.Symbol, bool, error) {
	neigh, err := s.Callees(ctx, snapshotID, symbolID, Options{MaxDepth: depth, MaxNodes: maxNodes, Limit: 1})
	if err != nil {
		return nil, false, err
	}
	out := make([]scg.Symbol, 0, len(neigh.Nodes))
	for _, node := range neigh.Nodes {
		out = append(out, node.Symbol)
	}
	return out, neigh.Meta.Truncated, nil
}
