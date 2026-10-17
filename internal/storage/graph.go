package storage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// SymbolQuery filters a symbol listing. Zero values mean "no filter".
type SymbolQuery struct {
	SnapshotID string
	ModuleID   string
	FileID     string
	Kinds      []scg.SymbolKind
	// NameContains is a case-sensitive substring match on the symbol name.
	NameContains string
	// QualifiedName matches one symbol exactly. Qualified names contain slashes
	// and dots, so they are a query parameter rather than a path segment.
	QualifiedName string
	Limit         int
	Offset        int
}

// CallSiteQuery filters a call site listing.
type CallSiteQuery struct {
	SnapshotID string
	// CallerSymbolID filters on one caller; CallerIn filters on a set. The set
	// form is what a bounded neighbourhood query needs.
	CallerSymbolID string
	CallerIn       []string
	// CallSiteID selects exactly one call site.
	CallSiteID     string
	FileID         string
	CalleeSymbolID string
	Resolution     []scg.Resolution
	Limit          int
	Offset         int
}

// GraphStore persists and reads SCG documents.
//
// ReplaceGraph is the only write: it swaps the whole graph of one snapshot
// inside a transaction, which keeps rebuilds idempotent and readers consistent.
// Every read is scoped to one snapshot id, as the design doc requires.
type GraphStore interface {
	ReplaceGraph(ctx context.Context, snapshotID string, g *scg.Graph) error
	DeleteGraph(ctx context.Context, snapshotID string) error
	GraphSummary(ctx context.Context, snapshotID string) (*scg.Summary, error)

	ListModules(ctx context.Context, snapshotID string) ([]scg.Module, error)
	GetModule(ctx context.Context, snapshotID, moduleID string) (scg.Module, error)
	ListFiles(ctx context.Context, snapshotID, moduleID string) ([]scg.File, error)
	GetFile(ctx context.Context, snapshotID, fileID string) (scg.File, error)

	ListSymbols(ctx context.Context, q SymbolQuery) ([]scg.Symbol, int, error)
	GetSymbol(ctx context.Context, snapshotID, symbolID string) (scg.Symbol, error)

	ListCallSites(ctx context.Context, q CallSiteQuery) ([]scg.CallSite, int, error)

	EdgesFrom(ctx context.Context, snapshotID string, from []string, kinds []scg.EdgeKind) ([]scg.Edge, error)
	EdgesTo(ctx context.Context, snapshotID string, to []string, kinds []scg.EdgeKind) ([]scg.Edge, error)
}

// validateGraph rejects a graph whose elements were built for another
// snapshot. Mixing them would leak rows across snapshots and collide on ids, so
// it fails loudly instead.
func validateGraph(snapshotID string, g *scg.Graph) error {
	if g == nil || snapshotID == "" {
		return fmt.Errorf("%w: graph and snapshot id are required", ErrConflict)
	}
	if g.SnapshotID != snapshotID {
		return fmt.Errorf("%w: graph snapshot id %q does not match %q", ErrConflict, g.SnapshotID, snapshotID)
	}
	check := func(kind, id, owner string) error {
		if owner != snapshotID {
			return fmt.Errorf("%w: %s %s belongs to snapshot %q", ErrConflict, kind, id, owner)
		}
		return nil
	}
	for _, mod := range g.Modules {
		if err := check("module", mod.ID, mod.SnapshotID); err != nil {
			return err
		}
	}
	for _, f := range g.Files {
		if err := check("file", f.ID, f.SnapshotID); err != nil {
			return err
		}
	}
	for _, sym := range g.Symbols {
		if err := check("symbol", sym.ID, sym.SnapshotID); err != nil {
			return err
		}
	}
	for _, cs := range g.CallSites {
		if err := check("call site", cs.ID, cs.SnapshotID); err != nil {
			return err
		}
	}
	for _, e := range g.Edges {
		if err := check("edge", e.ID, e.SnapshotID); err != nil {
			return err
		}
	}
	return nil
}

// FullStore is what the API and CLI need: documents, graph, attack surface and
// durable idempotency.
type FullStore interface {
	// SetFindingSeverity updates only the grade, with optimistic concurrency.
	SetFindingSeverity(id, severity string, expectedVersion int64) error
	Store
	GraphStore
	ASGStore
	IdempotencyStore

	// AuditStore is the path engine's persistence contract (P4).
	AuditStore
	// AgentStore is the agent runtime's persistence contract (P5). Its event
	// methods are run-scoped (AppendRunEvents and friends) so the two logs stay
	// distinguishable in Go, which has no overloading.
	AgentStore
	// VerificationStore is the verification layer's persistence contract (P6):
	// isolated runs, immutable evidence and one finding per hypothesis. Its run
	// methods are verification-scoped (CreateVerificationRun and friends) for the
	// same reason the agent log's are run-scoped.
	VerificationStore
	// ObservationStore is the plugin observation ledger and severity audit
	// history that the findings service groups. Findings themselves stay in the
	// verification table.
	findings.ObservationStore
}

// sameAnalysis reports whether two serialised manifests describe the same
// analysis. Timestamps differ between runs, so identity must come from the
// analysis id: same snapshot, engine, rule set and configuration.
func sameAnalysis(a, b []byte) bool {
	var ma, mb analysis.Manifest
	if err := json.Unmarshal(a, &ma); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &mb); err != nil {
		return false
	}
	return ma.AnalysisID != "" && ma.AnalysisID == mb.AnalysisID
}

// normaliseLimit applies a default and a hard cap to a page size, so a caller
// cannot ask a store for an unbounded result.
func normaliseLimit(limit, def, max int) int {
	if limit <= 0 {
		limit = def
	}
	if max > 0 && limit > max {
		limit = max
	}
	return limit
}
