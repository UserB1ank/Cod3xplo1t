package path

import (
	"context"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
)

// The path engine reads two graphs and writes neither. Both readers are declared
// here, in terms of this package's own fact shapes, so the engine can be tested
// against fixtures and so the dependency direction stays acyclic: storage
// implements Store, the query layer implements ASGReader and SCGReader, and this
// package imports neither.

// ASGReader supplies the attack surface of a snapshot.
type ASGReader interface {
	// ASGFacts returns every attack-surface node and relation edge. Generation is a
	// whole-document operation, so it reads the document rather than paging a view.
	ASGFacts(ctx context.Context, snapshotID string) (*ASGFacts, error)
}

// SCGReader supplies the call-level facts a path needs: the chain of observed
// calls between two symbols, and the symbols themselves.
type SCGReader interface {
	// Chains returns up to maxPaths observed call chains from one symbol to
	// another. A chain is not a taint path: it proves the call can happen, not
	// that data moves along it.
	Chains(ctx context.Context, snapshotID, fromSymbolID, toSymbolID string, maxDepth, maxPaths int) ([]CallChain, error)
	// CallSiteCaller returns the symbol a call site belongs to.
	CallSiteCaller(ctx context.Context, snapshotID, callSiteID string) (SymbolFact, bool, error)
	// Symbol returns one symbol.
	Symbol(ctx context.Context, snapshotID, symbolID string) (SymbolFact, bool, error)
}

// ASGNode is the part of an attack-surface node the engine consumes.
type ASGNode struct {
	ID         string
	Kind       string
	Subject    string
	Label      string
	Evidence   string
	Confidence string
	File       string
	Line       int
	Detail     map[string]string
	SCGRefs    []string
}

// ASGEdge is the part of an attack-surface edge the engine consumes.
type ASGEdge struct {
	ID         string
	From       string
	To         string
	Kind       string
	Evidence   string
	Confidence string
	Detail     map[string]string
	SCGRefs    []string
}

// ASGFacts is one attack surface, indexed for generation.
type ASGFacts struct {
	SnapshotID string
	SCGVersion string
	ASGVersion string
	Nodes      map[string]ASGNode
	Edges      []ASGEdge
	// Limitations and truncation travel with the facts: a path ranking built from
	// an incomplete surface must say so.
	Limitations       []string
	Truncated         bool
	TruncationReasons []string
	Summary           *asg.Summary
}

// SymbolFact is the part of an SCG symbol a path needs.
type SymbolFact struct {
	ID            string
	QualifiedName string
	Kind          string
	File          string
	Line          int
	ModuleID      string
	ResultType    string
}

// CallHop is one observed call edge of a chain.
type CallHop struct {
	From       string
	To         string
	EdgeID     string
	Kind       string
	Resolution string
	File       string
	Line       int
	// ToQualified is the callee's qualified name, for display.
	ToQualified string
}

// CallChain is a resolved call chain: the symbols in order and the edges between
// them. Length is len(Symbols)-1.
type CallChain struct {
	Symbols []SymbolFact
	Hops    []CallHop
}

// Depth is the number of hops.
func (c CallChain) Depth() int { return len(c.Hops) }

// Resolved reports whether every hop of the chain is an observed call edge. A
// chain with a best-effort or dynamic hop is not evidence of a call.
func (c CallChain) Resolved() bool {
	for _, hop := range c.Hops {
		if hop.Resolution != "" && hop.Resolution != "resolved" {
			return false
		}
	}
	return len(c.Hops) > 0
}
