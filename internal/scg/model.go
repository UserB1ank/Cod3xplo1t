// Package scg implements the Source Code Graph (SCG) of Codexploit: a
// modular, deterministic code graph built from a frozen snapshot.
//
// The SCG is the fact layer (design doc §3.1). It is produced by static
// analysis only: no agent and no LLM participate. Everything the graph asserts
// carries its provenance — analyzer, analyzer version, source location and a
// resolution status — because static call edges are approximations and the
// graph must say so instead of pretending to be exact.
//
// Two levels are modelled as in the design doc:
//
//   - module level: which modules exist and how they import each other;
//   - symbol level: declarations, call sites and their (possibly unresolved)
//     call relationships inside a module.
//
// The graph never enumerates execution paths; deep traversals happen on demand
// through the query service, bounded by explicit budgets.
package scg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// NodeKind enumerates the node types of the SCG (design doc §3.1).
type NodeKind string

const (
	NodeRepository NodeKind = "Repository"
	NodeModule     NodeKind = "Module"
	NodeFile       NodeKind = "File"
	NodeSymbol     NodeKind = "Symbol"
	NodeCallSite   NodeKind = "CallSite"
)

// EdgeKind enumerates the edge types of the SCG. FLOWS_TO and CONTROLS are
// declared because later phases produce them; the P2 builder emits CONTAINS,
// IMPORTS, CALLS and REFERENCES only, and says so in its limitations.
type EdgeKind string

const (
	EdgeContains   EdgeKind = "CONTAINS"
	EdgeImports    EdgeKind = "IMPORTS"
	EdgeCalls      EdgeKind = "CALLS"
	EdgeReferences EdgeKind = "REFERENCES"
	EdgeFlowsTo    EdgeKind = "FLOWS_TO"
	EdgeControls   EdgeKind = "CONTROLS"
)

// AllEdgeKinds lists every declared edge kind in a stable order.
func AllEdgeKinds() []EdgeKind {
	return []EdgeKind{EdgeContains, EdgeImports, EdgeCalls, EdgeReferences, EdgeFlowsTo, EdgeControls}
}

// Resolution states how a relationship was established. It is deliberately
// finer grained than a boolean: "we could not resolve this" has several
// meanings, and each one has different consequences for an audit.
type Resolution string

const (
	// Resolved means the target is a symbol in this snapshot, found through an
	// unambiguous language-level rule.
	Resolved Resolution = "resolved"
	// ResolvedBestEffort means the target was selected by a heuristic (for
	// example a local type inference). It may be wrong and must be re-checked
	// before it is treated as fact.
	ResolvedBestEffort Resolution = "resolved_best_effort"
	// Ambiguous means several candidates matched and the analysis refused to
	// pick one.
	Ambiguous Resolution = "unresolved_ambiguous"
	// Dynamic means the target depends on runtime dispatch, function values or
	// reflection.
	Dynamic Resolution = "unresolved_dynamic"
	// External means the target is outside the snapshot (a dependency).
	External Resolution = "unresolved_external"
	// Builtin means the callee is a language builtin, not a symbol in the
	// snapshot.
	Builtin Resolution = "builtin"
	// Unsupported means the construct is not understood by the frontend.
	Unsupported Resolution = "unresolved_unsupported"
)

// IsResolved reports whether the resolution points at a symbol in the snapshot.
func (r Resolution) IsResolved() bool {
	return r == Resolved || r == ResolvedBestEffort
}

// Confidence is how a fact was obtained: observed, inferred or unresolved. It
// is a class, never a probability.
type Confidence string

const (
	// Observed facts come from language-level resolution rules with no guessing.
	Observed Confidence = "observed"
	// Inferred facts come from heuristics that can be wrong.
	Inferred Confidence = "inferred"
	// Unresolved facts could not be established.
	Unresolved Confidence = "unresolved"
)

// SymbolKind enumerates the declaration kinds the P2 frontends emit.
type SymbolKind string

const (
	KindFunction  SymbolKind = "function"
	KindMethod    SymbolKind = "method"
	KindType      SymbolKind = "type"
	KindInterface SymbolKind = "interface"
	KindConst     SymbolKind = "const"
	KindVar       SymbolKind = "var"
	KindPackage   SymbolKind = "package"
)

// Location is a source position. Line and column are 1-based.
type Location struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
	Col  int    `json:"col,omitempty"`
}

// String renders the location as file:line for messages.
func (l Location) String() string {
	if l.Line == 0 {
		return l.File
	}
	return fmt.Sprintf("%s:%d", l.File, l.Line)
}

// Module is a build unit: a directory with its own manifest, or the repository
// root when no manifest exists (design doc §3.1, module level).
type Module struct {
	ID           string `json:"module_id"`
	SnapshotID   string `json:"snapshot_id"`
	Path         string `json:"path"` // "." for the repository root
	Name         string `json:"name"` // module name when the manifest declares one
	Language     string `json:"language,omitempty"`
	ManifestFile string `json:"manifest_file,omitempty"`
	Files        int    `json:"files"`
	Symbols      int    `json:"symbols"`
	Lines        int    `json:"lines"`
}

// File is one source file of the snapshot.
type File struct {
	ID         string `json:"file_id"`
	SnapshotID string `json:"snapshot_id"`
	ModuleID   string `json:"module_id"`
	Path       string `json:"path"`
	Language   string `json:"language"`
	Bytes      int64  `json:"bytes"`
	Lines      int    `json:"lines"`
	// ParseStatus is ok, partial, unparsed or unsupported_language. Files that no
	// frontend handles are still recorded: omission would look like absence.
	ParseStatus string `json:"parse_status"`
	ParseError  string `json:"parse_error,omitempty"`
}

// Symbol is one declaration with a stable identity inside the snapshot.
type Symbol struct {
	ID            string     `json:"symbol_id"`
	SnapshotID    string     `json:"snapshot_id"`
	ModuleID      string     `json:"module_id"`
	FileID        string     `json:"file_id"`
	File          string     `json:"file"`
	Language      string     `json:"language"`
	Kind          SymbolKind `json:"kind"`
	Name          string     `json:"name"`
	QualifiedName string     `json:"qualified_name"`
	Signature     string     `json:"signature,omitempty"`
	Receiver      string     `json:"receiver,omitempty"`
	// ResultType is the named type of the single result, when there is exactly
	// one. It is what makes `x := pkg.New()` resolvable without type checking.
	ResultType string `json:"result_type,omitempty"`
	Exported   bool   `json:"exported"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	StartCol   int    `json:"start_col,omitempty"`
	EndCol     int    `json:"end_col,omitempty"`
}

// ArgKind classifies one call argument by what static analysis can see.
type ArgKind string

const (
	// ArgStringLiteral is a string literal; StringValue holds the unquoted text,
	// which is what makes route paths and SQL prefixes readable.
	ArgStringLiteral ArgKind = "string_literal"
	// ArgLiteral is another literal (number, boolean); Text holds its source form.
	ArgLiteral ArgKind = "literal"
	// ArgSymbolRef is an identifier or selector that resolved to a symbol in the
	// snapshot — for example a handler function passed to a router.
	ArgSymbolRef ArgKind = "symbol_ref"
	// ArgExpression is anything else: only its source text is known.
	ArgExpression ArgKind = "expression"
)

// ArgRef is one argument of one call site. It is what turns "GET was called"
// into "GET(\"/users/:id\", handler) was called", which is the fact attack
// surface extraction needs.
type ArgRef struct {
	Position int     `json:"position"`
	Kind     ArgKind `json:"kind"`
	// Text is the argument as written, bounded in length.
	Text string `json:"text,omitempty"`
	// StringValue is the unquoted value of a string literal.
	StringValue string `json:"string_value,omitempty"`
	// SymbolID/SymbolQualified are set when the argument names a symbol.
	SymbolID        string     `json:"symbol_id,omitempty"`
	SymbolQualified string     `json:"symbol_qualified,omitempty"`
	Resolution      Resolution `json:"resolution,omitempty"`
	Confidence      Confidence `json:"confidence,omitempty"`
}

// CallSite is a call expression found in the source. It exists whether or not
// the callee could be resolved: unresolved calls are kept, never deleted
// (implementation guide §6.2).
type CallSite struct {
	ID              string     `json:"call_site_id"`
	SnapshotID      string     `json:"snapshot_id"`
	CallerSymbolID  string     `json:"caller_symbol_id,omitempty"`
	FileID          string     `json:"file_id"`
	File            string     `json:"file"`
	Line            int        `json:"line"`
	Col             int        `json:"col,omitempty"`
	CalleeText      string     `json:"callee_text"`
	CalleeSymbolID  string     `json:"callee_symbol_id,omitempty"`
	CalleeQualified string     `json:"callee_qualified,omitempty"`
	Resolution      Resolution `json:"resolution"`
	Confidence      Confidence `json:"confidence"`
	Detail          string     `json:"detail,omitempty"`
	Analyzer        string     `json:"analyzer"`
	AnalyzerVersion string     `json:"analyzer_version"`
	// Args holds the call's arguments, up to a bounded number.
	Args []ArgRef `json:"args,omitempty"`
	// ReceiverFrom names the call a selector's receiver was bound from, for
	// example "gin.Default" for `r := gin.Default(); r.GET(...)`. It is how a
	// rule attributes a route to a framework without type checking.
	ReceiverFrom string `json:"receiver_from,omitempty"`
}

// Edge is one relationship between two nodes.
type Edge struct {
	ID              string            `json:"edge_id"`
	SnapshotID      string            `json:"snapshot_id"`
	From            string            `json:"from"`
	To              string            `json:"to"`
	Kind            EdgeKind          `json:"kind"`
	Resolution      Resolution        `json:"resolution"`
	Confidence      Confidence        `json:"confidence"`
	SourceLocation  Location          `json:"source_location"`
	Analyzer        string            `json:"analyzer"`
	AnalyzerVersion string            `json:"analyzer_version"`
	CallSiteID      string            `json:"call_site_id,omitempty"`
	Detail          map[string]string `json:"detail,omitempty"`
}

// ResolutionCounts summarises how much of the graph is resolved. It is part of
// the graph's coverage statement, not a quality score.
type ResolutionCounts struct {
	Resolved           int `json:"resolved"`
	ResolvedBestEffort int `json:"resolved_best_effort"`
	Ambiguous          int `json:"ambiguous"`
	Dynamic            int `json:"dynamic"`
	External           int `json:"external"`
	Builtin            int `json:"builtin"`
	Unsupported        int `json:"unsupported"`
}

// Total is the number of call sites accounted for.
func (c ResolutionCounts) Total() int {
	return c.Resolved + c.ResolvedBestEffort + c.Ambiguous + c.Dynamic + c.External + c.Builtin + c.Unsupported
}

// Add accumulates one call site resolution.
func (c *ResolutionCounts) Add(r Resolution) {
	switch r {
	case Resolved:
		c.Resolved++
	case ResolvedBestEffort:
		c.ResolvedBestEffort++
	case Ambiguous:
		c.Ambiguous++
	case Dynamic:
		c.Dynamic++
	case External:
		c.External++
	case Builtin:
		c.Builtin++
	default:
		c.Unsupported++
	}
}

// Coverage states how much of the snapshot the build actually examined.
type Coverage struct {
	FilesInSnapshot int `json:"files_in_snapshot"`
	// FilesTooLarge counts files the builder refused to read. They are part of
	// the snapshot but contribute nothing to the graph, which is stated as a
	// limitation rather than hidden.
	FilesTooLarge    int `json:"files_too_large"`
	FilesParsed      int `json:"files_parsed"`
	FilesPartial     int `json:"files_partial"`
	FilesUnparsed    int `json:"files_unparsed"`
	FilesUnsupported int `json:"files_unsupported"`
	// FilesNotSource counts files that are not source code at all (data formats
	// and tooling descriptors). They are graph nodes for traceability but
	// contribute no symbols, and they are not "unsupported".
	FilesNotSource   int `json:"files_not_source"`
	SymbolsSkipped   int `json:"symbols_skipped"`
	CallSitesSkipped int `json:"call_sites_skipped"`
}

// Graph is the built SCG of one snapshot.
type Graph struct {
	SchemaVersion   int              `json:"schema_version"`
	SnapshotID      string           `json:"snapshot_id"`
	GraphVersion    string           `json:"graph_version"`
	Engine          Engine           `json:"engine"`
	Frontends       []FrontendInfo   `json:"frontends"`
	Modules         []Module         `json:"modules"`
	Files           []File           `json:"files"`
	Symbols         []Symbol         `json:"symbols"`
	CallSites       []CallSite       `json:"call_sites"`
	Edges           []Edge           `json:"edges"`
	Resolution      ResolutionCounts `json:"resolution"`
	Coverage        Coverage         `json:"coverage"`
	Limitations     []string         `json:"limitations"`
	BuiltAt         string           `json:"built_at"`
	BuildDurationMS int64            `json:"build_duration_ms"`
}

// Engine identifies the component that built the graph.
type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// FrontendInfo records one frontend that participated in the build.
type FrontendInfo struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Language []string `json:"language"`
}

// SchemaVersion is the SCG document version.
const SchemaVersion = 1

// JSON renders the graph deterministically.
func (g *Graph) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ArtifactName is the content-addressed file name of a graph document. The graph
// version and a digest of the bytes are both present, so two builds of the same
// rule set never overwrite each other and every stored document can be traced
// back to what produced it.
func (g *Graph) ArtifactName() (string, error) {
	doc, err := g.JSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(doc)
	return fmt.Sprintf("scg-%s-%s.json", strings.TrimPrefix(g.GraphVersion, "graph-"), hex.EncodeToString(sum[:6])), nil
}

// Summary is the cheap, queryable description of a stored graph, used by the
// API before anyone asks for the full document.
type Summary struct {
	SnapshotID      string           `json:"snapshot_id"`
	GraphVersion    string           `json:"graph_version"`
	Engine          Engine           `json:"engine"`
	Frontends       []FrontendInfo   `json:"frontends"`
	Modules         int              `json:"modules"`
	Files           int              `json:"files"`
	Symbols         int              `json:"symbols"`
	CallSites       int              `json:"call_sites"`
	Edges           int              `json:"edges"`
	EdgesByKind     map[string]int   `json:"edges_by_kind"`
	Resolution      ResolutionCounts `json:"resolution"`
	Coverage        Coverage         `json:"coverage"`
	Limitations     []string         `json:"limitations"`
	BuiltAt         string           `json:"built_at"`
	BuildDurationMS int64            `json:"build_duration_ms"`
}

// Summarize derives the summary from a graph.
func (g *Graph) Summarize() *Summary {
	s := &Summary{
		SnapshotID:      g.SnapshotID,
		GraphVersion:    g.GraphVersion,
		Engine:          g.Engine,
		Frontends:       g.Frontends,
		Modules:         len(g.Modules),
		Files:           len(g.Files),
		Symbols:         len(g.Symbols),
		CallSites:       len(g.CallSites),
		Edges:           len(g.Edges),
		EdgesByKind:     map[string]int{},
		Resolution:      g.Resolution,
		Coverage:        g.Coverage,
		Limitations:     g.Limitations,
		BuiltAt:         g.BuiltAt,
		BuildDurationMS: g.BuildDurationMS,
	}
	for _, e := range g.Edges {
		s.EdgesByKind[string(e.Kind)]++
	}
	if s.Limitations == nil {
		s.Limitations = []string{}
	}
	return s
}

// addLimitation appends a unique coverage statement.
func (g *Graph) addLimitation(format string, args ...any) {
	note := fmt.Sprintf(format, args...)
	for _, existing := range g.Limitations {
		if existing == note {
			return
		}
	}
	g.Limitations = append(g.Limitations, note)
}

// sortForDeterminism orders every collection by id so that two builds of the
// same snapshot produce byte-identical documents.
func (g *Graph) sortForDeterminism() {
	sort.Slice(g.Modules, func(i, j int) bool { return g.Modules[i].ID < g.Modules[j].ID })
	sort.Slice(g.Files, func(i, j int) bool { return g.Files[i].ID < g.Files[j].ID })
	sort.Slice(g.Symbols, func(i, j int) bool { return g.Symbols[i].ID < g.Symbols[j].ID })
	sort.Slice(g.CallSites, func(i, j int) bool { return g.CallSites[i].ID < g.CallSites[j].ID })
	sort.Slice(g.Edges, func(i, j int) bool { return g.Edges[i].ID < g.Edges[j].ID })
	sort.Strings(g.Limitations)
}

// BuiltAtNow is the timestamp format used for graph builds.
func BuiltAtNow() string { return time.Now().UTC().Format(time.RFC3339) }
