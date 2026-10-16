package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// The read-only toolset an audit agent may call.
//
// Every tool is bounded and read-only, and the executor contract is the agent
// package's: a bad argument is answered inside ToolResult.Error and never as a Go
// error, because the argument is the agent's mistake to fix and a failed call must
// not end the run. A context cancellation is the one exception — the run is over,
// and the orchestrator should record a failed call rather than a result the agent
// could mistake for an answer.
//
// The caps below mirror the MCP surface's discipline (internal/mcp): every limit
// is bounded by a documented maximum and hitting one is reported inside the
// result, so a partial answer never reads as a complete one. They are tighter than
// the service's own caps because a tool result is paid for out of a model's
// context.

// Agent tool names. They are exported because the toolset is a contract: the
// runtime that advertises the list and the registry that executes it must agree on
// the exact strings.
const (
	ToolGetSymbol      = "get_symbol"
	ToolListSymbols    = "list_symbols"
	ToolGetCallers     = "get_callers"
	ToolGetCallees     = "get_callees"
	ToolFindCallPaths  = "find_call_paths"
	ToolGetCodeSlice   = "get_code_slice"
	ToolGraphSummary   = "graph_summary"
	ToolGetPath        = "get_path"
	ToolListAuditPaths = "list_audit_paths"
	ToolListHypotheses = "list_hypotheses"
)

// Caps on the tool arguments and on the text a tool returns.
const (
	agentToolDefaultLimit     = 20
	agentToolMaxLimit         = 100
	agentToolDefaultDepth     = 1
	agentToolMaxDepth         = 5
	agentToolDefaultNodes     = 200
	agentToolMaxNodes         = 500
	agentToolDefaultPaths     = 3
	agentToolMaxPaths         = 10
	agentToolDefaultDepthPath = 6
	agentToolMaxDepthPath     = 10
	agentToolDefaultLines     = 60
	agentToolMaxLines         = 200
	agentToolMaxOffset        = 10000
	// agentToolMaxTextChars bounds one tool result before the orchestrator's own
	// cap applies. The run pays for this text either way.
	agentToolMaxTextChars = 8000
	// agentToolMaxSummaryLimitations bounds how many of a summary's caveats a tool
	// answer carries; the rest are enumerations of the same statement.
	agentToolMaxSummaryLimitations = 5
	// agentToolMaxPathSteps and friends bound one path document.
	agentToolMaxPathSteps = 20
	agentToolMaxPathRefs  = 40
	agentToolMaxPathNotes = 10
	agentToolMaxStatement = 400
)

// agentToolNames is the default advertised toolset, in the order the registry
// sorts it. AgentToolNames returns a copy so a caller cannot reorder the contract.
var agentToolNames = []string{
	ToolFindCallPaths, ToolGetCallees, ToolGetCallers, ToolGetCodeSlice,
	ToolGetPath, ToolGetSymbol, ToolGraphSummary, ToolListAuditPaths,
	ToolListHypotheses, ToolListSymbols,
}

// AgentToolNames returns the toolset the runtime advertises by default.
func AgentToolNames() []string { return append([]string(nil), agentToolNames...) }

// HypothesisReader is the read-only part of the store the toolset needs. It is
// declared here, narrower than storage.FullStore, so no tool in this file can
// reach a mutating method even by accident.
type HypothesisReader interface {
	ListHypotheses(q agent.HypothesisQuery) ([]agent.Hypothesis, int, error)
}

// RegisterAgentTools registers the read-only toolset on a registry. The store is
// used only for read-only hypothesis lookups.
//
// A nil registry is a wiring bug and panics, like agent.Registry.Register's
// duplicate-name check: a server whose tools silently did not register would
// advertise a list it cannot execute.
func RegisterAgentTools(reg *agent.Registry, g *Service, a *ASGService, audit *path.Service, store storage.FullStore) {
	if reg == nil {
		panic("graph: RegisterAgentTools called with a nil registry")
	}
	env := toolEnv{graph: g, asg: a, audit: audit}
	if store != nil {
		env.store = store
	}
	for _, tool := range agentToolset() {
		reg.Register(tool.bind(env))
	}
}

// toolEnv is what every tool is wired to.
type toolEnv struct {
	graph *Service
	asg   *ASGService
	audit *path.Service
	store HypothesisReader
}

// agentReadTool binds a name, a one-line description and a call that still needs
// its wiring. The tools differ only in their arguments and their answer, so they
// share one shape instead of ten near-identical structs.
type agentReadTool struct {
	name     string
	describe string
	call     func(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error)
}

// boundTool is one tool closed over its wiring, which is what the registry stores.
type boundTool struct {
	name     string
	describe string
	call     func(ctx context.Context, args map[string]string) (agent.ToolResult, error)
}

func (t agentReadTool) bind(env toolEnv) *boundTool {
	return &boundTool{
		name:     t.name,
		describe: t.describe,
		call: func(ctx context.Context, args map[string]string) (agent.ToolResult, error) {
			return t.call(ctx, env, args)
		},
	}
}

func (t *boundTool) Name() string     { return t.name }
func (t *boundTool) Describe() string { return t.describe }
func (t *boundTool) Call(ctx context.Context, args map[string]string) (agent.ToolResult, error) {
	if err := ctx.Err(); err != nil {
		return agent.ToolResult{Tool: t.name}, err
	}
	return t.call(ctx, args)
}

// agentToolset is the whole read-only toolset, keyed by the names AgentToolNames
// advertises. The registration order does not matter; the agreement between the
// two lists is asserted in the tests.
func agentToolset() []agentReadTool {
	return []agentReadTool{
		{
			name:     ToolGetSymbol,
			describe: "Fetch one declaration of a snapshot by symbol id or qualified name.",
			call:     callGetSymbol,
		},
		{
			name:     ToolListSymbols,
			describe: "Search the declarations of a snapshot, filtered by name substring, kind, module or qualified name; returns a bounded page and the total number of matches.",
			call:     callListSymbols,
		},
		{
			name:     ToolGetCallers,
			describe: "List the symbols that reach a symbol over observed CALLS edges, bounded by depth and node budgets; the answer carries the unresolved call sites inside the visited symbols.",
			call:     callGetCallers,
		},
		{
			name:     ToolGetCallees,
			describe: "List the symbols a symbol reaches over observed CALLS edges, bounded by depth and node budgets; the answer carries the unresolved call sites inside the visited symbols.",
			call:     callGetCallees,
		},
		{
			name:     ToolFindCallPaths,
			describe: "Enumerate bounded call paths between two symbols of a snapshot; a path is call-graph reachability, never proof that data flows.",
			call:     callFindCallPaths,
		},
		{
			name:     ToolGetCodeSlice,
			describe: "Read a bounded source excerpt of a snapshot, either for one symbol or for a window of one snapshot-relative file.",
			call:     callGetCodeSlice,
		},
		{
			name:     ToolGraphSummary,
			describe: "Return the stored summary of a snapshot's call graph: counts, call-site resolution and the build's coverage statement.",
			call:     callGraphSummary,
		},
		{
			name:     ToolGetPath,
			describe: "Fetch one AuditPath document (its ends, steps, refs, objectives and open questions) by path id.",
			call:     callGetPath,
		},
		{
			name:     ToolListAuditPaths,
			describe: "List the paths of one audit, optionally filtered by status, as a bounded page.",
			call:     callListAuditPaths,
		},
		{
			name:     ToolListHypotheses,
			describe: "List stored hypotheses scoped to a path, audit, run or snapshot, as a bounded page.",
			call:     callListHypotheses,
		},
	}
}

// --- argument parsing -------------------------------------------------------

// onlyArgs rejects an argument the tool does not define. Without it a typo would
// silently do nothing, and the agent would keep asking a question the tool never
// heard.
func onlyArgs(args map[string]string, allowed ...string) error {
	known := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		known[key] = true
	}
	var unknown []string
	for key := range args {
		if !known[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%w: unknown argument(s) %s; accepted: %s",
		agent.ErrInvalidArgument, strings.Join(unknown, ", "), strings.Join(allowed, ", "))
}

func requiredArg(args map[string]string, key string) (string, error) {
	value := strings.TrimSpace(args[key])
	if value == "" {
		return "", fmt.Errorf("%w: %s is required", agent.ErrInvalidArgument, key)
	}
	return value, nil
}

// boundedArg parses an optional integer and clamps it into [min,max]. The second
// return value reports a clamp, which the caller must state in the result.
func boundedArg(args map[string]string, key string, def, min, max int) (int, bool, error) {
	raw := strings.TrimSpace(args[key])
	if raw == "" {
		return def, false, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %s must be an integer, got %q", agent.ErrInvalidArgument, key, raw)
	}
	switch {
	case value < min:
		return min, true, nil
	case value > max:
		return max, true, nil
	default:
		return value, false, nil
	}
}

func clampNote(key string, value, max int) string {
	return fmt.Sprintf("%s was capped at %d", key, max)
}

// --- result building --------------------------------------------------------

// toolAnswer is the JSON envelope of a structured tool result. Notes live inside
// it rather than after it, so a capped answer stays parseable.
type toolAnswer struct {
	Tool   string   `json:"tool"`
	Result any      `json:"result"`
	Notes  []string `json:"notes,omitempty"`
}

func toolJSON(name string, result any, notes, refs []string) (agent.ToolResult, error) {
	payload, err := json.Marshal(toolAnswer{Tool: name, Result: result, Notes: dedupeStrings(notes)})
	if err != nil {
		return agent.ToolResult{Tool: name}, err
	}
	return agent.ToolResult{Tool: name, OK: true, Result: string(payload), Refs: dedupeStrings(refs)}, nil
}

// toolText answers with text (code or prose) and appends its notes, because a
// trailing note is the only place a text answer can carry them.
func toolText(name, text string, notes, refs []string) agent.ToolResult {
	if deduped := dedupeStrings(notes); len(deduped) > 0 {
		text += "\n[note] " + strings.Join(deduped, "; ")
	}
	if cut, truncated := cutRunes(text, agentToolMaxTextChars); truncated {
		text = cut + fmt.Sprintf("\n[note] the answer exceeded %d runes and was truncated", agentToolMaxTextChars)
	}
	return agent.ToolResult{Tool: name, OK: true, Result: text, Refs: dedupeStrings(refs)}
}

func invalidArg(name string, err error) agent.ToolResult {
	return agent.ToolResult{Tool: name, OK: false, Error: err.Error()}
}

func missingService(name, what string) agent.ToolResult {
	return agent.ToolResult{Tool: name, OK: false, Error: "graph: the " + what + " service is not configured"}
}

// failure answers a service error. A cancelled or expired context is returned as a
// Go error so the orchestrator sees a failed call; everything else — a missing
// snapshot, a missing row, a bad selector — becomes a readable result the agent
// can act on without ending the run.
func failure(name string, ctx context.Context, err error) (agent.ToolResult, error) {
	if cerr := ctx.Err(); cerr != nil {
		return agent.ToolResult{Tool: name}, cerr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return agent.ToolResult{Tool: name}, err
	}
	return agent.ToolResult{Tool: name, OK: false, Error: err.Error()}, nil
}

// --- result shapes ----------------------------------------------------------

type toolMeta struct {
	SnapshotID       string `json:"snapshot_id,omitempty"`
	GraphVersion     string `json:"graph_version,omitempty"`
	ASGVersion       string `json:"asg_version,omitempty"`
	SCGVersion       string `json:"scg_version,omitempty"`
	Query            string `json:"query,omitempty"`
	Truncated        bool   `json:"truncated,omitempty"`
	TruncationReason string `json:"truncation_reason,omitempty"`
}

func graphToolMeta(m Meta) toolMeta {
	return toolMeta{
		SnapshotID: m.SnapshotID, GraphVersion: m.GraphVersion, Query: m.Query,
		Truncated: m.Truncated, TruncationReason: m.TruncationReason,
	}
}

func asgToolMeta(m ASGMeta) toolMeta {
	return toolMeta{
		SnapshotID: m.SnapshotID, ASGVersion: m.ASGVersion, SCGVersion: m.SCGVersion, Query: m.Query,
		Truncated: m.Truncated, TruncationReason: m.TruncationReason,
	}
}

type toolSymbol struct {
	ID            string `json:"id"`
	QualifiedName string `json:"qualified_name"`
	Kind          string `json:"kind"`
	File          string `json:"file,omitempty"`
	Line          int    `json:"line,omitempty"`
	Signature     string `json:"signature,omitempty"`
	Exported      bool   `json:"exported,omitempty"`
}

func compactSymbol(sym scg.Symbol) toolSymbol {
	return toolSymbol{
		ID: sym.ID, QualifiedName: sym.QualifiedName, Kind: string(sym.Kind),
		File: sym.File, Line: sym.StartLine, Signature: sym.Signature, Exported: sym.Exported,
	}
}

type toolCallSite struct {
	ID         string `json:"id"`
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	CalleeText string `json:"callee_text,omitempty"`
	Resolution string `json:"resolution,omitempty"`
}

func compactCallSite(site scg.CallSite) toolCallSite {
	return toolCallSite{
		ID: site.ID, File: site.File, Line: site.Line,
		CalleeText: site.CalleeText, Resolution: string(site.Resolution),
	}
}

// --- tool implementations ---------------------------------------------------

func callGetSymbol(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error) {
	const name = ToolGetSymbol
	if err := onlyArgs(args, "snapshot_id", "symbol_id"); err != nil {
		return invalidArg(name, err), nil
	}
	snapshot, err := requiredArg(args, "snapshot_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	symbolID, err := requiredArg(args, "symbol_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	if env.graph == nil {
		return missingService(name, "source graph"), nil
	}
	sym, meta, err := env.graph.Symbol(ctx, snapshot, symbolID, Options{})
	if err != nil {
		return failure(name, ctx, err)
	}
	return toolJSON(name, struct {
		Symbol toolSymbol `json:"symbol"`
		Meta   toolMeta   `json:"meta"`
	}{compactSymbol(*sym), graphToolMeta(meta)}, nil, []string{sym.ID})
}

// agentSymbolKinds mirrors the frontends' declaration kinds, so a kind filter that
// would silently widen the search is rejected instead.
var agentSymbolKinds = []scg.SymbolKind{
	scg.KindFunction, scg.KindMethod, scg.KindType,
	scg.KindInterface, scg.KindConst, scg.KindVar, scg.KindPackage,
}

func callListSymbols(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error) {
	const name = ToolListSymbols
	if err := onlyArgs(args, "snapshot_id", "module_id", "kind", "name_contains", "qualified_name", "limit", "offset"); err != nil {
		return invalidArg(name, err), nil
	}
	snapshot, err := requiredArg(args, "snapshot_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	if env.graph == nil {
		return missingService(name, "source graph"), nil
	}
	var kinds []scg.SymbolKind
	if raw := strings.TrimSpace(args["kind"]); raw != "" {
		known := false
		for _, kind := range agentSymbolKinds {
			if string(kind) == raw {
				kinds = append(kinds, kind)
				known = true
			}
		}
		if !known {
			names := make([]string, 0, len(agentSymbolKinds))
			for _, kind := range agentSymbolKinds {
				names = append(names, string(kind))
			}
			return invalidArg(name, fmt.Errorf("%w: unknown kind %q; want one of %s",
				agent.ErrInvalidArgument, raw, strings.Join(names, ", "))), nil
		}
	}
	limit, clampedLimit, err := boundedArg(args, "limit", agentToolDefaultLimit, 1, agentToolMaxLimit)
	if err != nil {
		return invalidArg(name, err), nil
	}
	offset, clampedOffset, err := boundedArg(args, "offset", 0, 0, agentToolMaxOffset)
	if err != nil {
		return invalidArg(name, err), nil
	}
	var notes []string
	if clampedLimit {
		notes = append(notes, clampNote("limit", limit, agentToolMaxLimit))
	}
	if clampedOffset {
		notes = append(notes, clampNote("offset", offset, agentToolMaxOffset))
	}
	page, err := env.graph.Symbols(ctx, snapshot, SymbolQuery{
		ModuleID:      strings.TrimSpace(args["module_id"]),
		Kinds:         kinds,
		NameContains:  args["name_contains"],
		QualifiedName: strings.TrimSpace(args["qualified_name"]),
		Options:       Options{Limit: limit, Offset: offset},
	})
	if err != nil {
		return failure(name, ctx, err)
	}
	if page.Meta.Truncated {
		notes = append(notes, "the page is partial: "+page.Meta.TruncationReason)
	}
	rows := make([]toolSymbol, 0, len(page.Symbols))
	refs := make([]string, 0, len(page.Symbols))
	for _, sym := range page.Symbols {
		rows = append(rows, compactSymbol(sym))
		refs = append(refs, sym.ID)
	}
	return toolJSON(name, struct {
		Symbols []toolSymbol `json:"symbols"`
		Total   int          `json:"total"`
		Meta    toolMeta     `json:"meta"`
	}{rows, page.Total, graphToolMeta(page.Meta)}, notes, refs)
}

func callGetCallers(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error) {
	return callNeighborhood(ctx, env, args, ToolGetCallers, true)
}

func callGetCallees(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error) {
	return callNeighborhood(ctx, env, args, ToolGetCallees, false)
}

// callNeighborhood implements get_callers and get_callees: one traversal shape,
// two directions.
func callNeighborhood(ctx context.Context, env toolEnv, args map[string]string, name string, callers bool) (agent.ToolResult, error) {
	if err := onlyArgs(args, "snapshot_id", "symbol_id", "max_depth", "max_nodes", "limit"); err != nil {
		return invalidArg(name, err), nil
	}
	snapshot, err := requiredArg(args, "snapshot_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	symbolID, err := requiredArg(args, "symbol_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	if env.graph == nil {
		return missingService(name, "source graph"), nil
	}
	depth, clampedDepth, err := boundedArg(args, "max_depth", agentToolDefaultDepth, 1, agentToolMaxDepth)
	if err != nil {
		return invalidArg(name, err), nil
	}
	nodes, clampedNodes, err := boundedArg(args, "max_nodes", agentToolDefaultNodes, 1, agentToolMaxNodes)
	if err != nil {
		return invalidArg(name, err), nil
	}
	limit, clampedLimit, err := boundedArg(args, "limit", agentToolDefaultLimit, 1, agentToolMaxLimit)
	if err != nil {
		return invalidArg(name, err), nil
	}
	var notes []string
	if clampedDepth {
		notes = append(notes, clampNote("max_depth", depth, agentToolMaxDepth))
	}
	if clampedNodes {
		notes = append(notes, clampNote("max_nodes", nodes, agentToolMaxNodes))
	}
	if clampedLimit {
		notes = append(notes, clampNote("limit", limit, agentToolMaxLimit))
	}
	opt := Options{MaxDepth: depth, MaxNodes: nodes, Limit: limit}
	var hood *Neighborhood
	if callers {
		hood, err = env.graph.Callers(ctx, snapshot, symbolID, opt)
	} else {
		hood, err = env.graph.Callees(ctx, snapshot, symbolID, opt)
	}
	if err != nil {
		return failure(name, ctx, err)
	}
	if hood.Meta.Truncated {
		notes = append(notes, "the traversal is partial: "+hood.Meta.TruncationReason)
	}
	if hood.Meta.MoreBeyondDepth {
		notes = append(notes, fmt.Sprintf("neighbours exist beyond the depth of %d", depth))
	}
	rows := make([]toolNeighbor, 0, len(hood.Nodes))
	refs := make([]string, 0, len(hood.Nodes)+len(hood.Unresolved))
	refs = append(refs, hood.Root.ID)
	for _, node := range hood.Nodes {
		rows = append(rows, toolNeighbor{
			ID: node.Symbol.ID, QualifiedName: node.Symbol.QualifiedName, Kind: string(node.Symbol.Kind),
			File: node.Symbol.File, Line: node.Symbol.StartLine, Distance: node.Distance,
		})
		refs = append(refs, node.Symbol.ID)
	}
	sites := make([]toolCallSite, 0, len(hood.Unresolved))
	for _, site := range hood.Unresolved {
		sites = append(sites, compactCallSite(site))
		refs = append(refs, site.ID)
	}
	for _, edge := range hood.Edges {
		refs = append(refs, edge.ID)
	}
	return toolJSON(name, struct {
		Root        string         `json:"root"`
		Direction   string         `json:"direction"`
		Nodes       []toolNeighbor `json:"nodes"`
		Unresolved  []toolCallSite `json:"unresolved_call_sites"`
		Limitations []string       `json:"limitations,omitempty"`
		Meta        toolMeta       `json:"meta"`
	}{hood.Root.ID, hood.Direction, rows, sites, hood.Limitations, graphToolMeta(hood.Meta)}, notes, refs)
}

func callFindCallPaths(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error) {
	const name = ToolFindCallPaths
	if err := onlyArgs(args, "snapshot_id", "source_symbol_id", "sink_symbol_id", "max_depth", "max_paths"); err != nil {
		return invalidArg(name, err), nil
	}
	snapshot, err := requiredArg(args, "snapshot_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	source, err := requiredArg(args, "source_symbol_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	sink, err := requiredArg(args, "sink_symbol_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	if env.graph == nil {
		return missingService(name, "source graph"), nil
	}
	depth, clampedDepth, err := boundedArg(args, "max_depth", agentToolDefaultDepthPath, 1, agentToolMaxDepthPath)
	if err != nil {
		return invalidArg(name, err), nil
	}
	maxPaths, clampedPaths, err := boundedArg(args, "max_paths", agentToolDefaultPaths, 1, agentToolMaxPaths)
	if err != nil {
		return invalidArg(name, err), nil
	}
	var notes []string
	if clampedDepth {
		notes = append(notes, clampNote("max_depth", depth, agentToolMaxDepthPath))
	}
	if clampedPaths {
		notes = append(notes, clampNote("max_paths", maxPaths, agentToolMaxPaths))
	}
	set, err := env.graph.CallPaths(ctx, snapshot, PathRequest{
		Source: source, Sink: sink, MaxPaths: maxPaths, Options: Options{MaxDepth: depth},
	})
	if err != nil {
		return failure(name, ctx, err)
	}
	if set.Meta.Truncated {
		notes = append(notes, "the search is partial: "+set.Meta.TruncationReason)
	}
	paths := make([]toolCallPath, 0, len(set.Paths))
	refs := []string{set.Source.ID, set.Sink.ID}
	for _, callPath := range set.Paths {
		names := make([]string, 0, len(callPath.Symbols))
		for _, sym := range callPath.Symbols {
			names = append(names, sym.QualifiedName)
			refs = append(refs, sym.ID)
		}
		refs = append(refs, callPath.EdgeIDs...)
		paths = append(paths, toolCallPath{
			SymbolIDs: copyStrings(callPath.SymbolIDs), Symbols: names,
			EdgeIDs: copyStrings(callPath.EdgeIDs), Length: callPath.Length,
		})
	}
	return toolJSON(name, struct {
		Source      string         `json:"source"`
		Sink        string         `json:"sink"`
		Paths       []toolCallPath `json:"paths"`
		Limitations []string       `json:"limitations,omitempty"`
		Meta        toolMeta       `json:"meta"`
	}{set.Source.QualifiedName, set.Sink.QualifiedName, paths, set.Limitations, graphToolMeta(set.Meta)}, notes, refs)
}

func callGetCodeSlice(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error) {
	const name = ToolGetCodeSlice
	if err := onlyArgs(args, "snapshot_id", "symbol_id", "file", "include", "start_line", "end_line", "max_lines"); err != nil {
		return invalidArg(name, err), nil
	}
	snapshot, err := requiredArg(args, "snapshot_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	symbolID := strings.TrimSpace(args["symbol_id"])
	file := strings.TrimSpace(args["file"])
	if symbolID == "" && file == "" {
		return invalidArg(name, fmt.Errorf("%w: symbol_id or file is required", agent.ErrInvalidArgument)), nil
	}
	include := strings.TrimSpace(args["include"])
	if include == "" {
		include = SectionDeclaration
	}
	if !agentSliceIncludes[include] {
		return invalidArg(name, fmt.Errorf("%w: unknown include %q; want declaration, callers, calls or neighbors",
			agent.ErrInvalidArgument, include)), nil
	}
	if env.graph == nil {
		return missingService(name, "source graph"), nil
	}
	maxLines, clampedLines, err := boundedArg(args, "max_lines", agentToolDefaultLines, 1, agentToolMaxLines)
	if err != nil {
		return invalidArg(name, err), nil
	}
	start, clampedStart, err := boundedArg(args, "start_line", 0, 0, agentToolMaxOffset)
	if err != nil {
		return invalidArg(name, err), nil
	}
	end, clampedEnd, err := boundedArg(args, "end_line", 0, 0, agentToolMaxOffset)
	if err != nil {
		return invalidArg(name, err), nil
	}
	var notes []string
	if clampedLines {
		notes = append(notes, clampNote("max_lines", maxLines, agentToolMaxLines))
	}
	if clampedStart {
		notes = append(notes, clampNote("start_line", start, agentToolMaxOffset))
	}
	if clampedEnd {
		notes = append(notes, clampNote("end_line", end, agentToolMaxOffset))
	}
	slice, err := env.graph.Slice(ctx, snapshot, SliceRequest{
		SymbolID: symbolID, File: file, StartLine: start, EndLine: end,
		Include: include, MaxLines: maxLines,
		Options: Options{},
	})
	if err != nil {
		return failure(name, ctx, err)
	}
	if slice.Meta.Truncated {
		notes = append(notes, "the slice is partial: "+slice.Meta.TruncationReason)
	}
	var builder strings.Builder
	refs := make([]string, 0, len(slice.Sections)+1)
	if slice.Root.ID != "" {
		refs = append(refs, slice.Root.ID)
	}
	for _, section := range slice.Sections {
		header := fmt.Sprintf("--- %s:%d-%d (%s)", section.File, section.StartLine, section.EndLine, section.Reason)
		if section.Truncated {
			notes = append(notes, fmt.Sprintf("%s:%d-%d was cut at %d line(s)", section.File, section.StartLine, section.EndLine, maxLines))
		}
		if section.SymbolID != "" {
			refs = append(refs, section.SymbolID)
		}
		builder.WriteString(header)
		builder.WriteString("\n")
		builder.WriteString(strings.Join(section.Lines, "\n"))
		builder.WriteString("\n")
	}
	for _, limitation := range slice.Limitations {
		notes = append(notes, limitation)
	}
	return toolText(name, builder.String(), notes, refs), nil
}

// agentSliceIncludes is the set of slice sections the service understands: a typo
// would otherwise silently degrade to a declaration-only slice.
var agentSliceIncludes = map[string]bool{
	SectionDeclaration: true,
	"callers":          true,
	"calls":            true,
	"neighbors":        true,
}

func callGraphSummary(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error) {
	const name = ToolGraphSummary
	if err := onlyArgs(args, "snapshot_id"); err != nil {
		return invalidArg(name, err), nil
	}
	snapshot, err := requiredArg(args, "snapshot_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	if env.graph == nil {
		return missingService(name, "source graph"), nil
	}
	summary, err := env.graph.Summary(ctx, snapshot)
	if err != nil {
		return failure(name, ctx, err)
	}
	var notes []string
	limitations := summary.Limitations
	if len(limitations) > agentToolMaxSummaryLimitations {
		limitations = limitations[:agentToolMaxSummaryLimitations]
		notes = append(notes, fmt.Sprintf("limitations were capped at %d of %d",
			agentToolMaxSummaryLimitations, len(summary.Limitations)))
	}
	result := toolGraphSummary{
		SnapshotID:   summary.SnapshotID,
		GraphVersion: summary.GraphVersion,
		Engine:       summary.Engine.Name + "@" + summary.Engine.Version,
		Modules:      summary.Modules,
		Files:        summary.Files,
		Symbols:      summary.Symbols,
		CallSites:    summary.CallSites,
		Edges:        summary.Edges,
		Resolution: toolResolution{
			Resolved: summary.Resolution.Resolved, ResolvedBestEffort: summary.Resolution.ResolvedBestEffort,
			Ambiguous: summary.Resolution.Ambiguous, Dynamic: summary.Resolution.Dynamic,
			External: summary.Resolution.External, Builtin: summary.Resolution.Builtin,
			Unsupported: summary.Resolution.Unsupported,
		},
		Coverage: toolCoverage{
			FilesInSnapshot: summary.Coverage.FilesInSnapshot, FilesParsed: summary.Coverage.FilesParsed,
			FilesPartial: summary.Coverage.FilesPartial, FilesUnparsed: summary.Coverage.FilesUnparsed,
			FilesUnsupported: summary.Coverage.FilesUnsupported, FilesTooLarge: summary.Coverage.FilesTooLarge,
			SymbolsSkipped: summary.Coverage.SymbolsSkipped, CallSitesSkipped: summary.Coverage.CallSitesSkipped,
		},
		Limitations: limitations,
	}
	return toolJSON(name, result, notes, nil)
}

func callGetPath(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error) {
	const name = ToolGetPath
	if err := onlyArgs(args, "path_id"); err != nil {
		return invalidArg(name, err), nil
	}
	pathID, err := requiredArg(args, "path_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	if env.audit == nil {
		return missingService(name, "audit"), nil
	}
	document, _, err := env.audit.Path(pathID)
	if err != nil {
		return failure(name, ctx, err)
	}
	doc, notes := compactPathDocument(*document)
	return toolJSON(name, doc, notes, append(copyStrings(document.ASGRefs), document.SCGRefs...))
}

// compactPathDocument bounds the fields of a path that can grow with the graph.
// The full document is a database row; an agent needs its ends, its steps and its
// questions, not every feature it was scored with.
func compactPathDocument(p path.Path) (toolPathDocument, []string) {
	var notes []string
	steps := p.Steps
	if len(steps) > agentToolMaxPathSteps {
		steps = steps[:agentToolMaxPathSteps]
		notes = append(notes, fmt.Sprintf("steps were capped at %d of %d", agentToolMaxPathSteps, len(p.Steps)))
	}
	rows := make([]toolStep, 0, len(steps))
	for _, step := range steps {
		rows = append(rows, toolStep{
			Layer: step.Layer, From: step.From, To: step.To, Kind: step.Kind,
			Subject: step.Subject, File: step.File, Line: step.Line, Resolution: step.Resolution,
		})
	}
	doc := toolPathDocument{
		ID: p.ID, AuditID: p.AuditID, SnapshotID: p.SnapshotID,
		Status: string(p.Status), PathStatus: string(p.PathStatus),
		Entry:  toolEnd{NodeID: p.EntryNodeID, Subject: p.EntrySubject, Kind: p.EntryKind},
		Target: toolEnd{NodeID: p.TargetNodeID, Subject: p.TargetSubject, Kind: p.TargetKind},
		Depth:  p.Depth, Priority: p.Score.Priority, Attempts: p.Attempts, MaxAttempts: p.MaxAttempts,
		Objectives:    copyStrings(p.Objectives),
		Boundaries:    copyStrings(p.Boundaries),
		Controls:      copyStrings(p.Controls),
		Inputs:        copyStrings(p.Inputs),
		Assets:        copyStrings(p.Assets),
		Steps:         rows,
		OpenQuestions: capList(p.OpenQuestions, agentToolMaxPathNotes, "open_questions", &notes),
		Limitations:   capList(p.Limitations, agentToolMaxPathNotes, "limitations", &notes),
		SCGRefs:       capList(p.SCGRefs, agentToolMaxPathRefs, "scg_refs", &notes),
		ASGRefs:       capList(p.ASGRefs, agentToolMaxPathRefs, "asg_refs", &notes),
		UpdatedAt:     p.UpdatedAt,
	}
	return doc, notes
}

// capList bounds one list and records that it was bounded.
func capList(values []string, max int, label string, notes *[]string) []string {
	if len(values) <= max {
		return copyStrings(values)
	}
	*notes = append(*notes, fmt.Sprintf("%s were capped at %d of %d", label, max, len(values)))
	return append([]string(nil), values[:max]...)
}

func callListAuditPaths(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error) {
	const name = ToolListAuditPaths
	if err := onlyArgs(args, "audit_id", "status", "limit", "offset"); err != nil {
		return invalidArg(name, err), nil
	}
	auditID, err := requiredArg(args, "audit_id")
	if err != nil {
		return invalidArg(name, err), nil
	}
	if env.audit == nil {
		return missingService(name, "audit"), nil
	}
	var statuses []path.Status
	if raw := strings.TrimSpace(args["status"]); raw != "" {
		if !path.ValidStatus(path.Status(raw)) {
			return invalidArg(name, fmt.Errorf("%w: unknown status %q", agent.ErrInvalidArgument, raw)), nil
		}
		statuses = append(statuses, path.Status(raw))
	}
	limit, clampedLimit, err := boundedArg(args, "limit", agentToolDefaultLimit, 1, agentToolMaxLimit)
	if err != nil {
		return invalidArg(name, err), nil
	}
	offset, clampedOffset, err := boundedArg(args, "offset", 0, 0, agentToolMaxOffset)
	if err != nil {
		return invalidArg(name, err), nil
	}
	var notes []string
	if clampedLimit {
		notes = append(notes, clampNote("limit", limit, agentToolMaxLimit))
	}
	if clampedOffset {
		notes = append(notes, clampNote("offset", offset, agentToolMaxOffset))
	}
	paths, total, err := env.audit.Paths(path.PathQuery{AuditID: auditID, Status: statuses, Limit: limit, Offset: offset})
	if err != nil {
		return failure(name, ctx, err)
	}
	rows := make([]toolPathRow, 0, len(paths))
	refs := make([]string, 0, len(paths)*2)
	for _, p := range paths {
		rows = append(rows, toolPathRow{
			ID: p.ID, Status: string(p.Status), PathStatus: string(p.PathStatus),
			EntrySubject: p.EntrySubject, TargetSubject: p.TargetSubject,
			Priority: p.Score.Priority, Depth: p.Depth, Attempts: p.Attempts, LeaseOwner: p.LeaseOwner,
		})
		refs = append(refs, p.EntryNodeID, p.TargetNodeID)
	}
	if offset+len(paths) < total {
		notes = append(notes, fmt.Sprintf("the page holds %d of %d path(s)", len(paths), total))
	}
	return toolJSON(name, struct {
		Paths  []toolPathRow `json:"paths"`
		Total  int           `json:"total"`
		Offset int           `json:"offset"`
	}{rows, total, offset}, notes, refs)
}

func callListHypotheses(ctx context.Context, env toolEnv, args map[string]string) (agent.ToolResult, error) {
	const name = ToolListHypotheses
	if err := onlyArgs(args, "path_id", "audit_id", "run_id", "snapshot_id", "status", "finding_candidates_only", "limit", "offset"); err != nil {
		return invalidArg(name, err), nil
	}
	if env.store == nil {
		return missingService(name, "hypothesis store"), nil
	}
	query := agent.HypothesisQuery{
		PathID: strings.TrimSpace(args["path_id"]), AuditID: strings.TrimSpace(args["audit_id"]),
		RunID: strings.TrimSpace(args["run_id"]), SnapshotID: strings.TrimSpace(args["snapshot_id"]),
	}
	if query.PathID == "" && query.AuditID == "" && query.RunID == "" && query.SnapshotID == "" {
		return invalidArg(name, fmt.Errorf("%w: one of path_id, audit_id, run_id or snapshot_id is required", agent.ErrInvalidArgument)), nil
	}
	if raw := strings.TrimSpace(args["status"]); raw != "" {
		query.Status = []string{raw}
	}
	if raw := strings.TrimSpace(args["finding_candidates_only"]); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return invalidArg(name, fmt.Errorf("%w: finding_candidates_only must be true or false, got %q", agent.ErrInvalidArgument, raw)), nil
		}
		query.FindingCandidatesOnly = value
	}
	limit, clampedLimit, err := boundedArg(args, "limit", agentToolDefaultLimit, 1, 50)
	if err != nil {
		return invalidArg(name, err), nil
	}
	offset, clampedOffset, err := boundedArg(args, "offset", 0, 0, agentToolMaxOffset)
	if err != nil {
		return invalidArg(name, err), nil
	}
	var notes []string
	if clampedLimit {
		notes = append(notes, clampNote("limit", limit, 50))
	}
	if clampedOffset {
		notes = append(notes, clampNote("offset", offset, agentToolMaxOffset))
	}
	query.Limit, query.Offset = limit, offset
	hypotheses, total, err := env.store.ListHypotheses(query)
	if err != nil {
		return failure(name, ctx, err)
	}
	rows := make([]toolHypothesis, 0, len(hypotheses))
	for _, hypothesis := range hypotheses {
		rows = append(rows, toolHypothesis{
			ID: hypothesis.ID, PathID: hypothesis.PathID, RunID: hypothesis.RunID,
			Statement: capRunes(hypothesis.Statement, agentToolMaxStatement),
			Status:    hypothesis.Status, Confidence: hypothesis.Confidence,
			FindingCandidate: hypothesis.FindingCandidate, SeverityHint: hypothesis.SeverityHint,
			CreatedAt: hypothesis.CreatedAt,
		})
	}
	if offset+len(hypotheses) < total {
		notes = append(notes, fmt.Sprintf("the page holds %d of %d hypothesis(es)", len(hypotheses), total))
	}
	return toolJSON(name, struct {
		Hypotheses []toolHypothesis `json:"hypotheses"`
		Total      int              `json:"total"`
		Offset     int              `json:"offset"`
	}{rows, total, offset}, notes, nil)
}

// --- result documents -------------------------------------------------------

type toolNeighbor struct {
	ID            string `json:"id"`
	QualifiedName string `json:"qualified_name"`
	Kind          string `json:"kind,omitempty"`
	File          string `json:"file,omitempty"`
	Line          int    `json:"line,omitempty"`
	Distance      int    `json:"distance"`
}

type toolCallPath struct {
	SymbolIDs []string `json:"symbol_ids"`
	Symbols   []string `json:"symbols"`
	EdgeIDs   []string `json:"edge_ids,omitempty"`
	Length    int      `json:"length"`
}

type toolResolution struct {
	Resolved           int `json:"resolved"`
	ResolvedBestEffort int `json:"resolved_best_effort"`
	Ambiguous          int `json:"ambiguous"`
	Dynamic            int `json:"dynamic"`
	External           int `json:"external"`
	Builtin            int `json:"builtin"`
	Unsupported        int `json:"unsupported"`
}

type toolCoverage struct {
	FilesInSnapshot  int `json:"files_in_snapshot"`
	FilesParsed      int `json:"files_parsed"`
	FilesPartial     int `json:"files_partial"`
	FilesUnparsed    int `json:"files_unparsed"`
	FilesUnsupported int `json:"files_unsupported"`
	FilesTooLarge    int `json:"files_too_large"`
	SymbolsSkipped   int `json:"symbols_skipped"`
	CallSitesSkipped int `json:"call_sites_skipped"`
}

type toolGraphSummary struct {
	SnapshotID   string         `json:"snapshot_id"`
	GraphVersion string         `json:"graph_version,omitempty"`
	Engine       string         `json:"engine,omitempty"`
	Modules      int            `json:"modules"`
	Files        int            `json:"files"`
	Symbols      int            `json:"symbols"`
	CallSites    int            `json:"call_sites"`
	Edges        int            `json:"edges"`
	Resolution   toolResolution `json:"resolution"`
	Coverage     toolCoverage   `json:"coverage"`
	Limitations  []string       `json:"limitations"`
}

type toolEnd struct {
	NodeID  string `json:"node_id"`
	Subject string `json:"subject,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

type toolStep struct {
	Layer      string `json:"layer"`
	From       string `json:"from"`
	To         string `json:"to"`
	Kind       string `json:"kind"`
	Subject    string `json:"subject,omitempty"`
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	Resolution string `json:"resolution,omitempty"`
}

type toolPathDocument struct {
	ID            string     `json:"path_id"`
	AuditID       string     `json:"audit_id,omitempty"`
	SnapshotID    string     `json:"snapshot_id"`
	Status        string     `json:"status"`
	PathStatus    string     `json:"path_status"`
	Entry         toolEnd    `json:"entry"`
	Target        toolEnd    `json:"target"`
	Depth         int        `json:"depth"`
	Priority      float64    `json:"priority"`
	Attempts      int        `json:"attempts"`
	MaxAttempts   int        `json:"max_attempts,omitempty"`
	Objectives    []string   `json:"objectives,omitempty"`
	Boundaries    []string   `json:"boundaries,omitempty"`
	Controls      []string   `json:"controls,omitempty"`
	Inputs        []string   `json:"inputs,omitempty"`
	Assets        []string   `json:"assets,omitempty"`
	Steps         []toolStep `json:"steps"`
	OpenQuestions []string   `json:"open_questions,omitempty"`
	Limitations   []string   `json:"limitations,omitempty"`
	SCGRefs       []string   `json:"scg_refs,omitempty"`
	ASGRefs       []string   `json:"asg_refs,omitempty"`
	UpdatedAt     string     `json:"updated_at,omitempty"`
}

type toolPathRow struct {
	ID            string  `json:"path_id"`
	Status        string  `json:"status"`
	PathStatus    string  `json:"path_status"`
	EntrySubject  string  `json:"entry_subject,omitempty"`
	TargetSubject string  `json:"target_subject,omitempty"`
	Priority      float64 `json:"priority"`
	Depth         int     `json:"depth"`
	Attempts      int     `json:"attempts"`
	LeaseOwner    string  `json:"lease_owner,omitempty"`
}

type toolHypothesis struct {
	ID               string `json:"hypothesis_id"`
	PathID           string `json:"path_id"`
	RunID            string `json:"run_id,omitempty"`
	Statement        string `json:"statement"`
	Status           string `json:"status"`
	Confidence       string `json:"confidence"`
	FindingCandidate bool   `json:"finding_candidate"`
	SeverityHint     string `json:"severity_hint,omitempty"`
	CreatedAt        string `json:"created_at,omitempty"`
}
