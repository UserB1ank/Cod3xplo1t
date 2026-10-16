// Package mcp exposes the Codexploit Source Code Graph over the Model Context
// Protocol.
//
// The surface is closed on purpose: nine read-only tools, every one of them
// scoped to a single snapshot, bounded by the graph service's own budgets and
// returning its provenance block unchanged. There is no tool that writes, no
// shell, no arbitrary file access and no free-form query language, because an
// answer an audit agent cites has to come from a query the platform defined —
// otherwise it cannot be reproduced or attributed.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// Classification codes carried by tool errors. MCP tool errors travel as text,
// so the code is the first token of the message: a client must be able to tell
// "the snapshot does not exist" from "your arguments were rejected" without
// pattern-matching prose. The names match the REST API's error body codes.
const (
	CodeInvalidArgument = "invalid_argument"
	CodeNotFound        = "not_found"
	CodeTreeUnavailable = "tree_unavailable"
	CodeBudgetExceeded  = "budget_exceeded"
	CodeInternal        = "internal"
)

const (
	serverName         = "codexploit"
	serverVersion      = "0.1.0"
	serverTitle        = "Codexploit graph service"
	serverInstructions = `Read-only queries over the Source Code Graph of one snapshot. ` +
		`Every tool is scoped to a snapshot_id and every result carries a provenance block ` +
		`("meta") with the snapshot, graph version, budget applied and whether the answer was ` +
		`truncated; an answer without that block is incomplete and must not be cited as coverage. ` +
		`Call graph_summary first to learn how much of the snapshot the graph actually covers.`
)

// Every tool is read-only, idempotent and closed-world by construction; the
// hints let a client enforce that instead of trusting description text.
var (
	closedWorld    = false
	notDestructive = false
)

// NewServer builds the MCP surface of a graph service.
//
// store is the runtime's full store. The service is the read path for every
// tool, so the full store is only adopted when the service has none of its own.
//
// Panics on a nil service or when neither the service nor the argument carries a
// graph store: those are wiring bugs, not request errors, and every tool call
// would otherwise dereference nil.
func NewServer(svc *graph.Service, store storage.FullStore, logger *slog.Logger) *mcp.Server {
	if svc == nil {
		panic("mcp: NewServer called with a nil graph service")
	}
	if svc.Store == nil {
		svc.Store = store
	}
	if svc.Store == nil {
		panic("mcp: NewServer needs a graph store, on the service or as an argument")
	}
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: serverVersion,
		Title:   serverTitle,
	}, &mcp.ServerOptions{
		Instructions: serverInstructions,
		Logger:       logger,
	})
	registerTools(srv, svc)
	return srv
}

// snapshotArg is embedded by every tool input: the platform refuses to answer a
// query that is not scoped to one snapshot, so the field is required and its
// presence is checked before any store read.
type snapshotArg struct {
	SnapshotID string `json:"snapshot_id" jsonschema:"id of the snapshot the query is scoped to"`
}

func (a snapshotArg) snapshotID() string { return a.SnapshotID }

type snapshotScoped interface{ snapshotID() string }

// register adapts a typed query to an MCP tool. Unmarshaling and schema
// validation are the SDK's job; budget clamping is the service's. Classifying
// errors here keeps every tool's failure mode identical.
func register[In snapshotScoped, Out any](srv *mcp.Server, tool *mcp.Tool, query func(context.Context, In) (*Out, error)) {
	tool.Annotations = &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
		DestructiveHint: &notDestructive,
	}
	mcp.AddTool(srv, tool, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, *Out, error) {
		if strings.TrimSpace(in.snapshotID()) == "" {
			return nil, nil, coded(CodeInvalidArgument, errors.New("snapshot_id must not be empty"))
		}
		out, err := query(ctx, in)
		if err != nil {
			return nil, nil, coded(classify(err), err)
		}
		return nil, out, nil
	})
}

// coded prefixes the classification so the code survives into the tool error
// text a client sees, while errors.Is still reaches the sentinel underneath.
func coded(code string, err error) error {
	if code == "" {
		return err
	}
	return fmt.Errorf("%s: %w", code, err)
}

// classify maps a service error onto the code an agent branches on.
func classify(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, graph.ErrInvalidArgument):
		return CodeInvalidArgument
	case errors.Is(err, graph.ErrNoGraph), errors.Is(err, storage.ErrNotFound):
		return CodeNotFound
	case errors.Is(err, graph.ErrTreeUnavailable):
		return CodeTreeUnavailable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return CodeBudgetExceeded
	default:
		return CodeInternal
	}
}

// --- tool inputs ------------------------------------------------------------

type listModulesInput struct {
	snapshotArg
}

type listSymbolsInput struct {
	snapshotArg
	ModuleID     string `json:"module_id,omitempty" jsonschema:"restrict the search to one module id"`
	Kind         string `json:"kind,omitempty" jsonschema:"restrict the search to one declaration kind: function, method, type, interface, const, var or package"`
	NameContains string `json:"name_contains,omitempty" jsonschema:"case-sensitive substring of the symbol name"`
	Limit        int    `json:"limit,omitempty" jsonschema:"page size; the service default and cap apply when omitted"`
	Offset       int    `json:"offset,omitempty" jsonschema:"page offset into the matching symbols"`
}

type getSymbolInput struct {
	snapshotArg
	SymbolID string `json:"symbol_id" jsonschema:"symbol id or qualified name"`
}

type neighborhoodInput struct {
	snapshotArg
	SymbolID string `json:"symbol_id" jsonschema:"symbol id or qualified name of the root"`
	MaxDepth int    `json:"max_depth,omitempty" jsonschema:"traversal depth, 1 meaning direct neighbours; the service default and cap apply when omitted"`
	MaxNodes int    `json:"max_nodes,omitempty" jsonschema:"node budget for the traversal; the service default applies when omitted"`
	Limit    int    `json:"limit,omitempty" jsonschema:"maximum number of unresolved call sites returned alongside the neighbourhood"`
}

type pathsInput struct {
	snapshotArg
	SourceSymbolID string `json:"source_symbol_id" jsonschema:"symbol id or qualified name of the source"`
	SinkSymbolID   string `json:"sink_symbol_id" jsonschema:"symbol id or qualified name of the sink"`
	MaxDepth       int    `json:"max_depth,omitempty" jsonschema:"path length budget; path searches use a larger service default than neighbourhoods"`
	MaxPaths       int    `json:"max_paths,omitempty" jsonschema:"maximum number of distinct paths to return; the service default and cap apply when omitted"`
}

type sliceInput struct {
	snapshotArg
	SymbolID string `json:"symbol_id,omitempty" jsonschema:"symbol id or qualified name to slice"`
	File     string `json:"file,omitempty" jsonschema:"snapshot-relative file path; used only when symbol_id is empty"`
	Include  string `json:"include,omitempty" jsonschema:"extra sections: declaration (default), callers, calls or neighbors"`
	MaxLines int    `json:"max_lines,omitempty" jsonschema:"maximum lines per section; the service default and cap apply when omitted"`
}

type unresolvedCallsInput struct {
	snapshotArg
	CallerSymbolID string `json:"caller_symbol_id,omitempty" jsonschema:"restrict to the unresolved calls made by this symbol"`
	Limit          int    `json:"limit,omitempty" jsonschema:"page size; the service default and cap apply when omitted"`
}

type summaryInput struct {
	snapshotArg
}

// --- tool results -----------------------------------------------------------

// symbolResult pairs a symbol with the provenance block the service returns
// separately, so the tool result still carries its coverage information.
type symbolResult struct {
	Symbol scg.Symbol `json:"symbol"`
	Meta   graph.Meta `json:"meta"`
}

type unresolvedCallsResult struct {
	CallSites []scg.CallSite `json:"unresolved_call_sites"`
	Meta      graph.Meta     `json:"meta"`
}

type summaryResult struct {
	Summary scg.Summary `json:"summary"`
	Meta    graph.Meta  `json:"meta"`
}

// --- registration -----------------------------------------------------------

// Declaration kinds the P2 frontends emit, used to reject a kind filter that
// would otherwise silently widen the search.
var knownKinds = []scg.SymbolKind{
	scg.KindFunction, scg.KindMethod, scg.KindType,
	scg.KindInterface, scg.KindConst, scg.KindVar, scg.KindPackage,
}

// Slice sections the service understands. A typo would otherwise silently
// degrade to a declaration-only slice.
var sliceIncludes = map[string]bool{
	graph.SectionDeclaration: true,
	"callers":                true,
	"calls":                  true,
	"neighbors":              true,
}

func registerTools(srv *mcp.Server, svc *graph.Service) {
	register(srv, &mcp.Tool{
		Name:        "list_modules",
		Description: "List the modules (build units) of one snapshot, with their file, symbol and line counts.",
	}, func(ctx context.Context, in listModulesInput) (*graph.ModulePage, error) {
		return svc.Modules(ctx, in.SnapshotID, graph.Options{})
	})

	register(srv, &mcp.Tool{
		Name:        "list_symbols",
		Description: "Search the declarations of one snapshot, optionally filtered by module, kind or name substring. Returns a bounded page plus the total number of matches.",
	}, func(ctx context.Context, in listSymbolsInput) (*graph.SymbolPage, error) {
		kinds, err := parseKind(in.Kind)
		if err != nil {
			return nil, err
		}
		return svc.Symbols(ctx, in.SnapshotID, graph.SymbolQuery{
			ModuleID:     in.ModuleID,
			Kinds:        kinds,
			NameContains: in.NameContains,
			Options:      graph.Options{Limit: in.Limit, Offset: in.Offset},
		})
	})

	register(srv, &mcp.Tool{
		Name:        "get_symbol",
		Description: "Fetch one declaration of one snapshot by symbol id or qualified name.",
	}, func(ctx context.Context, in getSymbolInput) (*symbolResult, error) {
		sym, meta, err := svc.Symbol(ctx, in.SnapshotID, in.SymbolID, graph.Options{})
		if err != nil {
			return nil, err
		}
		return &symbolResult{Symbol: *sym, Meta: meta}, nil
	})

	register(srv, &mcp.Tool{
		Name:        "get_callers",
		Description: "List the symbols that call a symbol, bounded by depth, node and result budgets. The answer carries the unresolved call sites inside the visited symbols, which are its blind spots.",
	}, func(ctx context.Context, in neighborhoodInput) (*graph.Neighborhood, error) {
		return svc.Callers(ctx, in.SnapshotID, in.SymbolID, graph.Options{
			MaxDepth: in.MaxDepth,
			MaxNodes: in.MaxNodes,
			Limit:    in.Limit,
		})
	})

	register(srv, &mcp.Tool{
		Name:        "get_callees",
		Description: "List the symbols a symbol calls, bounded by depth, node and result budgets. The answer carries the unresolved call sites inside the visited symbols, which are its blind spots.",
	}, func(ctx context.Context, in neighborhoodInput) (*graph.Neighborhood, error) {
		return svc.Callees(ctx, in.SnapshotID, in.SymbolID, graph.Options{
			MaxDepth: in.MaxDepth,
			MaxNodes: in.MaxNodes,
			Limit:    in.Limit,
		})
	})

	register(srv, &mcp.Tool{
		Name:        "find_call_paths",
		Description: "Enumerate bounded call paths from a source symbol to a sink symbol. A call path is a reachability fact, not a dataflow fact: it never shows that data flows between the two.",
	}, func(ctx context.Context, in pathsInput) (*graph.PathSet, error) {
		return svc.CallPaths(ctx, in.SnapshotID, graph.PathRequest{
			Source:   in.SourceSymbolID,
			Sink:     in.SinkSymbolID,
			MaxPaths: in.MaxPaths,
			Options:  graph.Options{MaxDepth: in.MaxDepth},
		})
	})

	register(srv, &mcp.Tool{
		Name:        "get_code_slice",
		Description: "Read a bounded source excerpt out of the snapshot's frozen tree, either for one symbol or for a window of one snapshot-relative file. Paths outside the snapshot are rejected.",
	}, func(ctx context.Context, in sliceInput) (*graph.CodeSlice, error) {
		// Validate the selector here: the service resolves the frozen tree first,
		// so an empty selector would otherwise be reported as a missing tree.
		if strings.TrimSpace(in.SymbolID) == "" && strings.TrimSpace(in.File) == "" {
			return nil, fmt.Errorf("%w: symbol_id or file is required", graph.ErrInvalidArgument)
		}
		if in.Include != "" && !sliceIncludes[in.Include] {
			return nil, fmt.Errorf("%w: unknown include %q; want declaration, callers, calls or neighbors",
				graph.ErrInvalidArgument, in.Include)
		}
		return svc.Slice(ctx, in.SnapshotID, graph.SliceRequest{
			SymbolID: in.SymbolID,
			File:     in.File,
			Include:  in.Include,
			MaxLines: in.MaxLines,
		})
	})

	register(srv, &mcp.Tool{
		Name:        "list_unresolved_calls",
		Description: "List the call sites of one snapshot whose callee could not be resolved. They are where the graph is blind, and they bound every reachability answer.",
	}, func(ctx context.Context, in unresolvedCallsInput) (*unresolvedCallsResult, error) {
		sites, meta, err := svc.UnresolvedCalls(ctx, in.SnapshotID, in.CallerSymbolID, graph.Options{Limit: in.Limit})
		if err != nil {
			return nil, err
		}
		return &unresolvedCallsResult{CallSites: sites, Meta: meta}, nil
	})

	register(srv, &mcp.Tool{
		Name:        "graph_summary",
		Description: "Return the stored summary of one snapshot: node and edge counts, call-site resolution counts and the coverage statement of the build.",
	}, func(ctx context.Context, in summaryInput) (*summaryResult, error) {
		started := time.Now().UTC()
		summary, err := svc.Summary(ctx, in.SnapshotID)
		if err != nil {
			return nil, err
		}
		// Summary deliberately returns the summary document alone, so the
		// provenance block is built here: counts without their snapshot, engine
		// and budget are not evidence.
		return &summaryResult{
			Summary: *summary,
			Meta: graph.Meta{
				SnapshotID:   summary.SnapshotID,
				GraphVersion: summary.GraphVersion,
				Engine:       summary.Engine.Name + "@" + summary.Engine.Version,
				Query:        "summary",
				Budget:       graph.Options{}.WithDefaults(),
				ElapsedMS:    time.Now().UTC().Sub(started).Milliseconds(),
			},
		}, nil
	})
}

// parseKind turns the single kind filter of the tool surface into the service's
// slice form, rejecting anything the frontends never emit.
func parseKind(raw string) ([]scg.SymbolKind, error) {
	if raw == "" {
		return nil, nil
	}
	for _, kind := range knownKinds {
		if string(kind) == raw {
			return []scg.SymbolKind{kind}, nil
		}
	}
	names := make([]string, 0, len(knownKinds))
	for _, kind := range knownKinds {
		names = append(names, string(kind))
	}
	return nil, fmt.Errorf("%w: unknown kind %q; want one of %s",
		graph.ErrInvalidArgument, raw, strings.Join(names, ", "))
}
