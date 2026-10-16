package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// scgFlags are the flags shared by the graph subcommands.
type scgFlags struct {
	workspace string
	dbPath    string
	snapshot  string
	jsonOut   bool
	limit     int
	offset    int
	depth     int
	maxNodes  int
	timeoutMS int
	symbol    string
}

func parseSCG(name string, args []string) (*scgFlags, []string, error) {
	fs := flag.NewFlagSet("scg "+name, flag.ContinueOnError)
	c := &scgFlags{}
	fs.StringVar(&c.workspace, "workspace", ".codexploit", "workspace directory")
	fs.StringVar(&c.dbPath, "db", "", "SQLite database file (default <workspace>/codexploit.db)")
	fs.StringVar(&c.snapshot, "snapshot", "", "snapshot id")
	fs.BoolVar(&c.jsonOut, "json", false, "print the full document")
	fs.IntVar(&c.limit, "limit", 50, "maximum entries to return")
	fs.IntVar(&c.offset, "offset", 0, "entries to skip")
	fs.IntVar(&c.depth, "depth", 0, "traversal depth (0 uses the service default)")
	fs.IntVar(&c.maxNodes, "max-nodes", 0, "maximum nodes to visit (0 uses the service default)")
	fs.IntVar(&c.timeoutMS, "timeout-ms", 0, "query time budget in milliseconds")
	fs.StringVar(&c.symbol, "symbol", "", "symbol id or qualified name")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if abs, err := filepath.Abs(c.workspace); err == nil {
		c.workspace = abs
	}
	if c.dbPath == "" {
		c.dbPath = filepath.Join(c.workspace, "codexploit.db")
	}
	return c, fs.Args(), nil
}

func (c *scgFlags) build(ctx context.Context) (*app.Runtime, error) {
	return app.Build(ctx, app.Config{
		Workspace: c.workspace,
		DBPath:    c.dbPath,
	})
}

func (c *scgFlags) options() graph.Options {
	return graph.Options{
		MaxDepth: c.depth,
		MaxNodes: c.maxNodes,
		Limit:    c.limit,
		Offset:   c.offset,
	}.WithDefaults()
}

func (c *scgFlags) requireSnapshot() (string, error) {
	if strings.TrimSpace(c.snapshot) == "" {
		return "", errors.New("--snapshot is required")
	}
	return c.snapshot, nil
}

// runSCG dispatches the graph subcommands.
func runSCG(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit scg <build|summary|modules|files|symbols|callers|callees|paths|slice|unresolved> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "build":
		return runSCGBuild(ctx, rest)
	case "summary":
		return runSCGSummary(ctx, rest)
	case "modules":
		return runSCGModules(ctx, rest)
	case "files":
		return runSCGFiles(ctx, rest)
	case "symbols":
		return runSCGSymbols(ctx, rest)
	case "callers", "callees":
		return runSCGNeighborhood(ctx, sub, rest)
	case "paths":
		return runSCGPaths(ctx, rest)
	case "slice":
		return runSCGSlice(ctx, rest)
	case "unresolved":
		return runSCGUnresolved(ctx, rest)
	default:
		return fmt.Errorf("unknown scg subcommand %q", sub)
	}
}

// runSCGBuild produces the whole chain of one revision: snapshot, manifest and
// SCG, including the stored graph document.
func runSCGBuild(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scg build", flag.ContinueOnError)
	source := fs.String("source", "", "repository URL or local path")
	ref := fs.String("ref", "", "revision to pin")
	workspace := fs.String("workspace", ".codexploit", "workspace directory")
	dbPath := fs.String("db", "", "SQLite database file (default <workspace>/codexploit.db)")
	allowNetwork := fs.Bool("allow-network", false, "permit cloning remote git URLs")
	jsonOut := fs.Bool("json", false, "print the graph summary as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*source) == "" {
		return errors.New("--source is required")
	}
	abs, err := filepath.Abs(*workspace)
	if err != nil {
		return err
	}
	path := *dbPath
	if path == "" {
		path = filepath.Join(abs, "codexploit.db")
	}
	rt, err := app.Build(ctx, app.Config{Workspace: abs, DBPath: path, AllowNetwork: *allowNetwork})
	if err != nil {
		return err
	}
	defer rt.Close()

	snap, err := rt.Manager.Create(ctx, repository.Source{Raw: *source, Ref: *ref})
	if err != nil {
		return err
	}
	manifest, err := rt.Analyzer.Analyze(ctx, snap)
	if err != nil {
		return err
	}
	if err := manifest.WriteTo(snap); err != nil && !manifestStored(snap, manifest) {
		return err
	}
	g, err := rt.Builder.Build(ctx, snap)
	if err != nil {
		return err
	}
	doc, err := g.JSON()
	if err != nil {
		return err
	}
	name, err := g.ArtifactName()
	if err != nil {
		return err
	}
	if err := snap.WriteArtifact(name, doc); err != nil {
		return err
	}
	if err := rt.Store.ReplaceGraph(ctx, snap.SnapshotID, g); err != nil {
		return err
	}
	summary, err := rt.Graph.Summary(ctx, snap.SnapshotID)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(map[string]any{"snapshot": snap, "graph": summary})
	}
	printSnapshot(snap)
	printManifest(manifest)
	printGraphSummary(summary)
	fmt.Printf("\ngraph document %s\ngraph stored in %s\n", snap.ArtifactPath(name), path)
	return nil
}

// manifestStored reports whether the manifest already on disk describes the same
// analysis. Timestamps differ between runs, so the analysis id decides.
func manifestStored(snap *repository.Snapshot, m *analysis.Manifest) bool {
	got, err := snap.ReadManifest()
	if err != nil {
		return false
	}
	var prev analysis.Manifest
	if err := json.Unmarshal(got, &prev); err != nil {
		return false
	}
	return prev.AnalysisID != "" && prev.AnalysisID == m.AnalysisID
}

func printGraphSummary(s *scg.Summary) {
	fmt.Printf("\ngraph      %s (engine %s@%s)\n", s.GraphVersion, s.Engine.Name, s.Engine.Version)
	fmt.Printf("structure  %d module(s), %d file(s), %d symbol(s), %d call site(s), %d edge(s)\n",
		s.Modules, s.Files, s.Symbols, s.CallSites, s.Edges)
	fmt.Printf("calls      %d resolved, %d best effort, %d ambiguous, %d dynamic, %d external, %d builtin, %d unsupported\n",
		s.Resolution.Resolved, s.Resolution.ResolvedBestEffort, s.Resolution.Ambiguous, s.Resolution.Dynamic,
		s.Resolution.External, s.Resolution.Builtin, s.Resolution.Unsupported)
	if len(s.EdgesByKind) > 0 {
		kinds := make([]string, 0, len(s.EdgesByKind))
		for k, n := range s.EdgesByKind {
			kinds = append(kinds, fmt.Sprintf("%s=%d", k, n))
		}
		fmt.Printf("edges      %s\n", strings.Join(kinds, ", "))
	}
	printLimitations("coverage", s.Limitations)
}

func runSCGSummary(ctx context.Context, args []string) error {
	c, _, err := parseSCG("summary", args)
	if err != nil {
		return err
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	summary, err := rt.Graph.Summary(ctx, id)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(summary)
	}
	printGraphSummary(summary)
	return nil
}

func runSCGModules(ctx context.Context, args []string) error {
	c, _, err := parseSCG("modules", args)
	if err != nil {
		return err
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	page, err := rt.Graph.Modules(ctx, id, c.options())
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(page)
	}
	fmt.Printf("%-12s %-28s %-32s %-10s %6s %8s\n", "MODULE", "PATH", "NAME", "LANGUAGE", "FILES", "SYMBOLS")
	for _, mod := range page.Modules {
		name := mod.Name
		if name == "" {
			name = "(undeclared)"
		}
		fmt.Printf("%-12s %-28s %-32s %-10s %6d %8d\n",
			shortID(mod.ID), mod.Path, name, mod.Language, mod.Files, mod.Symbols)
	}
	return nil
}

func runSCGFiles(ctx context.Context, args []string) error {
	c, rest, err := parseSCG("files", args)
	if err != nil {
		return err
	}
	moduleID := ""
	if len(rest) > 0 {
		moduleID = rest[0]
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	files, meta, err := rt.Graph.Files(ctx, id, moduleID, c.options())
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(map[string]any{"files": files, "meta": meta})
	}
	for _, f := range files {
		fmt.Printf("%-9s %-45s %6d lines  %s\n", f.ParseStatus, f.Path, f.Lines, f.Language)
	}
	return nil
}

func runSCGSymbols(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scg symbols", flag.ContinueOnError)
	c := &scgFlags{}
	fs.StringVar(&c.workspace, "workspace", ".codexploit", "workspace directory")
	fs.StringVar(&c.dbPath, "db", "", "SQLite database file")
	fs.StringVar(&c.snapshot, "snapshot", "", "snapshot id")
	fs.BoolVar(&c.jsonOut, "json", false, "print JSON")
	fs.IntVar(&c.limit, "limit", 50, "maximum entries")
	fs.IntVar(&c.offset, "offset", 0, "entries to skip")
	module := fs.String("module", "", "restrict to a module id or path")
	kind := fs.String("kind", "", "comma-separated symbol kinds")
	name := fs.String("name", "", "substring match on the symbol name")
	qualified := fs.String("qualified-name", "", "exact qualified name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if abs, err := filepath.Abs(c.workspace); err == nil {
		c.workspace = abs
	}
	if c.dbPath == "" {
		c.dbPath = filepath.Join(c.workspace, "codexploit.db")
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	moduleID := *module
	if moduleID != "" && !strings.HasPrefix(moduleID, "mod-") {
		mod, _, merr := rt.Graph.Module(ctx, id, moduleID, c.options())
		if merr != nil {
			return merr
		}
		moduleID = mod.ID
	}
	page, err := rt.Graph.Symbols(ctx, id, graph.SymbolQuery{
		ModuleID:      moduleID,
		Kinds:         parseKinds(*kind),
		NameContains:  *name,
		QualifiedName: *qualified,
		Options:       c.options(),
	})
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(page)
	}
	for _, sym := range page.Symbols {
		fmt.Printf("%-9s %-60s %s:%d\n", sym.Kind, sym.QualifiedName, sym.File, sym.StartLine)
	}
	fmt.Printf("%d of %d symbol(s)\n", len(page.Symbols), page.Total)
	return nil
}

func runSCGNeighborhood(ctx context.Context, direction string, args []string) error {
	c, _, err := parseSCG(direction, args)
	if err != nil {
		return err
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	symbolID, err := resolveSymbol(ctx, rt, id, c.symbol, c.options())
	if err != nil {
		return err
	}
	var out *graph.Neighborhood
	if direction == "callers" {
		out, err = rt.Graph.Callers(ctx, id, symbolID, c.options())
	} else {
		out, err = rt.Graph.Callees(ctx, id, symbolID, c.options())
	}
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(out)
	}
	fmt.Printf("%s of %s (depth %d)\n", direction, out.Root.QualifiedName, out.Meta.DepthReached)
	for _, node := range out.Nodes {
		fmt.Printf("  d%d %-60s %s:%d\n", node.Distance, node.Symbol.QualifiedName, node.Symbol.File, node.Symbol.StartLine)
	}
	if out.Meta.MoreBeyondDepth {
		fmt.Println("  (more graph exists beyond the requested depth)")
	}
	if out.Meta.Truncated {
		fmt.Printf("  truncated: %s\n", out.Meta.TruncationReason)
	}
	if len(out.Unresolved) > 0 {
		fmt.Printf("  %d unresolved call site(s) inside these symbols\n", len(out.Unresolved))
	}
	return nil
}

func runSCGPaths(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scg paths", flag.ContinueOnError)
	c := &scgFlags{}
	fs.StringVar(&c.workspace, "workspace", ".codexploit", "workspace directory")
	fs.StringVar(&c.dbPath, "db", "", "SQLite database file")
	fs.StringVar(&c.snapshot, "snapshot", "", "snapshot id")
	fs.BoolVar(&c.jsonOut, "json", false, "print JSON")
	fs.IntVar(&c.depth, "depth", 0, "maximum path length")
	fs.IntVar(&c.maxNodes, "max-nodes", 0, "maximum nodes to visit")
	fs.IntVar(&c.timeoutMS, "timeout-ms", 0, "query time budget in milliseconds")
	fs.StringVar(&c.symbol, "symbol", "", "symbol id or qualified name")
	from := fs.String("from", "", "source symbol id or qualified name")
	to := fs.String("to", "", "sink symbol id or qualified name")
	maxPaths := fs.Int("max-paths", 5, "maximum paths to return")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if abs, err := filepath.Abs(c.workspace); err == nil {
		c.workspace = abs
	}
	if c.dbPath == "" {
		c.dbPath = filepath.Join(c.workspace, "codexploit.db")
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	sourceID, err := resolveSymbol(ctx, rt, id, *from, c.options())
	if err != nil {
		return err
	}
	sinkID, err := resolveSymbol(ctx, rt, id, *to, c.options())
	if err != nil {
		return err
	}
	paths, err := rt.Graph.CallPaths(ctx, id, graph.PathRequest{
		Source: sourceID, Sink: sinkID, MaxPaths: *maxPaths, Options: c.options(),
	})
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(paths)
	}
	fmt.Printf("%d path(s) from %s to %s\n", len(paths.Paths), paths.Source.QualifiedName, paths.Sink.QualifiedName)
	for i, path := range paths.Paths {
		names := make([]string, 0, len(path.Symbols))
		for _, sym := range path.Symbols {
			names = append(names, sym.Name)
		}
		fmt.Printf("  %d. %s (length %d)\n", i+1, strings.Join(names, " -> "), path.Length)
	}
	printLimitations("caveats", paths.Limitations)
	if paths.Meta.Truncated {
		fmt.Printf("truncated: %s\n", paths.Meta.TruncationReason)
	}
	return nil
}

func runSCGSlice(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scg slice", flag.ContinueOnError)
	c := &scgFlags{}
	fs.StringVar(&c.workspace, "workspace", ".codexploit", "workspace directory")
	fs.StringVar(&c.dbPath, "db", "", "SQLite database file")
	fs.StringVar(&c.snapshot, "snapshot", "", "snapshot id")
	fs.BoolVar(&c.jsonOut, "json", false, "print JSON")
	symbol := fs.String("symbol", "", "symbol id or qualified name")
	file := fs.String("file", "", "file path instead of a symbol")
	include := fs.String("include", "declaration", "declaration, callers, calls or neighbors")
	maxLines := fs.Int("max-lines", 0, "maximum lines per section")
	startLine := fs.Int("start-line", 0, "first line of a file slice")
	endLine := fs.Int("end-line", 0, "last line of a file slice")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if abs, err := filepath.Abs(c.workspace); err == nil {
		c.workspace = abs
	}
	if c.dbPath == "" {
		c.dbPath = filepath.Join(c.workspace, "codexploit.db")
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	req := graph.SliceRequest{
		File:      *file,
		StartLine: *startLine,
		EndLine:   *endLine,
		Include:   *include,
		MaxLines:  *maxLines,
		Options:   c.options(),
	}
	if *symbol != "" {
		symbolID, serr := resolveSymbol(ctx, rt, id, *symbol, c.options())
		if serr != nil {
			return serr
		}
		req.SymbolID = symbolID
	}
	slice, err := rt.Graph.Slice(ctx, id, req)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(slice)
	}
	for _, section := range slice.Sections {
		fmt.Printf("--- %s %s:%d-%d (%s)\n", section.File, section.Symbol, section.StartLine, section.EndLine, section.Reason)
		for i, line := range section.Lines {
			fmt.Printf("%5d  %s\n", section.StartLine+i, line)
		}
		if section.Truncated {
			fmt.Println("      (section truncated by the line budget)")
		}
	}
	printLimitations("caveats", slice.Limitations)
	return nil
}

func runSCGUnresolved(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scg unresolved", flag.ContinueOnError)
	c := &scgFlags{}
	fs.StringVar(&c.workspace, "workspace", ".codexploit", "workspace directory")
	fs.StringVar(&c.dbPath, "db", "", "SQLite database file")
	fs.StringVar(&c.snapshot, "snapshot", "", "snapshot id")
	fs.BoolVar(&c.jsonOut, "json", false, "print JSON")
	fs.IntVar(&c.limit, "limit", 50, "maximum entries")
	symbol := fs.String("symbol", "", "restrict to one caller symbol")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if abs, err := filepath.Abs(c.workspace); err == nil {
		c.workspace = abs
	}
	if c.dbPath == "" {
		c.dbPath = filepath.Join(c.workspace, "codexploit.db")
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	callerID := ""
	if *symbol != "" {
		callerID, err = resolveSymbol(ctx, rt, id, *symbol, c.options())
		if err != nil {
			return err
		}
	}
	sites, meta, err := rt.Graph.UnresolvedCalls(ctx, id, callerID, c.options())
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(map[string]any{"call_sites": sites, "meta": meta})
	}
	for _, cs := range sites {
		fmt.Printf("%-22s %s:%d  %s  (%s)\n", cs.Resolution, cs.File, cs.Line, cs.CalleeText, cs.Detail)
	}
	fmt.Printf("%d unresolved call site(s)\n", len(sites))
	return nil
}

// resolveSymbol accepts a symbol id or a qualified name, and reports ambiguity
// instead of picking one of several candidates.
func resolveSymbol(ctx context.Context, rt *app.Runtime, snapshotID, ref string, opt graph.Options) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", errors.New("a symbol id or qualified name is required")
	}
	if strings.HasPrefix(ref, "sym-") {
		return ref, nil
	}
	opt.Limit = 10
	page, err := rt.Graph.Symbols(ctx, snapshotID, graph.SymbolQuery{QualifiedName: ref, Options: opt})
	if err != nil {
		return "", err
	}
	if page.Total == 1 {
		return page.Symbols[0].ID, nil
	}
	if page.Total > 1 {
		return "", fmt.Errorf("%q matches %d symbols; use a symbol id", ref, page.Total)
	}
	page, err = rt.Graph.Symbols(ctx, snapshotID, graph.SymbolQuery{NameContains: ref, Options: opt})
	if err != nil {
		return "", err
	}
	switch page.Total {
	case 0:
		return "", fmt.Errorf("symbol %q not found in snapshot %s", ref, snapshotID)
	case 1:
		return page.Symbols[0].ID, nil
	default:
		names := make([]string, 0, len(page.Symbols))
		for _, sym := range page.Symbols {
			names = append(names, sym.QualifiedName)
		}
		return "", fmt.Errorf("%q matches several symbols: %s", ref, strings.Join(names, ", "))
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func parseKinds(value string) []scg.SymbolKind {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]scg.SymbolKind, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, scg.SymbolKind(p))
	}
	return out
}
