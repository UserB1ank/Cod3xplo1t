package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// asgFlags are the flags shared by the attack-surface subcommands. They mirror
// the HTTP query parameters one for one, so an answer can be reproduced with
// curl and with the CLI.
type asgFlags struct {
	workspace string
	dbPath    string
	snapshot  string
	jsonOut   bool
	kind      string
	subject   string
	generator string
	file      string
	from      string
	to        string
	limit     int
	offset    int
}

func parseASG(name string, args []string) (*asgFlags, []string, error) {
	fs := flag.NewFlagSet("asg "+name, flag.ContinueOnError)
	c := &asgFlags{}
	fs.StringVar(&c.workspace, "workspace", ".codexploit", "workspace directory")
	fs.StringVar(&c.dbPath, "db", "", "SQLite database file (default <workspace>/codexploit.db)")
	fs.StringVar(&c.snapshot, "snapshot", "", "snapshot id")
	fs.BoolVar(&c.jsonOut, "json", false, "print JSON")
	fs.StringVar(&c.kind, "kind", "", "comma-separated node or edge kinds")
	fs.StringVar(&c.subject, "subject", "", "exact node subject")
	fs.StringVar(&c.generator, "generator", "", "rule that produced the node")
	fs.StringVar(&c.file, "file", "", "file path")
	fs.StringVar(&c.from, "from", "", "comma-separated edge source node ids")
	fs.StringVar(&c.to, "to", "", "comma-separated edge target node ids")
	fs.IntVar(&c.limit, "limit", 0, "maximum entries (0 uses the service default)")
	fs.IntVar(&c.offset, "offset", 0, "entries to skip")
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

func (c *asgFlags) build(ctx context.Context) (*app.Runtime, error) {
	return app.Build(ctx, app.Config{Workspace: c.workspace, DBPath: c.dbPath})
}

func (c *asgFlags) requireSnapshot() (string, error) {
	if strings.TrimSpace(c.snapshot) == "" {
		return "", errors.New("--snapshot is required")
	}
	return c.snapshot, nil
}

// runASG dispatches the attack-surface subcommands.
func runASG(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit asg <build|summary|nodes|node|entrypoints|edges> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "build":
		return runASGBuild(ctx, rest)
	case "summary":
		return runASGSummary(ctx, rest)
	case "nodes":
		return runASGNodes(ctx, rest)
	case "node":
		return runASGNode(ctx, rest)
	case "entrypoints", "entry-points":
		return runASGEntryPoints(ctx, rest)
	case "edges":
		return runASGEdges(ctx, rest)
	default:
		return fmt.Errorf("unknown asg subcommand %q", sub)
	}
}

// runASGBuild produces the whole chain of one revision: snapshot, manifest, SCG
// and then the attack surface derived from that SCG.
func runASGBuild(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("asg build", flag.ContinueOnError)
	source := fs.String("source", "", "repository URL or local path")
	ref := fs.String("ref", "", "revision to pin")
	workspace := fs.String("workspace", ".codexploit", "workspace directory")
	dbPath := fs.String("db", "", "SQLite database file (default <workspace>/codexploit.db)")
	allowNetwork := fs.Bool("allow-network", false, "permit cloning remote git URLs")
	jsonOut := fs.Bool("json", false, "print the snapshot, graph and attack-surface summaries as JSON")
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

	chain, err := buildSCGChain(ctx, rt, *source, *ref)
	if err != nil {
		return err
	}
	doc, err := rt.ASGBuilder.Build(ctx, chain.snapshot.SnapshotID)
	if err != nil {
		if errors.Is(err, asg.ErrNoSCG) {
			return fmt.Errorf("%w: build the graph first with `codexploit scg build`", err)
		}
		return err
	}
	name, err := doc.ArtifactName()
	if err != nil {
		return err
	}
	data, err := doc.JSON()
	if err != nil {
		return err
	}
	if err := chain.snapshot.WriteArtifact(name, data); err != nil {
		return err
	}
	if err := rt.Store.ReplaceASG(ctx, chain.snapshot.SnapshotID, doc); err != nil {
		return err
	}
	summary := doc.Summarize()
	if *jsonOut {
		return printJSON(map[string]any{"snapshot": chain.snapshot, "graph": chain.summary, "asg": summary})
	}
	printSnapshot(chain.snapshot)
	printManifest(chain.manifest)
	printGraphSummary(chain.summary)
	printASGSummary(summary)
	fmt.Printf("\nattack-surface document %s\nattack surface stored in %s\n",
		chain.snapshot.ArtifactPath(name), path)
	return nil
}

func runASGSummary(ctx context.Context, args []string) error {
	c, _, err := parseASG("summary", args)
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
	summary, err := asgForSnapshot(ctx, rt, id)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(summary)
	}
	printASGSummary(summary)
	return nil
}

func runASGNodes(ctx context.Context, args []string) error {
	c, _, err := parseASG("nodes", args)
	if err != nil {
		return err
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	kinds, err := asgNodeKinds(c.kind)
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if err := requireASG(ctx, rt, id); err != nil {
		return err
	}
	page, err := rt.ASG.Nodes(ctx, id, graph.ASGNodeQuery{
		Kinds:     kinds,
		Subject:   c.subject,
		Generator: c.generator,
		File:      c.file,
		Limit:     c.limit,
		Offset:    c.offset,
	})
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(page)
	}
	for _, node := range page.Nodes {
		fmt.Printf("%-24s %-46s %s:%d  [%s]\n", node.Kind, node.Subject, node.File, node.Line, node.Evidence)
	}
	fmt.Printf("%d of %d node(s)\n", len(page.Nodes), page.Total)
	return nil
}

func runASGNode(ctx context.Context, args []string) error {
	c, rest, err := parseASG("node", args)
	if err != nil {
		return err
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	if len(rest) == 0 || strings.TrimSpace(rest[0]) == "" {
		return errors.New("a node id is required")
	}
	nodeID := rest[0]
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if err := requireASG(ctx, rt, id); err != nil {
		return err
	}
	view, err := rt.ASG.Node(ctx, id, nodeID)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(view)
	}
	node := view.Node
	fmt.Printf("%s %s\n", node.Kind, node.Subject)
	fmt.Printf("label      %s\n", node.Label)
	fmt.Printf("generator  %s  evidence %s  confidence %s\n", node.Generator, node.Evidence, node.Confidence)
	if node.File != "" {
		fmt.Printf("location   %s:%d\n", node.File, node.Line)
	}
	printDetail(node.Detail)
	printEdges("outgoing", view.Outgoing)
	printEdges("incoming", view.Incoming)
	if len(view.DerivedFrom) > 0 {
		fmt.Println("evidence")
		for _, ref := range view.DerivedFrom {
			label := ref.Label
			if label == "" {
				label = "(unresolved)"
			}
			fmt.Printf("  %-10s %-44s %s:%d %s\n", ref.Kind, label, ref.File, ref.Line, ref.Detail)
		}
	}
	return nil
}

func runASGEntryPoints(ctx context.Context, args []string) error {
	c, _, err := parseASG("entrypoints", args)
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
	if err := requireASG(ctx, rt, id); err != nil {
		return err
	}
	page, err := rt.ASG.EntryPoints(ctx, id, c.limit, c.offset)
	if err != nil {
		return err
	}
	summary, err := rt.ASG.Summary(ctx, id)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(map[string]any{
			"entry_points":    page.EntryPoints,
			"total":           page.Total,
			"meta":            page.Meta,
			"limitations":     summary.Limitations,
			"coverage":        summary.Coverage,
			"evidence_counts": summary.EvidenceCounts,
		})
	}
	printRouteTable(page.EntryPoints)
	fmt.Printf("%d of %d entry point(s)\n", len(page.EntryPoints), page.Total)
	if page.Meta.Truncated {
		fmt.Printf("truncated: %s\n", page.Meta.TruncationReason)
	}
	fmt.Printf("coverage   %d call site(s), %d symbol(s) examined; reachability depth %d, budget %d, %d entry point(s) cut short\n",
		summary.Coverage.CallSitesExamined, summary.Coverage.SymbolsExamined,
		summary.Coverage.ReachabilityDepth, summary.Coverage.ReachabilityBudget,
		summary.Coverage.EntryPointsTruncated)
	fmt.Printf("evidence   %s\n", formatCounts(summary.EvidenceCounts))
	printLimitations("limitations", summary.Limitations)
	return nil
}

func runASGEdges(ctx context.Context, args []string) error {
	c, _, err := parseASG("edges", args)
	if err != nil {
		return err
	}
	id, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	kinds, err := asgEdgeKinds(c.kind)
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if err := requireASG(ctx, rt, id); err != nil {
		return err
	}
	page, err := rt.ASG.Edges(ctx, id, splitList(c.from), splitList(c.to), kinds, c.limit)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(page)
	}
	for _, e := range page.Edges {
		fmt.Printf("%-14s %-28s -> %-28s %s\n", e.Kind, shortID(e.From), shortID(e.To), e.Detail["reason"])
	}
	fmt.Printf("%d edge(s)\n", len(page.Edges))
	if page.Meta.Truncated {
		fmt.Printf("truncated: %s\n", page.Meta.TruncationReason)
	}
	return nil
}

// requireASG turns a missing document into the command that produces it. Without
// this the store would answer "not found", which reads like a bad snapshot id.
func requireASG(ctx context.Context, rt *app.Runtime, snapshotID string) error {
	if _, err := rt.ASG.Summary(ctx, snapshotID); err != nil {
		if errors.Is(err, graph.ErrNoASG) || errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("snapshot %s has no attack surface yet; run `codexploit asg build`", snapshotID)
		}
		return err
	}
	return nil
}

// asgForSnapshot reports a missing attack surface as an actionable error.
func asgForSnapshot(ctx context.Context, rt *app.Runtime, snapshotID string) (*asg.Summary, error) {
	summary, err := rt.ASG.Summary(ctx, snapshotID)
	if err != nil {
		if errors.Is(err, graph.ErrNoASG) || errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("snapshot %s has no attack surface yet; run `codexploit asg build`", snapshotID)
		}
		return nil, err
	}
	return summary, nil
}

// printASGSummary is the human summary of an attack surface: what was found,
// how, and how much of the snapshot it covers.
func printASGSummary(s *asg.Summary) {
	fmt.Printf("\nattack surface %s (engine %s@%s, rules %s)\n",
		s.ASGVersion, s.Engine.Name, s.Engine.Version, s.RulesetHash)
	fmt.Printf("surface    %d node(s), %d edge(s)\n", s.Nodes, s.Edges)
	fmt.Printf("nodes      %s\n", formatCounts(s.NodesByKind))
	fmt.Printf("edges      %s\n", formatCounts(s.EdgesByKind))
	fmt.Printf("evidence   %s\n", formatCounts(s.EvidenceCounts))
	fmt.Printf("coverage   %d call site(s), %d symbol(s) examined; reachability depth %d, budget %d, %d entry point(s) cut short\n",
		s.Coverage.CallSitesExamined, s.Coverage.SymbolsExamined,
		s.Coverage.ReachabilityDepth, s.Coverage.ReachabilityBudget,
		s.Coverage.EntryPointsTruncated)
	printLimitations("limitations", s.Limitations)
}

// printRouteTable is the attack-surface answer an auditor reads first: what is
// reachable from outside, what guards it, and what it can touch.
func printRouteTable(entries []graph.ASGEntryPointView) {
	headers := []string{"METHOD PATH", "FRAMEWORK", "HANDLER", "BOUNDARY", "CONTROLS", "SINKS", "TRUNC"}
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		detail := entry.EntryPoint.Detail
		route := strings.TrimSpace(strings.ToUpper(detail["method"]) + " " + detail["path"])
		if route == "" {
			route = entry.EntryPoint.Label
		}
		boundary := ""
		if entry.Boundary != nil {
			boundary = entry.Boundary.Label
		}
		truncated := ""
		if detail["reachability_truncated"] == "true" {
			truncated = "yes"
		}
		rows = append(rows, []string{
			route,
			orNone(detail["framework"]),
			orNone(detail["handler"]),
			orNone(boundary),
			fmt.Sprintf("%d (%d observed)", len(entry.Controls), entry.ObservedControls),
			strconv.Itoa(len(entry.Sinks)),
			truncated,
		})
	}
	writeTable(headers, rows)
}

func printEdges(label string, edges []asg.Edge) {
	if len(edges) == 0 {
		return
	}
	fmt.Printf("%s\n", label)
	for _, e := range edges {
		fmt.Printf("  %-14s %-28s %s\n", e.Kind, shortID(e.To), e.Detail["reason"])
	}
}

func printDetail(detail map[string]string) {
	if len(detail) == 0 {
		return
	}
	keys := make([]string, 0, len(detail))
	for k := range detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-18s %s\n", k, detail[k])
	}
}

// asgNodeKinds validates the kind list against the ASG vocabulary, so a typo is
// an error instead of an empty listing.
func asgNodeKinds(value string) ([]asg.NodeKind, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	valid := map[string]asg.NodeKind{}
	for _, k := range asg.AllNodeKinds() {
		valid[string(k)] = k
	}
	var out []asg.NodeKind
	for _, part := range splitList(value) {
		kind, ok := valid[part]
		if !ok {
			return nil, fmt.Errorf("unknown node kind %q; valid kinds are %s", part, strings.Join(nodeKindNames(), ", "))
		}
		out = append(out, kind)
	}
	return out, nil
}

func asgEdgeKinds(value string) ([]asg.EdgeKind, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	valid := map[string]bool{}
	for _, k := range asg.AllEdgeKinds() {
		valid[string(k)] = true
	}
	var out []asg.EdgeKind
	for _, part := range splitList(value) {
		if !valid[part] {
			return nil, fmt.Errorf("unknown edge kind %q; valid kinds are %s", part, strings.Join(edgeKindNames(), ", "))
		}
		out = append(out, asg.EdgeKind(part))
	}
	return out, nil
}

func nodeKindNames() []string {
	kinds := asg.AllNodeKinds()
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}

func edgeKindNames() []string {
	kinds := asg.AllEdgeKinds()
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	out := make([]string, 0, strings.Count(value, ",")+1)
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// formatCounts renders a histogram in a stable order, because a map range would
// make two runs of the same query print differently.
func formatCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	return strings.Join(parts, ", ")
}

// writeTable prints a fixed-width table sized to its content.
func writeTable(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	printRow := func(cells []string) {
		parts := make([]string, 0, len(cells))
		for i, cell := range cells {
			parts = append(parts, fmt.Sprintf("%-*s", widths[i], cell))
		}
		fmt.Println(strings.TrimRight(strings.Join(parts, "  "), " "))
	}
	printRow(headers)
	for _, row := range rows {
		printRow(row)
	}
}
