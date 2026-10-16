package asg

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// Errors returned by the extractor.
var (
	// ErrNoSCG means the snapshot has not been indexed, so there is nothing to
	// derive an attack surface from.
	ErrNoSCG = errors.New("asg: snapshot has no source code graph")
	// ErrInvalidDocument means the produced document violated the evidence rule.
	ErrInvalidDocument = errors.New("asg: invalid attack surface document")
)

// SCGReader is the read-only view of the Source Code Graph the extractor needs.
//
// It is expressed in SCG types and primitives only, on purpose: the attack
// surface layer depends on the fact layer and on nothing else — not on the graph
// query service, not on a store. That is also what keeps the dependency graph
// acyclic, since the storage layer implements the ASG store in terms of this
// package's types.
type SCGReader interface {
	// ReadSummary returns the stored SCG summary. A missing graph is an error, so
	// "no graph" can never look like "no attack surface".
	ReadSummary(ctx context.Context, snapshotID string) (*scg.Summary, error)
	// ReadFiles returns every file of the snapshot.
	ReadFiles(ctx context.Context, snapshotID string) ([]scg.File, error)
	// ReadSymbols pages through the symbols.
	ReadSymbols(ctx context.Context, snapshotID string, offset, limit int) ([]scg.Symbol, int, error)
	// ReadCallSites pages through the call sites, argument facts included.
	ReadCallSites(ctx context.Context, snapshotID string, offset, limit int) ([]scg.CallSite, int, error)
	// ReadCallees returns the symbols reachable from one symbol over CALLS edges,
	// and whether a budget cut the walk short.
	ReadCallees(ctx context.Context, snapshotID, symbolID string, depth, maxNodes int) ([]scg.Symbol, bool, error)
}

// Limits bound an extraction.
type Limits struct {
	MaxCallSites int
	MaxSymbols   int
	MaxNodes     int
	MaxEdges     int
	// ReachDepth and ReachNodes bound the call-graph walk behind REACHES edges.
	ReachDepth int
	ReachNodes int
	// MaxEntryPoints bounds how many entry points are walked. Extraction still
	// records every entry point it finds; only the walk stops.
	MaxEntryPoints int
	// MaxSinksPerEntry bounds REACHES edges per entry point.
	MaxSinksPerEntry int
	// MaxObservationsPerControl bounds the evidence list of a shared control node.
	MaxObservationsPerControl int
	TotalTimeout              time.Duration
	QueryTimeout              time.Duration
}

// DefaultLimits returns the P3 defaults: small enough to stay bounded on a large
// repository, large enough to describe a service.
func DefaultLimits() Limits {
	return Limits{
		MaxCallSites:              50000,
		MaxSymbols:                100000,
		MaxNodes:                  20000,
		MaxEdges:                  60000,
		ReachDepth:                3,
		ReachNodes:                200,
		MaxEntryPoints:            2000,
		MaxSinksPerEntry:          50,
		MaxObservationsPerControl: 10,
		TotalTimeout:              5 * time.Minute,
		QueryTimeout:              30 * time.Second,
	}
}

// WithDefaults fills zero fields.
func (l Limits) WithDefaults() Limits {
	d := DefaultLimits()
	if l.MaxCallSites <= 0 {
		l.MaxCallSites = d.MaxCallSites
	}
	if l.MaxSymbols <= 0 {
		l.MaxSymbols = d.MaxSymbols
	}
	if l.MaxNodes <= 0 {
		l.MaxNodes = d.MaxNodes
	}
	if l.MaxEdges <= 0 {
		l.MaxEdges = d.MaxEdges
	}
	if l.ReachDepth <= 0 {
		l.ReachDepth = d.ReachDepth
	}
	if l.ReachNodes <= 0 {
		l.ReachNodes = d.ReachNodes
	}
	if l.MaxEntryPoints <= 0 {
		l.MaxEntryPoints = d.MaxEntryPoints
	}
	if l.MaxSinksPerEntry <= 0 {
		l.MaxSinksPerEntry = d.MaxSinksPerEntry
	}
	if l.MaxObservationsPerControl <= 0 {
		l.MaxObservationsPerControl = d.MaxObservationsPerControl
	}
	if l.TotalTimeout <= 0 {
		l.TotalTimeout = d.TotalTimeout
	}
	if l.QueryTimeout <= 0 {
		l.QueryTimeout = d.QueryTimeout
	}
	return l
}

// Extractor derives an ASG candidate from a stored SCG.
type Extractor struct {
	SCG        SCGReader
	Frameworks []FrameworkRule
	Sources    []MatchRule
	Sinks      []MatchRule
	Controls   []MatchRule
	Limits     Limits
}

// NewExtractor builds an extractor over the default rule set.
func NewExtractor(scgReader SCGReader) *Extractor {
	return &Extractor{
		SCG:        scgReader,
		Frameworks: DefaultFrameworkRules(),
		Sources:    DefaultSourceRules(),
		Sinks:      DefaultSinkRules(),
		Controls:   DefaultControlRules(),
		Limits:     DefaultLimits(),
	}
}

// RulesetHash identifies this extractor's rule set.
func (e *Extractor) RulesetHash() string {
	return RulesetHash(e.Frameworks, e.Sources, e.Sinks, e.Controls)
}

// extraction is the mutable state of one run.
type extraction struct {
	doc       *Document
	limits    Limits
	nodes     map[string]Node
	edges     map[string]Edge
	symbols   map[string]scg.Symbol
	files     map[string]scg.File
	callSites []scg.CallSite
	byCaller  map[string][]scg.CallSite
	// reachedBy counts how many entry points reach a node, filled after the walk.
	reachedBy map[string]int
	// callSiteIndex maps a call-site id to every ASG node derived from it.
	callSiteIndex map[string][]string
}

// Extract derives the ASG candidate of one snapshot.
func (e *Extractor) Extract(ctx context.Context, snapshotID string) (*Document, error) {
	limits := e.Limits.WithDefaults()
	ctx, cancel := context.WithTimeout(ctx, limits.TotalTimeout)
	defer cancel()

	summary, err := e.SCG.ReadSummary(ctx, snapshotID)
	if err != nil {
		if errors.Is(err, ErrNoSCG) {
			return nil, fmt.Errorf("%w: %s", ErrNoSCG, snapshotID)
		}
		return nil, err
	}
	x := &extraction{
		doc: &Document{
			SchemaVersion: SchemaVersion,
			SnapshotID:    snapshotID,
			SCGVersion:    summary.GraphVersion,
			Engine:        Engine{Name: DefaultEngine.Name, Version: DefaultEngine.Version},
			RulesetHash:   e.RulesetHash(),
			Limitations:   []string{},
		},
		limits:    limits,
		nodes:     map[string]Node{},
		edges:     map[string]Edge{},
		symbols:   map[string]scg.Symbol{},
		files:     map[string]scg.File{},
		byCaller:  map[string][]scg.CallSite{},
		reachedBy: map[string]int{},
	}

	if err := x.load(ctx, e.SCG, snapshotID, limits); err != nil {
		return nil, err
	}
	x.addStructuralLimitations(summary)
	entryPoints := x.scan(ctx, e, snapshotID)
	x.walkReachability(ctx, e, snapshotID, entryPoints)
	x.attachReachabilityCounts()
	x.addProvenanceEdges()
	x.addProvenanceEdges()

	x.doc.Nodes = make([]Node, 0, len(x.nodes))
	x.doc.Nodes = append(x.doc.Nodes, mapValues(x.nodes)...)
	x.doc.Edges = make([]Edge, 0, len(x.edges))
	x.doc.Edges = append(x.doc.Edges, mapValues(x.edges)...)
	x.doc.normalize()
	x.doc.ASGVersion = Version(snapshotID, summary.GraphVersion, x.doc.Engine, x.doc.RulesetHash)
	x.doc.sortForDeterminism()
	if err := x.doc.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	return x.doc, nil
}

// load reads the SCG once and indexes it: symbols by id, files by id and call
// sites both in full and grouped by caller.
func (x *extraction) load(ctx context.Context, reader SCGReader, snapshotID string, limits Limits) error {
	files, err := reader.ReadFiles(ctx, snapshotID)
	if err != nil {
		return err
	}
	for _, f := range files {
		x.files[f.ID] = f
	}

	offset := 0
	for len(x.symbols) < limits.MaxSymbols {
		symbols, total, err := reader.ReadSymbols(ctx, snapshotID, offset, 1000)
		if err != nil {
			return err
		}
		for _, sym := range symbols {
			x.symbols[sym.ID] = sym
		}
		offset += len(symbols)
		if len(symbols) == 0 || offset >= total {
			break
		}
	}

	offset = 0
	for len(x.callSites) < limits.MaxCallSites {
		sites, total, err := reader.ReadCallSites(ctx, snapshotID, offset, 1000)
		if err != nil {
			return err
		}
		x.callSites = append(x.callSites, sites...)
		offset += len(sites)
		if len(sites) == 0 || offset >= total {
			break
		}
	}
	sort.Slice(x.callSites, func(i, j int) bool { return x.callSites[i].ID < x.callSites[j].ID })
	for _, cs := range x.callSites {
		if cs.CallerSymbolID != "" {
			x.byCaller[cs.CallerSymbolID] = append(x.byCaller[cs.CallerSymbolID], cs)
		}
	}
	x.doc.Coverage.CallSitesExamined = len(x.callSites)
	x.doc.Coverage.SymbolsExamined = len(x.symbols)
	x.doc.Coverage.ReachabilityDepth = limits.ReachDepth
	x.doc.Coverage.ReachabilityBudget = limits.ReachNodes
	return nil
}

// addStructuralLimitations records what this extraction cannot say. These apply
// to every ASG candidate, so they are always stated.
func (x *extraction) addStructuralLimitations(summary *scg.Summary) {
	x.doc.addLimitation("REACHES means call-graph reachability, not dataflow: no rule here establishes that data from an input reaches a sink")
	x.doc.addLimitation("the presence of a security control is not evidence that it is effective; PROTECTED_BY records registration or reachability only, and bypass branches are not analysed")
	x.doc.addLimitation("SUPPORTED_BY and VERIFIED_BY edges and Hypothesis nodes belong to the semantic-agent and verification phases; the P3 rule extractor does not emit them")
	x.doc.addLimitation("file content and environment sources are external input, not necessarily attacker-controlled; controllability is a question for a later phase")
	x.doc.addLimitation("the sensitive-output sink rule is name-based and can be wrong in both directions")
	x.doc.addLimitation("all extraction is name- and shape-based over the SCG: a call whose receiver type could not be resolved cannot be attributed to a framework or a sink with certainty")
	res := summary.Resolution
	if total := res.Total(); total > 0 {
		unresolved := total - res.Resolved - res.ResolvedBestEffort
		x.doc.addLimitation("the SCG this ASG was derived from left %d of %d call site(s) unresolved (%d external, %d dynamic); any sink or control reached only through those calls is invisible here",
			unresolved, total, res.External, res.Dynamic)
	}
	if summary.Coverage.FilesUnsupported > 0 {
		x.doc.addLimitation("%d file(s) of the snapshot have no SCG frontend and contribute no attack surface", summary.Coverage.FilesUnsupported)
	}
}

// --- node and edge construction ---------------------------------------------

// addNode stores a node once, merging evidence if the same fact is observed
// twice.
func (x *extraction) addNode(n Node) bool {
	if len(n.SCGRefs) == 0 || n.Generator == "" {
		return false
	}
	if existing, ok := x.nodes[n.ID]; ok {
		existing.SCGRefs = mergeRefs(existing.SCGRefs, n.SCGRefs)
		x.nodes[n.ID] = existing
		return true
	}
	if len(x.nodes) >= x.limits.MaxNodes {
		x.doc.Coverage.NodesSkipped++
		return false
	}
	n.SCGRefs = mergeRefs(nil, n.SCGRefs)
	x.nodes[n.ID] = n
	return true
}

// addEdge stores an edge once.
func (x *extraction) addEdge(e Edge) bool {
	if len(e.SCGRefs) == 0 || e.Generator == "" {
		return false
	}
	if _, ok := x.edges[e.ID]; ok {
		return true
	}
	if len(x.edges) >= x.limits.MaxEdges {
		x.doc.Coverage.EdgesSkipped++
		return false
	}
	x.edges[e.ID] = e
	return true
}

func mergeRefs(existing, add []string) []string {
	seen := make(map[string]bool, len(existing)+len(add))
	out := make([]string, 0, len(existing)+len(add))
	for _, ref := range append(append([]string{}, existing...), add...) {
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

func mapValues[T any](m map[string]T) []T {
	out := make([]T, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// --- scanning ---------------------------------------------------------------

// scan walks every call site once and records entry points, sources, sinks and
// controls. It returns the entry points for the reachability pass.
func (x *extraction) scan(ctx context.Context, e *Extractor, snapshotID string) []Node {
	var entryPoints []Node
	for i := range x.callSites {
		if i%256 == 0 && ctx.Err() != nil {
			x.doc.addLimitation("extraction stopped at its time budget after %d call site(s); the attack surface is incomplete", i)
			break
		}
		cs := x.callSites[i]
		file := x.files[cs.FileID]
		base := nodeBase(cs, file)

		if node, ok := x.entryPointFrom(e, cs, base); ok {
			if x.addNode(node) {
				entryPoints = append(entryPoints, node)
			}
		}
		x.sourceFrom(e, cs, base)
		x.sinkFrom(e, cs, base)
		x.controlFrom(e, cs, base)
	}
	sort.Slice(entryPoints, func(i, j int) bool { return entryPoints[i].ID < entryPoints[j].ID })
	return entryPoints
}

// nodeBase is the location and module a node reports.
func nodeBase(cs scg.CallSite, file scg.File) Node {
	return Node{ModuleID: file.ModuleID, File: cs.File, Line: cs.Line}
}

// entryPointFrom recognises a route, RPC, consumer or CLI registration.
func (x *extraction) entryPointFrom(e *Extractor, cs scg.CallSite, base Node) (Node, bool) {
	// CLI flags are entry points too: a flag value comes from the command line.
	if kind, label, ok := cliEntryPoint(cs); ok {
		node := base
		node.ID = NodeID(cs.SnapshotID, NodeEntryPoint, label, cs.ID)
		node.SnapshotID = cs.SnapshotID
		node.Kind = NodeEntryPoint
		node.Subject = label
		node.Detail = map[string]string{"entry_kind": kind, "source": "cli"}
		if kind == EntryCLICommand {
			node.Detail["boundary"] = BoundaryProcess
		}
		node.Evidence = StatusObserved
		node.Confidence = scg.Observed
		node.Generator = "entrypoint/cli"
		node.SCGRefs = []string{cs.ID}
		return node, true
	}

	// A message consumer is an entry point regardless of framework rules: the
	// broker delivers payloads an external producer controls.
	if isConsumerCall(cs) {
		method := calleeBase(cs.CalleeText)
		subject := fmt.Sprintf("%s:%s", EntryMessageConsumer, method)
		detail := map[string]string{
			"entry_kind": EntryMessageConsumer,
			"method":     method,
			"boundary":   BoundaryMessage,
			"rule_note":  "message consumers deliver payloads from an external producer; the subscription destination is not resolved here",
		}
		if destination := firstStringArg(cs.Args, 0); destination != "" {
			detail["destination"] = destination
			subject = fmt.Sprintf("%s:%s:%s", EntryMessageConsumer, method, destination)
		}
		node := base
		node.SnapshotID = cs.SnapshotID
		node.Kind = NodeEntryPoint
		node.Subject = subject
		node.Label = "consume " + method
		node.Detail = detail
		node.Evidence = StatusObserved
		node.Confidence = scg.Observed
		node.Generator = "entrypoint/consumer"
		node.SCGRefs = []string{cs.ID}
		if handler := handlerArg(cs.Args, -1); handler != nil {
			node.Detail["handler"] = handler.SymbolQualified
			node.Detail["handler_symbol_id"] = handler.SymbolID
			node.SCGRefs = append(node.SCGRefs, handler.SymbolID)
		}
		node.ID = NodeID(cs.SnapshotID, NodeEntryPoint, subject, cs.ID)
		return node, true
	}

	receiverFrom := cs.ReceiverFrom
	var strong []FrameworkRule
	var weak []FrameworkRule
	for _, rule := range e.Frameworks {
		if !rule.matchRoute(cs.CalleeText, receiverFrom) {
			continue
		}
		// A package-level registration function must also match its own shape.
		switch rule.attributes(receiverFrom, cs.CalleeQualified) {
		case attribConstructor, attribQualified:
			strong = append(strong, rule)
		default:
			// Route-shaped but unattributable: only accept it when the argument
			// list really looks like a route.
			if _, _, ok := routeFromArgs(cs.Args, rule.PathArgIndex); ok {
				weak = append(weak, rule)
			}
		}
	}
	if len(strong) == 0 && len(weak) == 0 {
		return Node{}, false
	}

	path, pathIdx, hasPath := "", -1, false
	rule := FrameworkRule{}
	switch {
	case len(strong) > 0:
		rule = strong[0]
		path, pathIdx, hasPath = routeFromArgs(cs.Args, rule.PathArgIndex)
	case len(weak) > 0:
		rule = weak[0]
		path, pathIdx, hasPath = routeFromArgs(cs.Args, weak[0].PathArgIndex)
	}
	if !hasPath && !rule.AllowPathless {
		// A registration call without a path-shaped literal is not a route we can
		// name; recording it would produce an entry point with no identity.
		return Node{}, false
	}
	entryKind := rule.EntryKind
	boundary := rule.Boundary
	method := calleeBase(cs.CalleeText)
	// Handle and HandleFunc register a handler for every method, so naming them
	// after the registration function would read as "HANDLEFUNC /health". ANY is
	// what the route actually accepts.
	httpMethod := strings.ToUpper(method)
	if !isHTTPVerb(httpMethod) {
		httpMethod = "ANY"
	}
	var subject, label string
	if hasPath {
		subject = fmt.Sprintf("%s:%s %s", entryKind, httpMethod, path)
		label = fmt.Sprintf("%s %s", httpMethod, path)
	} else {
		subject = fmt.Sprintf("%s:%s", entryKind, method)
		label = entryKind + " " + method
	}

	detail := map[string]string{
		"entry_kind": entryKind,
		"method":     method,
		"boundary":   boundary,
	}
	if hasPath {
		detail["path"] = path
		detail["path_arg"] = fmt.Sprint(pathIdx)
	} else {
		// A pathless registration is real (a gRPC service), but where it is
		// served from is not visible here, so no path is invented.
		detail["path"] = ""
		detail["rule_note"] = "registration-carried entry without a route path; the path, if any, is set elsewhere"
	}
	framework := rule.Name
	switch {
	case len(strong) == 1:
		detail["framework_attribution"] = "receiver provenance or resolved package"
	case len(strong) > 1:
		detail["framework_attribution"] = "ambiguous"
		detail["framework_candidates"] = joinRuleNames(strong)
		framework = strong[0].Name
	default:
		detail["framework_attribution"] = "unknown"
		detail["framework_candidates"] = joinRuleNames(weak)
		detail["framework"] = "unknown"
	}
	if len(strong) > 0 {
		detail["framework"] = framework
	}
	if rule.Note != "" {
		detail["rule_note"] = rule.Note
	}
	if receiverFrom != "" {
		detail["receiver_from"] = receiverFrom
	}

	node := base
	node.SnapshotID = cs.SnapshotID
	node.Kind = NodeEntryPoint
	node.Subject = subject
	node.Label = label
	node.Detail = detail
	node.Evidence = StatusObserved
	node.Confidence = scg.Observed
	node.Generator = "entrypoint/framework"
	node.SCGRefs = []string{cs.ID}

	// The handler is the resolved symbol argument, preferring the rule's index and
	// falling back to the last symbolic argument (middleware chains end with the
	// handler).
	handler := handlerArg(cs.Args, rule.HandlerArgIndex)
	if handler != nil {
		node.Detail["handler"] = handler.SymbolQualified
		node.Detail["handler_symbol_id"] = handler.SymbolID
		node.SCGRefs = append(node.SCGRefs, handler.SymbolID)
	} else {
		node.Detail["handler"] = "unresolved"
		x.doc.addLimitation("at least one entry point has no resolvable handler (a closure or a value produced elsewhere); its reachable sinks are unknown")
	}
	// Middleware registered on the same receiver in the same call chain is a
	// protection candidate for this route.
	if receiverFrom != "" {
		node.Detail["receiver"] = receiverBase(cs.CalleeText)
	}
	node.ID = NodeID(cs.SnapshotID, NodeEntryPoint, subject, cs.ID)
	return node, true
}

// cliEntryPoint recognises command-line input definitions.
func cliEntryPoint(cs scg.CallSite) (string, string, bool) {
	base := calleeBase(cs.CalleeText)
	if base != "String" && base != "StringVar" && base != "Int" && base != "IntVar" &&
		base != "Bool" && base != "BoolVar" && base != "Arg" && base != "Args" && base != "Parse" {
		return "", "", false
	}
	if !strings.Contains(cs.CalleeQualified, "flag.") && !strings.Contains(cs.CalleeText, "flag.") {
		return "", "", false
	}
	name := ""
	if len(cs.Args) > 1 && cs.Args[0].Kind == scg.ArgStringLiteral {
		name = cs.Args[0].StringValue
	}
	if name == "" {
		if len(cs.Args) > 0 && cs.Args[0].Kind == scg.ArgStringLiteral {
			name = cs.Args[0].StringValue
		}
	}
	if name == "" {
		name = base
	}
	return EntryCLICommand, "cli_command:" + name, true
}

// isConsumerCall reports whether the call consumes an external message stream.
func isConsumerCall(cs scg.CallSite) bool {
	for _, suffix := range []string{".Consume", ".ConsumePartition", ".Subscribe", ".ReceiveMessage", ".Poll"} {
		if strings.HasSuffix(cs.CalleeText, suffix) {
			return true
		}
	}
	return false
}

// routeFromArgs finds the route path among the arguments: the preferred index
// first, then any string literal that looks like a path.
func routeFromArgs(args []scg.ArgRef, preferred int) (string, int, bool) {
	if preferred >= 0 && preferred < len(args) {
		if args[preferred].Kind == scg.ArgStringLiteral && looksLikePath(args[preferred].StringValue) {
			return args[preferred].StringValue, preferred, true
		}
	}
	for i, arg := range args {
		if arg.Kind == scg.ArgStringLiteral && looksLikePath(arg.StringValue) {
			return arg.StringValue, i, true
		}
	}
	return "", -1, false
}

// isHTTPVerb reports whether a registration method names an HTTP method.
func isHTTPVerb(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return true
	default:
		return false
	}
}

// looksLikePath accepts the shapes a route path has: an absolute path, or a
// framework pattern containing a parameter or wildcard.
func looksLikePath(value string) bool {
	if value == "" || strings.Contains(value, "://") || strings.ContainsAny(value, " \t") {
		// A URL is a destination, not a route path, and a value with whitespace is
		// a sentence.
		return false
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "*") {
		return true
	}
	// A framework pattern without a leading slash, for example "users/:id": it has
	// a parameter or wildcard and no file-extension or host punctuation.
	return strings.ContainsAny(value, ":*") && !strings.ContainsAny(value, ".@?")
}

// handlerArg returns the argument that names the handler.
func handlerArg(args []scg.ArgRef, preferred int) *scg.ArgRef {
	if preferred >= 0 && preferred < len(args) {
		if args[preferred].Kind == scg.ArgSymbolRef {
			return &args[preferred]
		}
	}
	for i := len(args) - 1; i >= 0; i-- {
		if args[i].Kind == scg.ArgSymbolRef {
			return &args[i]
		}
	}
	return nil
}

// receiverBase returns the source text before the last dot.
func receiverBase(calleeText string) string {
	if i := strings.LastIndex(calleeText, "."); i > 0 {
		return calleeText[:i]
	}
	return ""
}

func joinRuleNames(rules []FrameworkRule) string {
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// sourceFrom records an attacker-controlled input.
func (x *extraction) sourceFrom(e *Extractor, cs scg.CallSite, base Node) {
	argTexts := argTextsOf(cs)
	for _, rule := range e.Sources {
		ok, reasons := rule.matches(cs.CalleeText, cs.CalleeQualified, argTexts)
		if !ok {
			continue
		}
		name := firstStringArg(cs.Args, 0)
		if name == "" {
			name = "unknown"
		}
		subject := fmt.Sprintf("input:%s:%s", rule.Kind, name)
		detail := map[string]string{
			"source_kind": rule.Kind,
			"name":        name,
			"rule":        describeRule(rule, reasons),
		}
		if rule.Note != "" {
			detail["rule_note"] = rule.Note
		}
		if cs.ReceiverFrom != "" {
			detail["receiver_from"] = cs.ReceiverFrom
		}
		node := base
		node.ID = NodeID(cs.SnapshotID, NodeAttackerControlledInput, subject, cs.ID)
		node.SnapshotID = cs.SnapshotID
		node.Kind = NodeAttackerControlledInput
		node.Subject = subject
		node.Label = fmt.Sprintf("%s %s", rule.Kind, name)
		node.Detail = detail
		node.Evidence = rule.Evidence
		node.Confidence = confidenceFor(rule)
		node.Generator = "source/" + rule.Kind
		node.SCGRefs = []string{cs.ID}
		x.addNode(node)
		return
	}
}

// sinkFrom records a sensitive operation, and derives an asset and a
// parameterisation control where a literal makes that justified.
func (x *extraction) sinkFrom(e *Extractor, cs scg.CallSite, base Node) {
	argTexts := argTextsOf(cs)
	for _, rule := range e.Sinks {
		ok, reasons := rule.matches(cs.CalleeText, cs.CalleeQualified, argTexts)
		if !ok {
			continue
		}
		literal, literalPos := firstStringLiteral(cs.Args)
		subject := "sink:" + rule.Kind
		detail := map[string]string{
			"sink_kind": rule.Kind,
			"rule":      describeRule(rule, reasons),
		}
		if rule.Note != "" {
			detail["rule_note"] = rule.Note
		}
		if literal != "" {
			detail["literal"] = truncate(literal, 200)
			detail["literal_arg"] = fmt.Sprint(literalPos)
		}
		node := base
		node.ID = NodeID(cs.SnapshotID, NodeSensitiveOperation, subject, cs.ID)
		node.SnapshotID = cs.SnapshotID
		node.Kind = NodeSensitiveOperation
		node.Subject = subject
		node.Label = rule.Kind + sinkLabel(literal)
		node.Detail = detail
		node.Evidence = rule.Evidence
		node.Confidence = confidenceFor(rule)
		node.Generator = "sink/" + rule.Kind
		node.SCGRefs = []string{cs.ID}
		if !x.addNode(node) {
			return
		}
		switch rule.Kind {
		case SinkSQL:
			if literal != "" {
				if parameterised(literal) {
					control := x.parameterizationControl(cs, base, literal)
					x.addEdge(x.relationEdge(EdgeProtectedBy, node.ID, control.ID,
						"parameterised statement observed at the sink", StatusInferred, scg.Inferred,
						"sink/parameterization", []string{cs.ID}))
				}
				for _, table := range sqlTables(literal) {
					asset := x.assetNode(cs, base, AssetTable, table, "sql literal")
					x.addEdge(x.relationEdge(EdgeMayAffect, node.ID, asset.ID,
						"the statement names this table", StatusInferred, scg.Inferred,
						"sink/asset", []string{cs.ID}))
				}
			}
		case SinkFileWrite:
			if literal != "" && looksLikePath(literal) {
				asset := x.assetNode(cs, base, AssetFile, literal, "filesystem literal")
				x.addEdge(x.relationEdge(EdgeMayAffect, node.ID, asset.ID,
					"the call names this path", StatusInferred, scg.Inferred,
					"sink/asset", []string{cs.ID}))
			}
		case SinkProcess:
			if literal != "" {
				asset := x.assetNode(cs, base, AssetCommand, literal, "process literal")
				x.addEdge(x.relationEdge(EdgeMayAffect, node.ID, asset.ID,
					"the call names this executable", StatusInferred, scg.Inferred,
					"sink/asset", []string{cs.ID}))
			}
		case SinkNetwork:
			if literal != "" && (strings.Contains(literal, "://") || strings.HasPrefix(literal, "/")) {
				asset := x.assetNode(cs, base, AssetEndpoint, literal, "network literal")
				x.addEdge(x.relationEdge(EdgeMayAffect, node.ID, asset.ID,
					"the request targets this endpoint", StatusInferred, scg.Inferred,
					"sink/asset", []string{cs.ID}))
			}
		}
		return
	}
}

// controlFrom records a security control.
func (x *extraction) controlFrom(e *Extractor, cs scg.CallSite, base Node) {
	argTexts := argTextsOf(cs)
	for _, rule := range e.Controls {
		ok, reasons := rule.matches(cs.CalleeText, cs.CalleeQualified, argTexts)
		if !ok {
			continue
		}
		pattern := rule.Kind + ":" + controlPattern(cs, rule)
		subject := "control:" + pattern
		id := NodeID(cs.SnapshotID, NodeSecurityControl, subject, "")
		if existing, ok := x.nodes[id]; ok {
			if count := existing.Detail["observations"]; count != "" && len(existing.SCGRefs) >= x.limits.MaxObservationsPerControl {
				// Keep counting observations without growing the evidence list.
				existing.Detail["observations"] = incrementCount(count)
				x.nodes[id] = existing
				return
			}
			existing.SCGRefs = mergeRefs(existing.SCGRefs, []string{cs.ID})
			if existing.Detail == nil {
				existing.Detail = map[string]string{}
			}
			existing.Detail["observations"] = incrementCount(existing.Detail["observations"])
			x.nodes[id] = existing
			return
		}
		detail := map[string]string{
			"control_kind":  rule.Kind,
			"pattern":       pattern,
			"observations":  "1",
			"rule":          describeRule(rule, reasons),
			"effectiveness": "not assessed: this records that the control is present",
		}
		if rule.Note != "" {
			detail["rule_note"] = rule.Note
		}
		node := base
		node.ID = id
		node.SnapshotID = cs.SnapshotID
		node.Kind = NodeSecurityControl
		node.Subject = subject
		node.Label = rule.Kind + " " + pattern
		node.Detail = detail
		node.Evidence = rule.Evidence
		node.Confidence = confidenceFor(rule)
		node.Generator = "control/" + rule.Kind
		node.SCGRefs = []string{cs.ID}
		x.addNode(node)
		return
	}
}

// parameterizationControl records the derived control that a statement is
// parameterised, which is a fact about the literal and nothing more.
func (x *extraction) parameterizationControl(cs scg.CallSite, base Node, literal string) Node {
	subject := "control:" + ControlParameterization + ":sql_placeholders"
	id := NodeID(cs.SnapshotID, NodeSecurityControl, subject, "")
	if existing, ok := x.nodes[id]; ok {
		existing.SCGRefs = mergeRefs(existing.SCGRefs, []string{cs.ID})
		x.nodes[id] = existing
		return existing
	}
	node := base
	node.ID = id
	node.SnapshotID = cs.SnapshotID
	node.Kind = NodeSecurityControl
	node.Subject = subject
	node.Label = "parameterization sql_placeholders"
	node.Detail = map[string]string{
		"control_kind":  ControlParameterization,
		"pattern":       "sql_placeholders",
		"effectiveness": "not assessed: a placeholder in the literal does not prove that the value is bound as a parameter",
		"example":       truncate(literal, 120),
	}
	node.Evidence = StatusInferred
	node.Confidence = scg.Inferred
	node.Generator = "control/parameterization"
	node.SCGRefs = []string{cs.ID}
	x.addNode(node)
	return node
}

// assetNode records something a sensitive operation acts on.
func (x *extraction) assetNode(cs scg.CallSite, base Node, kind, name, evidence string) Node {
	subject := fmt.Sprintf("asset:%s:%s", kind, name)
	id := NodeID(cs.SnapshotID, NodeAsset, subject, "")
	if existing, ok := x.nodes[id]; ok {
		existing.SCGRefs = mergeRefs(existing.SCGRefs, []string{cs.ID})
		x.nodes[id] = existing
		return existing
	}
	node := base
	node.ID = id
	node.SnapshotID = cs.SnapshotID
	node.Kind = NodeAsset
	node.Subject = subject
	node.Label = kind + " " + name
	node.Detail = map[string]string{"asset_kind": kind, "name": name, "evidence": evidence}
	node.Evidence = StatusInferred
	node.Confidence = scg.Inferred
	node.Generator = "asset/" + kind
	node.SCGRefs = []string{cs.ID}
	x.addNode(node)
	return node
}

// addProvenanceEdges records, for every node, the SCG facts it was derived from.
// It runs after the reachability pass so shared nodes (controls, boundaries,
// assets) have collected their evidence too.
func (x *extraction) addProvenanceEdges() {
	ids := make([]string, 0, len(x.nodes))
	for id := range x.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		x.addDerivedFrom(x.nodes[id])
	}
}

// --- edges ------------------------------------------------------------------

// relationEdge builds an edge between two ASG nodes.
func (x *extraction) relationEdge(kind EdgeKind, from, to, detail string, evidence EvidenceStatus, confidence scg.Confidence, generator string, refs []string) Edge {
	return Edge{
		ID:         EdgeID(x.doc.SnapshotID, kind, from, to, detail),
		SnapshotID: x.doc.SnapshotID,
		From:       from,
		To:         to,
		Kind:       kind,
		Evidence:   evidence,
		Confidence: confidence,
		Generator:  generator,
		Detail:     map[string]string{"reason": detail},
		SCGRefs:    refs,
	}
}

// addDerivedFrom records that a node came from SCG facts.
func (x *extraction) addDerivedFrom(n Node) {
	for _, ref := range n.SCGRefs {
		if !strings.HasPrefix(ref, "sym-") && !strings.HasPrefix(ref, "cs-") {
			continue
		}
		x.addEdge(Edge{
			ID:         EdgeID(x.doc.SnapshotID, EdgeDerivedFrom, n.ID, ref, ""),
			SnapshotID: x.doc.SnapshotID,
			From:       n.ID,
			To:         ref,
			Kind:       EdgeDerivedFrom,
			Evidence:   StatusObserved,
			Confidence: scg.Observed,
			Generator:  "provenance/derived_from",
			Detail:     map[string]string{"reason": "the node was read from this SCG fact"},
			SCGRefs:    []string{ref},
		})
	}
}

// --- reachability -----------------------------------------------------------

// walkReachability links entry points to the inputs, controls and sinks their
// handler can reach through the call graph, and to the trust boundary they cross.
func (x *extraction) walkReachability(ctx context.Context, e *Extractor, snapshotID string, entryPoints []Node) {
	walked := 0
	for _, entry := range entryPoints {
		// Every entry point crosses exactly one boundary, and that is observed:
		// the kind of the entry point determines the boundary.
		boundaryKind := entry.Detail["boundary"]
		if boundaryKind == "" {
			boundaryKind = BoundaryNetwork
		}
		boundary := x.boundaryNode(snapshotID, boundaryKind)
		x.addEdge(x.relationEdge(EdgeCrosses, entry.ID, boundary.ID,
			"control enters the process here", StatusObserved, scg.Observed,
			"entrypoint/boundary", []string{firstRef(entry.SCGRefs)}))

		handler := entry.Detail["handler_symbol_id"]
		if handler == "" {
			continue
		}
		if walked >= x.limits.MaxEntryPoints {
			x.doc.addLimitation("reachability was walked for the first %d entry points; %d more were not walked, so their sinks are unknown",
				x.limits.MaxEntryPoints, len(entryPoints)-walked)
			break
		}
		walked++

		visited := map[string]bool{handler: true}
		truncated := false
		reachable, cut, err := e.SCG.ReadCallees(ctx, snapshotID, handler, x.limits.ReachDepth, x.limits.ReachNodes)
		if err != nil {
			x.doc.addLimitation("reachability for at least one entry point failed: %v", err)
			continue
		}
		for _, sym := range reachable {
			visited[sym.ID] = true
		}
		if cut {
			truncated = true
			x.doc.Coverage.EntryPointsTruncated++
		}

		// Middleware registered on the same receiver before the route is the
		// observed form of protection; anything reachable from the handler is the
		// inferred form.
		observedControls := x.middlewareControls(snapshotID, entry)
		for _, control := range observedControls {
			x.addEdge(x.relationEdge(EdgeProtectedBy, entry.ID, control.ID,
				"middleware registered on the same receiver", StatusObserved, scg.Observed,
				"entrypoint/middleware", []string{firstRef(entry.SCGRefs)}))
		}

		sinks, inputs := 0, 0
		symbolIDs := make([]string, 0, len(visited))
		for id := range visited {
			symbolIDs = append(symbolIDs, id)
		}
		sort.Strings(symbolIDs)
		for _, symbolID := range symbolIDs {
			for _, cs := range x.byCaller[symbolID] {
				for _, nodeID := range x.nodeIDsForCallSite(cs) {
					node := x.nodes[nodeID]
					switch node.Kind {
					case NodeSensitiveOperation:
						if sinks >= x.limits.MaxSinksPerEntry {
							x.doc.Coverage.EdgesSkipped++
							continue
						}
						if x.addEdge(x.relationEdge(EdgeReaches, entry.ID, node.ID,
							"the handler reaches this operation through the call graph", StatusInferred, scg.Inferred,
							"reachability/call_graph", []string{nodeID})) {
							sinks++
							x.reachedBy[node.ID]++
						}
					case NodeAttackerControlledInput:
						if x.addEdge(x.relationEdge(EdgeReaches, entry.ID, node.ID,
							"the handler reads this input", StatusInferred, scg.Inferred,
							"reachability/call_graph", []string{nodeID})) {
							inputs++
							x.reachedBy[node.ID]++
						}
					case NodeSecurityControl:
						if x.addEdge(x.relationEdge(EdgeProtectedBy, entry.ID, node.ID,
							"a control is reachable from the handler; whether it guards this entry point is not established", StatusInferred, scg.Inferred,
							"reachability/call_graph", []string{nodeID})) {
							x.reachedBy[node.ID]++
						}
					}
				}
			}
		}
		entry := entry
		entry.Detail = cloneDetail(entry.Detail)
		entry.Detail["reachable_sinks"] = fmt.Sprint(sinks)
		entry.Detail["reachable_inputs"] = fmt.Sprint(inputs)
		if truncated {
			entry.Detail["reachability_truncated"] = "true"
		}
		x.nodes[entry.ID] = entry
		if sinks == 0 {
			x.doc.addLimitation("at least one entry point has no reachable sensitive operation within %d call levels; that is not evidence that none exists", x.limits.ReachDepth)
		}
	}
}

// middlewareControls finds controls registered on the entry point's receiver
// before the route registration in the same file.
func (x *extraction) middlewareControls(snapshotID string, entry Node) []Node {
	receiver := entry.Detail["receiver"]
	if receiver == "" {
		return nil
	}
	var out []Node
	for _, cs := range x.callSites {
		if cs.File != entry.File || cs.Line >= entry.Line {
			continue
		}
		if receiverBase(cs.CalleeText) != receiver {
			continue
		}
		// Only wrapper registrations are interesting here: a call that merely
		// mentions auth is a control observation, not a middleware registration.
		if !isMiddlewareRegistration(calleeBase(cs.CalleeText)) {
			continue
		}
		for _, id := range x.nodeIDsForCallSite(cs) {
			if node, ok := x.nodes[id]; ok && node.Kind == NodeSecurityControl {
				out = append(out, node)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// isMiddlewareRegistration reports whether a call registers middleware on a
// receiver rather than performing a check inline.
func isMiddlewareRegistration(method string) bool {
	switch method {
	case "Use", "Pre", "Middleware", "Wrap", "UseFunc":
		return true
	default:
		return false
	}
}

// boundaryNode returns the shared trust-boundary node of one kind.
func (x *extraction) boundaryNode(snapshotID, kind string) Node {
	subject := "boundary:" + kind
	id := NodeID(snapshotID, NodeTrustBoundary, subject, "")
	if existing, ok := x.nodes[id]; ok {
		return existing
	}
	node := Node{
		ID:         id,
		SnapshotID: snapshotID,
		Kind:       NodeTrustBoundary,
		Subject:    subject,
		Label:      kind + " boundary",
		Detail:     map[string]string{"boundary_kind": kind},
		Evidence:   StatusObserved,
		Confidence: scg.Observed,
		Generator:  "boundary/entry_kind",
		SCGRefs:    []string{},
	}
	// The boundary is derived from the entry points of that kind; refs are added
	// when the first entry point crosses it.
	x.nodes[id] = node
	return node
}

// attachReachabilityCounts records how many entry points reach each node, which
// is what makes "this sink is not reachable from any entry point" checkable.
func (x *extraction) attachReachabilityCounts() {
	for id, count := range x.reachedBy {
		node, ok := x.nodes[id]
		if !ok {
			continue
		}
		node.Detail = cloneDetail(node.Detail)
		node.Detail["reachable_entry_points"] = fmt.Sprint(count)
		// The boundary nodes are referenced by the entry points that cross them;
		// they need at least one SCG ref to satisfy the evidence rule.
		x.nodes[id] = node
	}
	// Boundary nodes exist to be crossed, so they take their evidence from the
	// CROSSES edges that point at them.
	for id, node := range x.nodes {
		if node.Kind != NodeTrustBoundary || len(node.SCGRefs) > 0 {
			continue
		}
		var refs []string
		for _, edge := range x.edges {
			if edge.Kind == EdgeCrosses && edge.To == id {
				refs = mergeRefs(refs, edge.SCGRefs)
			}
		}
		node.SCGRefs = refs
		x.nodes[id] = node
	}
}

// nodeIDsForCallSite maps a call site to every ASG node derived from it. One
// call can be several facts at once: a database call is a sensitive operation,
// and the same call can also be a source when its argument carries the statement.
// The index is built once, in id order, so the result does not depend on map
// iteration.
func (x *extraction) nodeIDsForCallSite(cs scg.CallSite) []string {
	if x.callSiteIndex == nil {
		x.callSiteIndex = map[string][]string{}
		ids := make([]string, 0, len(x.nodes))
		for id := range x.nodes {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			for _, ref := range x.nodes[id].SCGRefs {
				if strings.HasPrefix(ref, "cs-") {
					x.callSiteIndex[ref] = append(x.callSiteIndex[ref], id)
				}
			}
		}
		for ref, list := range x.callSiteIndex {
			sort.Strings(list)
			x.callSiteIndex[ref] = list
		}
	}
	return x.callSiteIndex[cs.ID]
}

func firstRef(refs []string) string {
	if len(refs) == 0 {
		return ""
	}
	return refs[0]
}

func firstStringArg(args []scg.ArgRef, from int) string {
	for i := from; i < len(args); i++ {
		if args[i].Kind == scg.ArgStringLiteral && args[i].StringValue != "" {
			return args[i].StringValue
		}
	}
	return ""
}

func firstStringLiteral(args []scg.ArgRef) (string, int) {
	for i, arg := range args {
		if arg.Kind == scg.ArgStringLiteral && arg.StringValue != "" {
			return arg.StringValue, i
		}
	}
	return "", -1
}

func argTextsOf(cs scg.CallSite) []string {
	out := make([]string, 0, len(cs.Args))
	for _, arg := range cs.Args {
		if arg.Text != "" {
			out = append(out, arg.Text)
		}
		if arg.SymbolQualified != "" {
			out = append(out, arg.SymbolQualified)
		}
	}
	return out
}

func describeRule(rule MatchRule, reasons []string) string {
	out := rule.Kind
	if len(reasons) > 0 {
		out += " (" + strings.Join(reasons, "; ") + ")"
	}
	return out
}

func confidenceFor(rule MatchRule) scg.Confidence {
	if rule.Heuristic {
		return scg.Inferred
	}
	if rule.Evidence == StatusInferred {
		return scg.Inferred
	}
	return scg.Observed
}

func controlPattern(cs scg.CallSite, rule MatchRule) string {
	if name := firstStringArg(cs.Args, 0); name != "" {
		return name
	}
	return calleeBase(cs.CalleeText)
}

func incrementCount(value string) string {
	n := 0
	fmt.Sscanf(value, "%d", &n)
	return fmt.Sprint(n + 1)
}

func cloneDetail(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sinkLabel(literal string) string {
	if literal == "" {
		return ""
	}
	return " " + truncate(strings.Fields(literal)[0], 40)
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

var sqlTablePattern = regexp.MustCompile(`(?i)\b(?:from|into|update|join)\s+([a-zA-Z_][\w.]*)`)

// sqlTables extracts table names from a statement literal. It is deliberately
// naive: the result is an inferred asset, not a schema fact.
func sqlTables(literal string) []string {
	matches := sqlTablePattern.FindAllStringSubmatch(literal, 4)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		name := strings.Trim(m[1], `"`+"`")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// parameterised reports whether a statement literal uses placeholders.
func parameterised(literal string) bool {
	if strings.Contains(literal, "?") {
		return true
	}
	return regexp.MustCompile(`\$\d+`).MatchString(literal)
}
