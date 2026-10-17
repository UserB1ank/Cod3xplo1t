package path

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
)

// PathKind is the only kind P4 produces: a path over the call graph. Dataflow
// paths and verification plans are later phases with their own kinds.
const PathKindCallGraph = "call_graph_reachability"

// Engine derives candidate audit paths from one attack surface.
type Engine struct {
	ASG ASGReader
	SCG SCGReader
	Now func() time.Time
}

// NewEngine builds a path engine over the two readers.
func NewEngine(asgReader ASGReader, scgReader SCGReader) *Engine {
	return &Engine{ASG: asgReader, SCG: scgReader, Now: func() time.Time { return time.Now().UTC() }}
}

func (e *Engine) now() time.Time {
	if e.Now == nil {
		return time.Now().UTC()
	}
	return e.Now()
}

// GenerateOptions configures one generation run.
type GenerateOptions struct {
	// Scope selects entries/sinks by repository-relative file prefix. Calls may
	// cross that prefix; it is a seed selection, not an execution sandbox.
	Scope []string
	// AuditID scopes the produced path ids.
	AuditID string
	Budget  Budget
	Limits  Limits
	// Sensitivity maps a lowercased asset or subject substring to the business
	// sensitivity feature (B). It exists because business value cannot be read out
	// of source code; without an entry the engine uses a documented neutral prior.
	Sensitivity map[string]float64
	// AlreadyCovered lists attack-surface nodes already scheduled by earlier
	// audits of this snapshot. It feeds novelty and the duplicate discount.
	AlreadyCovered []string
}

// GenerateResult is one generation run.
type GenerateResult struct {
	SnapshotID  string
	SCGVersion  string
	ASGVersion  string
	Paths       []Path
	Coverage    Coverage
	Limitations []string
}

// entryFacts is one entry point with everything the attack surface says about it.
type entryFacts struct {
	entry     ASGNode
	boundary  *ASGNode
	controls  []ASGNode
	inputs    []ASGNode
	sinks     []ASGNode
	assets    map[string][]ASGNode
	reachEdge map[string]ASGEdge
	truncated bool
}

// Generate enumerates candidate paths (implementation guide §8.1).
//
// The enumeration is bounded at every step and every bound it hits is recorded:
// a short path list must never be readable as "no vulnerability". Two pieces of
// evidence are kept apart on purpose — the ASG reachability edge says the sink is
// reachable from the entry point, the SCG call chain says how the calls connect.
// Neither says that data flows, and no path produced here claims it.
func (e *Engine) Generate(ctx context.Context, snapshotID string, opts GenerateOptions) (*GenerateResult, error) {
	budget := opts.Budget.Normalize()
	limits := opts.Limits.Normalize()
	facts, err := e.ASG.ASGFacts(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	if facts == nil || facts.ASGVersion == "" {
		return nil, fmt.Errorf("%w: %s", ErrNoASG, snapshotID)
	}
	result := &GenerateResult{
		SnapshotID:  snapshotID,
		SCGVersion:  facts.SCGVersion,
		ASGVersion:  facts.ASGVersion,
		Coverage:    Coverage{ChainQueryBudget: limits.ChainQueryBudget},
		Limitations: []string{},
	}
	if facts.Truncated {
		result.Coverage.Truncated = true
		result.Coverage.TruncationReasons = append(result.Coverage.TruncationReasons, facts.TruncationReasons...)
	}
	result.Limitations = append(result.Limitations, facts.Limitations...)
	result.Limitations = append(result.Limitations,
		"a candidate path is call-graph reachability plus the resolved call chain; data propagation from the input to the sink is not established in this phase",
		"path_status describes how much static evidence supports the path, not the likelihood that a vulnerability exists",
		"a security control on a path is recorded as present; its effectiveness is never established by this phase")

	entries, skipped := groupEntries(facts, limits.MaxEntries)
	result.Coverage.EntryPointsSkipped = skipped
	if skipped > 0 {
		result.Coverage.Truncated = true
		result.Coverage.TruncationReasons = append(result.Coverage.TruncationReasons,
			fmt.Sprintf("%d entry point(s) beyond the limit of %d were not enumerated", skipped, limits.MaxEntries))
	}

	covered := map[string]bool{}
	for _, id := range opts.AlreadyCovered {
		covered[id] = true
	}

	var candidates []Path
	chainBudget := limits.ChainQueryBudget
	symbolCache := map[string]SymbolFact{}
	callerCache := map[string]SymbolFact{}
	for _, ef := range entries {
		result.Coverage.EntryPointsExamined++
		if ctx.Err() != nil {
			result.Coverage.Truncated = true
			result.Coverage.TruncationReasons = append(result.Coverage.TruncationReasons, "generation stopped at its deadline")
			break
		}
		sinks := append([]ASGNode(nil), ef.sinks...)
		sort.Slice(sinks, func(i, j int) bool {
			ii, ij := sinkImpact(sinks[i]), sinkImpact(sinks[j])
			if ii != ij {
				return ii > ij
			}
			return sinks[i].ID < sinks[j].ID
		})
		if len(sinks) > limits.MaxSinksPerEntry {
			result.Coverage.SinksSkipped += len(sinks) - limits.MaxSinksPerEntry
			result.Coverage.Truncated = true
			result.Coverage.TruncationReasons = append(result.Coverage.TruncationReasons,
				fmt.Sprintf("entry %s: %d reachable sensitive operation(s) beyond the limit of %d were not enumerated",
					ef.entry.Subject, len(sinks)-limits.MaxSinksPerEntry, limits.MaxSinksPerEntry))
			sinks = sinks[:limits.MaxSinksPerEntry]
		}
		handler := ef.entry.Detail["handler_symbol_id"]
		for _, sink := range sinks {
			if len(opts.Scope) > 0 && !InScope(ef.entry.File, opts.Scope) && !InScope(sink.File, opts.Scope) {
				continue
			}
			result.Coverage.SinksExamined++
			caller, callerKnown := resolveSinkCaller(ctx, e, snapshotID, sink, callerCache)
			chains, unresolved, exhausted := e.chainsFor(ctx, snapshotID, handler, caller, callerKnown, budget, limits, &chainBudget)
			if exhausted {
				result.Coverage.Truncated = true
				result.Coverage.TruncationReasons = append(result.Coverage.TruncationReasons,
					fmt.Sprintf("the chain query budget of %d was exhausted; later entry points are incomplete", limits.ChainQueryBudget))
			}
			if len(chains) == 0 {
				// No chain: keep the reachability statement, and say why the chain is
				// missing instead of pretending it is short.
				status := PathCandidate
				if handler == "" || unresolved || exhausted {
					status = PathUnresolved
				}
				result.Coverage.ChainsUnresolved++
				candidates = append(candidates, e.buildPath(snapshotID, facts, ef, sink, nil, status, budget, limits, opts, covered, symbolCache,
					chainReason(handler, callerKnown, unresolved, exhausted)))
				continue
			}
			result.Coverage.ChainsResolved++
			for _, chain := range chains {
				status := PathStaticallySupported
				if !chain.Resolved() || sink.Evidence != string(asg.StatusObserved) {
					status = PathCandidate
				}
				if ef.truncated {
					status = PathUnresolved
				}
				candidates = append(candidates, e.buildPath(snapshotID, facts, ef, sink, &chain, status, budget, limits, opts, covered, symbolCache, ""))
			}
		}
	}

	kept, duplicates := Deduplicate(candidates)
	result.Coverage.PathsConsidered = len(candidates)
	result.Coverage.DuplicatePaths = duplicates
	if len(kept) > limits.MaxPaths {
		result.Coverage.PathsSkipped = len(kept) - limits.MaxPaths
		result.Coverage.Truncated = true
		result.Coverage.TruncationReasons = append(result.Coverage.TruncationReasons,
			fmt.Sprintf("%d path(s) beyond the limit of %d were dropped", len(kept)-limits.MaxPaths, limits.MaxPaths))
		kept = kept[:limits.MaxPaths]
	}
	result.Paths = kept
	result.Coverage.PathsEmitted = len(kept)
	if result.Coverage.Truncated {
		result.Limitations = append(result.Limitations,
			"generation was truncated: "+strings.Join(result.Coverage.TruncationReasons, "; "))
	}
	return result, nil
}

// groupEntries indexes the attack surface by entry point. The result is sorted by
// entry id so generation is reproducible.
func groupEntries(facts *ASGFacts, maxEntries int) ([]entryFacts, int) {
	byFrom := map[string][]ASGEdge{}
	for _, edge := range facts.Edges {
		byFrom[edge.From] = append(byFrom[edge.From], edge)
	}
	assetsBySink := map[string][]ASGNode{}
	for _, edge := range facts.Edges {
		if edge.Kind != string(asg.EdgeMayAffect) {
			continue
		}
		if node, ok := facts.Nodes[edge.To]; ok {
			assetsBySink[edge.From] = append(assetsBySink[edge.From], node)
		}
	}
	var entryIDs []string
	for id, node := range facts.Nodes {
		if node.Kind == string(asg.NodeEntryPoint) {
			entryIDs = append(entryIDs, id)
		}
	}
	sort.Strings(entryIDs)
	skipped := 0
	if maxEntries > 0 && len(entryIDs) > maxEntries {
		skipped = len(entryIDs) - maxEntries
		entryIDs = entryIDs[:maxEntries]
	}
	out := make([]entryFacts, 0, len(entryIDs))
	for _, id := range entryIDs {
		ef := entryFacts{entry: facts.Nodes[id], assets: map[string][]ASGNode{}, reachEdge: map[string]ASGEdge{}}
		for _, edge := range byFrom[id] {
			target, ok := facts.Nodes[edge.To]
			if !ok {
				continue
			}
			switch edge.Kind {
			case string(asg.EdgeCrosses):
				node := target
				ef.boundary = &node
			case string(asg.EdgeProtectedBy):
				ef.controls = append(ef.controls, target)
			case string(asg.EdgeReaches):
				ef.reachEdge[target.ID] = edge
				switch target.Kind {
				case string(asg.NodeSensitiveOperation):
					ef.sinks = append(ef.sinks, target)
				case string(asg.NodeAttackerControlledInput):
					ef.inputs = append(ef.inputs, target)
				case string(asg.NodeSecurityControl):
					ef.controls = append(ef.controls, target)
				}
			}
		}
		for _, sink := range ef.sinks {
			ef.assets[sink.ID] = assetsBySink[sink.ID]
		}
		ef.truncated = ef.entry.Detail["reachability_truncated"] == "true"
		sortNodes(ef.inputs)
		sortNodes(ef.controls)
		out = append(out, ef)
	}
	return out, skipped
}

// resolveSinkCaller finds the symbol that contains the sink's call site, which is
// where a chain has to end.
func resolveSinkCaller(ctx context.Context, e *Engine, snapshotID string, sink ASGNode, cache map[string]SymbolFact) (SymbolFact, bool) {
	for _, ref := range sink.SCGRefs {
		if !strings.HasPrefix(ref, "cs-") {
			continue
		}
		if cached, ok := cache[ref]; ok {
			return cached, cached.ID != ""
		}
		caller, ok, err := e.SCG.CallSiteCaller(ctx, snapshotID, ref)
		if err != nil || !ok {
			cache[ref] = SymbolFact{}
			continue
		}
		cache[ref] = caller
		return caller, true
	}
	return SymbolFact{}, false
}

// chainsFor resolves the call chain behind one reachability edge. The zero-hop
// case is real and common: the sink sits in the handler itself.
func (e *Engine) chainsFor(ctx context.Context, snapshotID, handler string, caller SymbolFact, callerKnown bool, budget Budget, limits Limits, remaining *int) ([]CallChain, bool, bool) {
	if handler == "" || !callerKnown {
		return nil, true, false
	}
	if handler == caller.ID {
		return []CallChain{{Symbols: []SymbolFact{caller}}}, false, false
	}
	if *remaining <= 0 {
		return nil, true, true
	}
	*remaining--
	chains, err := e.SCG.Chains(ctx, snapshotID, handler, caller.ID, budget.MaxDepth, limits.MaxChainsPerPair)
	if err != nil || len(chains) == 0 {
		return nil, true, *remaining <= 0
	}
	out := make([]CallChain, 0, len(chains))
	for _, chain := range chains {
		if len(chain.Hops) == 0 {
			continue
		}
		out = append(out, chain)
	}
	if len(out) == 0 {
		return nil, true, false
	}
	return out, false, false
}

// chainReason explains why a path has no resolved chain.
func chainReason(handler string, callerKnown, unresolved, exhausted bool) string {
	switch {
	case handler == "":
		return "the entry point has no resolved handler symbol, so no call chain can be shown"
	case exhausted:
		return "the chain query budget was exhausted before this chain was resolved"
	case !callerKnown:
		return "the symbol containing the sensitive call could not be resolved"
	case unresolved:
		return "no observed call chain connects the handler to the sensitive call within the path budget"
	default:
		return "no call chain was resolved"
	}
}

// buildPath assembles one AuditPath from the attack-surface facts, the resolved
// chain and the rules that describe why it is worth auditing.
func (e *Engine) buildPath(snapshotID string, facts *ASGFacts, ef entryFacts, sink ASGNode, chain *CallChain, status PathStatus,
	budget Budget, limits Limits, opts GenerateOptions, covered map[string]bool, symbols map[string]SymbolFact, noChainReason string) Path {

	now := NowString(e.now())
	steps := make([]Step, 0, 8)
	if ef.boundary != nil {
		steps = append(steps, Step{Layer: "asg", From: ef.entry.ID, To: ef.boundary.ID, Kind: string(asg.EdgeCrosses),
			Subject: ef.boundary.Subject, Evidence: ef.boundary.Evidence})
	}
	for _, input := range ef.inputs {
		if edge, ok := ef.reachEdge[input.ID]; ok {
			steps = append(steps, Step{Layer: "asg", From: edge.From, To: edge.To, Kind: edge.Kind,
				Subject: input.Subject, File: input.File, Line: input.Line, Evidence: edge.Evidence, Confidence: edge.Confidence})
		}
	}
	if chain != nil {
		for i, hop := range chain.Hops {
			step := Step{Layer: "scg", From: hop.From, To: hop.To, Kind: nonEmpty(hop.Kind, "CALLS"),
				File: hop.File, Line: hop.Line, Resolution: hop.Resolution}
			if i < len(chain.Symbols)-1 {
				step.Subject = chain.Symbols[i+1].QualifiedName
			}
			steps = append(steps, step)
		}
	}
	if edge, ok := ef.reachEdge[sink.ID]; ok {
		steps = append(steps, Step{Layer: "asg", From: edge.From, To: edge.To, Kind: edge.Kind,
			Subject: sink.Subject, File: sink.File, Line: sink.Line, Evidence: edge.Evidence, Confidence: edge.Confidence})
	}
	for _, control := range ef.controls {
		edges := controlEdges(facts, ef.entry.ID, control.ID)
		evidence := control.Evidence
		if len(edges) > 0 {
			evidence = edges[0].Evidence
		}
		steps = append(steps, Step{Layer: "asg", From: ef.entry.ID, To: control.ID, Kind: string(asg.EdgeProtectedBy),
			Subject: control.Subject, File: control.File, Line: control.Line, Evidence: evidence})
	}
	for _, asset := range ef.assets[sink.ID] {
		steps = append(steps, Step{Layer: "asg", From: sink.ID, To: asset.ID, Kind: string(asg.EdgeMayAffect),
			Subject: asset.Subject, Evidence: asset.Evidence})
	}

	asgRefs := []string{ef.entry.ID, sink.ID}
	if ef.boundary != nil {
		asgRefs = append(asgRefs, ef.boundary.ID)
	}
	scgRefs := []string{}
	if chain != nil {
		for _, sym := range chain.Symbols {
			scgRefs = append(scgRefs, sym.ID)
		}
		for _, hop := range chain.Hops {
			if hop.EdgeID != "" {
				scgRefs = append(scgRefs, hop.EdgeID)
			}
		}
	}
	scgRefs = append(scgRefs, sink.SCGRefs...)

	inputKinds := map[string]bool{}
	for _, input := range ef.inputs {
		asgRefs = append(asgRefs, input.ID)
		inputKinds[input.Detail["source_kind"]] = true
	}
	controlSubjects := []string{}
	observedControls := 0
	for _, control := range ef.controls {
		asgRefs = append(asgRefs, control.ID)
		controlSubjects = append(controlSubjects, control.Subject)
		if control.Evidence == string(asg.StatusObserved) && control.Detail["control_kind"] != "parameterization" {
			observedControls++
		}
	}
	assets := []string{}
	for _, asset := range ef.assets[sink.ID] {
		asgRefs = append(asgRefs, asset.ID)
		assets = append(assets, asset.Subject)
	}
	boundaries := []string{}
	if ef.boundary != nil {
		boundaries = append(boundaries, ef.boundary.Detail["boundary_kind"])
	}

	kind := PathKindCallGraph
	canonical := canonicalEdgesOf(steps)
	p := Path{
		AuditID:       opts.AuditID,
		SnapshotID:    snapshotID,
		SCGVersion:    facts.SCGVersion,
		ASGVersion:    facts.ASGVersion,
		EntryNodeID:   ef.entry.ID,
		EntryKind:     ef.entry.Detail["entry_kind"],
		EntrySubject:  ef.entry.Subject,
		TargetNodeID:  sink.ID,
		TargetSubject: sink.Subject,
		TargetKind:    sink.Kind,
		PathKind:      kind,
		PathStatus:    status,
		Status:        StatusDiscovered,
		Steps:         steps,
		Signature:     Signature(snapshotID, ef.entry.ID, sink.ID, kind, canonical),
		SCGRefs:       uniqueStrings(scgRefs),
		ASGRefs:       uniqueStrings(asgRefs),
		Boundaries:    uniqueStrings(boundaries),
		Controls:      uniqueStrings(controlSubjects),
		Inputs:        inputSubjects(ef.inputs),
		Assets:        uniqueStrings(assets),
		Objectives:    objectives(sink, inputKinds, observedControls, len(ef.controls)),
		OpenQuestions: openQuestions(ef, sink, status, noChainReason),
		Limitations:   pathLimitations(status, ef.truncated, noChainReason),
		Depth:         chainDepth(chain),
		Budget:        budget,
		MaxAttempts:   limits.MaxAttempts,
		CreatedAt:     now,
		UpdatedAt:     now,
		Version:       1,
	}
	if chain != nil {
		p.BranchCount = maxInt(0, len(chain.Symbols)-2)
	}
	p.ID = PathID(opts.AuditID, snapshotID, ef.entry.ID, sink.ID, canonical, kind)
	return p
}

// sinkImpact ranks sinks for enumeration; it mirrors the impact feature and is
// deliberately a table, not a model.
func sinkImpact(node ASGNode) float64 { return impactFor(node.Subject) }

// controlEdges returns the PROTECTED_BY edges that point at a control.
func controlEdges(facts *ASGFacts, entryID, controlID string) []ASGEdge {
	var out []ASGEdge
	for _, edge := range facts.Edges {
		if edge.Kind == string(asg.EdgeProtectedBy) && edge.From == entryID && edge.To == controlID {
			out = append(out, edge)
		}
	}
	return out
}

func canonicalEdgesOf(steps []Step) []string {
	out := make([]string, 0, len(steps))
	for _, step := range steps {
		if step.Kind == "" {
			continue
		}
		out = append(out, step.Layer+":"+step.From+"->"+step.To+":"+step.Kind)
	}
	return out
}

func chainDepth(chain *CallChain) int {
	if chain == nil {
		return 0
	}
	return chain.Depth()
}

func inputSubjects(inputs []ASGNode) []string {
	out := make([]string, 0, len(inputs))
	for _, input := range inputs {
		out = append(out, input.Subject)
	}
	return uniqueStrings(out)
}

// objectives derives the security goals of a path from its sink and its controls.
// It is a mapping from sink kind to goal, not a claim about exploitability.
func objectives(sink ASGNode, inputKinds map[string]bool, observedControls, totalControls int) []string {
	var out []string
	kind := strings.TrimPrefix(sink.Subject, "sink:")
	switch kind {
	case string(asg.SinkSQL):
		out = append(out, "sql_injection")
	case string(asg.SinkProcess):
		out = append(out, "command_injection")
	case string(asg.SinkNetwork):
		out = append(out, "server_side_request_forgery")
	case string(asg.SinkDeserialization):
		out = append(out, "unsafe_deserialization")
	case string(asg.SinkSensitiveOutput):
		out = append(out, "sensitive_data_exposure")
	case string(asg.SinkFileWrite):
		out = append(out, "arbitrary_file_write")
		if inputKinds["path_param"] || inputKinds["file_content"] || inputKinds["query_param"] {
			out = append(out, "path_traversal")
		}
	}
	if totalControls == 0 {
		out = append(out, "missing_security_control")
	} else if observedControls == 0 {
		out = append(out, "unverified_security_control")
	}
	sort.Strings(out)
	return out
}

// openQuestions are the questions the path hands to the audit phase. They are the
// reason a path exists: they must be answerable by evidence, not by opinion.
func openQuestions(ef entryFacts, sink ASGNode, status PathStatus, noChainReason string) []string {
	out := []string{}
	for _, input := range ef.inputs {
		out = append(out, fmt.Sprintf("does %s reach %s? no dataflow analysis exists in this phase, so this needs a slice and an agent or solver",
			input.Subject, sink.Subject))
	}
	if len(ef.inputs) == 0 {
		out = append(out, fmt.Sprintf("no attacker-controlled input was found on this entry point; confirm whether %s can be reached with external data", sink.Subject))
	}
	for _, control := range ef.controls {
		out = append(out, fmt.Sprintf("is %s effective on this path? its presence is recorded, its behaviour is not analysed", control.Subject))
	}
	if len(ef.controls) == 0 {
		out = append(out, "no security control was observed on this path; confirm whether one is applied outside the analysed call chain")
	}
	if status == PathUnresolved && noChainReason != "" {
		out = append(out, noChainReason)
	}
	if ef.truncated {
		out = append(out, "reachability for this entry point was truncated, so the sink list may be incomplete")
	}
	return out
}

// pathLimitations states what this path does not establish.
func pathLimitations(status PathStatus, truncated bool, noChainReason string) []string {
	out := []string{
		"the path is call-graph reachability; data propagation is not established",
		"no dataflow evidence exists in this phase, so the ranking cannot order paths by propagation",
		"priorities are heuristic scores, not vulnerability probabilities",
	}
	switch status {
	case PathUnresolved:
		out = append(out, "a fact needed to describe this path is missing: "+noChainReason)
	case PathCandidate:
		out = append(out, "no fully observed call chain supports this path, so it rests on attack-surface reachability alone")
	}
	if truncated {
		out = append(out, "the reachability walk for this entry point was truncated")
	}
	return out
}

func sortNodes(nodes []ASGNode) {
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, value := range in {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
