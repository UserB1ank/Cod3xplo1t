// Package analysisengine is the whole-engine boundary for project analysis.
// A provider owns the complete workflow and its projection into review facts.
// It does not build another graph or resolve calls with a second engine.
package analysisengine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	audit "github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

type Provider interface {
	Workflow() workflow.Spec
	Project(Bundle) (*plugin.NativeReport, error)
}
type Input struct {
	Ref      artifact.Ref
	Document plugin.StageDocument
}
type Bundle struct {
	Code, Security, Generated, Selected Input
	Selection                           *Input
	BuiltAt                             string
}
type Joern struct{}

func Default() Provider { return Joern{} }

func (Joern) Workflow() workflow.Spec { return workflow.DefaultAnalysisSpec() }

type location struct {
	File   string `json:"file"`
	Line   int    `json:"start_line"`
	Column int    `json:"start_column"`
	End    int    `json:"end_line"`
}
type symbol struct {
	ID         string `json:"id"`
	File       string `json:"file_id"`
	Kind, Name string
	Qualified  string `json:"qualified_name"`
	Signature  string
	Location   *location
}
type securityNode struct {
	ID                 string
	Symbol             *string `json:"symbol_ref"`
	Location           *location
	Entry              string   `json:"entry_kind"`
	Operation          string   `json:"operation_kind"`
	CatalogID          string   `json:"catalog_id"`
	CatalogVersion     string   `json:"catalog_version"`
	CatalogDigest      string   `json:"catalog_digest"`
	MethodFullName     string   `json:"method_full_name"`
	DangerousArguments []int    `json:"dangerous_arguments"`
	Priority           float64  `json:"priority"`
	HasFlow            bool     `json:"has_flow"`
	MatchEvidence      string   `json:"match_evidence"`
	RuleLimitations    string   `json:"limitations"`
	Observed           string   `json:"observed_or_inferred"`
	Evidence           []string `json:"evidence_refs"`
}
type relation struct {
	ID, From, To, Kind string
	Observed           string   `json:"observed_or_inferred"`
	Evidence           []string `json:"evidence_refs"`
}
type candidate struct {
	ID                  string
	Entry               string `json:"entry_ref"`
	Sink                string `json:"sink_ref"`
	Basis, Completeness string
	PriorityHint        float64 `json:"priority_hint"`
	Steps               []struct {
		From     string `json:"from_ref"`
		To       string `json:"to_ref"`
		Relation string `json:"relation_ref"`
	} `json:"ordered_steps"`
	Evidence    []string `json:"evidence_refs"`
	Unresolved  []string `json:"unresolved_segments"`
	Limitations []string
}
type pathData struct {
	Paths   []candidate
	Pins    map[string]string `json:"graph_pins"`
	Omitted struct {
		Count   int
		Reasons []string
	}
}
type selection struct {
	Source   string `json:"source_path_artifact"`
	Version  string `json:"scoring_version"`
	Weights  string `json:"weights_digest"`
	Selected []struct {
		ID      string `json:"path_id"`
		Rank    int
		Score   float64
		Reasons []string `json:"reason_codes"`
	}
	Filtered []struct {
		ID     string `json:"path_id"`
		Code   string `json:"filter_code"`
		Reason string
	}
}

func contains(refs []artifact.Ref, id string) bool {
	for _, ref := range refs {
		if ref.ID == id {
			return true
		}
	}
	return false
}
func sameEngine(a, b artifact.Producer) bool {
	return a.PluginID == b.PluginID && a.PluginVersion == b.PluginVersion && a.PackageDigest == b.PackageDigest
}
func invalid() error {
	return fmt.Errorf("analysis engine: incompatible Joern lineage or graph references")
}
func (Joern) Project(b Bundle) (*plugin.NativeReport, error) {
	scope := b.Code.Ref.Scope
	for _, input := range []Input{b.Code, b.Security, b.Generated, b.Selected} {
		d := input.Document
		if d.Scope != scope || input.Ref.Scope != scope || d.Producer != input.Ref.Producer || d.Producer.PluginID != "codexploit.joern" || !sameEngine(d.Producer, b.Code.Document.Producer) || d.APIVersion != "codexploit/v2" {
			return nil, invalid()
		}
	}
	if b.Code.Document.Producer.OperationID != "parse" || b.Security.Document.Producer.OperationID != "taint" || b.Generated.Document.Producer.OperationID != "paths" || !contains(b.Security.Document.Inputs, b.Code.Ref.ID) || !contains(b.Generated.Document.Inputs, b.Code.Ref.ID) || !contains(b.Generated.Document.Inputs, b.Security.Ref.ID) {
		return nil, invalid()
	}
	var paths, generated pathData
	if json.Unmarshal(b.Selected.Document.Data, &paths) != nil || json.Unmarshal(b.Generated.Document.Data, &generated) != nil || paths.Pins["code"] != b.Code.Ref.ID || paths.Pins["security"] != b.Security.Ref.ID || generated.Pins["code"] != b.Code.Ref.ID || generated.Pins["security"] != b.Security.Ref.ID {
		return nil, invalid()
	}
	ledger := selection{Version: "joern.static-support/v2", Source: b.Generated.Ref.ID, Weights: workflow.Digest([]byte(`{"data_flow":1,"call_reachability":0.4,"hypothesis":0.1,"catalog_priority":0.5}`))}
	if b.Selected.Ref.ID != b.Generated.Ref.ID {
		if b.Selected.Document.Producer.OperationID != "enhance" || !contains(b.Selected.Document.Inputs, b.Generated.Ref.ID) || b.Selection == nil {
			return nil, invalid()
		}
		s := b.Selection
		if s.Document.Scope != scope || s.Ref.Scope != scope || s.Document.Producer != s.Ref.Producer || !sameEngine(s.Document.Producer, b.Code.Document.Producer) || s.Document.Producer.InvocationID != b.Selected.Document.Producer.InvocationID || json.Unmarshal(s.Document.Data, &ledger) != nil || ledger.Source != b.Generated.Ref.ID {
			return nil, invalid()
		}
	}
	// Exact retained candidates must still be present in the generating artifact.
	originals := map[string]string{}
	for _, p := range generated.Paths {
		raw, _ := json.Marshal(p)
		originals[p.ID] = string(raw)
	}
	seenPaths := map[string]bool{}
	for _, p := range paths.Paths {
		raw, _ := json.Marshal(p)
		if seenPaths[p.ID] || originals[p.ID] != string(raw) {
			return nil, invalid()
		}
		seenPaths[p.ID] = true
	}
	var code struct {
		Files []struct {
			ID             string `json:"file_id"`
			Path, Language string
			Status         string `json:"parse_status"`
			Reason         *string
		}
		Symbols []symbol
		Calls   []struct {
			ID         string
			Caller     *string `json:"caller_ref"`
			Callee     *string `json:"callee_ref"`
			Text       string  `json:"callee_text"`
			Location   *location
			Resolution string
		}
		Mappings []struct {
			Native string `json:"native_artifact_ref"`
		} `json:"native_id_mappings"`
	}
	var security struct {
		Entries, Sinks, Controls []securityNode
		Relations                []relation
		Ruleset                  struct{ Digest string }
	}
	if json.Unmarshal(b.Code.Document.Data, &code) != nil || json.Unmarshal(b.Security.Document.Data, &security) != nil {
		return nil, invalid()
	}
	version := "graph-" + workflow.Digest([]byte("joern-review/v1:" + b.Code.Ref.SHA256))[:32]
	g := &scg.Graph{SchemaVersion: scg.SchemaVersion, SnapshotID: scope.SnapshotID, GraphVersion: version, Engine: scg.Engine{Name: b.Code.Document.Producer.PluginID, Version: b.Code.Document.Producer.PluginVersion}, BuiltAt: b.BuiltAt, Frontends: []scg.FrontendInfo{}, Modules: []scg.Module{}, Files: []scg.File{}, Symbols: []scg.Symbol{}, CallSites: []scg.CallSite{}, Edges: []scg.Edge{}, Limitations: append([]string{}, b.Code.Document.Limitations...)}
	g.Limitations = append(g.Limitations, "Review index projects Joern facts only. Full AST, CFG and data-flow nodes remain in the pinned native CPGs; modules are file directories, not inferred build units.")
	moduleIndex := map[string]int{}
	files := map[string]scg.File{}
	fileByPath := map[string]scg.File{}
	addEdge := func(from, to string, kind scg.EdgeKind, loc scg.Location, call string, confidence scg.Confidence) {
		g.Edges = append(g.Edges, scg.Edge{ID: scg.EdgeID(from, to, kind, loc, call), SnapshotID: scope.SnapshotID, From: from, To: to, Kind: kind, SourceLocation: loc, CallSiteID: call, Analyzer: g.Engine.Name, AnalyzerVersion: g.Engine.Version, Confidence: confidence, Resolution: scg.Resolved})
	}
	for _, f := range code.Files {
		dir := "."
		if i := strings.LastIndex(f.Path, "/"); i >= 0 {
			dir = f.Path[:i]
		}
		idx, ok := moduleIndex[dir]
		if !ok {
			idx = len(g.Modules)
			moduleIndex[dir] = idx
			g.Modules = append(g.Modules, scg.Module{ID: scg.ModuleID(scope.SnapshotID, dir), SnapshotID: scope.SnapshotID, Path: dir, Name: dir})
		}
		g.Modules[idx].Files++
		status := map[string]string{"parsed": "ok", "partial": "partial", "unparsed": "unparsed", "unhandled": "unsupported_language"}[f.Status]
		file := scg.File{ID: f.ID, SnapshotID: scope.SnapshotID, ModuleID: g.Modules[idx].ID, Path: f.Path, Language: strings.ToLower(f.Language), ParseStatus: status}
		if f.Reason != nil {
			file.ParseError = *f.Reason
		}
		files[f.ID] = file
		fileByPath[f.Path] = file
		g.Files = append(g.Files, file)
		addEdge(file.ModuleID, f.ID, scg.EdgeContains, scg.Location{File: f.Path}, "", scg.Observed)
		g.Coverage.FilesInSnapshot++
		switch status {
		case "ok":
			g.Coverage.FilesParsed++
		case "partial":
			g.Coverage.FilesParsed++
			g.Coverage.FilesPartial++
		case "unsupported_language":
			g.Coverage.FilesUnsupported++
		default:
			g.Coverage.FilesUnparsed++
		}
	}
	symbols := map[string]scg.Symbol{}
	for _, s := range code.Symbols {
		f, ok := files[s.File]
		if !ok || s.ID == "" {
			return nil, invalid()
		}
		v := scg.Symbol{ID: s.ID, SnapshotID: scope.SnapshotID, ModuleID: f.ModuleID, FileID: f.ID, File: f.Path, Language: f.Language, Kind: scg.SymbolKind(s.Kind), Name: s.Name, QualifiedName: s.Qualified, Signature: s.Signature}
		if s.Location != nil {
			v.StartLine = s.Location.Line
			v.StartCol = s.Location.Column
			v.EndLine = s.Location.End
			if v.EndLine == 0 {
				v.EndLine = v.StartLine
			}
		}
		symbols[s.ID] = v
		g.Symbols = append(g.Symbols, v)
		addEdge(f.ID, s.ID, scg.EdgeContains, scg.Location{File: f.Path, Line: v.StartLine}, "", scg.Observed)
	}
	for _, c := range code.Calls {
		if c.Location == nil {
			continue
		}
		f, ok := fileByPath[c.Location.File]
		if !ok {
			return nil, invalid()
		}
		resolution := map[string]scg.Resolution{"resolved": scg.Resolved, "external": scg.External, "dynamic": scg.Dynamic, "unresolved": scg.Unsupported}[c.Resolution]
		confidence := scg.Unresolved
		if resolution == scg.Resolved {
			confidence = scg.Inferred
		}
		v := scg.CallSite{ID: c.ID, SnapshotID: scope.SnapshotID, FileID: f.ID, File: f.Path, Line: c.Location.Line, Col: c.Location.Column, CalleeText: c.Text, Resolution: resolution, Confidence: confidence, Analyzer: g.Engine.Name, AnalyzerVersion: g.Engine.Version}
		if c.Caller != nil {
			v.CallerSymbolID = *c.Caller
		}
		if c.Callee != nil {
			v.CalleeSymbolID = *c.Callee
		}
		g.CallSites = append(g.CallSites, v)
		g.Resolution.Add(resolution)
		if v.CallerSymbolID != "" && v.CalleeSymbolID != "" {
			if symbols[v.CallerSymbolID].ID == "" || symbols[v.CalleeSymbolID].ID == "" {
				return nil, invalid()
			}
			addEdge(v.CallerSymbolID, v.CalleeSymbolID, scg.EdgeCalls, scg.Location{File: f.Path, Line: v.Line, Col: v.Col}, v.ID, confidence)
		}
	}
	surface := &asg.Document{SchemaVersion: asg.SchemaVersion, SnapshotID: scope.SnapshotID, SCGVersion: version, Engine: asg.Engine{Name: g.Engine.Name, Version: g.Engine.Version}, RulesetHash: security.Ruleset.Digest, Nodes: []asg.Node{}, Edges: []asg.Edge{}, BuiltAt: b.BuiltAt, Limitations: append([]string{}, b.Security.Document.Limitations...)}
	surface.ASGVersion = asg.Version(scope.SnapshotID, version, surface.Engine, b.Security.Ref.SHA256)
	cpgs := map[string]bool{}
	for _, m := range code.Mappings {
		cpgs[m.Native] = true
	}
	evidenceOK := func(refs []string) bool {
		if len(refs) == 0 {
			return false
		}
		for _, r := range refs {
			if !cpgs[r] {
				return false
			}
		}
		return true
	}
	nodes := map[string]asg.Node{}
	addNode := func(n securityNode, kind asg.NodeKind) error {
		if !evidenceOK(n.Evidence) {
			return invalid()
		}
		refs := []string{}
		if n.Symbol != nil {
			if symbols[*n.Symbol].ID == "" {
				return invalid()
			}
			refs = append(refs, *n.Symbol)
		}
		if len(refs) == 0 && n.Location != nil {
			if f, ok := fileByPath[n.Location.File]; ok {
				refs = append(refs, f.ID)
			}
		}
		if len(refs) == 0 {
			surface.Coverage.NodesSkipped++
			return nil
		}
		subject := n.Entry
		if subject == "" {
			subject = n.Operation
		}
		evidence, confidence := asg.StatusObserved, scg.Observed
		if kind == asg.NodeEntryPoint || n.Observed == "inferred" {
			evidence, confidence = asg.StatusInferred, scg.Inferred
		}
		detail := map[string]string{"standard_id": n.ID, "code_artifact_id": b.Code.Ref.ID, "security_artifact_id": b.Security.Ref.ID, "evidence_artifacts": strings.Join(n.Evidence, ","), "sensitivity": "rule_selected; runtime and controls unassessed"}
		if n.CatalogID != "" {
			detail["catalog_id"] = n.CatalogID
			detail["catalog_version"] = n.CatalogVersion
			detail["catalog_digest"] = n.CatalogDigest
			detail["method_full_name"] = n.MethodFullName
			detail["dangerous_arguments"] = fmt.Sprint(n.DangerousArguments)
			detail["priority"] = fmt.Sprint(n.Priority)
			detail["has_flow"] = fmt.Sprint(n.HasFlow)
			detail["match_evidence"] = n.MatchEvidence
			detail["sensitivity"] = "catalog_selected; runtime and controls unassessed"
		}
		if n.RuleLimitations != "" {
			detail["rule_limitations"] = n.RuleLimitations
		}
		v := asg.Node{ID: asg.NodeID(scope.SnapshotID, kind, subject, n.ID), SnapshotID: scope.SnapshotID, Kind: kind, Subject: subject, Label: subject, Evidence: evidence, Confidence: confidence, Generator: "joern.configured-taint", SCGRefs: refs, Detail: detail}
		if n.Location != nil {
			v.File = n.Location.File
			v.Line = n.Location.Line
		}
		if n.Symbol != nil && symbols[*n.Symbol].ID != "" {
			v.Label = symbols[*n.Symbol].QualifiedName
		}
		if kind == asg.NodeSensitiveOperation && n.Location != nil {
			names := map[string]bool{}
			for _, call := range g.CallSites {
				if call.File == n.Location.File && call.Line == n.Location.Line {
					names[call.CalleeText] = true
				}
			}
			if len(names) == 1 {
				for name := range names {
					v.Label = name
				}
			}
		}
		if n.Location != nil {
			v.Label += fmt.Sprintf(" · %s:%d", n.Location.File, n.Location.Line)
		}
		nodes[n.ID] = v
		surface.Nodes = append(surface.Nodes, v)
		return nil
	}
	for _, n := range security.Entries {
		if err := addNode(n, asg.NodeEntryPoint); err != nil {
			return nil, err
		}
	}
	for _, n := range security.Sinks {
		if err := addNode(n, asg.NodeSensitiveOperation); err != nil {
			return nil, err
		}
	}
	edges := map[string]asg.Edge{}
	for _, r := range security.Relations {
		if r.Kind != "taint_flow" || !evidenceOK(r.Evidence) {
			return nil, invalid()
		}
		from, to := nodes[r.From], nodes[r.To]
		if from.ID == "" || to.ID == "" {
			surface.Coverage.EdgesSkipped++
			continue
		}
		refs := append(append([]string{}, from.SCGRefs...), to.SCGRefs...)
		edge := asg.Edge{ID: asg.EdgeID(scope.SnapshotID, asg.EdgeReaches, from.ID, to.ID, r.ID), SnapshotID: scope.SnapshotID, From: from.ID, To: to.ID, Kind: asg.EdgeReaches, Evidence: asg.StatusObserved, Confidence: scg.Observed, Generator: "joern.reachableByFlows", SCGRefs: refs, Detail: map[string]string{"basis": "data_flow", "standard_id": r.ID, "evidence_artifacts": strings.Join(r.Evidence, ",")}}
		edges[r.ID] = edge
		surface.Edges = append(surface.Edges, edge)
	}
	result := &audit.GenerateResult{SnapshotID: scope.SnapshotID, SCGVersion: version, ASGVersion: surface.ASGVersion, Paths: []audit.Path{}, Coverage: audit.Coverage{EntryPointsExamined: len(security.Entries), SinksExamined: len(security.Sinks), PathsConsidered: len(generated.Paths), TruncationReasons: []string{}}, Limitations: append([]string{}, b.Selected.Document.Limitations...)}
	upstreamLimits := []string{}
	for _, input := range []Input{b.Code, b.Security, b.Generated, b.Selected} {
		if input.Document.Coverage.Truncated {
			result.Coverage.Truncated = true
			result.Coverage.TruncationReasons = append(result.Coverage.TruncationReasons, input.Document.Coverage.Reasons...)
			upstreamLimits = append(upstreamLimits, input.Document.Limitations...)
		}
	}
	result.Limitations = append(result.Limitations, upstreamLimits...)
	enhancement := &audit.EnhancementSummary{SchemaVersion: "codexploit/path-enhancement/v2", ProducerID: g.Engine.Name, ProducerVersion: g.Engine.Version, InvocationID: b.Selected.Document.Producer.InvocationID, ConfigDigest: b.Selected.Document.Producer.ConfigDigest, InputArtifactIDs: []string{b.Generated.Ref.ID}, ScoreVersion: 1, WeightsDigest: ledger.Weights, Selected: []audit.EnhancementPath{}, Filtered: []audit.EnhancementPath{}, Limitations: []string{"Static support priority is not severity or a vulnerability verdict."}}
	rank := map[string]float64{}
	for _, p := range ledger.Selected {
		rank[p.ID] = p.Score
	}
	for _, p := range paths.Paths {
		entry, sink := nodes[p.Entry], nodes[p.Sink]
		if p.Basis != "data_flow" || entry.ID == "" || sink.ID == "" {
			result.Coverage.PathsSkipped++
			continue
		}
		steps := []audit.Step{}
		refs := []string{}
		asgRefs := []string{entry.ID, sink.ID}
		for _, step := range p.Steps {
			edge, ok := edges[step.Relation]
			if !ok || edge.From != nodes[step.From].ID || edge.To != nodes[step.To].ID {
				return nil, invalid()
			}
			steps = append(steps, audit.Step{Layer: "asg", From: edge.From, To: edge.To, Kind: string(edge.Kind), Evidence: "observed", Confidence: "observed", Subject: sink.Label, File: sink.File, Line: sink.Line})
			asgRefs = append(asgRefs, edge.ID)
		}
		if len(steps) == 0 {
			return nil, invalid()
		}
		refSeen := map[string]bool{}
		for _, id := range append(append([]string{}, entry.SCGRefs...), sink.SCGRefs...) {
			if !refSeen[id] {
				refs = append(refs, id)
				refSeen[id] = true
			}
		}
		for _, evidence := range p.Evidence {
			if !contains(b.Generated.Document.Inputs, evidence) {
				return nil, invalid()
			}
		}
		priority, ok := rank[p.ID]
		if !ok {
			priority = 1 + p.PriorityHint/2
		}
		selected := &audit.PathSelection{SchemaVersion: enhancement.SchemaVersion, Selection: "selected", Reason: "Joern static data-flow support; source trust and control effectiveness remain unassessed", ScoreVersion: 1, WeightsDigest: ledger.Weights, SourcePathID: p.ID, SourceArtifactID: b.Generated.Ref.ID, ProducerID: g.Engine.Name, ProducerVersion: g.Engine.Version, InvocationID: enhancement.InvocationID}
		reasons := map[string]string{"dataflow_evidence": "Joern reachableByFlows on the pinned CPG; native evidence " + strings.Join(p.Evidence, ","), "controllability": "unassessed", "control_suspicion": "unassessed"}
		weights := map[string]float64{"static_support": 1}
		if p.PriorityHint > 0 {
			reasons["catalog_priority"] = "Versioned sink-review hint; not severity or exploitability"
			weights["catalog_priority"] = 0.5
		}
		v := audit.Path{ID: p.ID, SnapshotID: scope.SnapshotID, SCGVersion: version, ASGVersion: surface.ASGVersion, EntryNodeID: entry.ID, EntryKind: entry.Subject, EntrySubject: entry.Label, TargetNodeID: sink.ID, TargetKind: "rule_selected", TargetSubject: sink.Label, PathKind: "data_flow", PathStatus: audit.PathCandidate, Status: audit.StatusDiscovered, Steps: steps, SCGRefs: refs, ASGRefs: asgRefs, EvidenceRefs: append(append([]string{}, p.Evidence...), b.Code.Ref.ID, b.Security.Ref.ID, b.Selected.Ref.ID), Depth: len(steps), Inputs: []string{entry.ID}, Controls: []string{}, Boundaries: []string{}, Assets: []string{}, Objectives: []string{}, OpenQuestions: append([]string{"source_trust_and_sanitizers_unassessed"}, p.Unresolved...), Limitations: append(append([]string{}, p.Limitations...), "Pinned Joern static trace; this candidate does not establish source controllability, ineffective controls or exploitability.", "Native trace artifacts: "+strings.Join(p.Evidence, ",")), Budget: audit.DefaultBudget(), Selection: selected, Features: audit.Features{DataflowEvidence: 1, Reasons: reasons}, Score: audit.Score{Priority: priority, Support: priority, ScoreVersion: 1, Weights: weights, ComputedAt: b.BuiltAt}, CreatedAt: b.BuiltAt, UpdatedAt: b.BuiltAt, Version: 1}
		v.Signature = audit.Signature(scope.SnapshotID, entry.ID, sink.ID, v.PathKind, v.CanonicalEdges())
		v.Limitations = append(v.Limitations, upstreamLimits...)
		result.Paths = append(result.Paths, v)
		enhancement.Selected = append(enhancement.Selected, audit.EnhancementPath{PathID: p.ID, EntrySubject: v.EntrySubject, TargetSubject: v.TargetSubject, EntryNodeID: entry.ID, TargetNodeID: sink.ID, PathStatus: string(v.PathStatus), Priority: priority, Support: priority, ScoreVersion: 1, Selection: *selected, Limitations: v.Limitations})
	}
	for _, p := range ledger.Filtered {
		enhancement.Filtered = append(enhancement.Filtered, audit.EnhancementPath{PathID: p.ID, Selection: audit.PathSelection{Selection: "filtered", Reason: p.Reason, FilterCode: p.Code, SourcePathID: p.ID, SourceArtifactID: b.Generated.Ref.ID, ScoreVersion: 1, WeightsDigest: ledger.Weights}})
	}
	result.Coverage.PathsEmitted = len(result.Paths)
	result.Coverage.ChainsResolved = len(result.Paths)
	if result.Coverage.PathsSkipped > 0 || paths.Omitted.Count > 0 || b.Selected.Document.Coverage.Truncated {
		result.Coverage.Truncated = true
		result.Coverage.TruncationReasons = append(result.Coverage.TruncationReasons, "unindexable_or_budgeted_candidates")
		result.Limitations = append(result.Limitations, "Unindexable or budgeted candidates remain in immutable standard/native artifacts.")
	}
	sort.Slice(g.Symbols, func(i, j int) bool { return g.Symbols[i].ID < g.Symbols[j].ID })
	if err := surface.Validate(); err != nil {
		return nil, err
	}
	surface.Summarize()
	return &plugin.NativeReport{Format: "codexploit/joern-review/v1", Scope: scope, Graph: g, Surface: surface, Paths: result, Enhancement: enhancement, Limitations: result.Limitations}, nil
}
