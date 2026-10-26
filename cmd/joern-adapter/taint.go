package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

type selector struct {
	Kind        string `json:"kind"`
	Method      string `json:"method"`
	Index       int    `json:"index"`
	CodePattern string `json:"code_pattern"`
}
type sinkSelector struct {
	Method        string `json:"method"`
	ArgumentIndex int    `json:"argument_index"`
}
type rule struct {
	ID     string       `json:"id"`
	Source selector     `json:"source"`
	Sink   sinkSelector `json:"sink"`
}
type flowNode struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Code          string `json:"code"`
	CodeTruncated bool   `json:"code_truncated"`
	Filename      string `json:"filename"`
	MethodID      string `json:"method_id"`
	Line          *int   `json:"line"`
	Column        *int   `json:"column"`
}
type flow struct {
	RuleID         string     `json:"rule_id"`
	CPG            string     `json:"cpg_artifact_id"`
	SinkCallID     string     `json:"sink_call_id,omitempty"`
	SinkCatalogIDs []string   `json:"sink_catalog_ids,omitempty"`
	Nodes          []flowNode `json:"nodes"`
}
type sinkMatch struct {
	RuleID             string   `json:"rule_id"`
	Category           string   `json:"category"`
	CPG                string   `json:"cpg_artifact_id"`
	MethodFullName     string   `json:"method_full_name"`
	DangerousArguments []int    `json:"dangerous_arguments"`
	Priority           float64  `json:"priority"`
	Evidence           string   `json:"evidence"`
	Limitations        []string `json:"limitations"`
	Node               flowNode `json:"node"`
}
type flowPartition struct {
	ID             string   `json:"id"`
	CPG            string   `json:"cpg_artifact_id"`
	Kind           string   `json:"kind"`
	Rules          []string `json:"rule_ids"`
	Priority       float64  `json:"priority"`
	CandidateSinks int      `json:"candidate_sinks"`
	FlowBudget     int      `json:"flow_budget"`
	Flows          int      `json:"flows"`
	Status         string   `json:"status"`
}
type flowReport struct {
	FailedCPGs                []string        `json:"failed_cpgs,omitempty"`
	FailedFrontends           []string        `json:"failed_frontends,omitempty"`
	SkippedCPGs               []string        `json:"skipped_cpgs,omitempty"`
	SkippedFrontends          []string        `json:"skipped_frontends,omitempty"`
	SelectionTruncated        bool            `json:"selection_truncated,omitempty"`
	FlowTruncated             bool            `json:"flow_truncated,omitempty"`
	CatalogSelectionTruncated bool            `json:"catalog_selection_truncated,omitempty"`
	CatalogFlowTruncated      bool            `json:"catalog_flow_truncated,omitempty"`
	Version                   string          `json:"api_version"`
	Code                      string          `json:"code_artifact_id"`
	RulesDigest               string          `json:"rules_digest"`
	Catalog                   catalogRef      `json:"catalog,omitempty"`
	SourceCount               int             `json:"source_count"`
	SinkCount                 int             `json:"sink_count"`
	CatalogSinkMatchCount     int             `json:"catalog_sink_match_count"`
	CatalogSinkNodeCount      int             `json:"catalog_sink_node_count"`
	Sinks                     []sinkMatch     `json:"sink_inventory"`
	Flows                     []flow          `json:"flows"`
	Partitions                []flowPartition `json:"partitions"`
	Truncated                 bool            `json:"truncated"`
}
type codeData struct {
	Files []struct {
		ID             string `json:"file_id"`
		Path, Language string
	} `json:"files"`
	Mappings []struct {
		Native    string  `json:"native_artifact_ref"`
		ID        string  `json:"native_id"`
		Canonical *string `json:"canonical_ref"`
	} `json:"native_id_mappings"`
}

func digest(raw []byte) string        { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func identity(parts ...string) string { return "joern:" + digest([]byte(strings.Join(parts, "\x00"))) }
func (j *job) data(port string, target any) error {
	raw, e := j.read(port)
	if e != nil {
		return e
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &env) != nil || env.Data == nil || json.Unmarshal(env.Data, target) != nil {
		return failed("invalid_input")
	}
	return nil
}
func oneInput(j *job, port string) (pluginsdk.LocalInput, error) {
	i := j.inputs(port)
	if len(i) != 1 || i[0].ArtifactID == "" {
		return pluginsdk.LocalInput{}, failed("invalid_input")
	}
	return i[0], nil
}

func cpgLanguages(code codeData) map[string][]string {
	languageByCanonical := map[string]string{}
	for _, file := range code.Files {
		languageByCanonical[file.ID] = file.Language
	}
	languages := map[string]map[string]bool{}
	for _, mapping := range code.Mappings {
		if mapping.Canonical == nil {
			continue
		}
		language := languageByCanonical[*mapping.Canonical]
		if language == "" {
			continue
		}
		if languages[mapping.Native] == nil {
			languages[mapping.Native] = map[string]bool{}
		}
		languages[mapping.Native][language] = true
	}
	result := make(map[string][]string, len(languages))
	for cpg, set := range languages {
		for language := range set {
			result[cpg] = append(result[cpg], language)
		}
		sort.Strings(result[cpg])
	}
	return result
}

func appendUniqueStrings(target *[]string, values ...string) {
	for _, value := range values {
		if value == "" || slicesContains(*target, value) {
			continue
		}
		*target = append(*target, value)
	}
	sort.Strings(*target)
}

func slicesContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (j *job) taint() error {
	var config struct {
		Rules    []rule `json:"rules"`
		MaxFlows int    `json:"max_flows"`
		MaxDepth int    `json:"max_call_depth"`
		Heap     int    `json:"heap_mib"`
	}
	if e := decodeConfig(j.Request.Config, &config); e != nil {
		return e
	}
	if config.Rules == nil {
		raw, e := os.ReadFile(filepath.Join(j.Package, "rules.json"))
		if e != nil || json.Unmarshal(raw, &config.Rules) != nil {
			return unavailable("dependency_unavailable")
		}
	}
	if len(config.Rules) == 0 || len(config.Rules) > 32 {
		return failed("invalid_config")
	}
	if config.MaxFlows == 0 {
		config.MaxFlows = 100
	}
	if config.MaxDepth == 0 {
		config.MaxDepth = 4
	}
	if config.MaxFlows < 1 || config.MaxFlows > 1000 || config.MaxDepth < 1 || config.MaxDepth > 10 {
		return failed("invalid_config")
	}
	ids := map[string]bool{}
	for i := range config.Rules {
		r := &config.Rules[i]
		if r.ID == "" || len(r.ID) > 128 || ids[r.ID] || r.Source.Index < 0 || r.Source.Index > 64 || r.Sink.ArgumentIndex < 1 || r.Sink.ArgumentIndex > 64 || (r.Source.Kind != "parameter" && r.Source.Kind != "call_return") {
			return failed("invalid_config")
		}
		ids[r.ID] = true
		if r.Source.CodePattern == "" {
			r.Source.CodePattern = ".*"
		}
		for _, p := range []string{r.Source.Method, r.Source.CodePattern, r.Sink.Method} {
			if len(p) == 0 || len(p) > 512 {
				return failed("invalid_config")
			}
			if _, e := regexp.Compile(p); e != nil {
				return failed("invalid_config")
			}
		}
	}
	rulesRaw, _ := json.Marshal(config.Rules)
	rulesFile := filepath.Join(j.Work, "rules.json")
	if e := os.WriteFile(rulesFile, rulesRaw, 0600); e != nil {
		return e
	}
	catalog, catalogDigest, e := loadJavaCatalog(j.Package)
	if e != nil {
		return e
	}
	catalogRaw, _ := json.Marshal(catalog)
	catalogFile := filepath.Join(j.Work, "java-sinks.json")
	if e = os.WriteFile(catalogFile, catalogRaw, 0600); e != nil {
		return e
	}
	codeInput, e := oneInput(j, "code")
	if e != nil {
		return e
	}
	var code codeData
	if e = j.data("code", &code); e != nil {
		return e
	}
	languages := cpgLanguages(code)
	cpgs := j.inputs("cpg")
	if len(cpgs) == 0 || len(cpgs) > 14 {
		return failed("invalid_input")
	}
	known := map[string]bool{}
	for _, m := range code.Mappings {
		known[m.Native] = true
	}
	report := flowReport{
		Version: "joern/taint-flows/v2", Code: codeInput.ArtifactID, RulesDigest: digest(rulesRaw),
		Catalog: catalogRef{ID: catalog.ID, Version: catalog.Version, Digest: catalogDigest, Entries: len(catalog.Entries)},
		Sinks:   []sinkMatch{}, Flows: []flow{}, Partitions: []flowPartition{},
	}
	seenCPGs := int64(len(cpgs))
	analyzedCPGs, failedCPGs := int64(0), int64(0)
	j.Result.Coverage = pluginsdk.Coverage{Unit: "cpgs", Seen: &seenCPGs, Analyzed: &analyzedCPGs, Failed: &failedCPGs, Reasons: []string{}}
	var lastFailure error
	for index, input := range cpgs {
		if !known[input.ArtifactID] {
			return failed("invalid_input")
		}
		raw, e := j.readBound(input)
		if e != nil {
			return failed("invalid_input")
		}
		native := filepath.Join(j.Work, fmt.Sprintf("taint-%d.bin", index))
		if e = os.WriteFile(native, raw, 0600); e != nil {
			return e
		}
		out := filepath.Join(j.Work, fmt.Sprintf("flows-%d.json", index))
		remainingFlows := config.MaxFlows - len(report.Flows)
		remainingCPGs := len(cpgs) - index
		cpgBudget := shareBudget(remainingFlows, remainingCPGs)
		if e = j.script("taint.sc", config.Heap, "cpgFile="+native, "rulesFile="+rulesFile, "catalogFile="+catalogFile, "outFile="+out, fmt.Sprintf("maxFlows=%d", cpgBudget), fmt.Sprintf("maxDepth=%d", config.MaxDepth)); e != nil {
			if j.Context.Err() != nil {
				return e
			}
			label := fmt.Sprintf("CPG_%d", index)
			frontends := languages[input.ArtifactID]
			if len(frontends) == 0 {
				frontends = []string{label}
			}
			f, ok := e.(*failure)
			if !ok || f.Unsupported {
				return j.frontendFailure(strings.Join(frontends, "+"), "taint", "", e)
			}
			for _, frontend := range frontends {
				j.frontendFailure(frontend, "taint", "", e)
			}
			failedCPGs++
			lastFailure = e
			report.FailedCPGs = append(report.FailedCPGs, input.ArtifactID)
			appendUniqueStrings(&report.FailedFrontends, frontends...)
			report.Truncated = true
			continue
		}
		info, e := os.Stat(out)
		if e != nil || info.Size() > 16<<20 {
			return failed("normalization_failed")
		}
		raw, e = os.ReadFile(out)
		if e != nil {
			return e
		}
		var part flowReport
		if json.Unmarshal(raw, &part) != nil || part.Flows == nil || len(part.Flows) > cpgBudget || part.Sinks == nil || len(part.Sinks) > 10000 {
			return failed("normalization_failed")
		}
		analyzedCPGs++
		report.SelectionTruncated = report.SelectionTruncated || part.SelectionTruncated
		report.FlowTruncated = report.FlowTruncated || part.FlowTruncated
		report.CatalogSelectionTruncated = report.CatalogSelectionTruncated || part.CatalogSelectionTruncated
		report.CatalogFlowTruncated = report.CatalogFlowTruncated || part.CatalogFlowTruncated
		report.SourceCount += part.SourceCount
		report.SinkCount += part.SinkCount
		report.Truncated = report.Truncated || part.Truncated
		for _, match := range part.Sinks {
			match.CPG = input.ArtifactID
			match.Node.Filename = sourcePath(match.Node.Filename, code)
			report.Sinks = append(report.Sinks, match)
		}
		for _, f := range part.Flows {
			f.CPG = input.ArtifactID
			for i := range f.Nodes {
				f.Nodes[i].Filename = sourcePath(f.Nodes[i].Filename, code)
				for _, file := range code.Files {
					if file.Path == f.Nodes[i].Filename && (file.Language == "Java bytecode" || file.Language == "Binary / Ghidra") {
						f.Nodes[i].Line = nil
						f.Nodes[i].Column = nil
					}
				}
			}
			report.Flows = append(report.Flows, f)
		}
		for _, partition := range part.Partitions {
			if partition.ID == "" || (partition.Kind != "catalog" && partition.Kind != "fallback") ||
				partition.CandidateSinks < 0 || partition.FlowBudget < 0 || partition.Flows < 0 ||
				partition.Flows > partition.FlowBudget ||
				(partition.Status != "complete" && partition.Status != "truncated" && partition.Status != "pending") {
				return failed("normalization_failed")
			}
			partition.CPG = input.ArtifactID
			report.Partitions = append(report.Partitions, partition)
		}
	}
	if analyzedCPGs == 0 {
		skipped := int64(len(report.SkippedCPGs))
		j.Result.Coverage.Skipped = &skipped
		if lastFailure != nil {
			return lastFailure
		}
		return failed("normalization_failed")
	}
	uniqueCatalogNodes := map[string]bool{}
	for _, match := range report.Sinks {
		uniqueCatalogNodes[match.CPG+"\x00"+match.Node.ID] = true
	}
	report.CatalogSinkMatchCount = len(report.Sinks)
	report.CatalogSinkNodeCount = len(uniqueCatalogNodes)
	security, e := securityFacts(report, code)
	if e != nil {
		return e
	}
	if e = j.jsonOutput("flows", "tool.native", "codexploit/native-bytes/v1", "flows.json", report); e != nil {
		return e
	}
	if e = j.jsonOutput("security", "security.facts", "codexploit/security-facts/v2", "security.json", security); e != nil {
		return e
	}
	diagnostics := append([]string{}, j.Result.Limitations...)
	j.partial(int64(len(cpgs)), "cpgs", []string{"Static data flow is a candidate: source trust and sink sensitivity follow the selected rules and Java catalogue; sanitizer effectiveness and runtime exploitability are unassessed.", "Joern data-flow semantics and call-depth limits apply independently to each language CPG; no cross-language bridge is inferred.", "Every matched Java-catalogue sink is retained independently of the flow budget; selection caps and zero flows remain explicit."})
	skipped := int64(len(report.SkippedCPGs))
	j.Result.Coverage.Analyzed = &analyzedCPGs
	j.Result.Coverage.Failed = &failedCPGs
	j.Result.Coverage.Skipped = &skipped
	j.Result.Limitations = append(j.Result.Limitations, diagnostics...)
	if len(report.FailedCPGs) > 0 {
		j.Result.Coverage.Reasons = append(j.Result.Coverage.Reasons, "dataflow_cpg_failed")
		if len(report.FailedFrontends) > 0 {
			j.Result.Limitations = append(j.Result.Limitations, "Data-flow coverage unavailable for frontends: "+strings.Join(report.FailedFrontends, ", "))
		}
		j.Result.Limitations = append(j.Result.Limitations, "Data-flow coverage unavailable for CPGs: "+strings.Join(report.FailedCPGs, ", "))
	}
	if len(report.SkippedCPGs) > 0 {
		if len(report.SkippedFrontends) > 0 {
			j.Result.Limitations = append(j.Result.Limitations, "Data-flow analysis skipped for frontends after max_flows was exhausted: "+strings.Join(report.SkippedFrontends, ", "))
		}
	}
	if report.SelectionTruncated {
		j.Result.Coverage.Reasons = append(j.Result.Coverage.Reasons, "selection_budget_truncated")
		j.Result.Limitations = append(j.Result.Limitations, "Source/sink selection retained at most 10000 nodes per rule; matched counts include all observed matches.")
	}
	if report.FlowTruncated {
		j.Result.Coverage.Reasons = append(j.Result.Coverage.Reasons, "flow_budget_exceeded")
		j.Result.Limitations = append(j.Result.Limitations, "Flow enumeration reached max_flows; retained traces and analyzed CPGs are a bounded subset.")
	}
	if report.CatalogSelectionTruncated {
		j.Result.Coverage.Reasons = append(j.Result.Coverage.Reasons, "catalog_selection_budget_truncated")
		j.Result.Limitations = append(j.Result.Limitations, "Java-catalogue sink inventory reached its per-entry cap; counts are bounded observations, not a source-code completeness claim.")
	}
	if report.CatalogFlowTruncated {
		j.Result.Coverage.Reasons = append(j.Result.Coverage.Reasons, "catalog_partition_budget_exceeded")
		j.Result.Limitations = append(j.Result.Limitations, "At least one high-risk catalogue partition reached its flow share; unmatched suffix is retained as a coverage gap rather than treated as safe.")
	}
	for _, partition := range report.Partitions {
		if partition.Status == "truncated" || partition.Status == "pending" {
			j.Result.Coverage.Reasons = append(j.Result.Coverage.Reasons, "partition_ledger_incomplete")
			j.Result.Limitations = append(j.Result.Limitations, "Data-flow partition "+partition.ID+" on "+partition.CPG+" is "+partition.Status+"; the native flow artifact records the remaining query gap.")
			break
		}
	}
	j.Result.Coverage.Truncated = report.Truncated
	return nil
}

// shareBudget reserves a deterministic minimum for every remaining CPG. Unused
// capacity rolls forward because the next call recomputes from remaining flow
// count and remaining CPG count.
func shareBudget(remaining, partitions int) int {
	if remaining <= 0 || partitions <= 0 {
		return 0
	}
	return (remaining + partitions - 1) / partitions
}

func sourcePath(name string, code codeData) string {
	name = filepath.ToSlash(name)
	match := ""
	for _, f := range code.Files {
		if name == f.Path || strings.HasSuffix(name, "/"+f.Path) {
			if match != "" && match != f.Path {
				return ""
			}
			match = f.Path
		}
	}
	return match
}
func nodeLocation(n flowNode) any {
	if n.Filename == "" || !safeRelative(n.Filename) || n.Line == nil || *n.Line < 1 {
		return nil
	}
	var col any
	if n.Column != nil && *n.Column > 0 {
		col = *n.Column
	}
	return map[string]any{"file": n.Filename, "start_line": *n.Line, "start_column": col, "end_line": nil, "end_column": nil}
}
func securityFacts(report flowReport, code codeData) (map[string]any, error) {
	entries, sinks, relations := []any{}, []any{}, []any{}
	seen := map[string]bool{}
	symbol := func(cpg, id string) any {
		for _, m := range code.Mappings {
			if m.Native == cpg && m.ID == id && m.Canonical != nil {
				return *m.Canonical
			}
		}
		return nil
	}
	sinkRecords := map[string]map[string]any{}
	sinkOrder := []string{}
	sinkByRuleCall := map[string]string{}
	sinkByKey := map[string]sinkMatch{}
	for _, match := range report.Sinks {
		if match.CPG == "" || match.RuleID == "" || match.Category == "" || match.Node.ID == "" ||
			match.Priority < 0 || match.Priority > 1 || (match.Evidence != "observed" && match.Evidence != "inferred") {
			return nil, failed("normalization_failed")
		}
		key := strings.Join([]string{match.CPG, match.Node.ID, match.RuleID}, "\x00")
		if existing, ok := sinkByKey[key]; ok {
			if existing.Category != match.Category || existing.MethodFullName != match.MethodFullName {
				return nil, failed("normalization_failed")
			}
			continue
		}
		sinkByKey[key] = match
		sinkID := identity("sink", match.RuleID, match.CPG, match.Node.ID)
		sinkByRuleCall[strings.Join([]string{match.CPG, match.Node.ID, match.RuleID}, "\x00")] = sinkID
		sinkRecords[sinkID] = map[string]any{
			"id": sinkID, "symbol_ref": symbol(match.CPG, match.Node.MethodID), "location": nodeLocation(match.Node),
			"operation_kind": "sink:" + match.Category, "sensitivity": "catalog_selected",
			"catalog_id": match.RuleID, "catalog_version": report.Catalog.Version,
			"catalog_digest": report.Catalog.Digest, "method_full_name": match.MethodFullName,
			"dangerous_arguments": match.DangerousArguments, "priority": match.Priority,
			"match_evidence": match.Evidence, "has_flow": false,
			"limitations": strings.Join(match.Limitations, " "), "evidence_refs": []string{match.CPG},
		}
		sinkOrder = append(sinkOrder, sinkID)
	}
	for _, f := range report.Flows {
		if len(f.Nodes) < 1 || f.CPG == "" || f.RuleID == "" {
			return nil, failed("normalization_failed")
		}
		first, last := f.Nodes[0], f.Nodes[len(f.Nodes)-1]
		if first.ID == "" || last.ID == "" {
			return nil, failed("normalization_failed")
		}
		entry := identity("entry", f.RuleID, f.CPG, first.ID)
		if !seen[entry] {
			entries = append(entries, map[string]any{"id": entry, "symbol_ref": symbol(f.CPG, first.MethodID), "location": nodeLocation(first), "entry_kind": f.RuleID, "observed_or_inferred": "inferred", "evidence_refs": []string{f.CPG}})
			seen[entry] = true
		}
		sinkIDs := []string{}
		for _, catalogID := range f.SinkCatalogIDs {
			sinkCallID := f.SinkCallID
			if sinkCallID == "" {
				return nil, failed("normalization_failed")
			}
			key := strings.Join([]string{f.CPG, sinkCallID, catalogID}, "\x00")
			sinkID := sinkByRuleCall[key]
			if sinkID == "" {
				return nil, failed("normalization_failed")
			}
			sinkIDs = append(sinkIDs, sinkID)
		}
		if len(sinkIDs) == 0 {
			sinkID := identity("sink", f.RuleID, f.CPG, last.ID)
			if !seen[sinkID] {
				sinkRecords[sinkID] = map[string]any{"id": sinkID, "symbol_ref": symbol(f.CPG, last.MethodID), "location": nodeLocation(last), "operation_kind": "sink:" + f.RuleID, "sensitivity": "rule_selected", "has_flow": true, "evidence_refs": []string{f.CPG}}
				sinkOrder = append(sinkOrder, sinkID)
			}
			sinkIDs = append(sinkIDs, sinkID)
		}
		for _, sink := range sinkIDs {
			if record := sinkRecords[sink]; record != nil {
				record["has_flow"] = true
			}
			edge := identity("flow", entry, sink)
			if !seen[edge] {
				relations = append(relations, map[string]any{"id": edge, "from": entry, "to": sink, "kind": "taint_flow", "observed_or_inferred": "observed", "evidence_refs": []string{f.CPG}})
				seen[edge] = true
			}
		}
	}
	for _, sinkID := range sinkOrder {
		sinks = append(sinks, sinkRecords[sinkID])
	}
	catalogNodeIDs := map[string]bool{}
	for _, match := range report.Sinks {
		catalogNodeIDs[match.CPG+"\x00"+match.Node.ID] = true
	}
	ruleset := map[string]any{"id": "joern.configured-taint", "version": "1.0.0", "digest": report.RulesDigest}
	if report.Catalog.ID != "" {
		ruleset = map[string]any{
			"id": "joern.catalog-taint", "version": "2.0.0", "digest": report.RulesDigest,
			"catalog_id": report.Catalog.ID, "catalog_version": report.Catalog.Version,
			"catalog_digest": report.Catalog.Digest, "catalog_entries": report.Catalog.Entries,
			"catalog_sink_matches": len(report.Sinks), "catalog_sink_nodes": len(catalogNodeIDs),
		}
	}
	return map[string]any{"entries": entries, "sinks": sinks, "controls": []any{}, "relations": relations, "ruleset": ruleset}, nil
}
func (j *job) partial(count int64, unit string, limits []string) {
	zero := int64(0)
	j.Result.Status = "PARTIAL"
	j.Result.Coverage = pluginsdk.Coverage{Unit: unit, Seen: &count, Analyzed: &count, Skipped: &zero, Failed: &zero, Reasons: []string{"static_analysis_limits"}}
	j.Result.Limitations = limits
}
func (j *job) paths() error {
	var config struct{}
	if e := decodeConfig(j.Request.Config, &config); e != nil {
		return e
	}
	code, e := oneInput(j, "code")
	if e != nil {
		return e
	}
	security, e := oneInput(j, "security")
	if e != nil {
		return e
	}
	rawInput, e := oneInput(j, "flows")
	if e != nil {
		return e
	}
	raw, e := j.read("flows")
	if e != nil {
		return e
	}
	var report flowReport
	if json.Unmarshal(raw, &report) != nil || (report.Version != "joern/taint-flows/v1" && report.Version != "joern/taint-flows/v2") || report.Code != code.ArtifactID || len(report.Flows) > 1000 || len(report.Sinks) > 10000 {
		return failed("invalid_input")
	}
	var sec struct {
		Ruleset struct{ Digest string }
		Sinks   []struct {
			ID             string
			Priority       float64
			CatalogID      string `json:"catalog_id"`
			CatalogVersion string `json:"catalog_version"`
			CatalogDigest  string `json:"catalog_digest"`
		}
		Relations []struct{ ID, From, To, Kind string }
	}
	if e = j.data("security", &sec); e != nil {
		return e
	}
	var facts codeData
	if e = j.data("code", &facts); e != nil {
		return e
	}
	expected, e := securityFacts(report, facts)
	if e != nil {
		return e
	}
	expectedRaw, _ := json.Marshal(expected)
	actualRaw, e := j.read("security")
	if e != nil {
		return e
	}
	var env struct{ Data json.RawMessage }
	_ = json.Unmarshal(actualRaw, &env)
	var a, b any
	_ = json.Unmarshal(expectedRaw, &a)
	_ = json.Unmarshal(env.Data, &b)
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(aa) != string(bb) || sec.Ruleset.Digest != report.RulesDigest {
		return failed("invalid_input")
	}
	paths := []any{}
	type sinkPin struct {
		priority float64
		catalog  string
		version  string
		digest   string
	}
	sinkMetadata := map[string]sinkPin{}
	for _, sink := range sec.Sinks {
		sinkMetadata[sink.ID] = sinkPin{
			priority: sink.Priority, catalog: sink.CatalogID,
			version: sink.CatalogVersion, digest: sink.CatalogDigest,
		}
	}
	for _, edge := range sec.Relations {
		metadata := sinkMetadata[edge.To]
		limitations := []string{"Summary edge is justified by a real reachableByFlows trace in the pinned native report; it is not a confirmed vulnerability."}
		unresolved := []string{"source_trust_and_sanitizers_unassessed"}
		if metadata.catalog != "" {
			limitations = append(limitations, "Catalog rule "+metadata.catalog+"@"+metadata.version+" digest "+metadata.digest+"; a rule match is not exploitability.")
			unresolved = append(unresolved, "catalog_rule_match_not_exploitability")
		}
		paths = append(paths, map[string]any{"id": identity("path", security.ArtifactID, edge.ID), "entry_ref": edge.From, "sink_ref": edge.To, "ordered_steps": []any{map[string]any{"from_ref": edge.From, "to_ref": edge.To, "relation_ref": edge.ID, "location": nil}}, "basis": "data_flow", "completeness": "partial", "priority_hint": metadata.priority, "scg_refs": []string{}, "asg_refs": []string{edge.From, edge.To, edge.ID}, "evidence_refs": []string{rawInput.ArtifactID}, "unresolved_segments": unresolved, "limitations": limitations})
	}
	omissionReasons := []string{}
	if report.Truncated {
		omissionReasons = append(omissionReasons, "upstream_semantic_partial")
	}
	value := map[string]any{"paths": paths, "graph_pins": map[string]string{"code": code.ArtifactID, "security": security.ArtifactID}, "omitted": map[string]any{"count": 0, "reasons": omissionReasons}}
	if e = j.jsonOutput("paths", "discovery.paths", "codexploit/discovery-paths/v2", "paths.json", value); e != nil {
		return e
	}
	j.partial(int64(len(paths)), "paths", []string{"Candidate data-flow paths retain fixed code/security inputs and raw traces; source trust, controls and exploitability remain unassessed."})
	if report.Truncated {
		j.Result.Coverage.Truncated = true
		j.Result.Coverage.Reasons = append(j.Result.Coverage.Reasons, "upstream_semantic_partial")
		j.Result.Limitations = append(j.Result.Limitations, "Upstream semantic coverage is partial; missing CPGs and selection/flow budgets remain recorded in the native report.")
	}
	return nil
}
