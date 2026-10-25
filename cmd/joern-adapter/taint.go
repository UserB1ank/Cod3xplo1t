package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	RuleID string     `json:"rule_id"`
	CPG    string     `json:"cpg_artifact_id"`
	Nodes  []flowNode `json:"nodes"`
}
type flowReport struct {
	Version     string `json:"api_version"`
	Code        string `json:"code_artifact_id"`
	RulesDigest string `json:"rules_digest"`
	SourceCount int    `json:"source_count"`
	SinkCount   int    `json:"sink_count"`
	Flows       []flow `json:"flows"`
	Truncated   bool   `json:"truncated"`
}
type codeData struct {
	Files    []struct{ Path, Language string } `json:"files"`
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
	codeInput, e := oneInput(j, "code")
	if e != nil {
		return e
	}
	var code codeData
	if e = j.data("code", &code); e != nil {
		return e
	}
	cpgs := j.inputs("cpg")
	if len(cpgs) == 0 || len(cpgs) > 14 {
		return failed("invalid_input")
	}
	known := map[string]bool{}
	for _, m := range code.Mappings {
		known[m.Native] = true
	}
	report := flowReport{Version: "joern/taint-flows/v1", Code: codeInput.ArtifactID, RulesDigest: digest(rulesRaw), Flows: []flow{}}
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
		if e = j.script("taint.sc", config.Heap, "cpgFile="+native, "rulesFile="+rulesFile, "outFile="+out, fmt.Sprintf("maxFlows=%d", config.MaxFlows-len(report.Flows)), fmt.Sprintf("maxDepth=%d", config.MaxDepth)); e != nil {
			return e
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
		if json.Unmarshal(raw, &part) != nil || part.Flows == nil || len(part.Flows) > config.MaxFlows-len(report.Flows) {
			return failed("normalization_failed")
		}
		report.SourceCount += part.SourceCount
		report.SinkCount += part.SinkCount
		report.Truncated = report.Truncated || part.Truncated
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
	}
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
	j.partial(int64(len(cpgs)), "cpgs", []string{"Static data flow is a candidate: source trust and sink sensitivity follow the selected rules; sanitizer effectiveness and runtime exploitability are unassessed.", "Joern data-flow semantics and call-depth limits apply independently to each language CPG; no cross-language bridge is inferred.", "Native traces and matched source/sink counts are preserved; zero flows does not establish safety."})
	if report.Truncated {
		j.Result.Coverage.Truncated = true
		j.Result.Coverage.Reasons = append(j.Result.Coverage.Reasons, "flow_budget_exceeded")
		j.Result.Limitations = append(j.Result.Limitations, "Flow enumeration reached max_flows; retained traces are a bounded subset, not exhaustive coverage.")
	}
	return nil
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
	for _, f := range report.Flows {
		if len(f.Nodes) < 1 || f.CPG == "" || f.RuleID == "" {
			return nil, failed("normalization_failed")
		}
		first, last := f.Nodes[0], f.Nodes[len(f.Nodes)-1]
		if first.ID == "" || last.ID == "" {
			return nil, failed("normalization_failed")
		}
		entry := identity("entry", f.RuleID, f.CPG, first.ID)
		sink := identity("sink", f.RuleID, f.CPG, last.ID)
		edge := identity("flow", entry, sink)
		if !seen[entry] {
			entries = append(entries, map[string]any{"id": entry, "symbol_ref": symbol(f.CPG, first.MethodID), "location": nodeLocation(first), "entry_kind": f.RuleID, "observed_or_inferred": "inferred", "evidence_refs": []string{f.CPG}})
			seen[entry] = true
		}
		if !seen[sink] {
			sinks = append(sinks, map[string]any{"id": sink, "symbol_ref": symbol(f.CPG, last.MethodID), "location": nodeLocation(last), "operation_kind": f.RuleID, "sensitivity": "rule_selected", "evidence_refs": []string{f.CPG}})
			seen[sink] = true
		}
		if !seen[edge] {
			relations = append(relations, map[string]any{"id": edge, "from": entry, "to": sink, "kind": "taint_flow", "observed_or_inferred": "observed", "evidence_refs": []string{f.CPG}})
			seen[edge] = true
		}
	}
	return map[string]any{"entries": entries, "sinks": sinks, "controls": []any{}, "relations": relations, "ruleset": map[string]any{"id": "joern.configured-taint", "version": "1.0.0", "digest": report.RulesDigest}}, nil
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
	if json.Unmarshal(raw, &report) != nil || report.Version != "joern/taint-flows/v1" || report.Code != code.ArtifactID || len(report.Flows) > 1000 {
		return failed("invalid_input")
	}
	var sec struct {
		Ruleset   struct{ Digest string }
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
	for _, edge := range sec.Relations {
		paths = append(paths, map[string]any{"id": identity("path", security.ArtifactID, edge.ID), "entry_ref": edge.From, "sink_ref": edge.To, "ordered_steps": []any{map[string]any{"from_ref": edge.From, "to_ref": edge.To, "relation_ref": edge.ID, "location": nil}}, "basis": "data_flow", "completeness": "partial", "scg_refs": []string{}, "asg_refs": []string{edge.From, edge.To, edge.ID}, "evidence_refs": []string{rawInput.ArtifactID}, "unresolved_segments": []string{"source_trust_and_sanitizers_unassessed"}, "limitations": []string{"Summary edge is justified by a real reachableByFlows trace in the pinned native report; it is not a confirmed vulnerability."}})
	}
	value := map[string]any{"paths": paths, "graph_pins": map[string]string{"code": code.ArtifactID, "security": security.ArtifactID}, "omitted": map[string]any{"count": 0, "reasons": []string{}}}
	if e = j.jsonOutput("paths", "discovery.paths", "codexploit/discovery-paths/v2", "paths.json", value); e != nil {
		return e
	}
	j.partial(int64(len(paths)), "paths", []string{"Candidate data-flow paths retain fixed code/security inputs and raw traces; source trust, controls and exploitability remain unassessed."})
	return nil
}
