package plugin

import (
	"encoding/json"
	"path"
	"strings"
)

type boundaryNode struct {
	ID     string  `json:"id"`
	Symbol *string `json:"symbol_ref"`
}
type boundaryEdge struct {
	ID         string  `json:"id"`
	From       string  `json:"from"`
	To         string  `json:"to"`
	Kind       string  `json:"kind"`
	Caller     *string `json:"caller_ref"`
	Callee     *string `json:"callee_ref"`
	Resolution string  `json:"resolution"`
}

// Only the immutable inputs named by this invocation may justify references.
func validateStageReferences(inv Invocation, inputs [][]byte, schema string, raw []byte) error {
	if schema != "codexploit/security-facts/v2" && schema != "codexploit/discovery-paths/v2" {
		return nil
	}
	symbols := map[string]bool{}
	nodes := map[string]bool{}
	entries := map[string]bool{}
	sinks := map[string]bool{}
	edges := map[string]boundaryEdge{}
	pins := map[string]string{}
	for i, ref := range inv.Request.Inputs {
		if i >= len(inputs) {
			return ErrInvalid
		}
		if ref.SchemaID != "codexploit/code-facts/v2" && ref.SchemaID != "codexploit/security-facts/v2" {
			continue
		}
		data, err := stageData(inputs[i])
		if err != nil {
			return err
		}
		var d struct {
			Symbols   []boundaryNode `json:"symbols"`
			Calls     []boundaryEdge `json:"calls"`
			Entries   []boundaryNode `json:"entries"`
			Sinks     []boundaryNode `json:"sinks"`
			Controls  []boundaryNode `json:"controls"`
			Relations []boundaryEdge `json:"relations"`
		}
		if json.Unmarshal(data, &d) != nil {
			return ErrInvalid
		}
		if ref.SchemaID == "codexploit/code-facts/v2" {
			pins["code"] = ref.ID
		}
		if ref.SchemaID == "codexploit/security-facts/v2" {
			pins["security"] = ref.ID
		}
		for _, n := range d.Symbols {
			symbols[n.ID] = true
			nodes[n.ID] = true
		}
		for _, n := range d.Entries {
			entries[n.ID] = true
			nodes[n.ID] = true
		}
		for _, n := range d.Sinks {
			sinks[n.ID] = true
			nodes[n.ID] = true
		}
		for _, n := range d.Controls {
			nodes[n.ID] = true
		}
		for _, e := range d.Calls {
			if e.Caller != nil && e.Callee != nil && e.Resolution == "resolved" {
				e.From = *e.Caller
				e.To = *e.Callee
				e.Kind = "call"
				edges[e.ID] = e
			}
		}
		for _, e := range d.Relations {
			edges[e.ID] = e
		}
	}
	if schema == "codexploit/security-facts/v2" {
		var d struct {
			Entries   []boundaryNode `json:"entries"`
			Sinks     []boundaryNode `json:"sinks"`
			Controls  []boundaryNode `json:"controls"`
			Relations []boundaryEdge `json:"relations"`
		}
		if json.Unmarshal(raw, &d) != nil {
			return ErrInvalid
		}
		ids := map[string]bool{}
		for _, group := range [][]boundaryNode{d.Entries, d.Sinks, d.Controls} {
			for _, n := range group {
				if ids[n.ID] || nodes[n.ID] || (n.Symbol != nil && !symbols[*n.Symbol]) {
					return ErrInvalid
				}
				ids[n.ID] = true
			}
		}
		for id := range ids {
			nodes[id] = true
		}
		for _, e := range d.Relations {
			if ids[e.ID] || !nodes[e.From] || !nodes[e.To] {
				return ErrInvalid
			}
			ids[e.ID] = true
		}
		return nil
	}
	// Enhancement compares an exact subset against its paths input separately.
	if pins["code"] == "" || pins["security"] == "" {
		for _, ref := range inv.Request.Inputs {
			if ref.SchemaID == schema {
				return nil
			}
		}
		return ErrInvalid
	}
	var d struct {
		Pins  map[string]string `json:"graph_pins"`
		Paths []struct {
			ID           string   `json:"id"`
			Entry        *string  `json:"entry_ref"`
			Sink         *string  `json:"sink_ref"`
			Basis        string   `json:"basis"`
			Completeness string   `json:"completeness"`
			Unresolved   []string `json:"unresolved_segments"`
			Steps        []struct {
				From     string `json:"from_ref"`
				To       string `json:"to_ref"`
				Relation string `json:"relation_ref"`
			} `json:"ordered_steps"`
		} `json:"paths"`
	}
	if json.Unmarshal(raw, &d) != nil || d.Pins["code"] != pins["code"] || d.Pins["security"] != pins["security"] {
		return ErrInvalid
	}
	ids := map[string]bool{}
	for _, p := range d.Paths {
		if ids[p.ID] || (p.Entry != nil && !entries[*p.Entry]) || (p.Sink != nil && !sinks[*p.Sink]) {
			return ErrInvalid
		}
		ids[p.ID] = true
		if p.Entry == nil || p.Sink == nil {
			if p.Basis != "hypothesis" || p.Completeness != "partial" {
				return ErrInvalid
			}
		}
		if p.Completeness == "complete" && (len(p.Unresolved) > 0 || len(p.Steps) == 0) {
			return ErrInvalid
		}
		for i, step := range p.Steps {
			e, ok := edges[step.Relation]
			if !ok || e.From != step.From || e.To != step.To || !nodes[step.From] || !nodes[step.To] {
				return ErrInvalid
			}
			if i > 0 && p.Steps[i-1].To != step.From {
				return ErrInvalid
			}
			if p.Basis == "data_flow" && e.Kind != "data_flow" && e.Kind != "taint_flow" {
				return ErrInvalid
			}
		}
	}
	return nil
}

func safeSourcePath(value string) bool {
	return value != "" && value != "." && path.Clean(value) == value && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && !strings.ContainsAny(value, "\\:\x00")
}
