package plugin

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

const stageNormalizer = "codexploit/stage-normalizer/v2"

func normalizeCodeIDs(inv Invocation, raw []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return nil, ErrInvalid
	}
	var files, symbols, calls, mappings []map[string]any
	for key, target := range map[string]*[]map[string]any{"files": &files, "symbols": &symbols, "calls": &calls, "native_id_mappings": &mappings} {
		if json.Unmarshal(doc[key], target) != nil {
			return nil, ErrInvalid
		}
	}
	fileInfo := map[string]map[string]any{}
	ids := map[string]string{}
	seen := map[string]bool{}
	text := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }
	for _, f := range files {
		old := text(f, "file_id")
		id := scg.FileID(inv.Request.Scope.SnapshotID, text(f, "path"))
		if seen[id] {
			return nil, ErrInvalid
		}
		seen[id] = true
		ids[old] = id
		fileInfo[old] = f
	}
	location := func(m map[string]any) scg.Location {
		var loc scg.Location
		if v, ok := m["location"].(map[string]any); ok {
			loc.File = text(v, "file")
			if n, ok := v["start_line"].(float64); ok {
				loc.Line = int(n)
			}
			if n, ok := v["start_column"].(float64); ok {
				loc.Col = int(n)
			}
		}
		return loc
	}
	for _, s := range symbols {
		f := fileInfo[text(s, "file_id")]
		if f == nil {
			return nil, ErrInvalid
		}
		language := strings.ToLower(text(f, "language"))
		id := scg.SymbolID(inv.Request.Scope.SnapshotID, language, text(f, "path"), text(s, "qualified_name"), text(s, "signature"), location(s))
		if seen[id] {
			return nil, ErrInvalid
		}
		seen[id] = true
		ids[text(s, "id")] = id
	}
	for _, f := range files {
		f["file_id"] = ids[text(f, "file_id")]
	}
	for _, s := range symbols {
		s["id"] = ids[text(s, "id")]
		s["file_id"] = ids[text(s, "file_id")]
	}
	for _, c := range calls {
		loc := location(c)
		id := scg.CallSiteID(inv.Request.Scope.SnapshotID, loc.File, loc.Line, loc.Col, text(c, "callee_text"))
		if seen[id] {
			return nil, ErrInvalid
		}
		seen[id] = true
		ids[text(c, "id")] = id
		c["id"] = id
		for _, k := range []string{"caller_ref", "callee_ref"} {
			if c[k] != nil {
				mapped := ids[text(c, k)]
				if mapped == "" {
					return nil, ErrInvalid
				}
				c[k] = mapped
			}
		}
	}
	for _, m := range mappings {
		if m["canonical_ref"] != nil {
			mapped := ids[text(m, "canonical_ref")]
			if mapped == "" {
				return nil, ErrInvalid
			}
			m["canonical_ref"] = mapped
		}
	}
	for key, value := range map[string]any{"files": files, "symbols": symbols, "calls": calls, "native_id_mappings": mappings} {
		doc[key], _ = json.Marshal(value)
	}
	return json.Marshal(doc)
}

// A tool can refer to a single native output using output:<port>. Only the
// host assigns its ArtifactRef identity. Existing native input refs stay pinned.
func bindNativeMappingReferences(inv Invocation, outputs []RawOutput, raw []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return nil, ErrInvalid
	}
	var mappings []map[string]any
	if json.Unmarshal(doc["native_id_mappings"], &mappings) != nil {
		return nil, ErrInvalid
	}
	bindings := map[string]string{}
	counts := map[string]int{}
	for i, out := range outputs {
		if out.Kind == "tool.native" {
			key := "output:" + out.Port
			indexed := fmt.Sprintf("%s:%d", key, counts[key])
			counts[indexed] = 1
			bindings[indexed] = fmt.Sprintf("artifact-%s-%s-%d", inv.ID, out.Port, i)
			counts[key]++
			bindings[key] = fmt.Sprintf("artifact-%s-%s-%d", inv.ID, out.Port, i)
		}
	}
	for _, ref := range inv.Request.Inputs {
		if ref.Kind == "tool.native" {
			bindings[ref.ID] = ref.ID
			counts[ref.ID] = 1
		}
	}
	seen := map[string]bool{}
	for _, m := range mappings {
		ref, ok := m["native_artifact_ref"].(string)
		if !ok || counts[ref] != 1 {
			return nil, ErrInvalid
		}
		native, ok := m["native_id"].(string)
		if !ok || native == "" || seen[ref+"\x00"+native] {
			return nil, ErrInvalid
		}
		seen[ref+"\x00"+native] = true
		m["native_artifact_ref"] = bindings[ref]
	}
	doc["native_id_mappings"], _ = json.Marshal(mappings)
	return json.Marshal(doc)
}
