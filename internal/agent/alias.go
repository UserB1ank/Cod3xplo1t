package agent

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// The alias table is the model's only vocabulary for domain ids. The ledger keeps
// canonical ids; the model sees short, collision-free names, and the host resolves
// them before it checks scope, evidence or budgets. It exists so a long run cannot
// transcribe a 32-character id wrongly, not so the ledger can forget the real one.

// Alias categories. The letter is part of the alias, which is what makes a
// mismatch between, say, an evidence id and a symbol id visible to the model and
// to the resolver.
const (
	AliasKindSymbol   = "S"
	AliasKindAudit    = "A"
	AliasKindCall     = "C"
	AliasKindEvidence = "E"
	AliasKindPath     = "P"

	// AliasTableVersion is the stored shape of the table. A checkpoint keeps the
	// table it was created with; a resume must not bind an old alias to a new
	// object.
	AliasTableVersion = 1
)

// AliasEntry is one canonical id and the short name the model uses for it.
type AliasEntry struct {
	Alias string `json:"alias"`
	Kind  string `json:"kind"`
	ID    string `json:"id"`
}

// AliasTable maps one run's canonical ids to model-facing aliases.
type AliasTable struct {
	Version int          `json:"version"`
	Entries []AliasEntry `json:"entries"`
	byAlias map[string]AliasEntry
	byID    map[string]string
}

// NewAliasTable allocates aliases in a deterministic first-appearance order:
// path, audit, evidence, symbol/call refs, then the path's ASG refs. The same task
// always produces the same table, so a retried run and a rendered prompt agree.
func NewAliasTable(task Task) *AliasTable {
	table := &AliasTable{Version: AliasTableVersion, byAlias: map[string]AliasEntry{}, byID: map[string]string{}}
	next := map[string]int{}
	add := func(kind, id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, exists := table.byID[id]; exists {
			return
		}
		next[kind]++
		alias := kind + strconv.Itoa(next[kind])
		entry := AliasEntry{Alias: alias, Kind: kind, ID: id}
		table.Entries = append(table.Entries, entry)
		table.byAlias[alias] = entry
		table.byID[id] = alias
	}
	add(AliasKindPath, task.PathID)
	add(AliasKindAudit, task.AuditID)
	for _, ref := range task.EvidenceRefs {
		add(AliasKindEvidence, ref.ID)
	}
	// The two ends of the path first: they are what the model reasons about, and a
	// stable order is what lets a rendered prompt be compared across runs.
	add(AliasKindSymbol, task.SourceSinkRefs.EntryNodeID)
	add(AliasKindSymbol, task.SourceSinkRefs.TargetNodeID)
	for _, section := range task.MinimalCodeSlice {
		// A slice section may name its symbol by qualified name rather than by SCG
		// id. Only ids become aliases: resolving a display name would hand a tool a
		// value it cannot query.
		if strings.HasPrefix(section.Symbol, "sym-") {
			add(AliasKindSymbol, section.Symbol)
		}
	}
	for _, ref := range task.SourceSinkRefs.SCGRefs {
		if kind := aliasKindForRef(ref); kind != "" {
			add(kind, ref)
		}
	}
	for _, ref := range task.SourceSinkRefs.ASGRefs {
		if kind := aliasKindForRef(ref); kind != "" {
			add(kind, ref)
		}
	}
	return table
}

// aliasKindForRef classifies a graph reference by its prefix. Unknown prefixes stay
// canonical: inventing an alias for a value the tools do not accept would only
// move the failure.
func aliasKindForRef(ref string) string {
	switch {
	case strings.HasPrefix(ref, "sym-"):
		return AliasKindSymbol
	case strings.HasPrefix(ref, "call-"), strings.HasPrefix(ref, "callsite-"):
		return AliasKindCall
	case strings.HasPrefix(ref, "asg-"), strings.HasPrefix(ref, "node-"):
		return AliasKindSymbol
	default:
		return ""
	}
}

// Alias returns the short name for one canonical id.
func (t *AliasTable) Alias(id string) (string, bool) {
	if t == nil {
		return "", false
	}
	alias, ok := t.byID[id]
	return alias, ok
}

// Resolve turns an alias, or a canonical id the table knows, into the canonical
// id. Anything else is rejected: a value from another run or outside this task's
// scope must not become a query.
func (t *AliasTable) Resolve(value string) (string, bool) {
	if t == nil {
		return "", false
	}
	value = strings.TrimSpace(value)
	if entry, ok := t.byAlias[value]; ok {
		return entry.ID, true
	}
	if _, ok := t.byID[value]; ok {
		return value, true
	}
	return "", false
}

// aliasArgKeys are the tool arguments that carry a domain id. Resolving only these
// is deliberate: a free-text query that happens to equal an alias must not be
// rewritten.
var aliasArgKeys = map[string]bool{
	"path_id": true, "audit_id": true, "symbol_id": true, "node_id": true,
	"call_site_id": true, "evidence_id": true, "ref": true, "id": true,
	"from": true, "to": true, "from_node": true, "to_node": true,
}

// ResolveArgs rewrites the id-bearing arguments of one tool call. A value that is
// neither an alias nor a known canonical id is an error, not something to pass
// through: the tool would otherwise receive an unchecked id.
func (t *AliasTable) ResolveArgs(args map[string]string) (map[string]string, error) {
	if len(args) == 0 {
		return args, nil
	}
	resolved := make(map[string]string, len(args))
	for key, value := range args {
		if !aliasArgKeys[key] || strings.TrimSpace(value) == "" {
			resolved[key] = value
			continue
		}
		id, ok := t.Resolve(value)
		if !ok {
			return nil, fmt.Errorf("unknown alias %q for %s", value, key)
		}
		resolved[key] = id
	}
	return resolved, nil
}

// aliasIDKeys are the JSON fields of a tool result that name a domain object.
var aliasIDKeys = map[string]bool{
	"id": true, "symbol_id": true, "node_id": true, "call_site_id": true,
	"path_id": true, "audit_id": true, "evidence_id": true, "ref": true,
	"entry_node_id": true, "target_node_id": true, "from": true, "to": true,
}

// aliasListKeys are the JSON arrays of ids in a tool result.
var aliasListKeys = map[string]bool{
	"refs": true, "evidence": true, "symbols": true, "nodes": true, "paths": true,
	"calls": true, "call_sites": true, "edges": true, "scg_refs": true, "asg_refs": true,
}

// ProjectJSON shortens the ids in a structured tool result. Free text and unknown
// fields are left alone; only exact matches on known id keys are rewritten.
func (t *AliasTable) ProjectJSON(raw string) string {
	if t == nil || strings.TrimSpace(raw) == "" {
		return raw
	}
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return raw
	}
	projected, err := json.Marshal(t.project(value))
	if err != nil {
		return raw
	}
	return string(projected)
}

func (t *AliasTable) project(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if aliasIDKeys[key] {
				if text, ok := item.(string); ok {
					if alias, ok := t.Alias(text); ok {
						typed[key] = alias
					}
					continue
				}
			}
			if aliasListKeys[key] {
				if list, ok := item.([]any); ok {
					for index, element := range list {
						if text, ok := element.(string); ok {
							if alias, ok := t.Alias(text); ok {
								list[index] = alias
							}
						}
					}
					continue
				}
			}
			typed[key] = t.project(item)
		}
		return typed
	case []any:
		for index, element := range typed {
			typed[index] = t.project(element)
		}
		return typed
	default:
		return value
	}
}

// ResolveAnswer rewrites the alias references in a proposed answer before the host
// validates it, so the stored hypothesis and finding carry canonical ids. It only
// touches the structured reference fields; prose is never rewritten.
func (t *AliasTable) ResolveAnswer(raw []byte) []byte {
	if t == nil || len(raw) == 0 {
		return raw
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return raw
	}
	for _, field := range []string{"supporting_evidence", "contradicting_evidence"} {
		list, _ := document[field].([]any)
		for _, item := range list {
			object, _ := item.(map[string]any)
			ref, _ := object["ref"].(string)
			if ref == "" {
				continue
			}
			if id, ok := t.Resolve(ref); ok {
				object["ref"] = id
			}
		}
	}
	if expansion, ok := document["requested_expansion"].(map[string]any); ok {
		if node, _ := expansion["target_node_id"].(string); node != "" {
			if id, ok := t.Resolve(node); ok {
				expansion["target_node_id"] = id
			}
		}
	}
	resolved, err := json.Marshal(document)
	if err != nil {
		return raw
	}
	return resolved
}

// ResolveToolArgs is ResolveArgs for the native JSON argument object. Only
// declared id-bearing string fields are resolved; every other value is untouched.
func (t *AliasTable) ResolveToolArgs(args json.RawMessage) (json.RawMessage, error) {
	if t == nil || len(args) == 0 {
		return args, nil
	}
	var fields map[string]any
	if err := json.Unmarshal(args, &fields); err != nil {
		return nil, fmt.Errorf("arguments must be a JSON object: %w", err)
	}
	for key, value := range fields {
		if !aliasArgKeys[key] {
			continue
		}
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			continue
		}
		id, ok := t.Resolve(text)
		if !ok {
			return nil, fmt.Errorf("unknown alias %q for %s", text, key)
		}
		fields[key] = id
	}
	resolved, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	return resolved, nil
}
