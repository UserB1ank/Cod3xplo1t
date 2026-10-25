package publication

import (
	"encoding/json"
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

// BatchFromStage publishes typed facts without claiming a native SCG/ASG index
// or a confirmed vulnerability. Native tool IDs must be normalized by the
// producing operation before they enter a standard stage document.
func BatchFromStage(id string, doc plugin.StageDocument, base string) (Batch, error) {
	batch := Batch{ID: id, Scope: Scope{ProjectID: doc.Scope.ProjectID, SnapshotID: doc.Scope.SnapshotID}, BaseRevision: base, Producer: doc.Producer, Facts: []BatchFact{}, Edges: []BatchEdge{}, Limitations: append([]string{}, doc.Limitations...)}
	if doc.Coverage.Seen != nil {
		batch.Coverage.FilesSeen = int(*doc.Coverage.Seen)
	}
	if doc.Coverage.Analyzed != nil {
		batch.Coverage.FilesAnalyzed = int(*doc.Coverage.Analyzed)
	}
	if doc.Coverage.Skipped != nil {
		batch.Coverage.FilesSkipped = int(*doc.Coverage.Skipped)
	}
	var data map[string]json.RawMessage
	if json.Unmarshal(doc.Data, &data) != nil {
		return Batch{}, ErrInvalidBatch
	}
	nodes := map[string]bool{}
	add := func(raw json.RawMessage, kind string) error {
		var node struct {
			ID        string   `json:"id"`
			Name      string   `json:"name"`
			Qualified string   `json:"qualified_name"`
			Entry     string   `json:"entry_kind"`
			Operation string   `json:"operation_kind"`
			Observed  string   `json:"observed_or_inferred"`
			Evidence  []string `json:"evidence_refs"`
			Location  *struct {
				File string `json:"file"`
				Line int    `json:"start_line"`
				End  *int   `json:"end_line"`
			} `json:"location"`
		}
		if json.Unmarshal(raw, &node) != nil || node.ID == "" || nodes[node.ID] {
			return ErrInvalidBatch
		}
		nodes[node.ID] = true
		label := node.Qualified
		if label == "" {
			label = node.Name
		}
		if label == "" {
			label = node.Entry
		}
		if label == "" {
			label = node.Operation
		}
		if label == "" {
			label = node.ID
		}
		confidence := "observed"
		if node.Observed == "inferred" {
			confidence = "inferred"
		}
		fact := BatchFact{ID: node.ID, Kind: kind, Label: label, Confidence: confidence, Attributes: map[string]string{"stage_schema": doc.SchemaID, "standard_data": string(raw)}, Evidence: node.Evidence}
		if node.Location != nil {
			end := node.Location.Line
			if node.Location.End != nil {
				end = *node.Location.End
			}
			fact.Location = &Location{File: node.Location.File, StartLine: node.Location.Line, EndLine: end}
		}
		batch.Facts = append(batch.Facts, fact)
		return nil
	}
	var omitted int
	switch doc.Kind {
	case "code.facts":
		batch.Layer = "code"
		var symbols []json.RawMessage
		if json.Unmarshal(data["symbols"], &symbols) != nil {
			return Batch{}, ErrInvalidBatch
		}
		for _, symbol := range symbols {
			if err := add(symbol, "code.symbol"); err != nil {
				return Batch{}, err
			}
		}
		var calls []struct {
			From *string `json:"caller_ref"`
			To   *string `json:"callee_ref"`
		}
		if json.Unmarshal(data["calls"], &calls) != nil {
			return Batch{}, ErrInvalidBatch
		}
		for _, call := range calls {
			if call.From == nil || call.To == nil || !nodes[*call.From] || !nodes[*call.To] {
				omitted++
				continue
			}
			batch.Edges = append(batch.Edges, BatchEdge{From: *call.From, To: *call.To, Kind: "CALLS"})
		}
	case "security.facts":
		batch.Layer = "security"
		for _, group := range []struct{ Key, Kind string }{{"entries", "security.entry"}, {"sinks", "security.sink"}, {"controls", "security.control"}} {
			var rows []json.RawMessage
			if json.Unmarshal(data[group.Key], &rows) != nil {
				return Batch{}, ErrInvalidBatch
			}
			for _, row := range rows {
				if err := add(row, group.Kind); err != nil {
					return Batch{}, err
				}
			}
		}
		var relations []struct {
			From string `json:"from"`
			To   string `json:"to"`
			Kind string `json:"kind"`
		}
		if json.Unmarshal(data["relations"], &relations) != nil {
			return Batch{}, ErrInvalidBatch
		}
		for _, edge := range relations {
			if !nodes[edge.From] || !nodes[edge.To] {
				omitted++
				continue
			}
			batch.Edges = append(batch.Edges, BatchEdge{From: edge.From, To: edge.To, Kind: edge.Kind})
		}
	case "discovery.paths":
		batch.Layer = "paths"
		var paths []json.RawMessage
		if json.Unmarshal(data["paths"], &paths) != nil {
			return Batch{}, ErrInvalidBatch
		}
		for _, path := range paths {
			if err := add(path, "candidate.path"); err != nil {
				return Batch{}, err
			}
			batch.Facts[len(batch.Facts)-1].Attributes["status"] = "candidate"
		}
	default:
		return Batch{}, ErrInvalidBatch
	}
	if omitted > 0 {
		batch.Limitations = append(batch.Limitations, fmt.Sprintf("%d unresolved or external edges omitted; no endpoint was invented", omitted))
	}
	return batch, nil
}
