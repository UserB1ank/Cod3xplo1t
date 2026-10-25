package plugin

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func validateEnhancement(source string, input, retained, enhancement []byte) error {
	var before, after struct {
		Paths []json.RawMessage `json:"paths"`
		Pins  json.RawMessage   `json:"graph_pins"`
	}
	var selection struct {
		Source   string `json:"source_path_artifact"`
		Selected []struct {
			ID    string  `json:"path_id"`
			Rank  int     `json:"rank"`
			Score float64 `json:"score"`
		} `json:"selected"`
		Filtered []struct {
			ID string `json:"path_id"`
		} `json:"filtered"`
	}
	if json.Unmarshal(input, &before) != nil || json.Unmarshal(retained, &after) != nil || json.Unmarshal(enhancement, &selection) != nil || source != selection.Source {
		return ErrInvalid
	}
	canonical := func(raw []byte) []byte { b, _ := jsoncanonicalizer.Transform(raw); return b }
	if !bytes.Equal(canonical(before.Pins), canonical(after.Pins)) {
		return ErrInvalid
	}
	original := map[string][]byte{}
	for _, p := range before.Paths {
		var id struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(p, &id) != nil || id.ID == "" || original[id.ID] != nil {
			return ErrInvalid
		}
		original[id.ID] = canonical(p)
	}
	selected := map[string]bool{}
	seen := map[string]bool{}
	sort.Slice(selection.Selected, func(i, j int) bool { return selection.Selected[i].Rank < selection.Selected[j].Rank })
	for i, p := range selection.Selected {
		if original[p.ID] == nil || seen[p.ID] || p.Rank != i+1 {
			return ErrInvalid
		}
		if i > 0 {
			prior := selection.Selected[i-1]
			if prior.Score < p.Score || (prior.Score == p.Score && prior.ID > p.ID) {
				return ErrInvalid
			}
		}
		seen[p.ID] = true
		selected[p.ID] = true
	}
	for _, p := range selection.Filtered {
		if original[p.ID] == nil || seen[p.ID] {
			return ErrInvalid
		}
		seen[p.ID] = true
	}
	if len(seen) != len(original) || len(after.Paths) != len(selected) {
		return ErrInvalid
	}
	retainedIDs := map[string]bool{}
	for _, p := range after.Paths {
		var id struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(p, &id) != nil || !selected[id.ID] || retainedIDs[id.ID] || !bytes.Equal(original[id.ID], canonical(p)) {
			return ErrInvalid
		}
		retainedIDs[id.ID] = true
	}
	return nil
}

func stageData(raw []byte) (json.RawMessage, error) {
	var doc StageDocument
	if json.Unmarshal(raw, &doc) != nil || doc.APIVersion != "codexploit/v2" || len(doc.Data) == 0 {
		return nil, ErrInvalid
	}
	return doc.Data, nil
}
