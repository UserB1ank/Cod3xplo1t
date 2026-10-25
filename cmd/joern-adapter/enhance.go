package main

import (
	"encoding/json"
	"sort"
)

// Enhancement changes scheduling priority only. Retained evidence and graph
// pins are copied verbatim; a filtered path is not a safe-path verdict.
func (j *job) enhance() error {
	var config struct {
		MaxPaths int `json:"max_paths"`
	}
	if err := decodeConfig(j.Request.Config, &config); err != nil {
		return err
	}
	if config.MaxPaths == 0 {
		config.MaxPaths = 1000
	}
	if config.MaxPaths < 1 || config.MaxPaths > 1000 {
		return failed("invalid_config")
	}
	input, err := oneInput(j, "paths")
	if err != nil {
		return err
	}
	var data struct {
		Paths   []json.RawMessage `json:"paths"`
		Pins    json.RawMessage   `json:"graph_pins"`
		Omitted json.RawMessage   `json:"omitted"`
	}
	if err = j.data("paths", &data); err != nil {
		return err
	}
	if data.Paths == nil || len(data.Paths) > 1000 || len(data.Pins) == 0 {
		return failed("invalid_input")
	}
	type ranked struct {
		ID    string
		Score float64
		Raw   json.RawMessage
		Basis string
	}
	rankedPaths := []ranked{}
	seen := map[string]bool{}
	for _, raw := range data.Paths {
		var p struct{ ID, Basis string }
		if json.Unmarshal(raw, &p) != nil || p.ID == "" || seen[p.ID] {
			return failed("invalid_input")
		}
		seen[p.ID] = true
		score := 0.1
		switch p.Basis {
		case "data_flow":
			score = 1
		case "call_reachability":
			score = 0.4
		case "hypothesis":
		default:
			return failed("invalid_input")
		}
		rankedPaths = append(rankedPaths, ranked{p.ID, score, raw, p.Basis})
	}
	sort.Slice(rankedPaths, func(i, k int) bool {
		if rankedPaths[i].Score != rankedPaths[k].Score {
			return rankedPaths[i].Score > rankedPaths[k].Score
		}
		return rankedPaths[i].ID < rankedPaths[k].ID
	})
	selected, filtered := []any{}, []any{}
	retained := []json.RawMessage{}
	chosen := map[string]bool{}
	for i, p := range rankedPaths {
		if i >= config.MaxPaths {
			filtered = append(filtered, map[string]any{"path_id": p.ID, "filter_code": "path_budget", "reason": "Retained candidate budget; evidence remains in the immutable source artifact."})
			continue
		}
		selected = append(selected, map[string]any{"path_id": p.ID, "rank": i + 1, "score": p.Score, "features": map[string]float64{"static_support": p.Score}, "reason_codes": []string{p.Basis, "source_trust_and_controls_unassessed"}})
		chosen[p.ID] = true
	}
	for _, raw := range data.Paths {
		var p struct{ ID string }
		_ = json.Unmarshal(raw, &p)
		if chosen[p.ID] {
			retained = append(retained, raw)
		}
	}
	selection := map[string]any{"source_path_artifact": input.ArtifactID, "selected": selected, "filtered": filtered, "scoring_version": "joern.static-support/v1", "weights_digest": digest([]byte(`{"data_flow":1,"call_reachability":0.4,"hypothesis":0.1}`))}
	value := map[string]any{"paths": retained, "graph_pins": data.Pins, "omitted": data.Omitted}
	if err = j.jsonOutput("paths", "discovery.paths", "codexploit/discovery-paths/v2", "paths.json", value); err != nil {
		return err
	}
	if err = j.jsonOutput("selection", "path.enhancement", "codexploit/path-enhancement/v2", "selection.json", selection); err != nil {
		return err
	}
	j.partial(int64(len(data.Paths)), "paths", []string{"Priority records static support, not vulnerability severity or exploitability. Filtered candidates remain unreviewed in the source artifact."})
	if len(filtered) > 0 {
		j.Result.Coverage.Truncated = true
		j.Result.Coverage.Reasons = append(j.Result.Coverage.Reasons, "path_budget")
	}
	return nil
}
