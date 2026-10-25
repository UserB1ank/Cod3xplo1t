package plugin

import (
	"context"
	"encoding/json"
	"io"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

type StageDocument struct {
	APIVersion  string            `json:"api_version"`
	Kind        string            `json:"kind"`
	SchemaID    string            `json:"schema_id"`
	Scope       artifact.Scope    `json:"scope"`
	Producer    artifact.Producer `json:"producer"`
	Inputs      []artifact.Ref    `json:"inputs"`
	Coverage    StageCoverage     `json:"coverage"`
	Limitations []string          `json:"limitations"`
	Data        json.RawMessage   `json:"data"`
}

// StandardResults reads host-authored immutable envelopes, not tool-native CPGs.
// A native-only invocation has an empty standard result set and makes no graph claim.
func (h *Host) StandardResults(ctx context.Context, scope artifact.Scope, id string, budget int64) ([]StageDocument, error) {
	inv, err := h.GetStatus(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	if inv.Status != "SUCCEEDED" && inv.Status != "PARTIAL" {
		return nil, ErrConflict
	}
	results := []StageDocument{}
	for _, ref := range inv.Outputs {
		if ref.SchemaID != "codexploit/code-facts/v2" && ref.SchemaID != "codexploit/security-facts/v2" && ref.SchemaID != "codexploit/discovery-paths/v2" {
			continue
		}
		reader, _, err := h.deps.Artifacts.Open(ctx, scope, ref.ID, budget)
		if err != nil {
			return nil, err
		}
		raw, readErr := io.ReadAll(io.LimitReader(reader, budget+1))
		closeErr := reader.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(len(raw)) > budget {
			return nil, ErrBudget
		}
		budget -= int64(len(raw))
		var document StageDocument
		if json.Unmarshal(raw, &document) != nil || document.APIVersion != "codexploit/v2" || document.Kind != ref.Kind || document.SchemaID != ref.SchemaID || document.Scope != scope || document.Producer != ref.Producer {
			return nil, ErrInvalid
		}
		results = append(results, document)
	}
	return results, nil
}
