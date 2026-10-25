package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

type StageCoverage struct {
	Unit      string   `json:"unit"`
	Seen      *int64   `json:"seen"`
	Analyzed  *int64   `json:"analyzed"`
	Skipped   *int64   `json:"skipped"`
	Failed    *int64   `json:"failed"`
	Truncated bool     `json:"truncated"`
	Reasons   []string `json:"reasons"`
}

type RawOutput struct {
	Port      string
	Kind      string
	SchemaID  string
	Bytes     int64
	SHA256    string
	MediaType string
	Open      func() (io.ReadCloser, error)
}

type StageEvent struct {
	Seq     int    `json:"seq"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

type RawResult struct {
	Events      []StageEvent
	Status      string
	Outputs     []RawOutput
	Coverage    StageCoverage
	Limitations []string
	Close       func()
}

func validateStageCoverage(status string, c StageCoverage) error {
	if c.Unit == "" || len(c.Unit) > 100 || len(c.Reasons) > 100 {
		return ErrInvalid
	}
	var sum int64
	for _, n := range []*int64{c.Seen, c.Analyzed, c.Skipped, c.Failed} {
		if n != nil && (*n < 0 || *n > 1<<40) {
			return ErrInvalid
		}
	}
	for _, n := range []*int64{c.Analyzed, c.Skipped, c.Failed} {
		if n != nil {
			sum += *n
		}
	}
	if c.Seen != nil && sum > *c.Seen {
		return ErrInvalid
	}
	if status == "SUCCEEDED" && (c.Truncated || (c.Failed != nil && *c.Failed > 0)) {
		return ErrInvalid
	}
	if c.Truncated && len(c.Reasons) == 0 {
		return ErrInvalid
	}
	return nil
}

func executionKey(id, version, operation string) string {
	key := id + "@" + version
	if operation != "" {
		key += "#" + operation
	}
	return key
}

// BindInputPorts validates the named boundary without requiring any specific
// upstream tool. Inference is allowed only for an unambiguous kind/schema pair.
func BindInputPorts(op Operation, refs []artifact.Ref, names []string) ([]string, error) {
	if len(refs) > 100 || (len(names) > 0 && len(names) != len(refs)) {
		return nil, ErrInvalid
	}
	result := make([]string, len(refs))
	counts := map[string]int{}
	for i, ref := range refs {
		matches := []Port{}
		for _, p := range op.Inputs {
			if p.Kind == ref.Kind && p.SchemaID == ref.SchemaID && (len(names) == 0 || p.Name == names[i]) {
				matches = append(matches, p)
			}
		}
		if len(matches) != 1 {
			return nil, ErrInvalid
		}
		result[i] = matches[0].Name
		counts[result[i]]++
	}
	for _, p := range op.Inputs {
		if (p.Required && counts[p.Name] == 0) || (p.Cardinality == "one" && counts[p.Name] > 1) {
			return nil, ErrInvalid
		}
	}
	return result, nil
}

func (h *Host) validateStageInputs(ctx context.Context, request Request) error {
	var total int64
	for _, ref := range request.Inputs {
		if ref.Scope != request.Scope || ref.Bytes < 0 {
			return ErrInvalid
		}
		if ref.Bytes > request.Budget.MaxInputBytes-total {
			return ErrBudget
		}
		total += ref.Bytes
		actual, err := h.deps.Artifacts.Stat(ctx, request.Scope, ref.ID, request.Budget.MaxInputBytes)
		if err != nil {
			return err
		}
		if actual != ref {
			return ErrConflict
		}
	}
	return nil
}

func (h *Host) prepareStageOutputs(ctx context.Context, inv Invocation, executor Executor, inputs [][]byte) ([]artifact.Ref, Coverage, []string, error) {
	result, err := executor.RunOutputs(ctx, inv, inputs)
	if result.Close != nil {
		defer result.Close()
	}
	if err != nil {
		return nil, Coverage{}, nil, err
	}
	if result.Status != "SUCCEEDED" && result.Status != "PARTIAL" {
		return nil, Coverage{}, nil, ErrExecutionFailed
	}
	if err := validateStageCoverage(result.Status, result.Coverage); err != nil {
		return nil, Coverage{}, nil, &ExecutionError{Code: "output_contract_mismatch"}
	}
	record, err := h.deps.Catalog.Get(ctx, inv.Request.PluginID, inv.Request.PluginVersion)
	if err != nil {
		return nil, Coverage{}, nil, err
	}
	op, err := record.Manifest.Operation(inv.Request.OperationID)
	if err != nil {
		return nil, Coverage{}, nil, err
	}
	counts := map[string]int{}
	dataByPort := map[string]json.RawMessage{}
	refs := []artifact.Ref{}
	var total int64
	if len(result.Outputs) > inv.Request.Budget.MaxFiles {
		return nil, Coverage{}, nil, ErrBudget
	}
	for i, out := range result.Outputs {
		var port *Port
		for j := range op.Outputs {
			if op.Outputs[j].Name == out.Port {
				port = &op.Outputs[j]
				break
			}
		}
		if port == nil || port.Kind != out.Kind || port.SchemaID != out.SchemaID || out.Open == nil || out.Bytes < 0 {
			return nil, Coverage{}, nil, ErrInvalid
		}
		counts[out.Port]++
		if out.Bytes > inv.Request.Budget.MaxOutputBytes-total {
			return nil, Coverage{}, nil, ErrBudget
		}
		total += out.Bytes
		reader, err := out.Open()
		if err != nil {
			return nil, Coverage{}, nil, err
		}
		if out.Kind != "tool.native" {
			if out.Bytes > 64<<20 {
				_ = reader.Close()
				return nil, Coverage{}, nil, ErrBudget
			}
			raw, readErr := io.ReadAll(io.LimitReader(reader, inv.Request.Budget.MaxOutputBytes+1))
			closeErr := reader.Close()
			if readErr != nil || closeErr != nil || int64(len(raw)) != out.Bytes || digest(raw) != out.SHA256 {
				return nil, Coverage{}, nil, ErrInvalid
			}
			if validateStageReferences(inv, inputs, out.SchemaID, raw) != nil {
				return nil, Coverage{}, nil, &ExecutionError{Code: "output_contract_mismatch"}
			}
			if out.SchemaID == "codexploit/code-facts/v2" {
				raw, err = bindNativeMappingReferences(inv, result.Outputs, raw)
				if err != nil {
					return nil, Coverage{}, nil, &ExecutionError{Code: "output_contract_mismatch"}
				}
			}
			dataByPort[out.Port] = append([]byte(nil), raw...)
			encoded := raw
			var validateErr error
			if out.Kind == "report.document" {
				validateErr = validateReport(out.MediaType, raw)
			} else {
				encoded, validateErr = standardOutput(inv, out, raw, result.Coverage, result.Limitations)
			}
			if validateErr != nil {
				return nil, Coverage{}, nil, &ExecutionError{Code: "output_contract_mismatch"}
			}
			if int64(len(encoded)) > inv.Request.Budget.MaxOutputBytes-total+out.Bytes {
				return nil, Coverage{}, nil, ErrBudget
			}
			total += int64(len(encoded)) - out.Bytes
			out.Bytes = int64(len(encoded))
			out.SHA256 = digest(encoded)
			reader = io.NopCloser(bytes.NewReader(encoded))
		}
		ref := artifact.Ref{ID: fmt.Sprintf("artifact-%s-%s-%d", inv.ID, out.Port, i), Kind: out.Kind, SchemaID: out.SchemaID, Bytes: out.Bytes, SHA256: out.SHA256, MediaType: out.MediaType, Scope: inv.Request.Scope, Producer: artifact.Producer{PluginID: inv.Request.PluginID, PluginVersion: inv.Request.PluginVersion, InvocationID: inv.ID, ConfigDigest: inv.ConfigDigest, OperationID: inv.Request.OperationID, OutputPort: out.Port, PackageDigest: inv.Request.PackageDigest}}
		switch out.SchemaID {
		case "codexploit/code-facts/v2", "codexploit/security-facts/v2", "codexploit/discovery-paths/v2", "codexploit/path-enhancement/v2", "codexploit/report-input/v1":
			ref.Producer.NormalizerDigest = stageNormalizerDigest()
		}
		prepared, err := h.deps.Artifacts.Prepare(ctx, ref, reader, inv.Request.Budget.MaxOutputBytes)
		closeErr := reader.Close()
		if err != nil {
			return nil, Coverage{}, nil, err
		}
		if closeErr != nil {
			return nil, Coverage{}, nil, closeErr
		}
		refs = append(refs, prepared)
	}
	for _, p := range op.Outputs {
		if (p.Required && counts[p.Name] == 0) || (p.Cardinality == "one" && counts[p.Name] > 1) {
			return nil, Coverage{}, nil, ErrInvalid
		}
	}
	if op.Stage == "path.enhance" && op.Profile == "standard" {
		var source string
		var input json.RawMessage
		for i, ref := range inv.Request.Inputs {
			if ref.SchemaID == "codexploit/discovery-paths/v2" {
				source = ref.ID
				input, err = stageData(inputs[i])
				if err != nil {
					return nil, Coverage{}, nil, err
				}
			}
		}
		var paths, enhancement json.RawMessage
		for _, p := range op.Outputs {
			if p.SchemaID == "codexploit/discovery-paths/v2" {
				paths = dataByPort[p.Name]
			}
			if p.SchemaID == "codexploit/path-enhancement/v2" {
				enhancement = dataByPort[p.Name]
			}
		}
		if validateEnhancement(source, input, paths, enhancement) != nil {
			return nil, Coverage{}, nil, &ExecutionError{Code: "output_contract_mismatch"}
		}
	}
	coverage := Coverage{Truncated: result.Coverage.Truncated || result.Status == "PARTIAL", Stage: &result.Coverage, Events: result.Events}
	if result.Coverage.Unit == "files" {
		if result.Coverage.Seen != nil {
			coverage.InputFiles = int(*result.Coverage.Seen)
		}
		if result.Coverage.Analyzed != nil {
			coverage.ParsedFiles = int(*result.Coverage.Analyzed)
		}
		if result.Coverage.Failed != nil {
			coverage.UnparsedFiles = int(*result.Coverage.Failed)
		}
		if result.Coverage.Skipped != nil {
			coverage.UnhandledFiles = int(*result.Coverage.Skipped)
		}
	}
	return refs, coverage, result.Limitations, nil
}
