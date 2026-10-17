package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

var ErrNormalization = errors.New("plugin: normalization failed")
var ErrReportVersion = errors.New("plugin: unsupported native report version")

// Executor is a compiled adapter, supplied by the composition root. Imported
// manifests cannot install code or add adapters through the HTTP API.
type Executor struct {
	Manifest      json.RawMessage
	PackageDigest string
	InputSchemas  []string
	InputPlugins  []string
	Run           func(context.Context, Invocation, [][]byte) ([]byte, error)
}

func (h *Host) validateInputs(ctx context.Context, request Request) error {
	schemas := []string{"codexploit/source-tar/v1"}
	owners := []string{""}
	if request.PluginID != BuiltinID {
		executor, ok := h.executors[request.PluginID+"@"+request.PluginVersion]
		if !ok {
			return ErrUnsupported
		}
		schemas, owners = executor.InputSchemas, executor.InputPlugins
	}
	if len(request.Inputs) != len(schemas) {
		return ErrInvalid
	}
	var total int64
	var previous string
	for i, ref := range request.Inputs {
		if ref.Scope != request.Scope || ref.SchemaID != schemas[i] {
			return ErrInvalid
		}
		total += ref.Bytes
		if total > request.Budget.MaxInputBytes {
			return ErrBudget
		}
		actual, err := h.deps.Artifacts.Stat(ctx, request.Scope, ref.ID, request.Budget.MaxInputBytes)
		if err != nil {
			return err
		}
		if actual != ref {
			return ErrConflict
		}
		if i < len(owners) && owners[i] != "" {
			origin, err := h.deps.Repository.GetInvocation(ctx, request.Scope, ref.Producer.InvocationID)
			if err != nil || origin.Request.PluginID != owners[i] || (origin.Status != "SUCCEEDED" && origin.Status != "PARTIAL") {
				return ErrInvalid
			}
			matched := false
			for _, out := range origin.Outputs {
				if out == ref {
					matched = true
				}
			}
			if !matched {
				return ErrInvalid
			}
			if request.PluginID == "builtin.security-semantics" && (len(origin.Request.Inputs) != 1 || origin.Request.Inputs[0] != request.Inputs[0]) {
				return ErrInvalid
			}
			if request.PluginID == "builtin.discovery-paths" {
				if previous != "" && previous != origin.ID {
					return ErrInvalid
				}
				previous = origin.ID
			}
		}
	}
	return nil
}

func (h *Host) prepareDocument(ctx context.Context, inv Invocation, suffix, kind, schema string, raw []byte) (artifact.Ref, error) {
	ref := artifact.Ref{ID: "artifact-" + inv.ID + "-" + suffix, Kind: kind, Scope: inv.Request.Scope, SHA256: digest(raw), Bytes: int64(len(raw)), MediaType: "application/json", SchemaID: schema, Producer: artifact.Producer{PluginID: inv.Request.PluginID, PluginVersion: inv.Request.PluginVersion, InvocationID: inv.ID, ConfigDigest: inv.ConfigDigest}}
	return h.deps.Artifacts.Prepare(ctx, ref, bytes.NewReader(raw), inv.Request.Budget.MaxOutputBytes)
}

func (h *Host) analyze(ctx context.Context, inv Invocation) ([]artifact.Ref, Coverage, []string, error) {
	executor := h.executors[inv.Request.PluginID+"@"+inv.Request.PluginVersion]
	inputs := [][]byte{}
	for _, ref := range inv.Request.Inputs {
		reader, _, err := h.deps.Artifacts.Open(ctx, inv.Request.Scope, ref.ID, inv.Request.Budget.MaxInputBytes)
		if err != nil {
			return nil, Coverage{}, nil, err
		}
		raw, err := io.ReadAll(io.LimitReader(reader, inv.Request.Budget.MaxInputBytes+1))
		reader.Close()
		if err != nil {
			return nil, Coverage{}, nil, err
		}
		if int64(len(raw)) > inv.Request.Budget.MaxInputBytes {
			return nil, Coverage{}, nil, ErrBudget
		}
		inputs = append(inputs, raw)
	}
	raw, err := executor.Run(ctx, inv, inputs)
	if err != nil {
		return nil, Coverage{}, nil, err
	}
	native, err := h.prepareDocument(ctx, inv, "native", "report.document", "codexploit/builtin-native/v1", raw)
	if err != nil {
		return nil, Coverage{}, nil, err
	}
	document, err := (Normalizer{}).Normalize(inv, native, raw)
	if err == nil {
		err = ValidateDiscovery(document)
	}
	if err != nil {
		cause := ErrNormalization
		if errors.Is(err, ErrUnsupported) {
			cause = ErrReportVersion
		}
		return []artifact.Ref{native}, Coverage{}, []string{"Native evidence retained; no normalized claims are available"}, fmt.Errorf("%w: %v", cause, err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, Coverage{}, nil, err
	}
	inv.Request.Budget.MaxOutputBytes -= native.Bytes
	if inv.Request.Budget.MaxOutputBytes < 1 {
		return nil, document.Coverage, document.Limitations, ErrBudget
	}
	normalized, err := h.prepareDocument(ctx, inv, "normalized", document.Kind, "codexploit/discovery/v1", encoded)
	return []artifact.Ref{native, normalized}, document.Coverage, document.Limitations, err
}
