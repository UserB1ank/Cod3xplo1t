package workflow

import (
	"context"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

type PluginExecutor struct {
	Host    *plugin.Host
	Catalog *plugin.Catalog
}

func (e PluginExecutor) RecoverNode(ctx context.Context, scope artifact.Scope, node NodeRun) (NodeResult, error) {
	inv, err := e.Host.GetStatus(ctx, scope, node.InvocationID)
	if err != nil {
		return NodeResult{}, err
	}
	return invocationResult(inv), nil
}

func (e PluginExecutor) Execute(ctx context.Context, node CompiledNode, scope artifact.Scope, inputs []artifact.Ref, id string) (NodeResult, error) {
	record, err := e.Catalog.Get(ctx, node.PluginID, node.PluginVersion)
	if err != nil {
		return NodeResult{}, err
	}
	if record.PackageDigest != node.Plugin.PackageDigest || record.ManifestDigest != node.Plugin.ManifestDigest {
		return NodeResult{}, ErrConflict
	}
	inv, err := e.Host.Execute(ctx, plugin.Request{APIVersion: "codexploit/v1", ID: id, PluginID: node.PluginID, PluginVersion: node.PluginVersion, PackageDigest: record.PackageDigest, Scope: scope, Inputs: inputs, Config: node.Config, Budget: plugin.Budget{TimeoutSeconds: node.TimeoutSeconds}})
	if err != nil {
		return NodeResult{}, err
	}
	result, err := e.Host.Wait(ctx, scope, inv.ID)
	if err == nil {
		return invocationResult(result), nil
	}
	if ctx.Err() == nil {
		return NodeResult{InvocationID: inv.ID}, err
	}
	// Waiting can be cancelled between its ticker and store read. Always cancel
	// the host invocation before returning, including that race.
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		latest, readErr := e.Host.GetStatus(cleanup, scope, inv.ID)
		if readErr == nil {
			inv = latest
			if plugin.Terminal(inv.Status) {
				return invocationResult(inv), ctx.Err()
			}
			_, _ = e.Host.Cancel(cleanup, scope, inv.ID, inv.Version)
		}
		select {
		case <-cleanup.Done():
			return NodeResult{Status: "FAILED", InvocationID: inv.ID, ErrorCode: "cancellation_unconfirmed"}, ErrInvalid
		case <-ticker.C:
		}
	}
}
func invocationResult(inv plugin.Invocation) NodeResult {
	return NodeResult{Status: inv.Status, InvocationID: inv.ID, Outputs: inv.Outputs, ErrorCode: inv.ErrorCode}
}
