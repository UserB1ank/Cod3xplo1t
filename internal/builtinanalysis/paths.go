package builtinanalysis

import (
	"context"
	"encoding/json"

	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func paths(ctx context.Context, inv plugin.Invocation, inputs [][]byte) ([]byte, error) {
	var security plugin.DiscoveryDocument
	var report plugin.NativeReport
	if json.Unmarshal(inputs[0], &security) != nil || json.Unmarshal(inputs[1], &report) != nil || security.NativeArtifact != inv.Request.Inputs[1] || security.Scope != inv.Request.Scope || report.Scope != inv.Request.Scope || report.Format != "codexploit/semantic-native/v1" || report.Graph == nil || report.Surface == nil {
		return nil, plugin.ErrInvalid
	}
	memory := storage.NewMemory()
	if err := memory.ReplaceGraph(ctx, report.Scope.SnapshotID, report.Graph); err != nil {
		return nil, err
	}
	if err := memory.ReplaceASG(ctx, report.Scope.SnapshotID, report.Surface); err != nil {
		return nil, err
	}
	code := graph.NewService(memory, nil)
	surface := graph.NewASGService(memory, code)
	facts := graph.NewPathFacts(code, surface, memory)
	var config struct {
		MaxPaths int `json:"max_paths"`
		MaxDepth int `json:"max_depth"`
	}
	_ = json.Unmarshal(inv.Request.Config, &config)
	if config.MaxPaths == 0 {
		config.MaxPaths = 200
	}
	result, err := path.NewEngine(facts, facts).Generate(ctx, report.Scope.SnapshotID, path.GenerateOptions{Budget: path.Budget{MaxDepth: config.MaxDepth}, Limits: path.Limits{MaxPaths: config.MaxPaths}})
	if err != nil {
		return nil, err
	}
	report.Format = "codexploit/paths-native/v1"
	report.Paths = result
	report.Coverage.Truncated = report.Coverage.Truncated || result.Coverage.Truncated
	report.Limitations = append(report.Limitations, result.Limitations...)
	return json.Marshal(report)
}
