package plugin_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func TestFailedStageRetainsObservedCoverageAndContextWithoutPublishingOutputs(t *testing.T) {
	old, request, objects, index := hostFixture(t, map[string]string{"main.go": "package main\n"})
	_ = old.Close()
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/parse.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := plugin.NewCatalog(t.Context(), index)
	if err != nil {
		t.Fatal(err)
	}
	executor := plugin.Executor{Manifest: raw, PackageDigest: strings.Repeat("c", 64), OperationID: "execute", RunOutputs: func(context.Context, plugin.Invocation, [][]byte) (plugin.RawResult, error) {
		seen, analyzed := int64(7), int64(2)
		return plugin.RawResult{Status: "FAILED", Coverage: plugin.StageCoverage{Unit: "files", Seen: &seen, Analyzed: &analyzed}, Limitations: []string{"joern:frontend=JAVASRC;step=parse;reason=memory_budget_exceeded"}, Outputs: []plugin.RawOutput{{Port: "code", Bytes: 10}}}, &plugin.ExecutionError{Code: "memory_budget_exceeded"}
	}}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Scopes: index, Artifacts: objects, Executors: []plugin.Executor{executor}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	request.PluginID = "example.parse"
	request.PluginVersion = "0.1.0"
	request.PackageDigest = executor.PackageDigest
	request.ID = "failed-with-observations"
	request.OperationID = "execute"
	inv, err := host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "FAILED" || done.ErrorCode != "memory_budget_exceeded" || len(done.Outputs) != 0 {
		t.Fatalf("failure published partial outputs: %+v", done)
	}
	if done.StageCoverage == nil || done.StageCoverage.Seen == nil || *done.StageCoverage.Seen != 7 || done.Coverage.ParsedFiles != 2 {
		t.Fatalf("failure lost observed coverage: %+v", done)
	}
	if !strings.Contains(strings.Join(done.Limitations, "\n"), "JAVASRC;step=parse") {
		t.Fatalf("failure lost context: %+v", done)
	}
}
