package mcp_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	internalmcp "github.com/open-mcp-ai/Codexploit/internal/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestProjectDiagnosticsReadsSourceBeforeGraphPublication(t *testing.T) {
	store := storage.NewMemory()
	ctx := context.Background()
	if _, err := store.CreateProject(ctx, storage.Project{ID: "project", Name: "fixture"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	tree := filepath.Join(root, repository.TreeDirName)
	if err := os.Mkdir(tree, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "README.md"), []byte("source exists\nsecond line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.PutSnapshot(ctx, "project", &repository.Snapshot{SnapshotID: testSnapshotID, Stats: repository.Stats{Files: 1, Bytes: 26}}); err != nil {
		t.Fatal(err)
	}
	svc := graph.NewService(store, treeResolver{dir: root})
	client, err := internalmcp.NewProjectClient(ctx, svc, store, "project", testSnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	status := callOK(t, client, "inspect_project", map[string]any{"snapshot_id": testSnapshotID, "section": "source"})
	if status["snapshot_present"] != true || status["graph_ready"] != false || status["tree_present"] != true {
		t.Fatalf("source existence must be independent of graph readiness: %+v", status)
	}
	source := callOK(t, client, "read_source_file", map[string]any{"snapshot_id": testSnapshotID, "file": "README.md", "start_line": 2, "max_lines": 1})
	if source["content"] != "second line\n" {
		t.Fatalf("source window: %+v", source)
	}
	if got := callErr(t, client, "graph_summary", map[string]any{"snapshot_id": testSnapshotID}); !strings.Contains(got, "graph_not_ready") {
		t.Fatalf("graph absence must be explicit: %s", got)
	}
	for _, file := range []string{"../README.md", "/etc/passwd", ".env", "missing.go"} {
		got := callErr(t, client, "read_source_file", map[string]any{"snapshot_id": testSnapshotID, "file": file})
		if strings.HasPrefix(got, "internal:") {
			t.Fatalf("a rejected or missing source path is not an internal fault: %s", got)
		}
	}
	callErr(t, client, "inspect_project", map[string]any{"snapshot_id": "foreign", "section": "source"})
	t.Run("operational diagnosis is project scoped and excludes configuration", func(t *testing.T) {
		_, err := store.CreateAnalysisRun(ctx, storage.AnalysisRun{ID: "analysis-failed", ProjectID: "project", SnapshotID: testSnapshotID, WorkflowRunID: "workflow-failed", PlanID: "plan", State: "FAILED", FailureCode: "selection_budget_exceeded", Stages: []storage.AnalysisRunStage{{Key: "semantic", Status: "FAILED", ErrorCode: "selection_budget_exceeded"}}}, "")
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = store.CreateInvocation(ctx, plugin.Invocation{ID: "invocation", Status: "FAILED", ErrorCode: "selection_budget_exceeded", Request: plugin.Request{Scope: artifact.Scope{ProjectID: "project", SourceID: "legacy-project", SnapshotID: testSnapshotID}, Config: json.RawMessage(`{"password":"private-fixture-value"}`)}})
		if err != nil {
			t.Fatal(err)
		}
		for _, section := range []string{"analysis", "workflow", "plugins", "tasks", "paths", "findings", "reports", "artifacts", "system", "invocations"} {
			out := callOK(t, client, "inspect_project", map[string]any{"snapshot_id": testSnapshotID, "section": section})
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), "private-fixture-value") {
				t.Fatalf("configuration leaked in %s", section)
			}
			if section == "analysis" && !strings.Contains(string(raw), "selection_budget_exceeded") {
				t.Fatalf("analysis failure missing: %s", raw)
			}
		}
	})
}

func TestProjectPluginDiagnosticsUsesCurrentWorkerPolicy(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemory()
	if _, err := store.CreateProject(ctx, storage.Project{ID: "project", Name: "fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutSnapshot(ctx, "project", &repository.Snapshot{SnapshotID: testSnapshotID}); err != nil {
		t.Fatal(err)
	}
	objects, err := artifact.NewLocal(t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := plugin.NewCatalogForWorker(ctx, store, "worker-fixture")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join("..", "..", "plugins", "joern", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: store, Artifacts: objects, Scopes: store, Executors: []plugin.Executor{{Manifest: manifest, PackageDigest: strings.Repeat("a", 64), OperationID: "parse", RunOutputs: func(context.Context, plugin.Invocation, [][]byte) (plugin.RawResult, error) {
		return plugin.RawResult{}, plugin.ErrUnsupported
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	client, err := internalmcp.NewProjectClient(ctx, graph.NewService(store, nil), store, "project", testSnapshotID, catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	before := callOK(t, client, "inspect_project", map[string]any{"snapshot_id": testSnapshotID, "section": "plugins", "limit": 20})
	rows, err := store.ListPluginInstallations(ctx)
	if err != nil {
		t.Fatalf("installations %v %v", rows, err)
	}
	var row plugin.Installation
	for _, installation := range rows {
		if installation.Release.PluginID == "codexploit.joern" {
			row = installation
		}
	}
	if row.ID == "" {
		t.Fatal("Joern installation missing")
	}
	expected := row.Version
	row.Version++
	row.Enabled = false
	if _, err := store.SavePluginInstallation(ctx, row, expected); err != nil {
		t.Fatal(err)
	}
	after := callOK(t, client, "inspect_project", map[string]any{"snapshot_id": testSnapshotID, "section": "plugins", "limit": 20})
	status := func(page map[string]any) (bool, bool) {
		raw, _ := json.Marshal(page)
		var decoded struct {
			Plugins []struct {
				ID         string `json:"id"`
				Enabled    bool   `json:"enabled"`
				Executable bool   `json:"executable"`
			}
		}
		if json.Unmarshal(raw, &decoded) != nil {
			t.Fatal("invalid plugin page")
		}
		for _, p := range decoded.Plugins {
			if p.ID == "codexploit.joern" {
				return p.Enabled, p.Executable
			}
		}
		t.Fatal("Joern absent in page")
		return false, false
	}
	wasEnabled, wasExecutable := status(before)
	enabled, executable := status(after)
	if !wasEnabled || !wasExecutable || enabled || executable {
		t.Fatalf("worker policy not reflected: enabled/executable %v/%v -> %v/%v", wasEnabled, wasExecutable, enabled, executable)
	}
}
