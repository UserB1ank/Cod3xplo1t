package workflow_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func TestDirectorySourceCompilesAbove500MiBWithExplicitBudgetWithoutAnArchive(t *testing.T) {
	rt, err := app.Build(t.Context(), app.Config{Workspace: t.TempDir(), DBPath: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.Store.PutProject(t.Context(), storage.Project{ID: "project", Name: "Directory source"}); err != nil {
		t.Fatal(err)
	}
	source, err := rt.Manager.ImportSource(t.Context(), repository.Source{Kind: repository.KindDir, Raw: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Manager.Remove(source.SnapshotID) })
	if err := os.Chmod(source.TreeDir(), 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(source.TreeDir(), "source.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(600 << 20); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := source.Freeze(); err != nil {
		t.Fatal(err)
	}
	if err := rt.Store.PutSnapshot(t.Context(), "project", source); err != nil {
		t.Fatal(err)
	}
	index := rt.Store.(artifact.Index)
	scope, err := index.ArtifactScope(t.Context(), "project", source.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := rt.WorkflowCompiler.Artifacts.(artifact.DirectoryStore).SourceDirectoryRef(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../plugins/joern/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	executors := []plugin.Executor{}
	for _, operation := range []string{"parse", "taint", "paths", "enhance"} {
		executors = append(executors, plugin.Executor{Manifest: raw, PackageDigest: strings.Repeat("b", 64), OperationID: operation, RunOutputs: func(context.Context, plugin.Invocation, [][]byte) (plugin.RawResult, error) {
			t.Error("compilation executed a plugin")
			return plugin.RawResult{}, plugin.ErrUnsupported
		}})
	}
	host, err := plugin.NewHost(plugin.Deps{Catalog: rt.PluginCatalog, Repository: rt.Store.(plugin.Repository), Scopes: index, Artifacts: rt.WorkflowCompiler.Artifacts.(plugin.ArtifactStore), Executors: executors})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	spec := workflow.DefaultAnalysisSpec()
	raw, _ = json.Marshal(spec)
	if _, err := rt.Workflows.Save(t.Context(), "project", raw, ""); err != nil {
		t.Fatal(err)
	}
	request := workflow.CompileRequest{APIVersion: "codexploit/v1", SnapshotID: source.SnapshotID, Inputs: []string{ref.ID}, Language: "Go"}
	if _, err := rt.WorkflowCompiler.Compile(t.Context(), "project", spec.ID, spec.Version, request); err == nil {
		t.Fatal("default 500 MiB budget ignored")
	}
	request.MaxInputBytes = ref.Bytes
	plan, err := rt.WorkflowCompiler.Compile(t.Context(), "project", spec.ID, spec.Version, request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.MaxInputBytes != 600<<20 || plan.Inputs[0].SchemaID != artifact.SourceDirectorySchema {
		t.Fatalf("plan: %+v", plan)
	}
	refs, err := rt.WorkflowCompiler.Artifacts.List(t.Context(), scope, "", 100)
	if err != nil || len(refs) != 0 {
		t.Fatalf("archives were created: %+v %v", refs, err)
	}
}
