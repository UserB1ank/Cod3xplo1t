package plugin_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func hostFixture(t *testing.T, files map[string]string) (*plugin.Host, plugin.Request, *artifact.Local, *storage.Memory) {
	t.Helper()
	ctx := context.Background()
	root, source := t.TempDir(), t.TempDir()
	for name, data := range files {
		file := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := repository.NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := manager.Create(ctx, repository.Source{Raw: source})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Remove(snap.SnapshotID) })
	index := storage.NewMemory()
	if err := index.PutProject(ctx, storage.Project{ID: "project-parser"}); err != nil {
		t.Fatal(err)
	}
	if err := index.PutSnapshot(ctx, "project-parser", snap); err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewLocal(filepath.Join(root, "artifacts"), index)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := index.ArtifactScope(ctx, "project-parser", snap.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifact.PublishSnapshot(ctx, store, scope, snap); err != nil {
		t.Fatal(err)
	}
	refs, err := store.List(ctx, scope, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	var input artifact.Ref
	for _, ref := range refs {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref
		}
	}
	catalog, err := plugin.NewCatalog(ctx, index)
	if err != nil {
		t.Fatal(err)
	}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Artifacts: store, Scopes: index})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return host, plugin.Request{APIVersion: "codexploit/v1", ID: "inv-fixture", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(), Scope: scope, Inputs: []artifact.Ref{input}, Config: json.RawMessage(`{}`)}, store, index
}

func TestGoParserASTBudgetIsInclusiveAndNeverPublishesPartialOutputs(t *testing.T) {
	host, request, store, _ := hostFixture(t, map[string]string{"main.go": "package p\nvar X int\n"})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The native syntax tree has six nodes: File, package Ident, GenDecl,
	// ValueSpec, variable Ident, and type Ident.
	request.Budget.MaxASTNodes = 6
	inv, err := host.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(ctx, request.Scope, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "SUCCEEDED" {
		t.Fatalf("inclusive budget: %+v", done)
	}
	request.ID = "inv-over-budget"
	request.Budget.MaxASTNodes = 5
	inv, err = host.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	done, err = host.Wait(ctx, request.Scope, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "FAILED" || done.ErrorCode != "budget_exceeded" || len(done.Outputs) != 0 {
		t.Fatalf("budget result: %+v", done)
	}
	if _, _, err := store.Open(ctx, request.Scope, "artifact-"+inv.ID+"-ast", 8<<20); !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("partial output visible: %v", err)
	}
}

func TestGoParserDoesNotReportOtherLanguagesAsScanned(t *testing.T) {
	host, request, _, _ := hostFixture(t, map[string]string{"app.py": "print('offline fixture')\n"})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inv, err := host.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(ctx, request.Scope, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "UNSUPPORTED" || done.Coverage.ParsedFiles != 0 || done.Coverage.UnhandledFiles != 1 || len(done.Outputs) != 0 {
		t.Fatalf("unsupported language claimed as scanned: %+v", done)
	}
}

func TestGoPluginCancellationFencesLateOutputs(t *testing.T) {
	host, request, store, _ := hostFixture(t, map[string]string{"main.go": "package main\n" + strings.Repeat("var X int\n", 50000)})
	request.Budget.MaxASTNodes = 500000
	request.Budget.MaxOutputBytes = 64 << 20
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inv, err := host.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	for {
		current, err := host.GetStatus(ctx, request.Scope, inv.ID)
		if err != nil {
			t.Fatal(err)
		}
		cancelled, err := host.Cancel(ctx, request.Scope, inv.ID, current.Version)
		if errors.Is(err, plugin.ErrConflict) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if cancelled.Status != "CANCELLED" {
			t.Fatalf("cancel: %+v", cancelled)
		}
		break
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	done, err := host.GetStatus(ctx, request.Scope, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "CANCELLED" || len(done.Outputs) != 0 {
		t.Fatalf("late completion: %+v", done)
	}
	refs, err := store.List(ctx, request.Scope, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if ref.Producer.InvocationID == inv.ID {
			t.Fatalf("cancelled output became visible: %+v", ref)
		}
	}
}

func TestGoPluginRejectsInvalidConfigVersionsAndForgedInputs(t *testing.T) {
	host, base, _, _ := hostFixture(t, map[string]string{"main.go": "package p\n"})
	for _, name := range []string{"protocol", "config", "package", "input", "scope", "budget", "id"} {
		t.Run(name, func(t *testing.T) {
			request := base
			request.Inputs = append([]artifact.Ref{}, base.Inputs...)
			want := plugin.ErrInvalid
			switch name {
			case "id":
				request.ID = "_invalid"
			case "protocol":
				request.APIVersion = "codexploit/v99"
			case "config":
				request.Config = json.RawMessage(`{"unexpected":true}`)
			case "package":
				request.PackageDigest = strings.Repeat("0", 64)
				want = plugin.ErrConflict
			case "input":
				request.Inputs[0].SHA256 = strings.Repeat("0", 64)
				want = plugin.ErrConflict
			case "scope":
				request.Scope.ProjectID = "other-project"
				want = plugin.ErrNotFound
			case "budget":
				request.Budget.TimeoutSeconds = 121
			}
			if _, err := host.Execute(context.Background(), request); !errors.Is(err, want) {
				t.Fatalf("invalid request: %v, want %v", err, want)
			}
		})
	}
}

func TestNewPluginHostReportsInterruptedPersistedWork(t *testing.T) {
	_, request, store, index := hostFixture(t, map[string]string{"main.go": "package main\n"})
	request.ID = "inv-interrupted"
	request.Budget = plugin.Budget{MaxInputBytes: 64 << 20, MaxOutputBytes: 16 << 20, MaxFiles: 2000, MaxFileBytes: 1 << 20, MaxASTNodes: 100000, TimeoutSeconds: 60}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, _, err := index.CreateInvocation(context.Background(), plugin.Invocation{ID: request.ID, Request: request, RequestDigest: strings.Repeat("0", 64), ConfigDigest: strings.Repeat("1", 64), Status: "RUNNING", Version: 2, Outputs: []artifact.Ref{}, Limitations: []string{}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	catalog, err := plugin.NewCatalog(context.Background(), index)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Artifacts: store, Scopes: index})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	inv, err := restarted.GetStatus(context.Background(), request.Scope, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Status != "FAILED" || inv.ErrorCode != "host_restarted" || inv.Version != 3 || len(inv.Outputs) != 0 {
		t.Fatalf("orphaned work remained runnable: %+v", inv)
	}
}

func TestPluginStartRetryReturnsTheSameInvocation(t *testing.T) {
	host, request, _, _ := hostFixture(t, map[string]string{"main.go": "package main\n" + strings.Repeat("var X int\n", 50000)})
	request.Budget.MaxASTNodes = 500000
	request.Budget.MaxOutputBytes = 64 << 20
	first, err := host.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := request
	secondRequest.ID = "inv-second-active"
	if _, err := host.Execute(context.Background(), secondRequest); err != nil {
		t.Fatal(err)
	}
	retry, err := host.Execute(context.Background(), request)
	if err != nil || retry.ID != first.ID || retry.RequestDigest != first.RequestDigest {
		t.Fatalf("idempotent start: %+v %v", retry, err)
	}
}

func TestGoPluginProducesNativeSyntaxAndFactsFromPinnedInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, source := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "main.go"), []byte("package main\nfunc Handler(){println(1)}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := repository.NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := manager.Create(ctx, repository.Source{Raw: source})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Remove(snap.SnapshotID) })
	index := storage.NewMemory()
	if err := index.PutProject(ctx, storage.Project{ID: "project-parser"}); err != nil {
		t.Fatal(err)
	}
	if err := index.PutSnapshot(ctx, "project-parser", snap); err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewLocal(filepath.Join(root, "artifacts"), index)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := index.ArtifactScope(ctx, "project-parser", snap.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifact.PublishSnapshot(ctx, store, scope, snap); err != nil {
		t.Fatal(err)
	}
	refs, err := store.List(ctx, scope, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	var input artifact.Ref
	for _, ref := range refs {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref
		}
	}
	catalog, err := plugin.NewCatalog(ctx, index)
	if err != nil {
		t.Fatal(err)
	}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Artifacts: store, Scopes: index})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	run, err := host.Execute(ctx, plugin.Request{APIVersion: "codexploit/v1", ID: "inv-parser-fixture", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(), Scope: scope, Inputs: []artifact.Ref{input}, Config: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	finished, err := host.Wait(ctx, scope, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if finished.Status != "SUCCEEDED" || finished.Coverage.ParsedFiles != 1 || len(finished.Outputs) != 2 {
		t.Fatalf("parse outcome: %+v", finished)
	}
	for _, ref := range finished.Outputs {
		reader, _, err := store.Open(ctx, scope, ref.ID, 8<<20)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if ref.Producer.InvocationID != run.ID || ref.Producer.PluginVersion != plugin.BuiltinVersion {
			t.Fatalf("wrong producer: %+v", ref.Producer)
		}
		if ref.Kind == "code.ast" && !strings.Contains(string(data), "FuncDecl") {
			t.Fatalf("native AST missing: %s", data)
		}
		if ref.Kind == "code.facts" && !strings.Contains(string(data), "Handler") {
			t.Fatalf("real declaration missing: %s", data)
		}
	}
}
