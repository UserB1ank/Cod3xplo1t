package processplugin_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin/wire"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scanner"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func buildScanner(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain is required for the scanner integration test: %v", err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	name := "scanner"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	command := exec.Command(goBin, "build", "-trimpath", "-o", binary, "./cmd/scanner")
	command.Dir = root
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build scanner: %v\n%s", err, output)
	}
	return binary
}

func scannerPackage(t *testing.T, binary string) string {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "codexploit.static-patterns@1.0.0")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), scanner.Manifest(), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "scanner")
	if runtime.GOOS == "windows" {
		target += ".exe"
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRealScannerRunsThroughTheHostOverAFrozenSnapshot(t *testing.T) {
	binary := buildScanner(t)
	packageRoot := scannerPackage(t, binary)
	executors, err := processplugin.Executors(packageRoot)
	if err != nil || len(executors) != 1 {
		t.Fatalf("Executors = %+v %v", executors, err)
	}
	executor := executors[0]
	var manifest plugin.Manifest
	if err := json.Unmarshal(executor.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	work := t.TempDir()
	source := t.TempDir()
	files := map[string]string{
		"main.go": "package main\n\nimport \"os/exec\"\n\nfunc run(input string) {\n\texec.Command(\"sh\", \"-c\", input)\n\texec.Command(\"echo\", \"safe\")\n}\n",
		"db.go":   "package main\n\nimport \"database/sql\"\n\nfunc find(db *sql.DB, id string) {\n\tdb.Query(\"SELECT * FROM t WHERE id=\" + id)\n}\n",
		"go.mod":  "module example.test/scanner\n\ngo 1.26\n",
	}
	for name, body := range files {
		path := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := repository.NewManager(work)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := manager.Create(ctx, repository.Source{Raw: source})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Remove(snap.SnapshotID) })
	index := storage.NewMemory()
	if err := index.PutProject(ctx, storage.Project{ID: "project-scanner"}); err != nil {
		t.Fatal(err)
	}
	if err := index.PutSnapshot(ctx, "project-scanner", snap); err != nil {
		t.Fatal(err)
	}
	objects, err := artifact.NewLocal(filepath.Join(work, "artifacts"), index)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := index.ArtifactScope(ctx, "project-scanner", snap.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifact.PublishSnapshot(ctx, objects, scope, snap); err != nil {
		t.Fatal(err)
	}
	refs, err := objects.List(ctx, scope, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	var input artifact.Ref
	for _, ref := range refs {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref
		}
	}
	if input.ID == "" {
		t.Fatal("source tar was not published")
	}
	catalog, err := plugin.NewCatalog(ctx, index)
	if err != nil {
		t.Fatal(err)
	}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Artifacts: objects, Scopes: index, Executors: executors})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })

	inv, err := host.Execute(ctx, plugin.Request{
		APIVersion:    "codexploit/v1",
		ID:            "inv-scanner-e2e",
		PluginID:      manifest.ID,
		PluginVersion: manifest.Version,
		PackageDigest: executor.PackageDigest,
		Scope:         scope,
		Inputs:        []artifact.Ref{input},
		Config:        json.RawMessage(`{"max_alerts":10}`),
		Budget:        plugin.Budget{TimeoutSeconds: 30},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	done, err := host.Wait(ctx, scope, inv.ID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if done.Status != "SUCCEEDED" {
		t.Fatalf("invocation = %+v", done)
	}
	if len(done.Outputs) != 2 {
		t.Fatalf("outputs = %+v", done.Outputs)
	}
	document, err := host.Result(ctx, scope, inv.ID, 8<<20)
	if err != nil {
		t.Fatalf("Result: %v", err)
	}
	if len(document.Candidates) != 2 || len(document.Paths) != 0 || len(document.Nodes) != 0 {
		t.Fatalf("document = %+v", document)
	}
	joined := strings.Join(document.Limitations, "\n")
	if !strings.Contains(joined, "taint") || !strings.Contains(joined, "not executed") {
		t.Fatalf("limitations = %+v", document.Limitations)
	}
	var native artifact.Ref
	for _, ref := range done.Outputs {
		if ref.SchemaID == "codexploit/scanner-alerts/v1" {
			native = ref
		}
	}
	if native.ID == "" {
		t.Fatal("native report ref missing")
	}
	reader, _, err := objects.Open(ctx, scope, native.ID, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	var report wire.ScannerReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Tool.ID != scanner.ID || report.Tool.Version != scanner.Version || len(report.Alerts) != 2 {
		t.Fatalf("native report = %+v", report)
	}
	rules := []string{report.Alerts[0].RuleID, report.Alerts[1].RuleID}
	if !reflect.DeepEqual(rules, []string{"CP001", "CP002"}) && !reflect.DeepEqual(rules, []string{"CP002", "CP001"}) {
		t.Fatalf("rules = %+v", rules)
	}
}

func TestScannerCandidatesArePublishedIntoAnImmutableKnowledgeRevision(t *testing.T) {
	binary := buildScanner(t)
	packageRoot := scannerPackage(t, binary)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	workspace := t.TempDir()
	rt, err := app.Build(ctx, app.Config{Workspace: workspace, DBPath: "memory", PluginPackages: packageRoot})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer rt.Close()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "main.go"), []byte("package main\n\nimport \"os/exec\"\n\nfunc run(input string) {\n\texec.Command(\"sh\", \"-c\", input)\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.Store.PutProject(ctx, storage.Project{ID: "scanner-project", Name: "Scanner"}); err != nil {
		t.Fatal(err)
	}
	snap, err := rt.Manager.Create(ctx, repository.Source{Kind: repository.KindDir, Raw: source})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Manager.Remove(snap.SnapshotID) })
	if err := rt.Store.PutSnapshot(ctx, "scanner-project", snap); err != nil {
		t.Fatal(err)
	}
	scope := artifact.Scope{ProjectID: "scanner-project", SourceID: "legacy-scanner-project", SnapshotID: snap.SnapshotID}
	if err := artifact.PublishSnapshot(ctx, rt.WorkflowCompiler.Artifacts, scope, snap); err != nil {
		t.Fatal(err)
	}
	refs, err := rt.WorkflowCompiler.Artifacts.List(ctx, scope, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	var input artifact.Ref
	for _, ref := range refs {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref
		}
	}
	if input.ID == "" {
		t.Fatal("source tar missing")
	}
	spec := workflow.Spec{
		APIVersion: "codexploit/v1", ID: "scanner-workflow", Version: "1.0.0",
		Name: "Process scanner", Description: "Scan a frozen source snapshot", Inputs: []string{"source.snapshot"},
		Nodes: []workflow.Node{{
			ID: "scan", PluginID: scanner.ID, PluginVersion: scanner.Version, Needs: []string{},
			Config: json.RawMessage(`{"max_alerts":10}`), TimeoutSeconds: 30,
		}},
	}
	raw, _ := json.Marshal(spec)
	if _, err := rt.Workflows.Save(ctx, scope.ProjectID, raw, ""); err != nil {
		t.Fatal(err)
	}
	plan, err := rt.WorkflowCompiler.Compile(ctx, scope.ProjectID, spec.ID, spec.Version, workflow.CompileRequest{
		APIVersion: "codexploit/v1", SnapshotID: scope.SnapshotID, Inputs: []string{input.ID}, Language: "Go",
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	run, err := rt.WorkflowRunner.Start(ctx, workflow.StartRequest{
		ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID, PlanID: plan.ID,
		Task: workflow.TaskDefinition{Name: "Scanner task", Objective: "Publish scanner candidates"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	var final workflow.Run
	for {
		final, err = rt.WorkflowRunner.Get(ctx, scope.ProjectID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if workflow.RunTerminal(final.Status) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run did not settle: %+v", final)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if final.Status != "SUCCEEDED" {
		t.Fatalf("run = %+v", final)
	}
	published := false
	for _, node := range final.Nodes {
		if node.NodeID == "scan" {
			if node.Status != "SUCCEEDED" || node.InvocationID == "" {
				t.Fatalf("scan node = %+v", node)
			}
		}
		if node.NodeID == "$publish" {
			if node.Status != "SUCCEEDED" || len(node.Knowledge) != 1 {
				t.Fatalf("publish node = %+v", node)
			}
			published = true
		}
	}
	if !published {
		t.Fatal("publish node did not run")
	}
	store, ok := rt.Store.(publication.Store)
	if !ok {
		t.Fatal("store cannot read revisions")
	}
	head, err := store.KnowledgeHead(ctx, publication.Scope{ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID})
	if err != nil || head == "rev-0" {
		t.Fatalf("knowledge head = %s %v", head, err)
	}
	revision, err := store.GetKnowledgeRevision(ctx, publication.Scope{ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID}, head)
	if err != nil {
		t.Fatal(err)
	}
	alerts := 0
	for _, fact := range revision.Facts {
		if fact.Kind == "scanner.alert" {
			alerts++
			if fact.Observations[0].Attributes["severity_hint"] != "high" || fact.Location == nil || fact.Location.File != "main.go" {
				t.Fatalf("scanner fact = %+v", fact)
			}
		}
	}
	if alerts != 1 {
		t.Fatalf("scanner facts = %d, revision = %+v", alerts, revision)
	}
	groups, err := rt.Findings.List(ctx, findings.ListQuery{ProjectID: scope.ProjectID})
	if err != nil || groups.Total != 1 || len(groups.Groups) != 1 || len(groups.Groups[0].Observations) != 1 {
		t.Fatalf("finding groups = %+v %v", groups, err)
	}
	observation := groups.Groups[0].Observations[0]
	if observation.RuleID != "CP001" || observation.TaskID == "" || observation.Producer.PluginID != scanner.ID || observation.FingerprintVersion != findings.FingerprintVersion {
		t.Fatalf("observation = %+v", observation)
	}
}
