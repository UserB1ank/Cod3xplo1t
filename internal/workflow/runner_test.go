package workflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func runnerFixture(t *testing.T, spec workflow.Spec) (*app.Runtime, workflow.StartRequest) {
	t.Helper()
	ctx := context.Background()
	rt, err := app.Build(ctx, app.Config{Workspace: t.TempDir(), DBPath: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "main.go"), []byte("package main\nfunc main(){}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := rt.Store.PutProject(ctx, storage.Project{ID: "workflow-project", Name: "Fixture"}); err != nil {
		t.Fatal(err)
	}
	snap, err := rt.Manager.Create(ctx, repository.Source{Kind: repository.KindDir, Raw: source})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Manager.Remove(snap.SnapshotID) })
	if err := rt.Store.PutSnapshot(ctx, "workflow-project", snap); err != nil {
		t.Fatal(err)
	}
	scope := artifact.Scope{ProjectID: "workflow-project", SourceID: "legacy-workflow-project", SnapshotID: snap.SnapshotID}
	if err := artifact.PublishSnapshot(ctx, rt.WorkflowCompiler.Artifacts, scope, snap); err != nil {
		t.Fatal(err)
	}
	refs, err := rt.WorkflowCompiler.Artifacts.List(ctx, scope, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	input := ""
	for _, ref := range refs {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref.ID
		}
	}
	raw, _ := json.Marshal(spec)
	if _, err := rt.Workflows.Save(ctx, scope.ProjectID, raw, ""); err != nil {
		t.Fatal(err)
	}
	plan, err := rt.WorkflowCompiler.Compile(ctx, scope.ProjectID, spec.ID, spec.Version, workflow.CompileRequest{APIVersion: "codexploit/v1", SnapshotID: scope.SnapshotID, Inputs: []string{input}, Language: "Go"})
	if err != nil {
		t.Fatal(err)
	}
	return rt, workflow.StartRequest{ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID, PlanID: plan.ID, Task: workflow.TaskDefinition{Name: "Runtime fixture", Objective: "Exercise workflow behavior"}}
}

type barrierExecutor struct {
	delegate workflow.NodeExecutor
	entered  chan string
	release  chan struct{}
}

func (e barrierExecutor) Execute(ctx context.Context, node workflow.CompiledNode, scope artifact.Scope, inputs []artifact.Ref, id string) (workflow.NodeResult, error) {
	e.entered <- node.ID
	select {
	case <-ctx.Done():
		return workflow.NodeResult{}, ctx.Err()
	case <-e.release:
	}
	return e.delegate.Execute(ctx, node, scope, inputs, id)
}
func TestRunnerStartsIndependentNodesBeforeEitherCompletes(t *testing.T) {
	spec := fixture()
	a := spec.Nodes[2]
	a.ID = "left"
	b := a
	b.ID = "right"
	spec.Nodes = []workflow.Node{a, b}
	rt, request := runnerFixture(t, spec)
	entered := make(chan string, 2)
	release := make(chan struct{})
	executor := barrierExecutor{delegate: workflow.PluginExecutor{Host: rt.Plugins, Catalog: rt.PluginCatalog}, entered: entered, release: release}
	runner := workflow.NewRunner(rt.WorkflowCompiler, rt.Store.(workflow.RunRepository), executor, rt.WorkflowCompiler.Artifacts)
	defer runner.Close()
	run, err := runner.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	observed := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case id := <-entered:
			observed[id] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("independent nodes did not overlap: %v", observed)
		}
	}
	close(release)
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, err := runner.Get(context.Background(), request.ProjectID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if workflow.RunTerminal(status.Status) {
			if status.Status != "SUCCEEDED" || status.Nodes[0].InvocationID == status.Nodes[1].InvocationID {
				t.Fatalf("independent results: %+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nodes did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type forgedExecutor struct{}

func (forgedExecutor) Execute(_ context.Context, _ workflow.CompiledNode, scope artifact.Scope, inputs []artifact.Ref, _ string) (workflow.NodeResult, error) {
	ref := inputs[0]
	ref.Scope.ProjectID = "another-project"
	ref.Kind = "code.ast"
	return workflow.NodeResult{Status: "SUCCEEDED", InvocationID: "fixture-forged", Outputs: []artifact.Ref{ref}}, nil
}
func TestRunnerRefusesUnpublishedOrCrossScopeNodeOutputs(t *testing.T) {
	spec := fixture()
	spec.Nodes = spec.Nodes[2:]
	rt, request := runnerFixture(t, spec)
	runner := workflow.NewRunner(rt.WorkflowCompiler, rt.Store.(workflow.RunRepository), forgedExecutor{}, rt.WorkflowCompiler.Artifacts)
	defer runner.Close()
	run, err := runner.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		result, err := runner.Get(context.Background(), request.ProjectID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if workflow.RunTerminal(result.Status) {
			if result.Status != "FAILED" || result.Nodes[0].ErrorCode != "output_integrity" {
				t.Fatalf("forged output accepted: %+v", result)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("run did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}

type partialExecutor struct{ delegate workflow.NodeExecutor }

func (e partialExecutor) Execute(ctx context.Context, node workflow.CompiledNode, scope artifact.Scope, inputs []artifact.Ref, id string) (workflow.NodeResult, error) {
	result, err := e.delegate.Execute(ctx, node, scope, inputs, id)
	if err == nil && result.Status == "SUCCEEDED" {
		result.Status = "PARTIAL"
	}
	return result, err
}
func TestRunnerRequiresExplicitAcceptanceOfPartialOutputs(t *testing.T) {
	for _, accept := range []bool{false, true} {
		t.Run(fmt.Sprint(accept), func(t *testing.T) {
			spec := fixture()
			spec.Nodes = spec.Nodes[2:]
			rt, request := runnerFixture(t, spec)
			if accept {
				request.AcceptPartialNodes = []string{"parse"}
			}
			executor := partialExecutor{workflow.PluginExecutor{Host: rt.Plugins, Catalog: rt.PluginCatalog}}
			runner := workflow.NewRunner(rt.WorkflowCompiler, rt.Store.(workflow.RunRepository), executor, rt.WorkflowCompiler.Artifacts)
			defer runner.Close()
			started, err := runner.Start(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			result := waitWorkflow(t, runner, request.ProjectID, started.ID)
			expected := "FAILED"
			if accept {
				expected = "PARTIAL"
			}
			if result.Status != expected || result.Nodes[0].Status != "PARTIAL" || (!accept && result.Nodes[0].ErrorCode != "partial_not_accepted") {
				t.Fatalf("partial policy: %+v", result)
			}
		})
	}
}
func waitWorkflow(t *testing.T, runner *workflow.Runner, project, id string) workflow.Run {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		result, err := runner.Get(context.Background(), project, id)
		if err != nil {
			t.Fatal(err)
		}
		if workflow.RunTerminal(result.Status) {
			return result
		}
		if time.Now().After(deadline) {
			t.Fatal("workflow did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}

type failingExecutor struct {
	entered chan string
	release chan struct{}
}

func (e failingExecutor) Execute(ctx context.Context, node workflow.CompiledNode, _ artifact.Scope, _ []artifact.Ref, _ string) (workflow.NodeResult, error) {
	e.entered <- node.ID
	select {
	case <-ctx.Done():
		return workflow.NodeResult{}, ctx.Err()
	case <-e.release:
	}
	if node.ID == "left" {
		return workflow.NodeResult{Status: "FAILED", ErrorCode: "fixture_failure"}, errors.New("fixture failure")
	}
	<-ctx.Done()
	return workflow.NodeResult{}, ctx.Err()
}
func TestRunnerFailureCancelsActiveSiblingAndSkipsDescendants(t *testing.T) {
	spec := fixture()
	left := spec.Nodes[2]
	left.ID = "left"
	right := left
	right.ID = "right"
	child := spec.Nodes[1]
	child.Needs = []string{"left"}
	spec.Nodes = []workflow.Node{left, right, child}
	rt, request := runnerFixture(t, spec)
	entered := make(chan string, 3)
	release := make(chan struct{})
	runner := workflow.NewRunner(rt.WorkflowCompiler, rt.Store.(workflow.RunRepository), failingExecutor{entered, release}, rt.WorkflowCompiler.Artifacts)
	defer runner.Close()
	started, err := runner.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("siblings did not start")
		}
	}
	close(release)
	result := waitWorkflow(t, runner, request.ProjectID, started.ID)
	states := map[string]string{}
	for _, n := range result.Nodes {
		states[n.NodeID] = n.Status
	}
	if result.Status != "FAILED" || states["left"] != "FAILED" || states["right"] != "CANCELLED" || states["semantic"] != "SKIPPED" {
		t.Fatalf("failure propagation: %+v", result)
	}
	select {
	case id := <-entered:
		t.Fatalf("unexpected descendant started: %s", id)
	default:
	}
}
