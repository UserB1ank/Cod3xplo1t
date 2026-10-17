package workflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

func waitRunStatus(t *testing.T, runner *workflow.Runner, project, runID, want string) workflow.Run {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last workflow.Run
	for time.Now().Before(deadline) {
		run, err := runner.Get(context.Background(), project, runID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		last = run
		if run.Status == want {
			return run
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("run status = %s, want %s", last.Status, want)
	return last
}

func TestPauseLetsTheActiveNodeFinishWithoutClaimingAnother(t *testing.T) {
	spec := fixture()
	left := spec.Nodes[2]
	left.ID = "left"
	right := left
	right.ID = "right"
	spec.Nodes = []workflow.Node{left, right}
	rt, request := runnerFixture(t, spec)
	request.Task.Limits.MaxActiveLeases = 1
	entered := make(chan string, 4)
	release := make(chan struct{}, 4)
	executor := barrierExecutor{delegate: workflow.PluginExecutor{Host: rt.Plugins, Catalog: rt.PluginCatalog}, entered: entered, release: release}
	runner := workflow.NewRunner(rt.WorkflowCompiler, rt.Store.(workflow.RunRepository), executor, rt.WorkflowCompiler.Artifacts)
	defer runner.Close()
	ctx := context.Background()
	run, err := runner.Start(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	first := <-entered
	paused, err := runner.Pause(ctx, run.Scope.ProjectID, run.ID)
	if err != nil {
		t.Fatalf("pause: %v", err)
	}
	if paused.Status != "PAUSING" {
		t.Fatalf("pause status = %s", paused.Status)
	}
	// A duplicate request is idempotent.
	if again, err := runner.Pause(ctx, run.Scope.ProjectID, run.ID); err != nil || again.Status != "PAUSING" {
		t.Fatalf("duplicate pause: %v %s", err, again.Status)
	}
	select {
	case id := <-entered:
		t.Fatalf("claimed %s while pausing", id)
	default:
	}
	release <- struct{}{}
	paused = waitRunStatus(t, runner, run.Scope.ProjectID, run.ID, "PAUSED")
	for _, node := range paused.Nodes {
		if node.Status != "SUCCEEDED" && node.Status != "PENDING" {
			t.Fatalf("node %s = %s during pause", node.NodeID, node.Status)
		}
	}
	select {
	case id := <-entered:
		t.Fatalf("claimed %s after pausing", id)
	default:
	}
	if _, err := runner.Resume(ctx, run.Scope.ProjectID, run.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	second := <-entered
	if second == first {
		t.Fatalf("resume re-ran %s", first)
	}
	release <- struct{}{}
	waitRunStatus(t, runner, run.Scope.ProjectID, run.ID, "SUCCEEDED")
}

// lateExecutor ignores cancellation and returns a real result, which is how a
// worker that lost its lease behaves.
type lateExecutor struct {
	delegate workflow.NodeExecutor
	entered  chan string
	release  chan struct{}
}

func (e lateExecutor) Execute(_ context.Context, node workflow.CompiledNode, scope artifact.Scope, inputs []artifact.Ref, id string) (workflow.NodeResult, error) {
	e.entered <- node.ID
	<-e.release
	return e.delegate.Execute(context.Background(), node, scope, inputs, id)
}

func TestCancelStopsPendingNodesAndDiscardsLateOutputs(t *testing.T) {
	spec := fixture()
	left := spec.Nodes[2]
	left.ID = "left"
	right := left
	right.ID = "right"
	spec.Nodes = []workflow.Node{left, right}
	rt, request := runnerFixture(t, spec)
	request.Task.Limits.MaxActiveLeases = 1
	entered := make(chan string, 2)
	release := make(chan struct{})
	executor := lateExecutor{delegate: workflow.PluginExecutor{Host: rt.Plugins, Catalog: rt.PluginCatalog}, entered: entered, release: release}
	runner := workflow.NewRunner(rt.WorkflowCompiler, rt.Store.(workflow.RunRepository), executor, rt.WorkflowCompiler.Artifacts)
	defer runner.Close()
	ctx := context.Background()
	run, err := runner.Start(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	if cancelled, err := runner.Cancel(ctx, run.Scope.ProjectID, run.ID); err != nil || cancelled.Status != "CANCELLING" {
		t.Fatalf("cancel: %v %s", err, cancelled.Status)
	}
	if again, err := runner.Cancel(ctx, run.Scope.ProjectID, run.ID); err != nil || again.Status != "CANCELLING" {
		t.Fatalf("duplicate cancel: %v %s", err, again.Status)
	}
	release <- struct{}{}
	final := waitRunStatus(t, runner, run.Scope.ProjectID, run.ID, "CANCELLED")
	for _, node := range final.Nodes {
		if node.Status != "CANCELLED" || len(node.Outputs) != 0 {
			t.Fatalf("node %s = %s with %d outputs after cancel", node.NodeID, node.Status, len(node.Outputs))
		}
	}
	select {
	case id := <-entered:
		t.Fatalf("pending node %s started after cancel", id)
	default:
	}
	if final.Events[len(final.Events)-1].Status != "CANCELLED" {
		t.Fatalf("last event = %+v", final.Events[len(final.Events)-1])
	}
}

type flakyExecutor struct {
	mu        sync.Mutex
	failures  int
	retryable bool
	attempts  []int
	delegate  workflow.NodeExecutor
}

func (e *flakyExecutor) Execute(ctx context.Context, node workflow.CompiledNode, scope artifact.Scope, inputs []artifact.Ref, id string) (workflow.NodeResult, error) {
	e.mu.Lock()
	e.attempts = append(e.attempts, len(e.attempts)+1)
	fail := len(e.attempts) <= e.failures
	e.mu.Unlock()
	if fail {
		if e.retryable {
			return workflow.NodeResult{}, workflow.Retryable(errors.New("transient failure"))
		}
		return workflow.NodeResult{}, errors.New("permanent failure")
	}
	return e.delegate.Execute(ctx, node, scope, inputs, id)
}

func (e *flakyExecutor) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.attempts)
}

func retryRunner(t *testing.T, rt *app.Runtime, executor workflow.NodeExecutor) *workflow.Runner {
	t.Helper()
	runner := workflow.NewRunner(rt.WorkflowCompiler, rt.Store.(workflow.RunRepository), executor, rt.WorkflowCompiler.Artifacts)
	runner.Backoff = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { _ = runner.Close() })
	return runner
}

func TestRetryableFailuresRetryWithBackoffAndBoundedAttempts(t *testing.T) {
	spec := fixture()
	spec.Nodes = spec.Nodes[2:]
	rt, request := runnerFixture(t, spec)
	request.Task.Limits.MaxAttempts = 3
	executor := &flakyExecutor{failures: 2, retryable: true, delegate: workflow.PluginExecutor{Host: rt.Plugins, Catalog: rt.PluginCatalog}}
	runner := retryRunner(t, rt, executor)
	run, err := runner.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	final := waitRunStatus(t, runner, run.Scope.ProjectID, run.ID, "SUCCEEDED")
	if executor.count() != 3 || final.Nodes[0].Attempt != 3 {
		t.Fatalf("attempts = %d (node %d), want 3", executor.count(), final.Nodes[0].Attempt)
	}
	retries := 0
	for _, event := range final.Events {
		if event.Type == "node_retry_scheduled" {
			retries++
		}
	}
	if retries != 2 {
		t.Fatalf("retry events = %d", retries)
	}
}

func TestNonRetryableFailuresAndExhaustedBudgetsStopTheRun(t *testing.T) {
	spec := fixture()
	spec.Nodes = spec.Nodes[2:]
	rt, request := runnerFixture(t, spec)
	request.Task.Limits.MaxAttempts = 2
	permanent := &flakyExecutor{failures: 5, retryable: false, delegate: workflow.PluginExecutor{Host: rt.Plugins, Catalog: rt.PluginCatalog}}
	runner := retryRunner(t, rt, permanent)
	run, err := runner.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	_ = waitRunStatus(t, runner, run.Scope.ProjectID, run.ID, "FAILED")
	if permanent.count() != 1 {
		t.Fatalf("permanent failure retried %d times", permanent.count())
	}

	spec2 := fixture()
	spec2.Nodes = spec2.Nodes[2:]
	rt2, request2 := runnerFixture(t, spec2)
	request2.Task.Limits.MaxAttempts = 2
	transient := &flakyExecutor{failures: 10, retryable: true, delegate: workflow.PluginExecutor{Host: rt2.Plugins, Catalog: rt2.PluginCatalog}}
	runner2 := retryRunner(t, rt2, transient)
	run2, err := runner2.Start(context.Background(), request2)
	if err != nil {
		t.Fatal(err)
	}
	exhausted := waitRunStatus(t, runner2, run2.Scope.ProjectID, run2.ID, "FAILED")
	if transient.count() != 2 || exhausted.Nodes[0].ErrorCode != "retry_exhausted" {
		t.Fatalf("exhausted budget: attempts=%d code=%s", transient.count(), exhausted.Nodes[0].ErrorCode)
	}
}

type selectiveBarrier struct {
	delegate workflow.NodeExecutor
	block    string
	entered  chan string
	release  chan struct{}
}

func (e selectiveBarrier) Execute(ctx context.Context, node workflow.CompiledNode, scope artifact.Scope, inputs []artifact.Ref, id string) (workflow.NodeResult, error) {
	if node.ID == e.block {
		e.entered <- node.ID
		select {
		case <-ctx.Done():
			return workflow.NodeResult{}, ctx.Err()
		case <-e.release:
		}
	}
	return e.delegate.Execute(ctx, node, scope, inputs, id)
}

func TestRecoveryResumesAPersistedRunWithoutRepublishingCompletedNodes(t *testing.T) {
	spec := fixture()
	spec.Nodes = spec.Nodes[1:]
	rt, request := runnerFixture(t, spec)
	entered := make(chan string, 2)
	release := make(chan struct{})
	delegate := workflow.PluginExecutor{Host: rt.Plugins, Catalog: rt.PluginCatalog}
	first := workflow.NewRunner(rt.WorkflowCompiler, rt.Store.(workflow.RunRepository), selectiveBarrier{delegate: delegate, block: "semantic", entered: entered, release: release}, rt.WorkflowCompiler.Artifacts)
	run, err := first.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	before, err := first.Get(context.Background(), request.ProjectID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if before.Nodes[0].NodeID != "parse" || before.Nodes[0].Status != "SUCCEEDED" || before.Nodes[1].Status != "RUNNING" {
		t.Fatalf("pre-crash state: %+v", before.Nodes)
	}
	_ = first.Close()

	second := retryRunner(t, rt, delegate)
	resumed, err := second.Recover(context.Background())
	if err != nil || len(resumed) != 1 {
		t.Fatalf("recover: %+v %v", resumed, err)
	}
	final := waitRunStatus(t, second, request.ProjectID, run.ID, "SUCCEEDED")
	if final.Nodes[0].InvocationID != before.Nodes[0].InvocationID || len(final.Nodes[0].Outputs) != len(before.Nodes[0].Outputs) {
		t.Fatalf("completed node was republished: %+v vs %+v", final.Nodes[0], before.Nodes[0])
	}
	if final.Nodes[1].Attempt < 2 || final.Nodes[1].Status != "SUCCEEDED" {
		t.Fatalf("recovered node: %+v", final.Nodes[1])
	}
	recovered := false
	for _, event := range final.Events {
		if event.Type == "run_recovered" {
			recovered = true
		}
	}
	if !recovered {
		t.Fatalf("no recovery event: %+v", final.Events)
	}
}

type failOnceExecutor struct {
	mu       sync.Mutex
	failed   bool
	node     string
	delegate workflow.NodeExecutor
}

func (e *failOnceExecutor) Execute(ctx context.Context, node workflow.CompiledNode, scope artifact.Scope, inputs []artifact.Ref, id string) (workflow.NodeResult, error) {
	if node.ID == e.node {
		e.mu.Lock()
		first := !e.failed
		e.failed = true
		e.mu.Unlock()
		if first {
			return workflow.NodeResult{}, errors.New("fixture failure")
		}
	}
	return e.delegate.Execute(ctx, node, scope, inputs, id)
}

func TestRetryReusesCompletedNodesAndRerunsOnlyTheFailure(t *testing.T) {
	spec := fixture()
	spec.Nodes = []workflow.Node{spec.Nodes[2], spec.Nodes[1]}
	rt, request := runnerFixture(t, spec)
	delegate := workflow.PluginExecutor{Host: rt.Plugins, Catalog: rt.PluginCatalog}
	executor := &failOnceExecutor{node: "semantic", delegate: delegate}
	runner := retryRunner(t, rt, executor)
	ctx := context.Background()
	first, err := runner.Start(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	failed := waitRunStatus(t, runner, request.ProjectID, first.ID, "FAILED")
	if failed.Nodes[0].Status != "SUCCEEDED" || failed.Nodes[1].Status != "FAILED" {
		t.Fatalf("first run: %+v", failed.Nodes)
	}
	retried, err := runner.Retry(ctx, request.ProjectID, first.ID)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if retried.RetryOf != first.ID || retried.ID == first.ID {
		t.Fatalf("retry lineage: %+v", retried)
	}
	final := waitRunStatus(t, runner, request.ProjectID, retried.ID, "SUCCEEDED")
	if final.Nodes[0].InvocationID != failed.Nodes[0].InvocationID || len(final.Nodes[0].Outputs) != len(failed.Nodes[0].Outputs) {
		t.Fatalf("completed node was republished: %+v vs %+v", final.Nodes[0], failed.Nodes[0])
	}
	if final.Nodes[1].Status != "SUCCEEDED" || final.Nodes[1].Attempt < 1 {
		t.Fatalf("retried node: %+v", final.Nodes[1])
	}
	if _, err := runner.Retry(ctx, request.ProjectID, retried.ID); !errors.Is(err, workflow.ErrConflict) {
		t.Fatalf("retry of a successful run: %v", err)
	}
}
