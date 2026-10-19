package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

type workflowControlFixture struct {
	env        *testEnv
	projectID  string
	snapshotID string
	planID     string
}

func newWorkflowControlFixture(t *testing.T, env *testEnv) *workflowControlFixture {
	return workflowControlFixtureWithSpec(t, env, workflowSpecFixture())
}
func workflowControlFixtureWithSpec(t *testing.T, env *testEnv, spec map[string]any) *workflowControlFixture {
	t.Helper()
	source := t.TempDir()
	writeFile(t, source, "main.go", `package main
import("net/http";"os/exec")
func run(s string){exec.Command(s).Run()}
func Handler(w http.ResponseWriter,r *http.Request){run(r.URL.Query().Get("cmd"))}
func main(){http.HandleFunc("/run",Handler)}
`)
	project := createProject(t, env.ts, source).Project
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	prefix := "/api/v1/projects/" + project.ID
	registered := do(t, env.ts, http.MethodPost, prefix+"/snapshots/"+snapshot.Snapshot.SnapshotID+"/artifacts", nil, nil)
	var page struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	registered.decode(t, &page)
	var input artifact.Ref
	for _, ref := range page.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref
		}
	}
	if saved := do(t, env.ts, http.MethodPost, prefix+"/workflows", map[string]any{"api_version": "codexploit/v1", "spec": spec}, nil); saved.status != 201 {
		t.Fatalf("save workflow: %s", saved.body)
	}
	compiled := do(t, env.ts, http.MethodPost, prefix+"/workflows/workflow-discovery/versions/1.0.0/compile", map[string]any{"api_version": "codexploit/v1", "snapshot_id": input.Scope.SnapshotID, "inputs": []string{input.ID}, "language": "Go"}, nil)
	var plan struct {
		Plan struct {
			ID string `json:"plan_id"`
		} `json:"plan"`
	}
	compiled.decode(t, &plan)
	return &workflowControlFixture{env: env, projectID: project.ID, snapshotID: input.Scope.SnapshotID, planID: plan.Plan.ID}
}

func (f *workflowControlFixture) startTask(t *testing.T) workflow.Run {
	t.Helper()
	created := do(t, f.env.ts, http.MethodPost, "/api/projects/"+f.projectID+"/tasks", map[string]any{
		"name": "Controlled workflow", "objective": "Exercise pause and cancel",
		"snapshot_id": f.snapshotID, "workflow_plan_id": f.planID, "analyze_candidates": false,
	}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create task: %d %s", created.status, created.body)
	}
	var out struct {
		Task struct {
			ID string `json:"audit_id"`
		} `json:"task"`
		Run workflow.Run `json:"workflow_run"`
	}
	created.decode(t, &out)
	if out.Run.ID == "" {
		t.Fatalf("no workflow run: %s", created.body)
	}
	return out.Run
}

func (f *workflowControlFixture) control(t *testing.T, runID, action string) workflow.Run {
	t.Helper()
	response := do(t, f.env.ts, http.MethodPost, "/api/v1/projects/"+f.projectID+"/workflow-runs/"+runID+"/"+action, nil, nil)
	if response.status != http.StatusOK && response.status != http.StatusCreated {
		t.Fatalf("%s: %d %s", action, response.status, response.body)
	}
	var out struct {
		Run workflow.Run `json:"run"`
	}
	response.decode(t, &out)
	return out.Run
}

func (f *workflowControlFixture) wait(t *testing.T, runID, want string) workflow.Run {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response := doAs(t, f.env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+f.projectID+"/workflow-runs/"+runID, nil, nil)
		var out struct {
			Run workflow.Run `json:"run"`
		}
		response.decode(t, &out)
		if out.Run.Status == want {
			return out.Run
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("run %s never reached %s", runID, want)
	return workflow.Run{}
}

type controlExecutor struct {
	delegate workflow.NodeExecutor
	blocked  chan string
	release  chan struct{}
}

func (e controlExecutor) Execute(ctx context.Context, node workflow.CompiledNode, scope artifact.Scope, inputs []artifact.Ref, id string) (workflow.NodeResult, error) {
	e.blocked <- node.ID
	select {
	case <-ctx.Done():
		return workflow.NodeResult{}, ctx.Err()
	case <-e.release:
	}
	return e.delegate.Execute(ctx, node, scope, inputs, id)
}

func TestWorkflowControlsPauseResumeAndCancelOverHTTP(t *testing.T) {
	workflowControlsPauseResumeAndCancel(t, newTestEnv(t, false))
}

func TestPostgresWorkflowControlsPauseResumeAndCancelOverHTTP(t *testing.T) {
	rt, err := app.Build(context.Background(), postgresConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	workflowControlsPauseResumeAndCancel(t, serveTestEnv(t, rt, false))
}

func workflowControlsPauseResumeAndCancel(t *testing.T, env *testEnv) {
	t.Helper()
	fixture := newWorkflowControlFixture(t, env)
	blocked := make(chan string, 8)
	release := make(chan struct{}, 8)
	env.rt.WorkflowRunner.Executor = controlExecutor{
		delegate: workflow.PluginExecutor{Host: env.rt.Plugins, Catalog: env.rt.PluginCatalog},
		blocked:  blocked,
		release:  release,
	}
	run := fixture.startTask(t)
	<-blocked
	if paused := fixture.control(t, run.ID, "pause"); paused.Status != "PAUSING" {
		t.Fatalf("pause status = %s", paused.Status)
	}
	if again := fixture.control(t, run.ID, "pause"); again.Status != "PAUSING" {
		t.Fatalf("duplicate pause = %s", again.Status)
	}
	release <- struct{}{}
	paused := fixture.wait(t, run.ID, "PAUSED")
	if paused.Nodes[0].Status != "SUCCEEDED" {
		t.Fatalf("active node did not finish at the pause boundary: %+v", paused.Nodes[0])
	}
	for _, node := range paused.Nodes[1:] {
		if node.Status != "PENDING" {
			t.Fatalf("paused run claimed %s (%s)", node.NodeID, node.Status)
		}
	}
	if resumed := fixture.control(t, run.ID, "resume"); resumed.Status != "RUNNING" {
		t.Fatalf("resume status = %s", resumed.Status)
	}
	fixture.wait(t, run.ID, "SUCCEEDED")

	// Cancellation stops the active node and the pending application stages.
	second := fixture.startTask(t)
	<-blocked
	if cancelling := fixture.control(t, second.ID, "cancel"); cancelling.Status != "CANCELLING" {
		t.Fatalf("cancel status = %s", cancelling.Status)
	}
	if again := fixture.control(t, second.ID, "cancel"); again.Status != "CANCELLING" && again.Status != "CANCELLED" {
		t.Fatalf("duplicate cancel = %s", again.Status)
	}
	release <- struct{}{}
	cancelled := fixture.wait(t, second.ID, "CANCELLED")
	for _, node := range cancelled.Nodes {
		if node.Status != "CANCELLED" {
			t.Fatalf("node %s = %s after cancel", node.NodeID, node.Status)
		}
	}

	// Pause on a terminal run conflicts; readers cannot control a run; another
	// project cannot address it.
	terminal := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+fixture.projectID+"/workflow-runs/"+run.ID+"/pause", nil, nil)
	if terminal.status != http.StatusConflict {
		t.Fatalf("pause on terminal run: %d %s", terminal.status, terminal.body)
	}
	reader := doAs(t, env.ts, readerSecret, http.MethodPost, "/api/v1/projects/"+fixture.projectID+"/workflow-runs/"+second.ID+"/cancel", nil, nil)
	if reader.status != http.StatusForbidden {
		t.Fatalf("reader cancel: %d %s", reader.status, reader.body)
	}
	foreign := do(t, env.ts, http.MethodPost, "/api/v1/projects/proj-other/workflow-runs/"+second.ID+"/cancel", nil, nil)
	if foreign.status != http.StatusNotFound {
		t.Fatalf("foreign project cancel: %d %s", foreign.status, foreign.body)
	}
}

type failOnceAPIExecutor struct {
	mu       sync.Mutex
	failed   bool
	delegate workflow.NodeExecutor
}

func (e *failOnceAPIExecutor) Execute(ctx context.Context, node workflow.CompiledNode, scope artifact.Scope, inputs []artifact.Ref, id string) (workflow.NodeResult, error) {
	e.mu.Lock()
	first := !e.failed
	e.failed = true
	e.mu.Unlock()
	if first {
		return workflow.NodeResult{}, errors.New("permanent fixture failure")
	}
	return e.delegate.Execute(ctx, node, scope, inputs, id)
}

func TestPostgresWorkflowRetryOverHTTPCreatesALinkedRun(t *testing.T) {
	rt, err := app.Build(context.Background(), postgresConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	workflowRetryOverHTTP(t, serveTestEnv(t, rt, false))
}
func TestWorkflowRetryOverHTTPCreatesALinkedRun(t *testing.T) {
	workflowRetryOverHTTP(t, newTestEnv(t, false))
}
func workflowRetryOverHTTP(t *testing.T, env *testEnv) {
	t.Helper()
	fixture := newWorkflowControlFixture(t, env)
	env.rt.WorkflowRunner.Executor = &failOnceAPIExecutor{delegate: workflow.PluginExecutor{Host: env.rt.Plugins, Catalog: env.rt.PluginCatalog}}
	run := fixture.startTask(t)
	failed := fixture.wait(t, run.ID, "FAILED")
	failedTasks := do(t, env.ts, http.MethodGet, "/api/projects/"+fixture.projectID+"/tasks?state=FAILED", nil, nil)
	if failedTasks.status != 200 || !strings.Contains(string(failedTasks.body), failed.TaskID) {
		t.Fatalf("failed workflow missing from task filter: %d %s", failedTasks.status, failedTasks.body)
	}
	response := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+fixture.projectID+"/workflow-runs/"+failed.ID+"/retry", nil, nil)
	if response.status != http.StatusCreated {
		t.Fatalf("retry: %d %s", response.status, response.body)
	}
	var out struct {
		Run workflow.Run `json:"run"`
	}
	response.decode(t, &out)
	if out.Run.RetryOf != failed.ID || out.Run.ID == failed.ID {
		t.Fatalf("retry lineage: %+v", out.Run)
	}
	fixture.wait(t, out.Run.ID, "SUCCEEDED")
	if second := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+fixture.projectID+"/workflow-runs/"+out.Run.ID+"/retry", nil, nil); second.status != http.StatusConflict {
		t.Fatalf("retry of a successful run: %d %s", second.status, second.body)
	}
}
