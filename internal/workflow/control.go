package workflow

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

// execution is the live handle of one run. Controls mutate the run under the
// same lock the loop uses, so a pause or cancel request can never be lost
// between a status read and a node claim.
type execution struct {
	mu      sync.Mutex
	run     *Run
	plan    Plan
	effects Effects
	signal  chan struct{}
	cancel  context.CancelFunc
	looping bool
	lease   *Lease
	err     error
	halted  atomic.Bool
}

func (e *execution) status() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.run.Status
}

func (e *execution) wake() {
	select {
	case e.signal <- struct{}{}:
	default:
	}
}

// saveLocked appends exactly one event and persists the run with its CAS.
func (e *execution) saveLocked(r *Runner, kind, node, status string) error {
	if e.err != nil {
		return e.err
	}
	prior := e.run.Version
	e.run.Version++
	e.run.UpdatedAt = runNow()
	e.run.Events = append(e.run.Events, RunEvent{Seq: int64(len(e.run.Events) + 1), Type: kind, NodeID: node, Status: status, CreatedAt: e.run.UpdatedAt})
	ctx := context.Background()
	if e.lease != nil {
		ctx = WithLease(ctx, *e.lease)
	}
	err := r.Repository.SaveWorkflowRun(ctx, *e.run, prior)
	if err != nil {
		e.err = err
		e.halted.Store(true)
		if e.cancel != nil {
			e.cancel()
		}
		e.wake()
	}
	return err
}

func (r *Runner) register(exec *execution) {
	r.mu.Lock()
	r.executions[exec.run.ID] = exec
	r.mu.Unlock()
}

func (r *Runner) unregister(runID string) {
	r.mu.Lock()
	delete(r.executions, runID)
	r.mu.Unlock()
}

func (r *Runner) lookup(runID string) *execution {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.executions[runID]
}

// executionFor returns the live handle or rebuilds one from the persisted run.
func (r *Runner) executionFor(ctx context.Context, project, runID string) (*execution, error) {
	if live := r.lookup(runID); live != nil {
		live.mu.Lock()
		owner := live.run.Scope.ProjectID
		live.mu.Unlock()
		if owner != project {
			return nil, ErrNotFound
		}
		return live, nil
	}
	run, err := r.Repository.GetWorkflowRun(ctx, project, runID)
	if err != nil {
		return nil, err
	}
	plan, err := r.Compiler.Get(ctx, project, run.PlanID)
	if err != nil {
		return nil, err
	}
	exec := &execution{run: &run, plan: plan, signal: make(chan struct{}, 1)}
	r.mu.Lock()
	if prior := r.executions[runID]; prior != nil {
		exec = prior
	} else {
		r.executions[runID] = exec
	}
	r.mu.Unlock()
	return exec, nil
}

// Pause asks the run to stop claiming new nodes. Active nodes are allowed to
// reach their natural boundary; the run becomes PAUSED once none is active.
func (r *Runner) Pause(ctx context.Context, project, runID string) (Run, error) {
	if r.coordinator() != nil {
		return r.controlLeased(ctx, project, runID, "pause")
	}
	return r.transition(ctx, project, runID, "PAUSING")
}

// Resume continues a paused run from its persisted state.
func (r *Runner) Resume(ctx context.Context, project, runID string) (Run, error) {
	if r.coordinator() != nil {
		return r.controlLeased(ctx, project, runID, "resume")
	}
	exec, err := r.executionFor(ctx, project, runID)
	if err != nil {
		return Run{}, err
	}
	exec.mu.Lock()
	switch exec.run.Status {
	case "RUNNING":
		run := cloneRun(*exec.run)
		exec.mu.Unlock()
		return run, nil
	case "PAUSED", "PAUSING", "CREATED":
		exec.run.Status = "RUNNING"
		if err := exec.saveLocked(r, "run_resumed", "", "RUNNING"); err != nil {
			exec.mu.Unlock()
			return Run{}, err
		}
		run := cloneRun(*exec.run)
		exec.mu.Unlock()
		r.startLoop(exec)
		return run, nil
	default:
		run := cloneRun(*exec.run)
		exec.mu.Unlock()
		return run, ErrConflict
	}
}

// Cancel requests cancellation. A running executor is cancelled and its result
// is recorded as CANCELLED; pending nodes never start.
func (r *Runner) Cancel(ctx context.Context, project, runID string) (Run, error) {
	if r.coordinator() != nil {
		return r.controlLeased(ctx, project, runID, "cancel")
	}
	exec, err := r.executionFor(ctx, project, runID)
	if err != nil {
		return Run{}, err
	}
	exec.mu.Lock()
	switch exec.run.Status {
	case "CANCELLING", "CANCELLED":
		run := cloneRun(*exec.run)
		exec.mu.Unlock()
		return run, nil
	case "CREATED", "RUNNING", "PAUSING", "PAUSED":
		paused, looping := exec.run.Status == "PAUSED", exec.looping
		exec.run.Status = "CANCELLING"
		if err := exec.saveLocked(r, "run_cancel_requested", "", "CANCELLING"); err != nil {
			exec.mu.Unlock()
			return Run{}, err
		}
		exec.mu.Unlock()
		if paused && !looping {
			// Nothing is running: finish the cancellation synchronously instead of
			// leaving the run in CANCELLING forever.
			exec.finishCancelled(r)
			exec.mu.Lock()
			run := cloneRun(*exec.run)
			exec.mu.Unlock()
			return run, nil
		}
		exec.wake()
		exec.mu.Lock()
		run := cloneRun(*exec.run)
		exec.mu.Unlock()
		return run, nil
	default:
		run := cloneRun(*exec.run)
		exec.mu.Unlock()
		return run, ErrConflict
	}
}

// Retry creates a new run for a failed run's plan. Nodes that already
// succeeded keep their invocation and outputs, so a retry never republishes
// committed artifacts.
func (r *Runner) Retry(ctx context.Context, project, runID string) (Run, error) {
	prior, err := r.Repository.GetWorkflowRun(ctx, project, runID)
	if err != nil {
		return Run{}, err
	}
	if prior.Status != "FAILED" {
		return prior, ErrConflict
	}
	plan, err := r.Compiler.Get(ctx, project, prior.PlanID)
	if err != nil {
		return Run{}, err
	}
	now := runNow()
	run := Run{
		RunnerVersion: RunnerVersion, MaxParallel: prior.MaxParallel, MaxAttempts: prior.MaxAttempts,
		RetryOf: prior.ID, Task: prior.Task, Model: prior.Model, AnalyzeCandidates: prior.AnalyzeCandidates,
		AcceptPartialNodes: append([]string{}, prior.AcceptPartialNodes...),
		ID:                 "wrun-" + rand.Text(), TaskID: "task-" + rand.Text(), Scope: prior.Scope,
		PlanID: prior.PlanID, PlanDigest: prior.PlanDigest, Status: "CREATED", Version: 1,
		Nodes: []NodeRun{},
		Events: []RunEvent{
			{Seq: 1, Type: "run_created", Status: "CREATED", CreatedAt: now},
			{Seq: 2, Type: "run_retry_created", Status: "CREATED", CreatedAt: now},
		},
		CreatedAt: now, UpdatedAt: now,
	}
	for i, node := range plan.Nodes {
		nr := NodeRun{ID: fmt.Sprintf("%s-n%d", run.ID, i+1), NodeID: node.ID, Kind: "plugin", Status: "PENDING", Inputs: []artifact.Ref{}, Outputs: []artifact.Ref{}}
		if i < len(prior.Nodes) {
			old := prior.Nodes[i]
			if old.NodeID == node.ID && old.Status == "SUCCEEDED" && len(old.Outputs) > 0 {
				nr.Status = "SUCCEEDED"
				nr.Inputs = old.Inputs
				nr.Outputs = old.Outputs
				nr.InvocationID = old.InvocationID
				nr.Attempt = old.Attempt
				nr.StartedAt = old.StartedAt
				nr.FinishedAt = old.FinishedAt
			}
		}
		run.Nodes = append(run.Nodes, nr)
	}
	if hasNode(&prior, "$publish") {
		run.Nodes = append(run.Nodes, NodeRun{ID: run.ID + "-publish", NodeID: "$publish", Kind: "knowledge_publish", Status: "PENDING", Inputs: []artifact.Ref{}, Outputs: []artifact.Ref{}})
	}
	if hasNode(&prior, "$analyze") {
		run.Nodes = append(run.Nodes, NodeRun{ID: run.ID + "-analyze", NodeID: "$analyze", Kind: "candidate_analysis", Status: "PENDING", Inputs: []artifact.Ref{}, Outputs: []artifact.Ref{}})
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return Run{}, ErrInvalid
	}
	r.mu.Unlock()
	if err := r.Repository.CreateWorkflowRun(ctx, run, prior.Task); err != nil {
		return Run{}, err
	}
	var effects Effects
	if r.Effects != nil {
		if bound, _, err := r.Effects.Bind(ctx, run.AnalyzeCandidates); err == nil {
			effects = bound
		}
	}
	exec := &execution{run: &run, plan: plan, effects: effects, signal: make(chan struct{}, 1)}
	result := cloneRun(run)
	r.register(exec)
	r.startLoop(exec)
	return result, nil
}

func (r *Runner) transition(ctx context.Context, project, runID, target string) (Run, error) {
	exec, err := r.executionFor(ctx, project, runID)
	if err != nil {
		return Run{}, err
	}
	exec.mu.Lock()
	switch exec.run.Status {
	case "RUNNING", "CREATED":
		exec.run.Status = target
		if err := exec.saveLocked(r, "run_pause_requested", "", target); err != nil {
			exec.mu.Unlock()
			return Run{}, err
		}
		run := cloneRun(*exec.run)
		exec.mu.Unlock()
		exec.wake()
		return run, nil
	case "PAUSING", "PAUSED":
		run := cloneRun(*exec.run)
		exec.mu.Unlock()
		return run, nil
	default:
		run := cloneRun(*exec.run)
		exec.mu.Unlock()
		return run, ErrConflict
	}
}

func (r *Runner) startLoop(exec *execution) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	exec.mu.Lock()
	if exec.looping {
		// The loop is still draining a pause. Waking it is enough: it re-checks
		// the status after finishing the pause and keeps running.
		exec.mu.Unlock()
		r.mu.Unlock()
		exec.wake()
		return
	}
	exec.looping = true
	exec.mu.Unlock()
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.wg.Done()
		defer func() {
			exec.mu.Lock()
			exec.looping = false
			// A resume can race the loop's exit; if the run is RUNNING again the
			// next attempt must not be lost.
			restart := exec.run.Status == "RUNNING" && exec.err == nil
			exec.mu.Unlock()
			if restart {
				r.startLoop(exec)
			}
		}()
		r.runExecution(exec)
	}()
}

// Recover resumes every non-terminal run this store knows about. It is what a
// new host calls on startup so a restart continues instead of leaking a run.
func (r *Runner) Recover(ctx context.Context) ([]Run, error) {
	if coordinator := r.coordinator(); coordinator != nil {
		r.ensureRecoveryLoop()
		return r.recoverLeased(ctx)
	}
	runs, err := r.Repository.ListRecoverableWorkflowRuns(ctx)
	if err != nil {
		return nil, err
	}
	resumed := []Run{}
	for _, run := range runs {
		if r.lookup(run.ID) != nil {
			continue
		}
		exec, err := r.executionFor(ctx, run.Scope.ProjectID, run.ID)
		if err != nil {
			continue
		}
		exec.mu.Lock()
		if exec.run.Status != "RUNNING" && exec.run.Status != "PAUSING" && exec.run.Status != "CREATED" {
			exec.mu.Unlock()
			continue
		}
		exec.run.Status = "RUNNING"
		for i := range exec.run.Nodes {
			node := &exec.run.Nodes[i]
			if node.Status == "RUNNING" {
				// The previous host is gone: its lease is reclaimed and the node
				// is queued again under a new attempt.
				node.Status = "PENDING"
				node.LeaseOwner = ""
				node.LeaseExpiresAt = ""
				node.LastError = "lease_reclaimed"
			}
		}
		if err := exec.saveLocked(r, "run_recovered", "", "RUNNING"); err != nil {
			exec.mu.Unlock()
			continue
		}
		resumed = append(resumed, cloneRun(*exec.run))
		exec.mu.Unlock()
		r.startLoop(exec)
	}
	return resumed, nil
}
