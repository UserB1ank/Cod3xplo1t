package workflow

import (
	"context"
	"time"
)

const coordinatorTTL = 10 * time.Second

func (r *Runner) controlLeased(ctx context.Context, project, id, action string) (Run, error) {
	run, err := r.coordinator().ControlWorkflowRun(ctx, project, id, action)
	if err != nil {
		return run, err
	}
	if live := r.lookup(id); live != nil {
		live.wake()
	} else if !RunTerminal(run.Status) && run.Status != "PAUSED" {
		exec, err := r.executionFor(ctx, project, id)
		if err != nil {
			return run, err
		}
		r.startLoop(exec)
	}
	return run, nil
}

func (r *Runner) coordinator() LeaseRepository {
	repo, ok := r.Repository.(LeaseRepository)
	if ok && repo.WorkflowLeaseClock() {
		return repo
	}
	return nil
}

// A database outage or lost fence stops scheduling immediately. The next pass
// discovers durable work again; no in-memory mutex grants execution authority.
func (r *Runner) ensureRecoveryLoop() {
	r.recoveryOnce.Do(func() {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return
		}
		r.wg.Add(1)
		r.mu.Unlock()
		go func() {
			defer r.wg.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-r.ctx.Done():
					return
				case <-ticker.C:
					_, _ = r.recoverLeased(r.ctx)
				}
			}
		}()
	})
}

func (r *Runner) recoverLeased(ctx context.Context) ([]Run, error) {
	runs, err := r.Repository.ListRecoverableWorkflowRuns(ctx)
	if err != nil {
		return nil, err
	}
	resumed := []Run{}
	for _, run := range runs {
		if run.Status == "PAUSED" || r.lookup(run.ID) != nil {
			continue
		}
		exec, err := r.executionFor(ctx, run.Scope.ProjectID, run.ID)
		if err != nil {
			continue
		}
		r.startLoop(exec)
		resumed = append(resumed, run)
	}
	return resumed, nil
}

func (r *Runner) coordinateExecution(ctx context.Context, cancel context.CancelFunc, e *execution) (context.Context, func()) {
	repo := r.coordinator()
	e.mu.Lock()
	project, id := e.run.Scope.ProjectID, e.run.ID
	e.mu.Unlock()
	run, lease, err := repo.AcquireWorkflowLease(ctx, project, id, r.InstanceID, coordinatorTTL)
	if err != nil {
		e.halted.Store(true)
		e.mu.Lock()
		e.err = err
		e.mu.Unlock()
		return ctx, nil
	}
	e.mu.Lock()
	e.run = &run
	e.lease = &lease
	// A previous coordinator can no longer publish. Completed invocations may
	// still be reused by the executor; incomplete attempts return to PENDING.
	recovered := false
	for i := range e.run.Nodes {
		node := &e.run.Nodes[i]
		if node.Status != "RUNNING" {
			continue
		}
		recovered = true
		if recovery, ok := r.Executor.(NodeRecovery); ok && i < len(e.plan.Nodes) {
			result, err := recovery.RecoverNode(ctx, e.plan.Scope, *node)
			if err == nil && (result.Status == "SUCCEEDED" || result.Status == "PARTIAL") && r.validOutputs(ctx, e.plan, e.plan.Nodes[i], node.InvocationID, result) {
				node.Status = result.Status
				node.Outputs = result.Outputs
				node.FinishedAt = runNow()
				node.LeaseOwner = ""
				node.LeaseExpiresAt = ""
				continue
			}
		}
		node.Status = "PENDING"
		node.LeaseOwner = ""
		node.LeaseExpiresAt = ""
		node.LastError = "lease_reclaimed"
	}
	if recovered {
		err = e.saveLocked(r, "run_recovered", "", e.run.Status)
	}
	e.mu.Unlock()
	if err != nil {
		_ = repo.ReleaseWorkflowLease(context.Background(), lease)
		return ctx, nil
	}
	heartbeatCtx, stop := context.WithCancel(r.ctx)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				probe, done := context.WithTimeout(heartbeatCtx, 3*time.Second)
				err := repo.RenewWorkflowLease(probe, lease, coordinatorTTL)
				done()
				if err != nil {
					e.halted.Store(true)
					cancel()
					e.wake()
					return
				}
				e.wake()
			}
		}
	}()
	return WithLease(ctx, lease), func() {
		stop()
		<-finished
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_ = repo.ReleaseWorkflowLease(cleanup, lease)
	}
}

func (e *execution) refreshLeased(r *Runner, ctx context.Context) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return false
	}
	read, done := context.WithTimeout(ctx, 3*time.Second)
	defer done()
	current, err := r.Repository.GetWorkflowRun(read, e.run.Scope.ProjectID, e.run.ID)
	if err != nil {
		e.err = err
		e.halted.Store(true)
		return false
	}
	if current.Version != e.run.Version {
		e.run = &current
	}
	return !RunTerminal(e.run.Status)
}
