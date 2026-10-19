package workflow

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

// Retryable marks an executor error as transient. Only marked errors (and
// deadline expiries) are retried; cancellation and invalid input never are.
func Retryable(err error) error {
	if err == nil {
		return nil
	}
	return retryableError{err: err}
}

type retryableError struct{ err error }

func (e retryableError) Error() string { return e.err.Error() }
func (e retryableError) Unwrap() error { return e.err }

func isRetryable(err error) bool {
	var marked retryableError
	if errors.As(err, &marked) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func hasNode(run *Run, id string) bool {
	for _, node := range run.Nodes {
		if node.NodeID == id {
			return true
		}
	}
	return false
}

func readyLocked(run *Run, node CompiledNode) bool {
	for _, need := range node.Needs {
		found := false
		for _, prior := range run.Nodes {
			if prior.NodeID == need && (prior.Status == "SUCCEEDED" || (prior.Status == "PARTIAL" && acceptsPartial(*run, need))) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (e *execution) hasPendingLocked() bool {
	for i := range e.plan.Nodes {
		if e.run.Nodes[i].Status == "PENDING" {
			return true
		}
	}
	return false
}

// nextRetry returns the wait until the earliest scheduled retry, if any.
func (e *execution) nextRetry() (time.Duration, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var earliest time.Duration
	found := false
	now := time.Now()
	for _, node := range e.run.Nodes {
		if node.Status != "PENDING" || node.NextAttemptAt == "" {
			continue
		}
		when, err := time.Parse(time.RFC3339Nano, node.NextAttemptAt)
		if err != nil {
			continue
		}
		delay := when.Sub(now)
		if delay < 0 {
			delay = 0
		}
		if !found || delay < earliest {
			earliest, found = delay, true
		}
	}
	return earliest, found
}

// claim starts every ready node the concurrency policy allows.
func (e *execution) claim(r *Runner, ctx context.Context, workers *sync.WaitGroup, completed chan<- nodeCompletion, active int) (int, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	started := 0
	for i := range e.plan.Nodes {
		if active+started >= e.run.MaxParallel {
			break
		}
		node := e.plan.Nodes[i]
		nr := &e.run.Nodes[i]
		if nr.Status != "PENDING" {
			continue
		}
		if !readyLocked(e.run, node) {
			continue
		}
		if nr.NextAttemptAt != "" {
			if when, err := time.Parse(time.RFC3339Nano, nr.NextAttemptAt); err == nil && when.After(time.Now()) {
				continue
			}
		}
		inputs, err := bindNode(e.plan, *e.run, node)
		if err != nil {
			nr.Status = "FAILED"
			nr.ErrorCode = "input_binding"
			nr.FinishedAt = runNow()
			_ = e.saveLocked(r, "node_finished", nr.NodeID, "FAILED")
			return started, true
		}
		nr.Inputs = inputs
		nr.InvocationID = "winv-" + newID()
		nr.Status = "RUNNING"
		nr.Attempt++
		nr.NextAttemptAt = ""
		nr.LeaseOwner = r.InstanceID
		nr.LeaseExpiresAt = time.Now().Add(leaseTTL(node)).UTC().Format(time.RFC3339Nano)
		nr.StartedAt = runNow()
		nr.FinishedAt = ""
		nr.Outputs = []artifact.Ref{}
		invocation := nr.InvocationID
		if err := e.saveLocked(r, "node_started", nr.NodeID, "RUNNING"); err != nil {
			return started, false
		}
		workers.Add(1)
		go func(index int, node CompiledNode, inputs []artifact.Ref, id string) {
			defer workers.Done()
			nodeCtx, done := context.WithTimeout(ctx, time.Duration(node.TimeoutSeconds)*time.Second)
			defer done()
			result, err := r.Executor.Execute(nodeCtx, node, e.plan.Scope, inputs, id)
			completed <- nodeCompletion{index, result, err}
		}(i, node, inputs, invocation)
		started++
	}
	return started, false
}

// complete records one node result. It returns true when the run must fail.
func (e *execution) complete(r *Runner, c nodeCompletion) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	nr := &e.run.Nodes[c.index]
	// A result that arrives after a cancel request, or from a lease that is no
	// longer current, is a late worker: it is recorded and discarded.
	if nr.Status != "RUNNING" || (nr.LeaseOwner != "" && nr.LeaseOwner != r.InstanceID) {
		_ = e.saveLocked(r, "node_result_rejected", nr.NodeID, nr.Status)
		return false
	}
	if e.run.Status == "CANCELLING" {
		// The cancel request won the race: the late result is discarded and the
		// node is recorded as cancelled.
		nr.Status = "CANCELLED"
		nr.ErrorCode = "cancelled"
		nr.Outputs = []artifact.Ref{}
		nr.LeaseOwner = ""
		nr.LeaseExpiresAt = ""
		nr.FinishedAt = runNow()
		_ = e.saveLocked(r, "node_finished", nr.NodeID, "CANCELLED")
		return true
	}
	result, err := c.result, c.err
	if (result.Status == "SUCCEEDED" || result.Status == "PARTIAL") && !r.validOutputs(context.Background(), e.plan, e.plan.Nodes[c.index], nr.InvocationID, result) {
		result.Status = "FAILED"
		result.ErrorCode = "output_integrity"
		result.Outputs = []artifact.Ref{}
		err = errors.New("output integrity")
	}
	nr.Outputs = result.Outputs
	if nr.Outputs == nil {
		nr.Outputs = []artifact.Ref{}
	}
	nr.Status = result.Status
	nr.ErrorCode = result.ErrorCode
	if nr.Status == "" {
		nr.Status = "FAILED"
	}
	accepted := nr.Status == "SUCCEEDED" || (nr.Status == "PARTIAL" && acceptsPartial(*e.run, nr.NodeID))
	if nr.Status == "PARTIAL" && !accepted {
		nr.ErrorCode = "partial_not_accepted"
	}
	if err != nil || !accepted {
		switch {
		case e.run.Status == "CANCELLING" || errors.Is(err, context.Canceled):
			nr.Status = "CANCELLED"
			nr.ErrorCode = "cancelled"
		case isRetryable(err) && nr.Attempt < e.run.MaxAttempts:
			nr.Status = "PENDING"
			nr.LastError = errorText(err, result.ErrorCode)
			nr.NextAttemptAt = time.Now().Add(r.Backoff(nr.Attempt)).UTC().Format(time.RFC3339Nano)
			nr.LeaseOwner = ""
			nr.LeaseExpiresAt = ""
			nr.FinishedAt = ""
			_ = e.saveLocked(r, "node_retry_scheduled", nr.NodeID, "PENDING")
			return false
		default:
			if nr.Status != "PARTIAL" {
				nr.Status = "FAILED"
				if nr.ErrorCode == "" {
					nr.ErrorCode = "node_failed"
				}
			}
			if isRetryable(err) && nr.Attempt >= e.run.MaxAttempts {
				nr.ErrorCode = "retry_exhausted"
			}
		}
	}
	nr.LeaseOwner = ""
	nr.LeaseExpiresAt = ""
	nr.FinishedAt = runNow()
	_ = e.saveLocked(r, "node_finished", nr.NodeID, nr.Status)
	return nr.Status == "FAILED" || nr.Status == "CANCELLED" || !accepted
}

func errorText(err error, code string) string {
	if err != nil {
		return err.Error()
	}
	if code != "" {
		return code
	}
	return "node failed"
}

func leaseTTL(node CompiledNode) time.Duration {
	return time.Duration(node.TimeoutSeconds+30) * time.Second
}

func newID() string {
	return rand.Text()
}

// runExecution drives one attempt of a run: it claims ready nodes up to the
// persisted concurrency limit, honours pause and cancel requests at node
// boundaries, retries transient errors with backoff, and only then runs the
// application stages.
func (r *Runner) runExecution(exec *execution) {
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	defer r.unregister(exec.run.ID)
	exec.mu.Lock()
	exec.cancel = cancel
	exec.mu.Unlock()
	if r.coordinator() != nil {
		var release func()
		ctx, release = r.coordinateExecution(ctx, cancel, exec)
		if release == nil {
			return
		}
		defer release()
	}
	exec.mu.Lock()
	if exec.effects == nil && r.Effects != nil {
		effects, _, err := r.Effects.Bind(ctx, exec.run.AnalyzeCandidates)
		if err == nil {
			exec.effects = effects
		}
	}
	if exec.run.Status == "CREATED" {
		exec.run.Status = "RUNNING"
		_ = exec.saveLocked(r, "run_started", "", "RUNNING")
	}
	if exec.effects == nil && hasNode(exec.run, "$publish") {
		// The application stages cannot run without their effects; failing is
		// honest, while skipping them would report a success that never analysed.
		exec.mu.Unlock()
		exec.finishFailedOrCancelled(r)
		return
	}
	exec.mu.Unlock()

	var workers sync.WaitGroup
	completed := make(chan nodeCompletion, len(exec.plan.Nodes))
	active := 0
	failed := false
	cancelling := false

	for {
		if r.ctx.Err() != nil || exec.halted.Load() {
			cancel()
			workers.Wait()
			return
		}
		if r.coordinator() != nil && !exec.refreshLeased(r, context.WithoutCancel(ctx)) {
			cancel()
			workers.Wait()
			return
		}
		status := exec.status()
		if status == "CANCELLING" && !cancelling {
			cancelling = true
			cancel()
		}
		if status == "RUNNING" && !cancelling && !failed {
			started, claimFailed := exec.claim(r, ctx, &workers, completed, active)
			active += started
			if claimFailed {
				failed = true
				cancel()
			}
			status = exec.status()
		}
		if status == "PAUSING" && active == 0 {
			exec.finishPaused(r)
			if exec.status() == "RUNNING" {
				continue
			}
			workers.Wait()
			return
		}
		if status == "CANCELLING" && active == 0 {
			exec.finishCancelled(r)
			workers.Wait()
			return
		}
		if active == 0 {
			if !exec.hasPendingLocked() || failed || cancelling {
				break
			}
		}
		var timerC <-chan time.Time
		var timer *time.Timer
		if delay, ok := exec.nextRetry(); ok {
			timer = time.NewTimer(delay)
			timerC = timer.C
		}
		haltC := ctx.Done()
		if ctx.Err() != nil && !exec.halted.Load() && r.ctx.Err() == nil {
			haltC = nil
		}
		select {
		case c := <-completed:
			active--
			if r.coordinator() != nil && !exec.refreshLeased(r, context.WithoutCancel(ctx)) {
				cancel()
				workers.Wait()
				return
			}
			if exec.complete(r, c) {
				failed = true
				cancel()
			}
		case <-exec.signal:
		case <-timerC:
		case <-r.ctx.Done():
			// The host is closing: leave the run recoverable rather than
			// pretending it finished.
			workers.Wait()
			return
		case <-haltC:
			if exec.halted.Load() || r.ctx.Err() != nil {
				workers.Wait()
				return
			}
		}
		if timer != nil {
			timer.Stop()
		}
	}
	if failed || cancelling {
		exec.finishFailedOrCancelled(r)
		workers.Wait()
		return
	}
	if exec.effects != nil && !exec.finishEffects(r, ctx) {
		exec.finishFailedOrCancelled(r)
		workers.Wait()
		return
	}
	exec.finishSucceeded(r)
	workers.Wait()
}

func (e *execution) finishPaused(r *Runner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.run.Status != "PAUSING" {
		return
	}
	e.run.Status = "PAUSED"
	_ = e.saveLocked(r, "run_paused", "", "PAUSED")
}

func (e *execution) finishCancelled(r *Runner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.run.Nodes {
		node := &e.run.Nodes[i]
		if node.Status == "PENDING" {
			node.Status = "CANCELLED"
			node.ErrorCode = "cancelled"
			node.FinishedAt = runNow()
			_ = e.saveLocked(r, "node_finished", node.NodeID, "CANCELLED")
		}
	}
	e.run.Status = "CANCELLED"
	_ = e.saveLocked(r, "run_finished", "", "CANCELLED")
}

func (e *execution) finishFailedOrCancelled(r *Runner) {
	if r.ctx.Err() != nil || e.halted.Load() {
		return
	}
	e.mu.Lock()
	if e.run.Status == "CANCELLING" {
		e.mu.Unlock()
		e.finishCancelled(r)
		return
	}
	defer e.mu.Unlock()
	for i := range e.run.Nodes {
		node := &e.run.Nodes[i]
		if node.Status == "PENDING" {
			node.Status = "SKIPPED"
			node.ErrorCode = "upstream_failed"
			node.FinishedAt = runNow()
			_ = e.saveLocked(r, "node_skipped", node.NodeID, "SKIPPED")
		}
	}
	e.run.Status = "FAILED"
	_ = e.saveLocked(r, "run_finished", "", "FAILED")
}

// finishEffects runs the application stages ($publish / $analyze) after every
// plugin node succeeded.
func (e *execution) finishEffects(r *Runner, ctx context.Context) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.plan.Nodes); i < len(e.run.Nodes); i++ {
		node := &e.run.Nodes[i]
		if node.Status != "PENDING" {
			continue
		}
		for j := 0; j < i; j++ {
			node.Inputs = append(node.Inputs, e.run.Nodes[j].Outputs...)
		}
		node.Status = "RUNNING"
		node.StartedAt = runNow()
		if err := e.saveLocked(r, "node_started", node.NodeID, "RUNNING"); err != nil {
			return false
		}
		result, err := e.effects.Execute(ctx, *e.run, e.plan, *node)
		if r.ctx.Err() != nil || e.halted.Load() {
			return false
		}
		node.Status = result.Status
		node.Outputs = result.Outputs
		if node.Outputs == nil {
			node.Outputs = []artifact.Ref{}
		}
		node.Knowledge = result.Knowledge
		node.AgentRunIDs = result.AgentRunIDs
		node.Note = result.Note
		node.ErrorCode = result.ErrorCode
		node.FinishedAt = runNow()
		accepted := node.Status == "SUCCEEDED" || node.Status == "SKIPPED" || (node.Status == "PARTIAL" && acceptsPartial(*e.run, node.NodeID))
		if err != nil || !accepted {
			if node.Status != "PARTIAL" {
				node.Status = "FAILED"
			}
			if node.Status == "PARTIAL" && node.ErrorCode == "" {
				node.ErrorCode = "partial_not_accepted"
			}
			if node.ErrorCode == "" {
				node.ErrorCode = "effect_failed"
			}
			_ = e.saveLocked(r, "node_finished", node.NodeID, node.Status)
			return false
		}
		_ = e.saveLocked(r, "node_finished", node.NodeID, node.Status)
	}
	return true
}

func (e *execution) finishSucceeded(r *Runner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.run.Status = "SUCCEEDED"
	for _, node := range e.run.Nodes {
		if node.Status == "PARTIAL" {
			e.run.Status = "PARTIAL"
		}
	}
	_ = e.saveLocked(r, "run_finished", "", e.run.Status)
}
