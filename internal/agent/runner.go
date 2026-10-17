// This file is the orchestrator: the loop that turns a claimed AuditPath into a
// bounded agent run.
//
// The split the package documents is implemented here. The orchestrator claims
// and renews the path lease, builds the task, starts the adapter, and then decides
// every request the adapter makes: a tool call runs only when the current policy
// allows it and the registry knows it, an expansion buys room only through
// ApplyExpansion, and the run ends with a status and a stop reason an operator can
// act on. The adapter never sees the lease, the budget or the registry.
//
// One invariant shapes every write below: a run's state and the events that
// explain it are written together. `record` and `appendRunEvents` exist for that
// reason — a counter that moved without its event, or an event with no counter,
// would make a replay disagree with the stored run. The Store contract splits
// UpdateRun and AppendRunEvents, so a run is always written before the event that
// describes it; a crash between the two leaves a log short by one entry, which is
// recoverable, while the reverse is not.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

const (
	// runnerDefaultHeartbeatEvery is the documented lease renewal cadence. A
	// heartbeat is never sent more often than this.
	runnerDefaultHeartbeatEvery = 30 * time.Second
	// runnerLeaseTTLFactor keeps two missed heartbeats from losing the lease: the
	// lease is asked for as a multiple of the heartbeat interval.
	runnerLeaseTTLFactor = 3
	// runnerDefaultMaxRuns bounds RunAudit when neither the argument nor the
	// Runner field says otherwise. It is a ceiling, not a target.
	runnerDefaultMaxRuns = 100
	// runnerEventNote types the notes an adapter sends that are not requests and
	// not answers. The adapter's own label is kept in the detail.
	runnerEventNote = "run_note"
	// runnerDetailAnswerJSON is the detail key an adapter may use to hand the
	// orchestrator its structured output verbatim. It goes through DecodeAnswer.
	// The key is explicit on purpose: a generic one would misread an ordinary
	// note's detail as an answer.
	runnerDetailAnswerJSON = "answer_json"
	// runnerActorAgent and runnerActorOrchestrator are the two writers of a run
	// log. The actor makes it obvious who decided what.
	runnerActorAgent        = "agent"
	runnerActorOrchestrator = "orchestrator"
	// runnerTerminalGrace is how long the orchestrator waits for the terminal
	// result after the adapter closed its event stream. A correct adapter writes
	// the result before closing the stream, so this only covers a slow writer.
	runnerTerminalGrace = 250 * time.Millisecond
)

// errRunnerNotConfigured is a programming error, not a runtime condition: a
// Runner without a store, a runtime, a task builder or a path coordinator cannot
// do its job and must not claim a lease it cannot record.
var errRunnerNotConfigured = errors.New("agent: runner is not configured")

// PathCoordinator is the orchestrator's narrow view of the path engine
// (internal/path). The package deliberately does not take a *path.Service: the
// runner only needs to claim, renew, advance and release a lease, and a narrow
// interface is what lets the whole loop be tested without a scheduler.
//
// The implementation is expected to translate these calls into the path engine's
// own vocabulary (Claim, Heartbeat, Transition, Release) and to keep each state
// change atomic with its path event, exactly as *path.Service does.
type PathCoordinator interface {
	// ClaimPathForRun leases the next claimable path of an audit and moves it to
	// an active status. It returns path.ErrNotFound when the queue is empty.
	ClaimPathForRun(ctx context.Context, auditID, owner string, ttl time.Duration) (*path.Path, error)
	// ClaimSpecificPath leases exactly the named path, never a neighbour, so a
	// scheduler that has already chosen what to run can hand that choice to the
	// orchestrator. It refuses with path.ErrNotClaimable when the path is not in a
	// claimable status and path.ErrLeaseHeld when another owner holds it; a claim
	// by the owner that already holds the lease renews it instead of failing,
	// because the scheduler claims a path before dispatching it and RunPath then
	// claims it for the run.
	ClaimSpecificPath(ctx context.Context, pathID, owner string, ttl time.Duration) (*path.Path, error)
	// HeartbeatPath renews a lease the owner still holds.
	HeartbeatPath(ctx context.Context, pathID, owner string, ttl time.Duration) error
	// CompletePath records the path's success: it is advanced to
	// HYPOTHESIS_FORMED and the worker's lease is released, because the run that
	// held the path is over. HYPOTHESIS_FORMED is an active path status, so an
	// implementation that only calls path.Service.Transition would leave the lease
	// attached to a finished run; the adapter is expected to clear it in the same
	// atomic state change (path.Store.Transition with ClearLease).
	CompletePath(ctx context.Context, pathID, owner, reason string) error
	// ReleasePath returns a path to the queue so another attempt can run.
	ReleasePath(ctx context.Context, pathID, owner, reason string) error
	// AdvancePath moves a claimed path to any other status the state machine
	// accepts, which is how a run that spent its attempts takes a path out of the
	// queue without pretending it was released.
	AdvancePath(ctx context.Context, pathID, owner string, to path.Status, reason string) error
}

// TaskBuilder turns a claimed path into the task an adapter receives. It is a
// seam, not an implementation: the code-slice and evidence assembly belongs to
// the graph layers, and keeping it behind an interface keeps this package free of
// them.
type TaskBuilder interface {
	BuildTask(ctx context.Context, p path.Path, policy ExplorationPolicy) (Task, error)
}

// Runner is the orchestrator of one adapter over the path queue.
//
// It owns everything durable about a run — the lease, the budget, the retries and
// the run record — and the adapter owns nothing but its bounded reasoning.
type Runner struct {
	Store    Store
	Registry *Registry
	Runtime  Runtime
	Tasks    TaskBuilder
	Paths    PathCoordinator
	// Policy is the starting exploration policy of a run. It is normalized, then
	// handed to the task builder, and it is the policy every request is judged
	// against until an approved expansion widens it.
	Policy ExplorationPolicy
	// Expand decides expansion requests. Only ApplyExpansion may change a run's
	// limits, and it never widens the tool allowlist.
	Expand ExpandPolicy
	// Owner names the lease holder. It defaults to "orchestrator".
	Owner string
	// Now is injectable so a replay produces the same timestamps.
	Now func() time.Time
	// HeartbeatEvery is the lease renewal cadence; it defaults to 30s and the
	// lease TTL is always a multiple of it.
	HeartbeatEvery time.Duration
	// MaxRuns bounds RunAudit when its maxRuns argument is not positive.
	MaxRuns int
	// MaxAttempts bounds how often a RunAudit call may retry one path when the
	// path itself carries no limit. MaxRepeatedOutputs comes from the policy.
	MaxAttempts int
}

// RunOnce claims one path of an audit, runs the adapter over it, decides
// everything the adapter asks for, records the exchange, and settles the path.
//
// An empty queue is agent.ErrNotFound, not an empty run: the caller asked for
// work and there was none. Every other outcome is a stored Run, including an
// adapter that failed, because the attempt itself is what the operator needs to
// see.
func (r *Runner) RunOnce(ctx context.Context, auditID string) (*Run, error) {
	if err := r.configured(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	owner := r.owner()
	p, err := r.Paths.ClaimPathForRun(ctx, auditID, owner, r.leaseTTL())
	if err != nil {
		// An empty queue is not a failure; every other error is.
		if errors.Is(err, path.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("agent: claim a path of audit %s: %w", auditID, err)
	}
	if p == nil {
		return nil, ErrNotFound
	}
	return r.execute(ctx, auditID, p, owner, r.Policy)
}

// RunPath claims a named path for one run and executes it. It is the entry point
// a scheduler uses; RunOnce remains the convenience form that picks the next path.
//
// The claim is path-scoped, so the run happens on the path the caller chose rather
// than on whatever the queue would hand out next. A path this worker may not have —
// path.ErrNotClaimable for a status the state machine does not lease, or
// path.ErrLeaseHeld for another worker's live lease — is refused with that
// sentinel and no run is invented. The policy argument is the run's policy; an
// empty one falls back to the runner's configured policy, and it is never widened
// past what the caller passed.
func (r *Runner) RunPath(ctx context.Context, pathID, owner string, ttl time.Duration, policy ExplorationPolicy) (*Run, error) {
	if err := r.configured(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	pathID = strings.TrimSpace(pathID)
	if pathID == "" {
		return nil, fmt.Errorf("%w: a path id is required", path.ErrInvalidArgument)
	}
	owner = r.claimOwner(owner)
	if ttl <= 0 {
		ttl = r.leaseTTL()
	}
	p, err := r.Paths.ClaimSpecificPath(ctx, pathID, owner, ttl)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrNotFound
	}
	if runnerPolicyEmpty(policy) {
		policy = r.Policy
	}
	return r.execute(ctx, "", p, owner, policy)
}

// execute runs one path the orchestrator already holds the lease on. RunOnce and
// RunPath differ only in how the path was chosen, so everything from the task
// build to the settlement lives here, once.
func (r *Runner) execute(ctx context.Context, auditID string, p *path.Path, owner string, policy ExplorationPolicy) (*Run, error) {
	caps := r.Runtime.Capabilities()
	runtimeName := caps.Name
	if strings.TrimSpace(runtimeName) == "" {
		runtimeName = "runtime"
	}

	// The task carries the policy the adapter is allowed to explore under. A task
	// that cannot be built or validated is an orchestrator bug, so the lease goes
	// straight back to the queue and no run is invented.
	policy = policy.Normalize()
	task, err := r.Tasks.BuildTask(ctx, *p, policy)
	if err != nil {
		r.releaseQuietly(ctx, p.ID, owner, "task could not be built: "+err.Error())
		return nil, fmt.Errorf("agent: build the task of path %s: %w", p.ID, err)
	}
	if strings.TrimSpace(task.PathID) == "" {
		task.PathID = p.ID
	}
	if strings.TrimSpace(task.SnapshotID) == "" {
		task.SnapshotID = p.SnapshotID
	}
	if strings.TrimSpace(task.AuditID) == "" {
		if p.AuditID != "" {
			task.AuditID = p.AuditID
		} else {
			task.AuditID = auditID
		}
	}
	if err := ValidateTask(task); err != nil {
		r.releaseQuietly(ctx, p.ID, owner, "task is not deliverable: "+err.Error())
		return nil, err
	}
	// The delivered policy is the one the exchange is judged against; the runner
	// only fills in for a builder that left it empty.
	if !runnerPolicyEmpty(task.Exploration) {
		policy = task.Exploration.Normalize()
	}
	expand := r.expandPolicy(policy)

	runAuditID := p.AuditID
	if runAuditID == "" {
		runAuditID = task.AuditID
	}
	if runAuditID == "" {
		runAuditID = auditID
	}
	attempt := r.attemptNumber(p)
	maxAttempts := r.maxAttempts(p)
	now := r.now()
	timeout := time.Duration(policy.TimeoutSeconds) * time.Second

	run := &Run{
		ID:             RunID(p.ID, runtimeName, attempt),
		PathID:         p.ID,
		AuditID:        runAuditID,
		SnapshotID:     task.SnapshotID,
		Runtime:        runtimeName,
		RuntimeVersion: caps.Version,
		Status:         RunCreated,
		Task:           task,
		Exploration:    policy,
		Budget:         Budget{TimeoutSeconds: policy.TimeoutSeconds, TokenBudget: policy.TokenBudget},
		Owner:          owner,
		DeadlineAt:     NowString(now.Add(timeout)),
		CreatedAt:      NowString(now),
		UpdatedAt:      NowString(now),
		Version:        1,
	}

	if err := r.Store.CreateRun(*run); err != nil {
		r.releaseQuietly(ctx, p.ID, owner, "the run could not be recorded: "+err.Error())
		return nil, fmt.Errorf("agent: create run %s: %w", run.ID, err)
	}
	if err := r.appendRunEvents(run, Event{
		Type: EventRunCreated, Actor: runnerActorOrchestrator,
		Summary: "run created for path " + p.ID,
		Detail: map[string]string{
			"runtime": runtimeName, "runtime_version": caps.Version,
			"attempt": fmt.Sprint(attempt), "owner": owner,
		},
	}); err != nil {
		return run, fmt.Errorf("agent: record run %s creation: %w", run.ID, err)
	}

	// The run is RUNNING before the adapter starts: an adapter that dies on its
	// first instruction must leave a visible attempt behind, not a CREATED row.
	run.Status = RunRunning
	run.StartedAt = NowString(now)
	if err := r.record(run,
		Event{Type: EventRunStarted, Actor: runnerActorOrchestrator, Summary: "adapter starting",
			Detail: map[string]string{"deadline_at": run.DeadlineAt}},
		Event{Type: EventTaskDelivered, Actor: runnerActorOrchestrator, Summary: "task delivered to the adapter",
			Detail: map[string]string{"security_goal": task.SecurityGoal, "path_id": task.PathID}},
	); err != nil {
		return run, fmt.Errorf("agent: mark run %s running: %w", run.ID, err)
	}

	handle, err := r.Runtime.Start(ctx, task)
	if err != nil {
		return r.finishAdapterStartFailure(ctx, p, owner, run, attempt, maxAttempts, err)
	}

	session := &runnerSession{
		runner:    r,
		run:       run,
		task:      task,
		owner:     owner,
		policy:    policy,
		expand:    expand,
		timeout:   timeout,
		startedAt: now,
		tracker:   NewRepeatTracker(policy.MaxRepeatedOutputs),
		branches:  1, // the run itself is the first active branch
		status:    RunRunning,
	}

	closed := false
	if handle != nil {
		closed = session.consume(ctx, handle)
		if !closed && handle.Cancel != nil {
			handle.Cancel()
		}
	}
	if closed {
		session.collect(ctx, handle)
	}
	return r.finish(ctx, p, owner, session, attempt, maxAttempts)
}

// RunAudit is the operator-facing entry point: it runs up to maxRuns paths of an
// audit sequentially and returns what ran.
//
// It is bounded twice over. maxRuns caps the call, and a path that produced
// nothing is not retried more than maxAttempts times inside the call; the moment
// either ceiling is reached the call returns what it has instead of spinning on a
// queue that keeps handing back the same work.
func (r *Runner) RunAudit(ctx context.Context, auditID string, maxRuns int) ([]Run, error) {
	if err := r.configured(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	limit := maxRuns
	if limit <= 0 {
		limit = r.MaxRuns
	}
	if limit <= 0 {
		limit = runnerDefaultMaxRuns
	}
	attempts := map[string]int{}
	bound := r.MaxAttempts
	if bound <= 0 {
		bound = path.DefaultLimits().MaxAttempts
	}
	runs := make([]Run, 0, 8)
	for len(runs) < limit {
		if err := ctx.Err(); err != nil {
			return runs, err
		}
		run, err := r.RunOnce(ctx, auditID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return runs, nil
			}
			return runs, err
		}
		if run == nil {
			return runs, nil
		}
		runs = append(runs, *run)
		if run.Status == RunSucceeded {
			continue
		}
		attempts[run.PathID]++
		if attempts[run.PathID] >= bound {
			// This path has spent its attempts here; claiming it again would
			// repeat a run that produced nothing.
			return runs, nil
		}
	}
	return runs, nil
}

// finishAdapterStartFailure records an adapter that could not start at all. The
// run is a FAILED attempt and the path goes back to the queue, because a start
// failure is exactly the case another attempt can survive.
func (r *Runner) finishAdapterStartFailure(ctx context.Context, p *path.Path, owner string, run *Run, attempt, maxAttempts int, startErr error) (*Run, error) {
	run.Status = RunFailed
	run.StopReason = StopAdapterFailed
	run.Error = startErr.Error()
	run.FinishedAt = NowString(r.now())
	// The path is settled before the run is closed, so the run record and its
	// events carry the same error the lease operation produced.
	r.settlePath(context.WithoutCancel(ctx), p, owner, run, StopAdapterFailed, false, attempt, maxAttempts)
	if err := r.record(run,
		Event{Type: EventRunError, Actor: runnerActorOrchestrator, Summary: "adapter failed to start: " + startErr.Error(),
			Detail: map[string]string{"stop_reason": StopAdapterFailed}},
		Event{Type: EventRunFinished, Actor: runnerActorOrchestrator, Summary: "run finished: FAILED (" + StopAdapterFailed + ")",
			Detail: map[string]string{"status": string(RunFailed), "stop_reason": StopAdapterFailed}},
	); err != nil {
		return run, fmt.Errorf("agent: record the failed start of run %s: %w", run.ID, err)
	}
	return run, nil
}

// finish settles the path, stores what the run produced, and writes the terminal
// run state with its closing events.
func (r *Runner) finish(ctx context.Context, p *path.Path, owner string, session *runnerSession, attempt, maxAttempts int) (*Run, error) {
	run := session.run
	if session.persistErr != nil {
		session.failPersist()
	}
	// A valid answer is a completed run unless the session already decided
	// otherwise. A clean end with no answer is not an adapter failure: the
	// adapter produced nothing the protocol accepts, which is invalid output.
	if session.stop == "" {
		if session.answer != nil {
			session.stop = StopCompleted
			session.status = RunSucceeded
		} else {
			session.stop = StopInvalidOutput
			session.status = RunInvalidOutput
			session.errText = "the adapter ended without a structured answer"
		}
	}

	settleCtx := context.WithoutCancel(ctx)
	if session.status == RunSucceeded {
		run.Answer = session.answer
		// SaveHypotheses upserts by (path_id, digest) and appends the
		// hypothesis_recorded event in the same transaction, which is why the
		// orchestrator does not append one itself.
		if err := r.Store.SaveHypotheses(runnerHypotheses(run, session.task, session.answer, r.now())); err != nil {
			session.stop = StopAdapterFailed
			session.status = RunFailed
			session.errText = "hypotheses could not be stored: " + err.Error()
		}
	}
	if session.status == RunSucceeded {
		if err := r.Paths.CompletePath(settleCtx, p.ID, owner, "hypothesis formed by run "+run.ID); err != nil {
			session.stop = StopPathNotActive
			session.status = RunFailed
			session.errText = "the path could not be advanced to HYPOTHESIS_FORMED: " + err.Error()
		}
	} else {
		r.settlePath(settleCtx, p, owner, run, session.stop, session.leaseLost, attempt, maxAttempts)
	}

	run.Status = session.status
	run.StopReason = session.stop
	run.Error = session.errText
	run.Exploration = session.policy
	run.ToolCalls = session.toolCalls
	run.Expansions = session.expansions
	run.ElapsedMS = r.now().Sub(session.startedAt).Milliseconds()
	run.FinishedAt = NowString(r.now())
	if session.exitCode != nil {
		run.ExitCode = session.exitCode
	}

	events := make([]Event, 0, 2)
	if session.status != RunSucceeded {
		events = append(events, Event{
			Type: EventRunError, Actor: runnerActorOrchestrator,
			Summary: runnerCapText(runnerFirstNonEmpty(session.errText, "run stopped: "+session.stop), MaxStatementChars),
			Detail:  map[string]string{"stop_reason": session.stop, "status": string(session.status)},
		})
	}
	events = append(events, Event{
		Type: EventRunFinished, Actor: runnerActorOrchestrator,
		Summary: "run finished: " + string(session.status) + " (" + session.stop + ")",
		Detail: map[string]string{
			"status": string(session.status), "stop_reason": session.stop,
			"tool_calls": fmt.Sprint(session.toolCalls), "expansions": fmt.Sprint(session.expansions),
			"input_tokens": fmt.Sprint(run.InputTokens), "output_tokens": fmt.Sprint(run.OutputTokens),
		},
	})
	if err := r.record(run, events...); err != nil {
		return run, fmt.Errorf("agent: finish run %s: %w", run.ID, err)
	}
	return run, nil
}

// settlePath applies the stop reason to the path. A lost lease is the one case
// the orchestrator must not touch: the path is not ours any more, and "releasing"
// it would either fail or steal it from a worker that is already running it.
func (r *Runner) settlePath(ctx context.Context, p *path.Path, owner string, run *Run, stop string, leaseLost bool, attempt, maxAttempts int) {
	if leaseLost {
		return
	}
	reason := "run " + run.ID + " stopped: " + stop
	var err error
	if attempt >= maxAttempts {
		// The path has spent its attempts: take it out of the queue so the
		// scheduler does not hand the same work to the next worker unchanged.
		err = r.Paths.AdvancePath(ctx, p.ID, owner, path.StatusFailed, reason)
	} else {
		err = r.Paths.ReleasePath(ctx, p.ID, owner, reason)
	}
	if err != nil {
		run.Error = strings.TrimSpace(run.Error + "; the path could not be settled: " + err.Error())
	}
}

// releaseQuietly returns a lease the orchestrator claimed but decided not to use.
// The release uses a context that outlives a cancelled run: the lease must not
// leak just because the caller gave up.
func (r *Runner) releaseQuietly(ctx context.Context, pathID, owner, reason string) {
	_ = r.Paths.ReleasePath(context.WithoutCancel(ctx), pathID, owner, reason)
}

// runnerSession is the state of one run while its adapter is alive. It exists so
// the event loop can decide and record without threading a dozen locals through
// every branch, and so a persistence failure has one place to land.
type runnerSession struct {
	runner    *Runner
	run       *Run
	task      Task
	owner     string
	policy    ExplorationPolicy
	expand    ExpandPolicy
	timeout   time.Duration
	startedAt time.Time

	tracker    *RepeatTracker
	toolCalls  int
	expansions int
	branches   int

	answer     *Answer
	stop       string
	status     RunStatus
	errText    string
	exitCode   *int
	leaseLost  bool
	persistErr error
}

// consume reads the adapter's stream until it ends or the orchestrator decides to
// stop it. It reports whether the stream ended on its own, because only then is
// there a terminal result worth reading.
func (s *runnerSession) consume(ctx context.Context, handle *Handle) bool {
	ticker := time.NewTicker(s.runner.heartbeatEvery())
	defer ticker.Stop()
	timer := time.NewTimer(s.timeout)
	defer timer.Stop()
	events := handle.Events
	for {
		select {
		case <-ctx.Done():
			s.stop = StopCancelled
			s.status = RunCancelled
			s.errText = runnerContextError(ctx)
			return false
		case <-timer.C:
			s.stop = StopDeadline
			s.status = RunTimedOut
			s.errText = "the run exceeded its wall-clock deadline"
			return false
		case <-ticker.C:
			if err := s.beat(ctx); err != nil {
				// A failed heartbeat means the lease is gone. Continuing would
				// spend budget on a path another worker may already hold.
				s.leaseLost = true
				s.stop = StopLeaseLost
				s.status = RunFailed
				s.errText = "the path lease was lost: " + err.Error()
				return false
			}
			if s.persistErr != nil {
				return false
			}
		case ev, ok := <-events:
			if !ok {
				return true
			}
			if s.applyEvent(ctx, ev) {
				return false
			}
		}
	}
}

// collect reads the terminal result the adapter produced. It never blocks longer
// than the grace period: an adapter that closed its stream without a result is
// judged on what it already said.
func (s *runnerSession) collect(ctx context.Context, handle *Handle) {
	if handle == nil || handle.Done == nil {
		return
	}
	timer := time.NewTimer(runnerTerminalGrace)
	defer timer.Stop()
	select {
	case res, ok := <-handle.Done:
		if ok {
			s.applyResult(res)
		}
	case <-ctx.Done():
		if s.stop == "" {
			s.stop = StopCancelled
			s.status = RunCancelled
			s.errText = runnerContextError(ctx)
		}
	case <-timer.C:
	}
}

// beat renews the path lease and records the fact. A renewal error is returned so
// the loop can stop; a recording error lands in persistErr, because it is a
// different failure with a different meaning.
func (s *runnerSession) beat(ctx context.Context) error {
	if err := s.runner.Paths.HeartbeatPath(ctx, s.run.PathID, s.owner, s.runner.leaseTTL()); err != nil {
		_ = s.append(Event{
			Type: EventRunError, Actor: runnerActorOrchestrator,
			Summary: "heartbeat failed: " + err.Error(),
			Detail:  map[string]string{"stop_reason": StopLeaseLost},
		})
		return err
	}
	s.run.HeartbeatAt = NowString(s.runner.now())
	if err := s.runner.record(s.run, Event{
		Type: EventRunHeartbeat, Actor: runnerActorOrchestrator, Summary: "path lease renewed",
		Detail: map[string]string{"lease_ttl_seconds": fmt.Sprint(int(s.runner.leaseTTL().Seconds()))},
	}); err != nil {
		s.persistErr = err
	}
	return nil
}

// applyEvent counts usage, dispatches one adapter event, and enforces the token
// budget. It returns true when the run must stop.
func (s *runnerSession) applyEvent(ctx context.Context, ev RuntimeEvent) bool {
	s.run.InputTokens += ev.InputTokens
	s.run.OutputTokens += ev.OutputTokens
	var stop bool
	switch {
	case ev.Tool != nil:
		stop = s.applyTool(ctx, ev)
	case ev.Expansion != nil:
		stop = s.applyExpansion(ev)
	case runnerHasAnswer(ev):
		stop = s.applyAnswerOutput(ev)
	case ev.Type == EventOutputRejected:
		// An adapter that already refused its own structured output says so with
		// this event. The protocol explained why; the orchestrator only decides
		// what that means for the run.
		stop = s.applyOutputRejected(ev)
	default:
		stop = s.applyNote(ev)
	}
	if stop {
		return true
	}
	if s.tokenBudgetExceeded() {
		s.stop = StopTokenBudget
		s.status = RunBudgetExceeded
		s.errText = fmt.Sprintf("the adapter reported %d token(s) against a budget of %d",
			s.run.InputTokens+s.run.OutputTokens, s.policy.TokenBudget)
		return true
	}
	return false
}

// applyTool validates a tool request against the current policy and either runs it
// through the registry or refuses it.
//
// A request outside the allowlist is denied and the run continues: refusing an
// over-reach is the protocol working, not the adapter failing. Exhausting the
// tool budget is different — the run is over it and stops.
func (s *runnerSession) applyTool(ctx context.Context, ev RuntimeEvent) bool {
	req := *ev.Tool
	reply := ToolResult{CallID: req.CallID, Tool: req.Tool, Error: "tool request denied"}
	defer func() {
		if ev.ToolReply != nil {
			select {
			case ev.ToolReply <- reply:
			case <-ctx.Done():
			}
		}
	}()
	asked := Event{
		Type: EventToolRequested, Actor: runnerActorAgent,
		CallID: req.CallID, Tool: req.Tool,
		Summary: "tool requested: " + runnerCapText(req.Tool, MaxNotesChars),
		Detail:  map[string]string{"arguments": fmt.Sprint(len(req.Args))},
	}
	if err := ValidateToolRequest(req, s.policy, s.toolCalls); err != nil {
		denied := Event{
			Type: EventToolDenied, Actor: runnerActorOrchestrator,
			CallID: req.CallID, Tool: req.Tool,
			Summary: "tool denied: " + err.Error(),
			Detail:  map[string]string{"reason": err.Error(), "allowed_tools": strings.Join(s.policy.AllowedTools, ",")},
		}
		if errors.Is(err, ErrBudgetExhausted) {
			if s.append(asked, denied) {
				return true
			}
			s.stop = StopToolBudget
			s.status = RunBudgetExceeded
			s.errText = err.Error()
			return true
		}
		return s.append(asked, denied)
	}
	executor, ok := s.lookup(req.Tool)
	if !ok {
		denied := Event{
			Type: EventToolDenied, Actor: runnerActorOrchestrator,
			CallID: req.CallID, Tool: req.Tool,
			Summary: "tool denied: " + req.Tool + " is allowed by the policy but not registered with the orchestrator",
			Detail:  map[string]string{"reason": "not registered"},
		}
		return s.append(asked, denied)
	}

	started := s.runner.now()
	result, callErr := executor.Call(ctx, req.Args)
	elapsed := s.runner.now().Sub(started).Milliseconds()
	s.toolCalls++
	s.run.ToolCalls = s.toolCalls
	reply.ElapsedMS = elapsed
	if callErr == nil {
		reply.OK, reply.Error, reply.Refs = result.OK, result.Error, result.Refs
		reply.Result, _ = TruncateToolResult(result.Result)
	} else {
		reply.Error = callErr.Error()
	}

	allowed := Event{
		Type: EventToolAllowed, Actor: runnerActorOrchestrator,
		CallID: req.CallID, Tool: req.Tool,
		Summary: "tool allowed: " + req.Tool + " is in the allowlist",
	}
	resultEvent := Event{
		Type: EventToolResult, Actor: runnerActorOrchestrator,
		CallID: req.CallID, Tool: req.Tool,
		Detail: map[string]string{"elapsed_ms": fmt.Sprint(elapsed)},
	}
	switch {
	case callErr != nil:
		resultEvent.Summary = "tool call failed: " + req.Tool
		resultEvent.Detail["ok"] = "false"
		resultEvent.Detail["error"] = callErr.Error()
	case !result.OK:
		resultEvent.Summary = "tool returned no result for " + req.Tool
		resultEvent.Detail["ok"] = "false"
		if result.Error != "" {
			resultEvent.Detail["error"] = result.Error
		}
	default:
		payload, truncated := TruncateToolResult(result.Result)
		resultEvent.Summary = "tool returned a result for " + req.Tool
		resultEvent.Detail["ok"] = "true"
		resultEvent.Detail["result"] = payload
		if truncated {
			resultEvent.Detail["truncated"] = "true"
		}
	}
	return s.update(asked, allowed, resultEvent)
}

// applyExpansion decides an expansion request with DecideExpansion, folds the
// grant into the run policy with ApplyExpansion, and records both halves. The
// tool allowlist is never part of the grant.
func (s *runnerSession) applyExpansion(ev RuntimeEvent) bool {
	ask := *ev.Expansion
	requested := Event{
		Type: EventExpansionAsked, Actor: runnerActorAgent,
		Summary: "expansion requested: " + runnerCapText(ask.Purpose, MaxExpansionText),
		Detail: map[string]string{
			"target_node_id":        runnerCapText(ask.TargetNodeID, MaxExpansionText),
			"purpose":               runnerCapText(ask.Purpose, MaxExpansionText),
			"expected_gain":         runnerCapText(ask.ExpectedGain, MaxExpansionText),
			"estimated_cost":        runnerCapText(ask.EstimatedCost, MaxExpansionText),
			"additional_hops":       fmt.Sprint(ask.Hops),
			"additional_tool_calls": fmt.Sprint(ask.ToolCalls),
		},
	}
	decision := s.decide(ask)
	decided := Event{
		Type: EventExpansionDecided, Actor: runnerActorOrchestrator,
		Summary: "expansion " + decision.Decision + ": " + runnerCapText(decision.Reason, MaxExpansionText),
		Detail: map[string]string{
			"decision": decision.Decision, "reason": decision.Reason,
			"granted_hops":       fmt.Sprint(decision.GrantedHops),
			"granted_tool_calls": fmt.Sprint(decision.GrantedToolCalls),
			"granted_tools":      strings.Join(decision.GrantedTools, ","),
		},
	}
	s.expansions++
	s.run.Expansions = s.expansions
	if decision.Decision == ExpansionApproved || decision.Decision == ExpansionShrunk {
		s.policy = ApplyExpansion(s.policy, decision)
		s.run.Exploration = s.policy
		s.branches += decision.GrantedHops
	}
	return s.update(requested, decided)
}

// decide asks the fixed protocol for a decision and then makes sure the grant
// cannot name a tool the run may not call. An expansion buys room, not
// permissions.
func (s *runnerSession) decide(ask ExpansionAsk) ExpansionDecision {
	decision := DecideExpansion(ask, s.expand, s.policy, s.expansions, s.branches)
	if len(decision.GrantedTools) > 0 {
		granted := make([]string, 0, len(decision.GrantedTools))
		for _, name := range decision.GrantedTools {
			if s.policy.Allows(name) {
				granted = append(granted, name)
			}
		}
		decision.GrantedTools = granted
	}
	return decision
}

// applyAnswerOutput validates one answer an adapter emitted as an event.
func (s *runnerSession) applyAnswerOutput(ev RuntimeEvent) bool {
	raw, ok := runnerRawAnswer(ev)
	if !ok {
		return s.applyNote(ev)
	}
	return !s.acceptAnswer(raw, "event")
}

// acceptAnswer runs adapter output through DecodeAnswer, rejects a repeat that
// carries no new evidence, and only then accepts it. Invalid output ends the run:
// an adapter that cannot produce the protocol is not going to produce it by being
// asked again in the same run.
func (s *runnerSession) acceptAnswer(raw []byte, source string) bool {
	answer, err := DecodeAnswer(raw, s.task)
	if err != nil {
		s.rejectOutput(source, err)
		s.stop = StopInvalidOutput
		s.status = RunInvalidOutput
		s.errText = err.Error()
		return false
	}
	if repeated, count := s.tracker.Observe(answer.Hypothesis.Statement, len(answer.SupportingEvidence)+len(answer.ContradictingEvidence)); repeated {
		reason := fmt.Sprintf("the same output was produced %d times without new evidence", count)
		s.rejectOutput(source, errors.New(reason))
		s.stop = StopRepeatedOutput
		s.status = RunFailed
		s.errText = reason
		return false
	}
	s.answer = answer
	return !s.update(Event{
		Type: EventOutputReceived, Actor: runnerActorAgent,
		Summary: "structured answer received: " + runnerCapText(answer.Hypothesis.Statement, MaxStatementChars),
		Detail: map[string]string{
			"status": answer.Hypothesis.Status, "confidence": answer.Hypothesis.Confidence,
			"supporting":        fmt.Sprint(len(answer.SupportingEvidence)),
			"contradicting":     fmt.Sprint(len(answer.ContradictingEvidence)),
			"finding_candidate": fmt.Sprint(answer.FindingCandidate),
		},
	})
}

// applyOutputRejected records an adapter's own refusal of its structured output
// and ends the run as invalid output: the adapter has told the orchestrator that
// what it produced is not the protocol, and repeating the run would spend budget
// on the same failure.
func (s *runnerSession) applyOutputRejected(ev RuntimeEvent) bool {
	reason := runnerFirstNonEmpty(ev.Detail["error"], ev.Summary, "the adapter reported invalid structured output")
	_ = s.append(Event{
		Type: EventOutputRejected, Actor: runnerActorOrchestrator,
		Summary: "output rejected: " + runnerCapText(reason, MaxStatementChars),
		Detail:  map[string]string{"source": "adapter", "reason": runnerCapText(reason, MaxNotesChars)},
	})
	s.stop = StopInvalidOutput
	s.status = RunInvalidOutput
	s.errText = reason
	return true
}

// rejectOutput records why an answer was not accepted. The reason is the
// protocol's own message, which names the offending field.
func (s *runnerSession) rejectOutput(source string, cause error) {
	_ = s.append(Event{
		Type: EventOutputRejected, Actor: runnerActorOrchestrator,
		Summary: "output rejected: " + cause.Error(),
		Detail:  map[string]string{"source": source, "reason": cause.Error()},
	})
}

// applyNote records a summary or a detail the adapter sent that is not a request
// and not an answer. Notes are capped: the log is an audit trail, not a
// transcript.
func (s *runnerSession) applyNote(ev RuntimeEvent) bool {
	event := Event{
		Type: runnerEventNote, Actor: runnerActorAgent,
		Summary: runnerCapText(ev.Summary, MaxStatementChars),
	}
	detail := runnerCapDetails(ev.Detail)
	if ev.Type != "" {
		detail["runtime_event"] = runnerCapText(ev.Type, MaxNotesChars)
	}
	if len(detail) > 0 {
		event.Detail = detail
	}
	return s.append(event)
}

// applyResult reads the terminal result the adapter produced. The answer, when
// there is one, is validated again: the adapter's word is never enough.
//
// A stop the orchestrator already decided is not overridden: an adapter that
// reported its own invalid output and then failed with the same error must be
// recorded as invalid output, not as an adapter failure.
func (s *runnerSession) applyResult(res RuntimeResult) {
	exitCode := res.ExitCode
	s.exitCode = &exitCode
	if res.Answer != nil && s.answer == nil {
		if raw, err := json.Marshal(res.Answer); err == nil {
			s.acceptAnswer(raw, "terminal result")
		}
	}
	if s.stop != "" {
		return
	}
	if res.Err != nil {
		s.stop = StopAdapterFailed
		s.status = RunFailed
		s.errText = res.Err.Error()
		return
	}
	if res.ExitCode != 0 && s.answer == nil {
		s.stop = StopAdapterFailed
		s.status = RunFailed
		s.errText = fmt.Sprintf("the adapter exited with code %d and no structured answer", res.ExitCode)
	}
}

// tokenBudgetExceeded reports whether reported usage has passed the policy's
// allowance. A budget of zero means "not enforced".
func (s *runnerSession) tokenBudgetExceeded() bool {
	if s.policy.TokenBudget <= 0 {
		return false
	}
	return s.run.InputTokens+s.run.OutputTokens > s.policy.TokenBudget
}

// lookup finds a registered tool, tolerating a Runner without a registry.
func (s *runnerSession) lookup(name string) (ToolExecutor, bool) {
	if s.runner.Registry == nil {
		return nil, false
	}
	return s.runner.Registry.Lookup(name)
}

// append records events that do not change the run's own counters.
func (s *runnerSession) append(events ...Event) bool {
	if err := s.runner.appendRunEvents(s.run, events...); err != nil {
		s.persistErr = err
		s.failPersist()
		return true
	}
	return false
}

// update records the run together with the events that explain the change.
func (s *runnerSession) update(events ...Event) bool {
	if err := s.runner.record(s.run, events...); err != nil {
		s.persistErr = err
		s.failPersist()
		return true
	}
	return false
}

// failPersist turns a storage failure into a terminal state. A run that cannot be
// recorded is over: continuing would spend budget on an attempt nobody can audit.
func (s *runnerSession) failPersist() {
	s.stop = StopAdapterFailed
	s.status = RunFailed
	if s.persistErr != nil {
		s.errText = "the run could not be recorded: " + s.persistErr.Error()
	}
}

// expandPolicy normalizes the expansion policy and closes it over the run's own
// allowlist. Whatever the configured ExpandPolicy advertises, the tool allowlist
// of a grant is the run's allowlist, and the run policy's expansion budget is an
// additional ceiling on the number of requests.
func (r *Runner) expandPolicy(policy ExplorationPolicy) ExpandPolicy {
	defaults := DefaultExpandPolicy(nil)
	expand := r.Expand
	if expand.MaxHopsPerExpansion <= 0 {
		expand.MaxHopsPerExpansion = defaults.MaxHopsPerExpansion
	}
	if expand.MaxToolCallsPerExpansion <= 0 {
		expand.MaxToolCallsPerExpansion = defaults.MaxToolCallsPerExpansion
	}
	if expand.MaxExpansionsPerRun <= 0 {
		expand.MaxExpansionsPerRun = defaults.MaxExpansionsPerRun
	}
	if policy.MaxExpansions > 0 && policy.MaxExpansions < expand.MaxExpansionsPerRun {
		expand.MaxExpansionsPerRun = policy.MaxExpansions
	}
	expand.AllowedTools = append([]string(nil), policy.AllowedTools...)
	return expand
}

// attemptNumber is how many attempts this run is, counted from the run log. The
// path engine's Attempts counter is not advanced by a claim, so the store is the
// authority on how many times a path has already been tried.
func (r *Runner) attemptNumber(p *path.Path) int {
	attempt := p.Attempts + 1
	if runs, _, err := r.Store.ListRuns(RunQuery{PathID: p.ID, Limit: 1000}); err == nil && len(runs)+1 > attempt {
		attempt = len(runs) + 1
	}
	return attempt
}

// maxAttempts prefers the path's own limit, then the runner's, then the
// documented default.
func (r *Runner) maxAttempts(p *path.Path) int {
	if p.MaxAttempts > 0 {
		return p.MaxAttempts
	}
	if r.MaxAttempts > 0 {
		return r.MaxAttempts
	}
	return path.DefaultLimits().MaxAttempts
}

func (r *Runner) configured() error {
	if r == nil {
		return errRunnerNotConfigured
	}
	var missing []string
	if r.Store == nil {
		missing = append(missing, "Store")
	}
	if r.Runtime == nil {
		missing = append(missing, "Runtime")
	}
	if r.Tasks == nil {
		missing = append(missing, "Tasks")
	}
	if r.Paths == nil {
		missing = append(missing, "Paths")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", errRunnerNotConfigured, strings.Join(missing, ", "))
	}
	if ready, ok := r.Runtime.(interface{ Ready() error }); ok {
		return ready.Ready()
	}
	return nil
}

// Ready allows schedulers to check live model configuration before claiming work.
func (r *Runner) Ready() error { return r.configured() }

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Runner) owner() string {
	if strings.TrimSpace(r.Owner) != "" {
		return r.Owner
	}
	return runnerActorOrchestrator
}

// claimOwner resolves the lease owner of an explicit claim. A caller that names
// one gets it; otherwise the runner's configured owner is used, so a scheduler
// and the runner it dispatches to agree on whose lease it is.
func (r *Runner) claimOwner(owner string) string {
	if trimmed := strings.TrimSpace(owner); trimmed != "" {
		return trimmed
	}
	return r.owner()
}

func (r *Runner) heartbeatEvery() time.Duration {
	if r.HeartbeatEvery > 0 {
		return r.HeartbeatEvery
	}
	return runnerDefaultHeartbeatEvery
}

// leaseTTL is the lease the orchestrator asks for: a multiple of the heartbeat
// interval, so the lease can survive a late renewal and the renewal is never sent
// more often than HeartbeatEvery.
func (r *Runner) leaseTTL() time.Duration {
	return runnerLeaseTTLFactor * r.heartbeatEvery()
}

// record writes run state and then the events that explain it, in that order: an
// event that describes a state the store does not hold is worse than a log that
// is one entry short.
func (r *Runner) record(run *Run, events ...Event) error {
	run.UpdatedAt = NowString(r.now())
	if err := r.Store.UpdateRun(*run, 0); err != nil {
		return err
	}
	run.Version++
	return r.appendRunEvents(run, events...)
}

// appendRunEvents numbers and identifies a batch of events. The sequence is read
// again for every batch because SaveHypotheses appends to the same log.
func (r *Runner) appendRunEvents(run *Run, events ...Event) error {
	if len(events) == 0 {
		return nil
	}
	seq, err := r.Store.NextRunEventSeq(run.ID)
	if err != nil {
		return err
	}
	now := NowString(r.now())
	for i := range events {
		if events[i].RunID == "" {
			events[i].RunID = run.ID
		}
		if events[i].PathID == "" {
			events[i].PathID = run.PathID
		}
		if events[i].Actor == "" {
			events[i].Actor = runnerActorOrchestrator
		}
		if events[i].CreatedAt == "" {
			events[i].CreatedAt = now
		}
		if events[i].Summary != "" {
			events[i].Summary = runnerCapText(events[i].Summary, MaxStatementChars)
		}
		events[i].Seq = seq
		events[i].ID = EventID(run.ID, seq)
		seq++
	}
	return r.Store.AppendRunEvents(events)
}

// runnerHypotheses turns one accepted answer into the claim it asserts. A run
// produces one hypothesis per claim, keyed by the statement so the same claim
// recorded twice is one hypothesis.
func runnerHypotheses(run *Run, task Task, answer *Answer, now time.Time) []Hypothesis {
	if answer == nil {
		return nil
	}
	statement := answer.Hypothesis.Statement
	stamp := NowString(now)
	return []Hypothesis{{
		ID:               HypothesisID(run.PathID, statement),
		RunID:            run.ID,
		PathID:           run.PathID,
		AuditID:          run.AuditID,
		SnapshotID:       run.SnapshotID,
		SecurityGoal:     task.SecurityGoal,
		Statement:        statement,
		Status:           answer.Hypothesis.Status,
		Confidence:       answer.Hypothesis.Confidence,
		Supporting:       runnerEvidence(answer.SupportingEvidence),
		Contradicting:    runnerEvidence(answer.ContradictingEvidence),
		NextAction:       answer.NextAction,
		FindingCandidate: answer.FindingCandidate,
		SeverityHint:     answer.SeverityHint,
		Digest:           Digest(statement),
		CreatedAt:        stamp,
		UpdatedAt:        stamp,
	}}
}

func runnerEvidence(items []AnswerEvidence) []EvidenceRef {
	out := make([]EvidenceRef, 0, len(items))
	for _, item := range items {
		out = append(out, EvidenceRef{
			Kind: item.Kind, ID: item.Ref, Summary: item.Summary, File: item.File, Line: item.Line,
		})
	}
	return out
}

// runnerHasAnswer reports whether an event carries structured output, either
// typed or as raw JSON.
func runnerHasAnswer(ev RuntimeEvent) bool {
	if ev.Answer != nil {
		return true
	}
	_, ok := runnerRawAnswer(ev)
	return ok
}

// runnerRawAnswer returns the JSON an event carries. A typed answer is marshalled
// back so that every path into the run goes through DecodeAnswer and its
// DisallowUnknownFields check.
func runnerRawAnswer(ev RuntimeEvent) ([]byte, bool) {
	if ev.Answer != nil {
		raw, err := json.Marshal(ev.Answer)
		if err != nil {
			return nil, false
		}
		return raw, true
	}
	for _, key := range []string{runnerDetailAnswerJSON} {
		if raw, ok := ev.Detail[key]; ok && strings.TrimSpace(raw) != "" {
			return []byte(raw), true
		}
	}
	return nil, false
}

// runnerPolicyEmpty reports whether a task builder left the policy untouched, in
// which case the runner's own policy is what the run is judged against.
func runnerPolicyEmpty(p ExplorationPolicy) bool {
	return p.MaxHops == 0 && p.MaxBranches == 0 && p.MaxToolCalls == 0 && p.MaxExpansions == 0 &&
		p.TimeoutSeconds == 0 && p.TokenBudget == 0 && p.MaxRepeatedOutputs == 0 && len(p.AllowedTools) == 0
}

// runnerCapText bounds a note before it reaches the event log. Only Summary,
// Detail and short reasons are ever stored, and none of them is a transcript.
func runnerCapText(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func runnerCapDetails(detail map[string]string) map[string]string {
	out := make(map[string]string, len(detail)+1)
	for key, value := range detail {
		out[runnerCapText(key, MaxNotesChars)] = runnerCapText(value, MaxNotesChars)
	}
	return out
}

func runnerContextError(ctx context.Context) string {
	if err := ctx.Err(); err != nil {
		return err.Error()
	}
	return "the run was cancelled"
}

func runnerFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
