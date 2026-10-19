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
	"sort"
	"strings"
	"sync"
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
	// Runtimes is the deployment's selectable catalog. A task's audit names one;
	// an empty or unknown name falls back to DefaultRuntime and then Runtime.
	Runtimes       map[string]Runtime
	DefaultRuntime string
	// RuntimeFor resolves a task's runtime choice. The app wires it to the audit
	// store; a nil resolver means "use the default".
	RuntimeFor func(auditID string) string
	Tasks      TaskBuilder
	Paths      PathCoordinator
	// Policy is the starting exploration policy of a run. It is normalized, then
	// handed to the task builder, and it is the policy every request is judged
	// against until an approved expansion widens it.
	Policy ExplorationPolicy
	// Expand decides expansion requests. Only ApplyExpansion may change a run's
	// limits, and it never widens the tool allowlist.
	Expand ExpandPolicy
	// Repair is the one correction budget every turn-control decision shares. It
	// defaults to two corrections of at most 300 bytes.
	Repair RepairPolicy
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
	return r.execute(ctx, auditID, p, owner, r.Policy, nil)
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
	return r.execute(ctx, "", p, owner, policy, nil)
}

// execute runs one path the orchestrator already holds the lease on. RunOnce and
// RunPath differ only in how the path was chosen, so everything from the task
// build to the settlement lives here, once.
func (r *Runner) execute(ctx context.Context, auditID string, p *path.Path, owner string, policy ExplorationPolicy, seed *runSeed) (*Run, error) {
	ctx = path.WithLease(ctx, p.ID, p.LeaseEpoch)
	adapter, err := r.selectRuntime(auditID)
	if err != nil {
		r.releaseQuietly(ctx, p.ID, owner, err.Error())
		return nil, err
	}
	caps := adapter.Capabilities()
	runtimeName := caps.Name
	if strings.TrimSpace(runtimeName) == "" {
		runtimeName = "runtime"
	}

	// The task carries the policy the adapter is allowed to explore under. A task
	// that cannot be built or validated is an orchestrator bug, so the lease goes
	// straight back to the queue and no run is invented.
	policy = policy.Normalize()
	var task Task
	if seed != nil {
		task = seed.task
		if seed.frontier != nil {
			task.Resume = &ResumeContext{PreviousRunID: seed.resumeOf, Frontier: seed.frontier}
		}
	} else {
		task, err = r.Tasks.BuildTask(ctx, *p, policy)
		if err != nil {
			r.releaseQuietly(ctx, p.ID, owner, "task could not be built: "+err.Error())
			return nil, fmt.Errorf("agent: build the task of path %s: %w", p.ID, err)
		}
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
	// One table and one projection per run. The table is persisted with the run, so
	// a resumed or audited run can resolve the aliases it handed the model; the
	// projection is what the model actually reads.
	aliases := NewAliasTable(task)
	rendered := RenderTask(task, aliases)

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

	toolDigest := ToolSchemaDigest(r.Registry.Descriptors(policy.AllowedTools))
	pin := RuntimePin{
		Runtime: runtimeName, RuntimeVersion: caps.Version,
		PromptVersion: PromptVersion, ToolSchemaDigest: toolDigest,
	}
	if provider, ok := adapter.(PinProvider); ok {
		resolved, err := provider.Pin()
		if err != nil {
			r.releaseQuietly(ctx, p.ID, owner, "the runtime configuration could not be pinned: "+err.Error())
			return nil, fmt.Errorf("agent: pin the runtime of path %s: %w", p.ID, err)
		}
		resolved.Runtime, resolved.RuntimeVersion = runtimeName, caps.Version
		resolved.PromptVersion, resolved.ToolSchemaDigest = PromptVersion, toolDigest
		pin = resolved
	}
	run := &Run{
		ID:               RunID(p.ID, runtimeName, attempt),
		ResumeOf:         seedResumeOf(seed),
		ToolSchemaDigest: toolDigest,
		Pin:              &pin,
		PathID:           p.ID,
		AuditID:          runAuditID,
		SnapshotID:       task.SnapshotID,
		Runtime:          runtimeName,
		RuntimeVersion:   caps.Version,
		Status:           RunCreated,
		Task:             task,
		Exploration:      policy,
		Budget:           Budget{TimeoutSeconds: policy.TimeoutSeconds, TokenBudget: policy.TokenBudget},
		Owner:            owner,
		Aliases:          aliases,
		LeaseEpoch:       p.LeaseEpoch,
		DeadlineAt:       NowString(now.Add(timeout)),
		CreatedAt:        NowString(now),
		UpdatedAt:        NowString(now),
		Version:          1,
	}

	created := Event{
		Type: EventRunCreated, Actor: runnerActorOrchestrator, CreatedAt: run.CreatedAt,
		Summary: "run created for path " + p.ID,
		Detail:  map[string]string{"runtime": runtimeName, "runtime_version": caps.Version, "attempt": fmt.Sprint(attempt), "owner": owner},
	}
	if err := r.createRun(ctx, run, created); err != nil {
		if !errors.Is(err, ErrConflict) {
			r.releaseQuietly(ctx, p.ID, owner, "the run could not be recorded: "+err.Error())
		}
		return nil, fmt.Errorf("agent: create run %s: %w", run.ID, err)
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

	if seed != nil {
		if err := r.record(run, Event{Type: EventRunResumed, Actor: runnerActorOrchestrator,
			Summary: "run resumed from checkpoint of " + seed.resumeOf,
			Detail:  map[string]string{"previous_run_id": seed.resumeOf, "frontier": fmt.Sprint(len(seed.frontier)), "tool_calls": fmt.Sprint(seed.usage.ToolCalls)}}); err != nil {
			return run, fmt.Errorf("agent: record the resume of %s: %w", seed.resumeOf, err)
		}
	}
	adapterCtx := WithRunGeneration(ctx, generationOf(p))
	adapterCtx = WithRunID(adapterCtx, run.ID)
	adapterCtx = WithAliasTable(adapterCtx, aliases)
	adapterCtx = WithRenderedTask(adapterCtx, rendered)
	handle, err := adapter.Start(adapterCtx, task)
	if err != nil {
		return r.finishAdapterStartFailure(ctx, p, owner, run, attempt, maxAttempts, err)
	}

	// Aliases are the model-facing vocabulary of turn-control adapters. A scripted
	// or cli adapter sends canonical ids, so resolving them would deny calls that
	// are already in scope; those adapters keep working unchanged.
	sessionAliases := aliases
	if !caps.TurnControl {
		sessionAliases = nil
	}
	session := &runnerSession{
		runner:       r,
		run:          run,
		task:         task,
		owner:        owner,
		policy:       policy,
		expand:       expand,
		timeout:      timeout,
		startedAt:    now,
		tracker:      NewRepeatTracker(policy.MaxRepeatedOutputs),
		branches:     1, // the run itself is the first active branch
		status:       RunRunning,
		generation:   generationOf(p),
		aliases:      sessionAliases,
		batchResults: map[string]batchCallRecord{},
		reservations: map[string]int{},
		usageSeen:    map[string]bool{},
		proposals:    map[string]proposalVerdict{},
	}
	if seed != nil {
		session.seenRefs = map[string]struct{}{}
		for _, ref := range seed.evidence {
			session.seenRefs[ref] = struct{}{}
		}
		session.toolCalls = seed.usage.ToolCalls
		run.InputTokens, run.OutputTokens = seed.usage.InputTokens, seed.usage.OutputTokens
		run.ToolCalls = seed.usage.ToolCalls
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
	// Close the last round for the record, but never convert a valid answer into a
	// converged stop: the answer is the run's conclusion.
	session.finishRound(false)
	run := session.run
	if session.persistErr != nil {
		session.failPersist()
	}
	// A valid answer is a completed run unless the session already decided
	// otherwise. A clean end with no answer is not an adapter failure: the
	// adapter produced nothing the protocol accepts, which is invalid output.
	// A clean end releases whatever the provider never reconciled. A crash leaves
	// those reservations in the ledger: unconfirmed in-flight spending is kept, not
	// cleared.
	for requestID, reserve := range session.reservations {
		if err := r.Store.SettleAuditTokens(session.run.AuditID, reserve, 0); err != nil && session.persistErr == nil {
			session.persistErr = err
		}
		delete(session.reservations, requestID)
	}
	if session.pauseRequested {
		return r.finishPaused(ctx, p, owner, session)
	}
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
	run.Metrics = session.metrics()
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
			"rounds": fmt.Sprint(run.Metrics.Rounds), "exchanges": fmt.Sprint(run.Metrics.Exchanges),
			"invalid_calls": fmt.Sprint(run.Metrics.InvalidCalls), "truncations": fmt.Sprint(run.Metrics.Truncations),
		},
	})
	if err := r.record(run, events...); err != nil {
		return run, fmt.Errorf("agent: finish run %s: %w", run.ID, err)
	}
	return run, nil
}

// runSeed is what a resumed attempt inherits from its checkpoint. The task is the
// paused run's own task; the frontier is its open work.
type runSeed struct {
	task     Task
	evidence []string
	usage    CheckpointUsage
	resumeOf string
	frontier []string
}

func seedResumeOf(seed *runSeed) string {
	if seed == nil {
		return ""
	}
	return seed.resumeOf
}

// finishPaused saves the checkpoint and only then publishes PAUSED. The attempt
// carries no answer; the path is released so a resume can claim it again.
func (r *Runner) finishPaused(ctx context.Context, p *path.Path, owner string, session *runnerSession) (*Run, error) {
	run := session.run
	checkpoint, err := BuildCheckpoint(CheckpointInput{
		Run: *run, Task: session.task, Evidence: sessionEvidence(session.seenRefs),
		Aliases: session.aliases, Usage: CheckpointUsage{InputTokens: run.InputTokens, OutputTokens: run.OutputTokens, ToolCalls: session.toolCalls},
		Reason: session.pauseReason, Now: r.now(),
	})
	if err != nil {
		return r.failPause(ctx, p, owner, session, err)
	}
	run.Status, run.StopReason, run.Error = RunPaused, StopBudgetPaused, session.pauseReason
	run.CheckpointID = checkpoint.ID
	run.Exploration = session.policy
	run.ToolCalls, run.ElapsedMS, run.Metrics = session.toolCalls, r.now().Sub(session.startedAt).Milliseconds(), session.metrics()
	run.FinishedAt = NowString(r.now())
	if err := r.Paths.ReleasePath(context.WithoutCancel(ctx), p.ID, owner, "run "+run.ID+" paused: "+session.pauseReason); err != nil {
		run.Error = strings.TrimSpace(run.Error + "; the path could not be released: " + err.Error())
	}
	events := []Event{
		{Type: EventCheckpointSaved, Actor: runnerActorOrchestrator, Summary: "checkpoint saved: " + checkpoint.ID,
			Detail: map[string]string{"frontier": fmt.Sprint(len(checkpoint.Frontier)), "evidence": fmt.Sprint(len(checkpoint.Evidence)), "checkpoint_digest": checkpoint.Digest}},
		{Type: EventRunFinished, Actor: runnerActorOrchestrator, Summary: "run paused: " + session.pauseReason,
			Detail: map[string]string{"status": string(RunPaused), "stop_reason": StopBudgetPaused, "checkpoint_id": checkpoint.ID}},
	}
	if err := r.Store.SaveCheckpointAndPause(*run, run.Version, checkpoint, events); err != nil {
		run.Status, run.StopReason, run.Error = RunFailed, StopCheckpointUnavailable, "the checkpoint could not be saved: "+err.Error()
		run.CheckpointID = ""
		return run, r.record(run, events...)
	}
	run.Version++
	return run, nil
}

func (r *Runner) failPause(ctx context.Context, p *path.Path, owner string, session *runnerSession, cause error) (*Run, error) {
	run := session.run
	run.Status, run.StopReason = RunFailed, StopCheckpointUnavailable
	run.Error = "the checkpoint could not be built: " + cause.Error()
	run.FinishedAt = NowString(r.now())
	_ = r.Paths.ReleasePath(context.WithoutCancel(ctx), p.ID, owner, "checkpoint unavailable: "+cause.Error())
	return run, r.record(run,
		Event{Type: EventRunError, Actor: runnerActorOrchestrator, Summary: runnerCapText(run.Error, MaxStatementChars),
			Detail: map[string]string{"stop_reason": StopCheckpointUnavailable}},
		Event{Type: EventRunFinished, Actor: runnerActorOrchestrator, Summary: "run failed: checkpoint unavailable",
			Detail: map[string]string{"status": string(RunFailed), "stop_reason": StopCheckpointUnavailable}})
}

func sessionEvidence(refs map[string]struct{}) []string {
	out := make([]string, 0, len(refs))
	for ref := range refs {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

// resumeDepth counts the attempts in a resume chain, the run itself included.
func (r *Runner) resumeDepth(run Run) int {
	depth := 1
	cursor := run
	for cursor.ResumeOf != "" && depth < 10 {
		parent, err := r.Store.GetRun(cursor.ResumeOf)
		if err != nil {
			break
		}
		cursor = *parent
		depth++
	}
	return depth
}

// Resume continues a paused run from its checkpoint as a new attempt: a new run
// id, generation and lease, with the checkpoint's evidence, usage and frontier.
func (r *Runner) Resume(ctx context.Context, runID string) (*Run, error) {
	if err := r.configured(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	run, err := r.Store.GetRun(runID)
	if err != nil {
		return nil, err
	}
	if run.Status != RunPaused {
		return nil, fmt.Errorf("%w: run %s is %s", ErrRunNotPaused, runID, run.Status)
	}
	if r.resumeDepth(*run) >= 3 {
		return nil, fmt.Errorf("%w: path %s has already been resumed three times", ErrNeedsHuman, run.PathID)
	}
	checkpoint, err := r.Store.GetCheckpoint(runID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCheckpointUnavailable, err)
	}
	if checkpoint.RunID != run.ID {
		return nil, fmt.Errorf("%w: the checkpoint belongs to another run", ErrCheckpointUnavailable)
	}
	if err := checkpoint.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCheckpointUnavailable, err)
	}
	adapter, err := r.selectRuntime(run.AuditID)
	if err != nil {
		return nil, err
	}
	if !adapter.Capabilities().TurnControl {
		return nil, ErrCheckpointUnsupported
	}
	if checkpoint.Pin != nil && checkpoint.Pin.ConfigVersion != "" {
		if provider, ok := adapter.(PinProvider); ok {
			current, err := provider.Pin()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrCheckpointStale, err)
			}
			if current.ConfigVersion != "" && current.ConfigVersion != checkpoint.Pin.ConfigVersion {
				return nil, fmt.Errorf("%w: the model configuration version changed", ErrCheckpointStale)
			}
		}
	}
	// The checkpoint is single-use: across instances only the CAS winner starts a
	// new attempt, so two resumes cannot fork the same paused work.
	if err := r.Store.ClaimCheckpointResume(checkpoint.ID); err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, fmt.Errorf("%w: %s", ErrCheckpointConsumed, checkpoint.ID)
		}
		return nil, fmt.Errorf("%w: claim the checkpoint: %v", ErrCheckpointUnavailable, err)
	}
	owner := r.owner()
	p, err := r.Paths.ClaimSpecificPath(ctx, checkpoint.PathID, owner, r.leaseTTL())
	if err != nil || p == nil {
		return nil, fmt.Errorf("%w: the path cannot be claimed", ErrCheckpointStale)
	}
	seed := &runSeed{task: checkpoint.Task, evidence: checkpoint.Evidence, usage: checkpoint.Usage, resumeOf: run.ID, frontier: checkpoint.Frontier}
	return r.execute(ctx, "", p, owner, checkpoint.Task.Exploration, seed)
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

	// What the run cost, counted as the orchestrator sees it. seenRefs is the
	// evidence already reported, so novelty counts ids no earlier exchange
	// reported rather than calls made.
	seenRefs     map[string]struct{}
	novelty      []int
	exchanges    int
	invalidCalls int
	truncations  int
	// Novelty is per completed model exploration round, not per tool exchange:
	// roundRefs collects the evidence of the round in progress, roundTouched
	// distinguishes a round with calls from a turn that only answered, and
	// emptyRounds counts consecutive rounds that added nothing.
	roundID      string
	roundRefs    map[string]struct{}
	roundTouched bool
	emptyRounds  int

	// Turn control: the host owns provider-request permission, answer
	// acceptance and the one repair budget. modelRequests counts permitted
	// requests, repairs counts granted corrections, reserved is the sum of the
	// reservations still outstanding.
	generation int64
	aliases    *AliasTable
	// toolMu serialises tool-call bookkeeping so a batch may execute its calls
	// concurrently without racing the run version; batchResults makes a replayed
	// call idempotent within one run.
	toolMu        sync.Mutex
	batchResults  map[string]batchCallRecord
	modelRequests int
	repairs       int
	reserved      int
	reservations  map[string]int
	usageSeen     map[string]bool
	proposals     map[string]proposalVerdict
	turnControl   bool
	// pauseRequested marks a budget boundary that saved a resumable checkpoint;
	// the run ends PAUSED instead of FAILED.
	pauseRequested bool
	pauseReason    string
	softWarned     bool

	answer     *Answer
	stop       string
	status     RunStatus
	errText    string
	exitCode   *int
	leaseLost  bool
	persistErr error
}

// NoEvidenceRounds is K: three completed exploration rounds without new evidence
// end exploration. A round is one model turn with tool calls, never a repair or a
// single tool exchange inside a batch.
const NoEvidenceRounds = 3

// noteToolRefs adds one call's evidence to the exploration round it belongs to.
// A single call from an adapter without round ids is its own round, which keeps
// the legacy adapters' counting intact.
func (s *runnerSession) noteToolRefs(roundID string, refs []string) {
	if strings.TrimSpace(roundID) == "" {
		s.beginRound("")
		s.addRoundRefs(refs)
		s.roundTouched = true
		s.finishRound(false)
		return
	}
	s.beginRound(roundID)
	s.addRoundRefs(refs)
	s.roundTouched = true
}

func (s *runnerSession) beginRound(roundID string) {
	if s.currentRoundID() == roundID {
		return
	}
	s.finishRound(false)
	s.roundID = roundID
	s.roundRefs = map[string]struct{}{}
	s.roundTouched = false
}

func (s *runnerSession) currentRoundID() string {
	return s.roundID
}

func (s *runnerSession) addRoundRefs(refs []string) {
	if s.roundRefs == nil {
		s.roundRefs = map[string]struct{}{}
	}
	for _, ref := range refs {
		if ref = strings.TrimSpace(ref); ref != "" {
			s.roundRefs[ref] = struct{}{}
		}
	}
}

// finishRound closes the round in progress, records one novelty sample and, when
// applyStop is set, ends exploration after K empty rounds. A turn that only
// answered has no round to record.
func (s *runnerSession) finishRound(applyStop bool) bool {
	if !s.roundTouched {
		s.roundID, s.roundRefs, s.roundTouched = "", nil, false
		return false
	}
	if s.seenRefs == nil {
		s.seenRefs = map[string]struct{}{}
	}
	fresh := 0
	for ref := range s.roundRefs {
		if _, seen := s.seenRefs[ref]; seen {
			continue
		}
		s.seenRefs[ref] = struct{}{}
		fresh++
	}
	s.novelty = append(s.novelty, fresh)
	if fresh == 0 {
		s.emptyRounds++
	} else {
		s.emptyRounds = 0
	}
	s.roundID, s.roundRefs, s.roundTouched = "", nil, false
	if applyStop && s.emptyRounds >= NoEvidenceRounds {
		s.stop = StopNoNewEvidence
		s.status = RunFailed
		s.errText = fmt.Sprintf("%d consecutive exploration rounds added no new evidence", s.emptyRounds)
		return true
	}
	return false
}

// metrics renders the session's counters. It is called once, when the run is
// finished, and the slice is copied so a later mutation cannot rewrite history.
func (s *runnerSession) metrics() *RunMetrics {
	m := &RunMetrics{
		Exchanges:    s.exchanges,
		Novelty:      append([]int(nil), s.novelty...),
		InvalidCalls: s.invalidCalls,
		Truncations:  s.truncations,
		Repairs:      s.repairs,
	}
	if s.turnControl {
		m.Source = MetricsSourceReported
		m.ModelRequests = s.modelRequests
		m.Rounds = s.modelRequests
	} else {
		// The legacy estimate is labelled as such: a stored run must never look
		// like it reported real provider requests when it did not.
		m.Source = MetricsSourceLegacyEstimate
		m.Rounds = s.exchanges + 1
	}
	return m
}

// generationOf is the fencing generation of one run's adapter. A path re-claimed
// by another attempt gets a different lease epoch, so a late frame from the old
// process can be rejected.
func generationOf(p *path.Path) int64 {
	if p != nil && p.LeaseEpoch > 0 {
		return p.LeaseEpoch
	}
	return 1
}

// proposalVerdict remembers the host's decision for one proposal request so a
// retransmission of the same bytes is answered identically instead of consuming a
// second repair.
type proposalVerdict struct {
	digest   string
	decision AnswerDecision
}

// repairPolicy is the run's correction budget, normalized.
func (r *Runner) repairPolicy() RepairPolicy {
	return r.Repair.Normalize()
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
	// Usage belongs to the request that produced it: release that request's
	// reservation and ignore a duplicate report instead of billing it twice.
	if ev.RequestID != "" {
		reserve := s.reservations[ev.RequestID]
		if reserve > 0 {
			s.reserved -= reserve
			delete(s.reservations, ev.RequestID)
		}
		if s.usageSeen[ev.RequestID] {
			ev.InputTokens, ev.OutputTokens = 0, 0
		} else if ev.InputTokens > 0 || ev.OutputTokens > 0 {
			s.usageSeen[ev.RequestID] = true
		}
		if s.run.AuditID != "" {
			if err := s.runner.Store.SettleAuditTokens(s.run.AuditID, reserve, ev.InputTokens+ev.OutputTokens); err != nil && s.persistErr == nil {
				s.persistErr = err
			}
		}
	}
	s.run.InputTokens += ev.InputTokens
	s.run.OutputTokens += ev.OutputTokens
	if s.policy.TokenBudget > 0 && !s.softWarned {
		used := s.run.InputTokens + s.run.OutputTokens
		if used >= s.policy.TokenBudget*4/5 {
			s.softWarned = true
			if selected := s.append(Event{
				Type: EventBudgetSoftLimit, Actor: runnerActorOrchestrator,
				Summary: fmt.Sprintf("token usage reached %d of the %d budget", used, s.policy.TokenBudget),
				Detail:  map[string]string{"used_tokens": fmt.Sprint(used), "budget": fmt.Sprint(s.policy.TokenBudget)},
			}); selected {
				return true
			}
		}
	}
	var stop bool
	switch {
	case ev.Permit != nil:
		stop = s.applyPermit(ctx, ev)
	case ev.Proposal != nil:
		stop = s.applyProposal(ctx, ev)
	case ev.Repair != nil:
		stop = s.applyRepair(ctx, ev)
	case ev.Batch != nil:
		stop = s.applyBatch(ctx, ev)
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
		return s.pauseBudget(fmt.Sprintf("the adapter reported %d token(s) against a budget of %d",
			s.run.InputTokens+s.run.OutputTokens, s.policy.TokenBudget))
	}
	return false
}

// applyPermit decides whether one provider request may start.
//
// The token budget is reserved before the request, not discovered after it: the
// reservation is the adapter's conservative input estimate plus the provider's
// output limit. Without both numbers the host cannot promise a bounded run, so it
// refuses instead of pretending the budget is enforced. A permit is spent once;
// a duplicate frame is rejected through the same decision path.
func (s *runnerSession) applyPermit(ctx context.Context, ev RuntimeEvent) bool {
	req := *ev.Permit
	// The adapter asked the host to decide, so this run is under turn control even
	// if the first request is refused: its counters must not be labelled legacy.
	s.turnControl = true
	reply := PermitDecision{Decision: DecisionStop, Reason: "the run is not accepting provider requests"}
	defer s.replyPermit(ctx, ev.PermitReply, &reply)
	if ctx.Err() != nil {
		reply.Reason = "the run was cancelled"
		return true
	}
	if s.stop != "" || s.leaseLost || s.persistErr != nil {
		reply.Reason = "the run is no longer active"
		return true
	}
	if strings.TrimSpace(req.RequestID) == "" {
		reply.Reason = "request_id is required"
		s.stop, s.status, s.errText = StopInvalidOutput, RunInvalidOutput, reply.Reason
		return true
	}
	if req.Generation != s.generation {
		reply.Reason = "stale generation"
		s.stop, s.status, s.errText = StopInvalidOutput, RunInvalidOutput, reply.Reason
		return true
	}
	// The previous exploration round is complete once the model asks for its next
	// request. Closing it here is what makes K consecutive empty rounds stop the
	// run before another request is spent.
	if s.finishRound(true) {
		reply.Reason = s.errText
		return s.update(Event{
			Type: EventModelPermitDenied, Actor: runnerActorOrchestrator, CallID: req.RequestID,
			Summary: "provider request denied: " + reply.Reason,
			Detail:  map[string]string{"reason": reply.Reason, "stop_reason": StopNoNewEvidence},
		})
	}
	reserve := 0
	if req.InputTokensEstimate <= 0 || req.MaxOutputTokens <= 0 {
		reply.Reason = "bounded token mode needs a positive input estimate and output limit"
		s.stop, s.status, s.errText = StopTokenBudget, RunBudgetExceeded, reply.Reason
		return s.update(Event{Type: EventModelPermitDenied, Actor: runnerActorOrchestrator, CallID: req.RequestID,
			Summary: "provider request denied: " + reply.Reason, Detail: map[string]string{"reason": reply.Reason}})
	}
	reserve = req.InputTokensEstimate + req.MaxOutputTokens
	if s.policy.TokenBudget > 0 && s.run.InputTokens+s.run.OutputTokens+s.reserved+reserve > s.policy.TokenBudget {
		reply.Reason = fmt.Sprintf("the reservation would exceed the token budget of %d", s.policy.TokenBudget)
		return s.pauseBudget(reply.Reason)
	}
	// The audit ledger is the shared ceiling: two runs (or two instances) cannot
	// each read the balance and then both spend it.
	if _, err := s.runner.Store.ReserveAuditTokens(s.run.AuditID, reserve); err != nil {
		reply.Reason = "the audit budget cannot reserve the request: " + err.Error()
		return s.pauseBudget(reply.Reason)
	}
	s.reserved += reserve
	s.reservations[req.RequestID] = reserve
	s.modelRequests++
	s.turnControl = true
	reply = PermitDecision{Decision: DecisionContinue, ReservedTokens: reserve}
	return s.update(Event{
		Type: EventModelPermitGranted, Actor: runnerActorOrchestrator, CallID: req.RequestID,
		Summary: "provider request permitted",
		Detail: map[string]string{
			"round_id": runnerCapText(req.RoundID, MaxNotesChars), "model": runnerCapText(req.Model, MaxNotesChars),
			"input_estimate": fmt.Sprint(req.InputTokensEstimate), "max_output_tokens": fmt.Sprint(req.MaxOutputTokens),
			"reserved_tokens": fmt.Sprint(reserve),
		},
	})
}

// applyProposal validates one proposed answer. Acceptance, one bounded correction
// and rejection are the only outcomes; the adapter cannot declare its own output
// valid, and a retransmitted proposal is answered without consuming a second
// repair.
func (s *runnerSession) applyProposal(ctx context.Context, ev RuntimeEvent) bool {
	proposal := *ev.Proposal
	reply := AnswerDecision{Decision: DecisionRejected, Reason: "answer rejected"}
	defer s.replyAnswer(ctx, ev.ProposalReply, &reply)
	if s.stop != "" {
		reply.Reason = "the run is no longer active"
		return true
	}
	if strings.TrimSpace(proposal.RequestID) == "" || len(proposal.Raw) == 0 {
		s.stop, s.status, s.errText = StopInvalidOutput, RunInvalidOutput, "a proposed answer needs a request id and bytes"
		return s.update(Event{Type: EventAnswerRejected, Actor: runnerActorOrchestrator,
			Summary: "proposed answer rejected: protocol", Detail: map[string]string{"reason": s.errText}})
	}
	digest := digest16("codexploit/answer-proposal/v1", string(proposal.Raw))
	if prior, ok := s.proposals[proposal.RequestID]; ok {
		if prior.digest != digest {
			s.stop, s.status, s.errText = StopInvalidOutput, RunInvalidOutput, "the same request id proposed different bytes"
			return s.update(Event{Type: EventAnswerRejected, Actor: runnerActorOrchestrator, CallID: proposal.RequestID,
				Summary: "proposed answer rejected: " + s.errText, Detail: map[string]string{"reason": s.errText}})
		}
		reply = prior.decision
		return prior.decision.Decision != DecisionRepair || s.failPersistIfNeeded()
	}
	raw := proposal.Raw
	if s.aliases != nil {
		raw = s.aliases.ResolveAnswer(raw)
	}
	answer, err := DecodeAnswer(raw, s.task)
	if err == nil {
		err = s.checkFalsifier(answer)
	}
	if err == nil {
		s.answer = answer
		reply = AnswerDecision{Decision: DecisionAccepted, RepairsUsed: s.repairs}
		s.proposals[proposal.RequestID] = proposalVerdict{digest: digest, decision: reply}
		_ = s.update(Event{Type: EventAnswerAccepted, Actor: runnerActorOrchestrator, CallID: proposal.RequestID,
			Summary: "proposed answer accepted", Detail: map[string]string{"repairs": fmt.Sprint(s.repairs)}})
		return true
	}
	policy := s.runner.repairPolicy()
	reason := modelClip(err.Error(), policy.MaxReasonChars)
	if s.repairs < policy.Max {
		s.repairs++
		reply = AnswerDecision{Decision: DecisionRepair, Reason: reason, RepairsUsed: s.repairs}
		s.proposals[proposal.RequestID] = proposalVerdict{digest: digest, decision: reply}
		return s.update(Event{Type: EventAnswerRepairAsked, Actor: runnerActorOrchestrator, CallID: proposal.RequestID,
			Summary: "proposed answer needs one correction", Detail: map[string]string{"reason": reason, "repairs": fmt.Sprint(s.repairs)}})
	}
	s.stop, s.status, s.errText = StopInvalidOutput, RunInvalidOutput, "the repair budget is exhausted: "+reason
	reply = AnswerDecision{Decision: DecisionRejected, Reason: reason, RepairsUsed: s.repairs}
	s.proposals[proposal.RequestID] = proposalVerdict{digest: digest, decision: reply}
	return s.update(Event{Type: EventAnswerRejected, Actor: runnerActorOrchestrator, CallID: proposal.RequestID,
		Summary: "proposed answer rejected", Detail: map[string]string{"reason": reason, "repairs": fmt.Sprint(s.repairs)}})
}

// applyRepair decides one protocol correction. The same policy covers malformed
// tool calls and invalid arguments, so a different failure mode cannot buy a
// second budget.
func (s *runnerSession) applyRepair(ctx context.Context, ev RuntimeEvent) bool {
	req := *ev.Repair
	reply := RepairDecision{Decision: DecisionStop, Reason: "no repair budget left"}
	defer s.replyRepair(ctx, ev.RepairReply, &reply)
	if s.stop != "" {
		reply.Reason = "the run is no longer active"
		return true
	}
	policy := s.runner.repairPolicy()
	reason := modelClip(req.Reason, policy.MaxReasonChars)
	if s.repairs >= policy.Max {
		s.stop, s.status, s.errText = StopInvalidOutput, RunInvalidOutput, "the repair budget is exhausted: "+reason
		return s.update(Event{Type: EventRepairRefused, Actor: runnerActorOrchestrator, CallID: req.RequestID,
			Summary: "repair refused: " + s.errText, Detail: map[string]string{"reason": reason}})
	}
	s.repairs++
	reply = RepairDecision{Decision: DecisionRepair, Reason: reason, RepairsUsed: s.repairs}
	return s.update(Event{Type: EventRepairGranted, Actor: runnerActorOrchestrator, CallID: req.RequestID,
		Summary: "repair granted", Detail: map[string]string{"kind": runnerCapText(req.Kind, MaxNotesChars), "reason": reason, "repairs": fmt.Sprint(s.repairs)}})
}

func (s *runnerSession) replyPermit(ctx context.Context, reply chan<- PermitDecision, decision *PermitDecision) {
	if reply == nil {
		return
	}
	select {
	case reply <- *decision:
	case <-ctx.Done():
	}
}

func (s *runnerSession) replyAnswer(ctx context.Context, reply chan<- AnswerDecision, decision *AnswerDecision) {
	if reply == nil {
		return
	}
	select {
	case reply <- *decision:
	case <-ctx.Done():
	}
}

func (s *runnerSession) replyRepair(ctx context.Context, reply chan<- RepairDecision, decision *RepairDecision) {
	if reply == nil {
		return
	}
	select {
	case reply <- *decision:
	case <-ctx.Done():
	}
}

// failPersistIfNeeded converts an earlier storage failure into a stop. It exists so
// the idempotent re-answer path cannot report success after persistence failed.
func (s *runnerSession) failPersistIfNeeded() bool {
	if s.persistErr == nil {
		return false
	}
	s.failPersist()
	return true
}

// applyTool validates a tool request against the current policy and either runs it
// through the registry or refuses it. Adapters that cannot batch use this path;
// the host rules are the same as for one call inside a batch.
// pauseBudget stops the attempt at a budget boundary and asks finish to persist a
// checkpoint. The stop is not an answer: the run carries no conclusion.
func (s *runnerSession) pauseBudget(reason string) bool {
	if s.persistErr != nil {
		s.failPersist()
		return true
	}
	s.pauseRequested = true
	s.pauseReason = reason
	s.stop, s.status, s.errText = StopBudgetPaused, RunPaused, reason
	return true
}

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
	asked := s.askTool(req)
	if err := ValidateToolRequest(req, s.policy, s.toolCalls); err != nil {
		deniedReply, denied := s.denyTool(req, err.Error(), map[string]string{"allowed_tools": strings.Join(s.policy.AllowedTools, ",")})
		reply = deniedReply
		if errors.Is(err, ErrBudgetExhausted) {
			_ = s.append(asked, denied)
			return s.pauseBudget(err.Error())
		}
		return s.append(asked, denied)
	}
	prepared, executor, deniedReply, deniedEvent := s.prepareToolCall(req)
	if deniedReply != nil {
		reply = *deniedReply
		return s.append(asked, *deniedEvent)
	}
	result, refs, stop := s.executeToolCall(ctx, prepared, executor, asked)
	s.noteToolRefs("", refs)
	reply = result
	return stop
}

// applyBatch decides one assistant turn's calls. The whole batch arrives before
// anything runs, so the host reserves the tool budget in source order; calls over
// the remaining budget are denied with paired results instead of being dropped.
// Allowed calls may execute concurrently, but results pair with provider history
// in source order and every call has exactly one outcome.
func (s *runnerSession) applyBatch(ctx context.Context, ev RuntimeEvent) bool {
	batch := *ev.Batch
	results := make([]ToolResult, len(batch.Calls))
	defer func() {
		if ev.BatchReply != nil {
			select {
			case ev.BatchReply <- results:
			case <-ctx.Done():
			}
		}
	}()
	summary := Event{
		Type: EventToolBatchRequested, Actor: runnerActorAgent,
		Summary: fmt.Sprintf("tool batch requested: %d call(s)", len(batch.Calls)),
		Detail: map[string]string{
			"round_id": runnerCapText(batch.RoundID, MaxNotesChars),
			"calls":    fmt.Sprint(len(batch.Calls)), "max_calls_per_turn": fmt.Sprint(s.policy.MaxCallsPerTurn),
			"concurrency": fmt.Sprint(s.policy.ToolConcurrency),
		},
	}
	if len(batch.Calls) == 0 {
		_ = s.update(summary)
		return false
	}
	if len(batch.Calls) > s.policy.MaxCallsPerTurn {
		reason := fmt.Sprintf("the batch has %d calls; at most %d are accepted per turn", len(batch.Calls), s.policy.MaxCallsPerTurn)
		events := []Event{summary}
		for i, call := range batch.Calls {
			results[i] = s.denialResult(call, reason)
			events = append(events, s.denialEvent(call, reason))
		}
		s.invalidCalls += len(batch.Calls)
		return s.update(events...)
	}

	type slot struct {
		request  ToolRequest
		executor ToolExecutor
		allow    bool
	}
	slots := make([]slot, len(batch.Calls))
	seen := map[string]bool{}
	used := 0
	budgetExhausted := false
	events := []Event{summary}
	for i, call := range batch.Calls {
		call.CallID = strings.TrimSpace(call.CallID)
		if call.CallID == "" || seen[call.CallID] {
			reason := "call_id is required and must be unique in a batch"
			results[i] = s.denialResult(call, reason)
			events = append(events, s.denialEvent(call, reason))
			s.invalidCalls++
			continue
		}
		seen[call.CallID] = true
		if cached, ok := s.batchResults[call.CallID]; ok && cached.Digest == batchCallDigest(call) {
			results[i] = cached.Result
			continue
		}
		if s.policy.MaxToolCalls > 0 && s.toolCalls+used >= s.policy.MaxToolCalls {
			reason := fmt.Sprintf("tool budget exhausted: %d of %d calls used", s.toolCalls+used, s.policy.MaxToolCalls)
			results[i] = s.denialResult(call, reason)
			events = append(events, s.denialEvent(call, reason))
			budgetExhausted = true
			continue
		}
		if err := ValidateToolRequest(call, s.policy, s.toolCalls+used); err != nil {
			results[i] = s.denialResult(call, err.Error())
			events = append(events, s.denialEvent(call, err.Error()))
			s.invalidCalls++
			if errors.Is(err, ErrBudgetExhausted) {
				budgetExhausted = true
			}
			continue
		}
		prepared, executor, deniedReply, deniedEvent := s.prepareToolCall(call)
		if deniedReply != nil {
			results[i] = *deniedReply
			events = append(events, *deniedEvent)
			continue
		}
		slots[i] = slot{request: prepared, executor: executor, allow: true}
		used++
	}
	if stop := s.update(events...); stop {
		return true
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.policy.ToolConcurrency)
	refsByCall := make([][]string, len(slots))
	for index := range slots {
		if !slots[index].allow {
			continue
		}
		wg.Add(1)
		go func(position int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			reply, refs, _ := s.executeToolCall(ctx, slots[position].request, slots[position].executor, s.askTool(slots[position].request))
			results[position] = reply
			refsByCall[position] = refs
		}(index)
	}
	wg.Wait()
	var roundRefs []string
	for _, refs := range refsByCall {
		roundRefs = append(roundRefs, refs...)
	}
	s.noteToolRefs(batch.RoundID, roundRefs)
	if s.persistErr != nil {
		s.failPersist()
		return true
	}
	if budgetExhausted {
		return s.pauseBudget(fmt.Sprintf("the tool budget of %d is exhausted", s.policy.MaxToolCalls))
	}
	return false
}

// askTool is the request event every call records, batch or not.
func (s *runnerSession) askTool(req ToolRequest) Event {
	return Event{
		Type: EventToolRequested, Actor: runnerActorAgent,
		CallID: req.CallID, Tool: req.Tool,
		Summary: "tool requested: " + runnerCapText(req.Tool, MaxNotesChars),
		Detail:  map[string]string{"arguments": fmt.Sprint(len(req.Args))},
	}
}

func (s *runnerSession) denyTool(req ToolRequest, reason string, extra map[string]string) (ToolResult, Event) {
	detail := map[string]string{"reason": reason}
	for key, value := range extra {
		detail[key] = value
	}
	return s.denialResult(req, reason), Event{
		Type: EventToolDenied, Actor: runnerActorOrchestrator,
		CallID: req.CallID, Tool: req.Tool,
		Summary: "tool denied: " + reason, Detail: detail,
	}
}

func (s *runnerSession) denialResult(req ToolRequest, reason string) ToolResult {
	return ToolResult{CallID: req.CallID, Tool: req.Tool, Error: reason, Result: s.toolEnvelope(false, "", reason)}
}

func (s *runnerSession) denialEvent(req ToolRequest, reason string) Event {
	return Event{
		Type: EventToolDenied, Actor: runnerActorOrchestrator,
		CallID: req.CallID, Tool: req.Tool,
		Summary: "tool denied: " + reason, Detail: map[string]string{"reason": reason},
	}
}

// prepareToolCall converts a policy-approved call into the exact request a tool
// receives, or returns the paired denial. It does not execute anything.
func (s *runnerSession) prepareToolCall(req ToolRequest) (ToolRequest, ToolExecutor, *ToolResult, *Event) {
	executor, ok := s.lookup(req.Tool)
	if !ok {
		result, event := s.denyTool(req, "tool is not registered with the orchestrator", nil)
		return req, nil, &result, &event
	}
	descriptor := executor.Descriptor()
	if len(req.LegacyArgs) > 0 && len(req.Args) == 0 {
		converted, err := LegacyToolArgs(descriptor.InputSchema, req.LegacyArgs)
		if err != nil {
			s.invalidCalls++
			result, event := s.denyTool(req, err.Error(), nil)
			return req, nil, &result, &event
		}
		req.Args = converted
	}
	if s.aliases != nil {
		resolved, err := s.aliases.ResolveToolArgs(req.Args)
		if err != nil {
			s.invalidCalls++
			result, event := s.denyTool(req, err.Error(), nil)
			return req, nil, &result, &event
		}
		req.Args = resolved
	}
	if err := ValidateToolArgs(descriptor.InputSchema, req.Args); err != nil {
		s.invalidCalls++
		result, event := s.denyTool(req, err.Error(), map[string]string{"schema_version": descriptor.Version})
		return req, nil, &result, &event
	}
	return req, executor, nil, nil
}

// executeToolCall runs one prepared call, records its exchange and returns the
// model-facing envelope. It is the only writer of the tool counters, so a batch
// can execute concurrently without racing the run's version.
func (s *runnerSession) executeToolCall(ctx context.Context, req ToolRequest, executor ToolExecutor, asked Event) (ToolResult, []string, bool) {
	toolCtx := WithToolScope(ctx, ToolScope{
		SnapshotID: s.task.SnapshotID, PathID: s.task.PathID,
		AuditID: s.task.AuditID, RunID: s.run.ID,
	})
	started := s.runner.now()
	result, callErr := executor.Call(toolCtx, req.Args)
	elapsed := s.runner.now().Sub(started).Milliseconds()

	s.toolMu.Lock()
	defer s.toolMu.Unlock()
	s.toolCalls++
	s.exchanges++
	s.run.ToolCalls = s.toolCalls
	reply := ToolResult{CallID: req.CallID, Tool: req.Tool, ElapsedMS: elapsed}
	payload, truncated := "", false
	if callErr == nil {
		reply.OK, reply.Error, reply.Refs = result.OK, result.Error, result.Refs
		payload, truncated = TruncateToolResult(result.Result)
		if s.aliases != nil {
			payload = s.aliases.ProjectJSON(payload)
		}
		reply.Result = s.toolEnvelope(result.OK, payload, result.Error)
		if truncated {
			s.truncations++
		}
		if !result.OK {
			s.invalidCalls++
		}
	} else {
		reply.Error = callErr.Error()
		reply.Result = s.toolEnvelope(false, "", reply.Error)
	}
	allowed := Event{
		Type: EventToolAllowed, Actor: runnerActorOrchestrator,
		CallID: req.CallID, Tool: req.Tool,
		Summary: "tool allowed: " + req.Tool + " is in the allowlist",
	}
	receipt := s.budgetReceipt()
	resultEvent := Event{
		Type: EventToolResult, Actor: runnerActorOrchestrator,
		CallID: req.CallID, Tool: req.Tool,
		Detail: map[string]string{
			"elapsed_ms": fmt.Sprint(elapsed),
			"calls_left": fmt.Sprint(receipt.CallsLeft), "repairs_left": fmt.Sprint(receipt.RepairsLeft),
			"obligations_total": fmt.Sprint(receipt.ObligationsTotal),
			"budget_enforced":   fmt.Sprint(receipt.BudgetEnforced), "usage_source": receipt.UsageSource,
		},
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
		resultEvent.Summary = "tool returned a result for " + req.Tool
		resultEvent.Detail["ok"] = "true"
		resultEvent.Detail["result"] = payload
		if truncated {
			resultEvent.Detail["truncated"] = "true"
		}
	}
	s.batchResults[req.CallID] = batchCallRecord{Digest: batchCallDigest(req), Result: reply}
	return reply, result.Refs, s.update(asked, allowed, resultEvent)
}

// batchCallRecord makes a replayed call idempotent: the same id and bytes return
// the earlier result, a different call under the same id is refused by the batch.
type batchCallRecord struct {
	Digest string
	Result ToolResult
}

func batchCallDigest(req ToolRequest) string {
	return digest16("codexploit/tool-call/v1", req.CallID, req.Tool, string(req.Args))
}

// toolEnvelope is the one model-facing shape of a tool result. The receipt is the
// host's count, not an estimate the model can drift from.
func (s *runnerSession) toolEnvelope(ok bool, result, failure string) string {
	envelope := ToolResultEnvelope{OK: ok, Result: result, Error: failure, Budget: s.budgetReceipt()}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return `{"ok":false,"error":"the tool result could not be encoded"}`
	}
	return string(encoded)
}

func (s *runnerSession) budgetReceipt() *BudgetReceipt {
	receipt := &BudgetReceipt{
		ObligationsTotal: len(s.task.Obligations),
		BudgetEnforced:   s.policy.TokenBudget > 0,
		UsageSource:      MetricsSourceLegacyEstimate,
	}
	if s.policy.MaxToolCalls > 0 {
		if left := s.policy.MaxToolCalls - s.toolCalls; left > 0 {
			receipt.CallsLeft = left
		}
	}
	if left := s.runner.repairPolicy().Max - s.repairs; left > 0 {
		receipt.RepairsLeft = left
	}
	if s.turnControl {
		receipt.UsageSource = MetricsSourceReported
	}
	if s.policy.TokenBudget > 0 {
		left := s.policy.TokenBudget - s.run.InputTokens - s.run.OutputTokens - s.reserved
		if left < 0 {
			left = 0
		}
		receipt.TokensLeft = &left
	}
	if s.answer != nil {
		closed := 0
		for _, verdict := range s.answer.Obligations {
			if verdict.Verdict == VerdictMet || verdict.Verdict == VerdictNotMet {
				closed++
			}
		}
		receipt.ObligationsClosed = closed
	}
	return receipt
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

// checkFalsifier resolves a checked falsifier against what this run can prove: a
// successful call result from this run, or evidence the task carried in. A call id
// alone, a denied or failed call, or another run's evidence does not pass.
func (s *runnerSession) checkFalsifier(answer *Answer) error {
	if answer == nil || answer.Falsifier == nil || !answer.Falsifier.Checked {
		return nil
	}
	inputs := map[string]struct{}{}
	for _, ref := range s.task.EvidenceRefs {
		if ref.ID != "" {
			inputs[ref.ID] = struct{}{}
		}
	}
	s.toolMu.Lock()
	defer s.toolMu.Unlock()
	for _, how := range answer.Falsifier.How {
		how = strings.TrimSpace(how)
		if _, ok := inputs[how]; ok {
			continue
		}
		record, ok := s.batchResults[how]
		if ok && record.Result.OK && record.Result.Error == "" {
			continue
		}
		return fmt.Errorf("%w: falsifier.how %q does not resolve to a successful call of this run or to input evidence", ErrInvalidAnswer, how)
	}
	return nil
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
	if err := s.checkFalsifier(answer); err != nil {
		s.rejectOutput(source, err)
		s.stop, s.status, s.errText = StopInvalidOutput, RunInvalidOutput, err.Error()
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

// selectRuntime resolves the runtime a task chose. The audit is the durable
// choice; an empty name means the deployment default. Unknown names fail closed:
// a task must not silently run under a different adapter.
func (r *Runner) selectRuntime(auditID string) (Runtime, error) {
	name := ""
	if r.RuntimeFor != nil {
		name = strings.TrimSpace(r.RuntimeFor(auditID))
	}
	defaultName := strings.TrimSpace(r.DefaultRuntime)
	if defaultName == "" && r.Runtime != nil {
		defaultName = r.Runtime.Capabilities().Name
	}
	if name == "" {
		name = defaultName
	}
	// The default name prefers the Runtime field: it is the object the deployment
	// (and a test) wired as the default, and it may have been replaced after the
	// catalog was built. A non-default name must come from the catalog.
	if name == defaultName && r.Runtime != nil {
		return r.Runtime, nil
	}
	if r.Runtimes != nil {
		if selected, ok := r.Runtimes[name]; ok {
			return selected, nil
		}
		if name != "" && name != defaultName {
			return nil, fmt.Errorf("%w: runtime %q is not available", ErrRuntimeUnavailable, name)
		}
	}
	if r.Runtime != nil {
		return r.Runtime, nil
	}
	return nil, fmt.Errorf("%w: no runtime is configured", ErrRuntimeUnavailable)
}

func (r *Runner) configured() error {
	if r == nil {
		return errRunnerNotConfigured
	}
	var missing []string
	if r.Store == nil {
		missing = append(missing, "Store")
	}
	if r.Runtime == nil && len(r.Runtimes) == 0 {
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

func (r *Runner) createRun(ctx context.Context, run *Run, event Event) error {
	if store, ok := r.Store.(AtomicCreator); ok {
		return store.CreateRunEventsContext(ctx, *run, []Event{event})
	}
	if err := r.Store.CreateRun(*run); err != nil {
		return err
	}
	return r.appendRunEvents(run, event)
}

// record commits state and its events together when the store supports it.
func (r *Runner) record(run *Run, events ...Event) error {
	run.UpdatedAt = NowString(r.now())
	if store, ok := r.Store.(AtomicRecorder); ok {
		for i := range events {
			if events[i].Actor == "" {
				events[i].Actor = runnerActorOrchestrator
			}
			if events[i].CreatedAt == "" {
				events[i].CreatedAt = run.UpdatedAt
			}
			events[i].Summary = runnerCapText(events[i].Summary, MaxStatementChars)
		}
		if err := store.SaveRunEvents(*run, run.Version, events); err != nil {
			return err
		}
		run.Version++
		return nil
	}
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
		p.TimeoutSeconds == 0 && p.TokenBudget == 0 && p.MaxRepeatedOutputs == 0 &&
		p.MaxCallsPerTurn == 0 && p.ToolConcurrency == 0 && len(p.AllowedTools) == 0
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
