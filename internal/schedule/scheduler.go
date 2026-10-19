package schedule

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// Dispatcher runs one path the scheduler has already chosen and leased. It is the
// only thing the scheduler asks of the agent runtime, and it is deliberately
// narrow: the scheduler owns the choice, the lease and the retry schedule, and the
// dispatcher owns executing the path under the run policy it was configured with.
//
// A dispatcher must acquire the path's lease itself (the runner's RunPath does);
// the scheduler claims the path first as its dispatch right, and the second claim
// by the same owner is a renewal, not a conflict. It must also report an attempt
// that finished without success — a failed, cancelled or invalid run — as a
// non-nil error: the scheduler cannot see the run's own status, and only the
// error makes it defer the path with a durable backoff instead of treating the
// attempt as completed.
type Dispatcher interface {
	DispatchPath(ctx context.Context, pathID string) error
}

// TickResult is the observable summary of one scheduler pass.
type TickResult struct {
	// Held is how many paths this scheduler still holds a lease on when the tick
	// returns. A clean pass settles everything and leaves zero behind.
	Held int `json:"held"`
	// Dispatched is how many paths were claimed and handed to the dispatcher.
	Dispatched int `json:"dispatched"`
	// Reclaimed is how many expired leases the pass recovered.
	Reclaimed int `json:"reclaimed"`
	// Skipped is how many due paths were not dispatched: already in flight, at
	// their attempt ceiling, or lost to another scheduler's claim.
	Skipped int `json:"skipped"`
	// Failed is how many dispatches returned an error.
	Failed int `json:"failed"`
	// Due is how many due queued paths the pass saw, before the concurrency budget.
	Due int `json:"due"`
}

// Scheduler is the resident P7 loop. It serves the due queued paths of a set of
// audits, bounds how many run at once, recovers expired leases and keeps a durable
// retry schedule per path.
//
// The scheduler is safe to run in more than one process: the path lease is what
// makes concurrent schedulers correct, because Store.ClaimPath is atomic and a
// path can only be claimed once. Within one process the in-flight set makes the
// same guarantee before the claim is even attempted.
type Scheduler struct {
	// Paths is the path engine the scheduler serves. It is the only writer of the
	// queue state the scheduler reads and changes.
	Paths *path.Service
	// Agent runs a path the scheduler has leased.
	Agent Dispatcher
	// Audits are the audit ids to serve. An empty list means every audit that has
	// due queued work.
	Audits []string
	// Owner names the lease holder. It defaults to "scheduler".
	Owner string
	// Interval is the pause between passes. It defaults to 30s.
	Interval time.Duration
	// MaxConcurrent bounds how many paths one scheduler runs at once. It defaults
	// to the engine's active-lease ceiling (4).
	MaxConcurrent int
	// LeaseTTL is asked for when a path is claimed. Zero uses the audit's own
	// lease TTL.
	LeaseTTL time.Duration
	// Backoff is the durable retry policy of a failed dispatch.
	Backoff path.Backoff
	// Now is injectable so a replay of the scheduler makes the same decisions.
	Now func() time.Time
	// Logger receives the scheduler's own narration. It defaults to slog.Default.
	Logger *slog.Logger
	// Metrics is the counters and gauges this scheduler updates. A nil value is
	// created lazily so a caller never has to wire one just to tick.
	Metrics *Metrics

	mu             sync.Mutex
	inflight       map[string]bool
	held           map[string]bool
	defaultMetrics *Metrics

	running atomic.Bool
}

// defaultSchedulerInterval is the documented tick cadence.
const defaultSchedulerInterval = 30 * time.Second

// defaultSchedulerOwner names the lease holder when the configuration does not.
const defaultSchedulerOwner = "scheduler"

// reclaimLimit bounds one recovery sweep. A crashed worker leaves a handful of
// leases, not thousands; a bounded sweep keeps one tick cheap.
const reclaimLimit = 100

// New builds a scheduler over a path service and a dispatcher.
func New(paths *path.Service, dispatcher Dispatcher, opts ...func(*Scheduler)) *Scheduler {
	s := &Scheduler{Paths: paths, Agent: dispatcher}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithOwner names the lease holder.
func WithOwner(owner string) func(*Scheduler) {
	return func(s *Scheduler) { s.Owner = owner }
}

// WithAudits restricts the scheduler to a set of audits. An empty list serves
// every audit with due work.
func WithAudits(audits []string) func(*Scheduler) {
	return func(s *Scheduler) { s.Audits = append([]string(nil), audits...) }
}

// WithInterval sets the tick cadence.
func WithInterval(interval time.Duration) func(*Scheduler) {
	return func(s *Scheduler) { s.Interval = interval }
}

// WithMaxConcurrent bounds how many paths run at once.
func WithMaxConcurrent(n int) func(*Scheduler) { return func(s *Scheduler) { s.MaxConcurrent = n } }

// WithLeaseTTL sets the lease duration asked for on a claim.
func WithLeaseTTL(ttl time.Duration) func(*Scheduler) { return func(s *Scheduler) { s.LeaseTTL = ttl } }

// WithBackoff sets the retry policy.
func WithBackoff(policy path.Backoff) func(*Scheduler) {
	return func(s *Scheduler) { s.Backoff = policy }
}

// WithClock injects the scheduler's clock.
func WithClock(now func() time.Time) func(*Scheduler) { return func(s *Scheduler) { s.Now = now } }

// WithLogger sets the scheduler logger.
func WithLogger(logger *slog.Logger) func(*Scheduler) {
	return func(s *Scheduler) { s.Logger = logger }
}

// WithMetrics attaches a metrics registry.
func WithMetrics(m *Metrics) func(*Scheduler) { return func(s *Scheduler) { s.Metrics = m } }

// IsRunning reports whether Run is in progress.
func (s *Scheduler) IsRunning() bool { return s != nil && s.running.Load() }

// EffectiveConfig is the scheduler's configuration with its defaults resolved. It
// is what an operator surface reports, so a caller never has to know which zero
// means "default" and which means "off".
type EffectiveConfig struct {
	Owner           string       `json:"owner"`
	IntervalSeconds float64      `json:"interval_seconds"`
	MaxConcurrent   int          `json:"max_concurrent"`
	LeaseTTLSeconds float64      `json:"lease_ttl_seconds"`
	Audits          []string     `json:"audits"`
	Backoff         path.Backoff `json:"backoff"`
}

// Config returns the effective configuration.
func (s *Scheduler) Config() EffectiveConfig {
	if s == nil {
		return EffectiveConfig{}
	}
	audits := append([]string(nil), s.Audits...)
	if audits == nil {
		audits = []string{}
	}
	return EffectiveConfig{
		Owner:           s.owner(),
		IntervalSeconds: s.interval().Seconds(),
		MaxConcurrent:   s.concurrency(),
		LeaseTTLSeconds: s.LeaseTTL.Seconds(),
		Audits:          audits,
		Backoff:         s.backoff(),
	}
}

// Snapshot is the stable JSON-shaped state of the scheduler: whether it is
// running, how it is configured and what its metrics say. Both the REST route and
// `scheduler status --json` print exactly this document.
func (s *Scheduler) Snapshot() map[string]any {
	if s == nil {
		return map[string]any{"running": false, "configured": false, "metrics": map[string]any{}}
	}
	return map[string]any{
		"running":    s.IsRunning(),
		"configured": true,
		"config":     s.Config(),
		"metrics":    s.metrics().Snapshot(),
	}
}

// Tick performs one scheduling pass with the configured audits and budget.
func (s *Scheduler) Tick(ctx context.Context) (TickResult, error) {
	return s.TickScoped(ctx, nil, 0)
}

// TickScoped performs one pass with per-call overrides. An empty audits list uses
// the configured set (or every audit with due work); a concurrency of zero uses
// the configured budget. It exists for the operator surfaces (`scheduler tick` and
// POST /api/scheduler/tick), which must not have to rewrite the resident config.
func (s *Scheduler) TickScoped(ctx context.Context, audits []string, concurrency int) (TickResult, error) {
	started := s.now()
	result, err := s.tick(ctx, audits, concurrency)
	s.metrics().ObserveTick(started, s.now().Sub(started))
	return result, err
}

func (s *Scheduler) tick(ctx context.Context, audits []string, concurrency int) (TickResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.Paths == nil {
		return TickResult{}, errors.New("schedule: the scheduler has no path service")
	}
	if s.Agent == nil {
		return TickResult{}, errors.New("schedule: the scheduler has no dispatcher")
	}
	// Live adapters may be configured after startup. Waiting must not consume a
	// queued path's attempts or leases before credentials have been supplied.
	if ready, ok := s.Agent.(interface{ Ready() error }); ok && ready.Ready() != nil {
		return TickResult{}, nil
	}
	now := s.now()
	nowStr := path.NowString(now)
	result := TickResult{}

	// A crashed worker's lease is recovered before anything is dispatched, so the
	// pass can immediately re-run the work it just recovered.
	if reclaimed, err := s.Paths.ReclaimExpired(reclaimLimit); err != nil {
		s.logger().Warn("scheduler could not reclaim expired leases", "error", err)
	} else {
		result.Reclaimed = len(reclaimed)
		s.metrics().AddReclaimed(len(reclaimed))
		for i := range reclaimed {
			s.forget(reclaimed[i].ID)
		}
	}

	ids := audits
	if len(ids) == 0 {
		ids = s.Audits
	}
	if len(ids) == 0 {
		found, err := s.auditsWithWork(nowStr)
		if err != nil {
			return result, err
		}
		ids = found
	}

	owner := s.owner()
	capacity := concurrency
	if capacity <= 0 {
		capacity = s.concurrency()
	}
	budget := capacity - s.inflightCount()
	if budget < 0 {
		budget = 0
	}

	var failed atomic.Int64
	var wg sync.WaitGroup
	var firstErr error

	for _, auditID := range ids {
		if budget <= 0 || ctx.Err() != nil {
			break
		}
		// The audit's own active-lease ceiling is enforced here, because taking a
		// lease is what spends it. It is counted over the audit's whole path set:
		// another worker may hold the rest.
		auditMax := path.DefaultLimits().MaxActiveLeases
		if audit, err := s.Paths.Store.GetAudit(auditID); err == nil {
			if audit.Paused {
				continue
			}
			auditMax = audit.Limits.Normalize().MaxActiveLeases
		}
		_, active, _ := s.queueShape(auditID, now)

		due, err := s.Paths.Store.ListDuePaths(auditID, nowStr, capacity)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("schedule: list due paths of audit %s: %w", auditID, err)
			}
			continue
		}
		result.Due += len(due)

		for i := range due {
			if budget <= 0 || ctx.Err() != nil {
				break
			}
			candidate := due[i]
			if active >= auditMax {
				result.Skipped++
				break
			}
			if max := s.maxAttempts(candidate); max > 0 && candidate.Attempts >= max {
				// The path spent its attempts. It is not dispatched again; an
				// operator resume is a separate, explicit decision.
				result.Skipped++
				continue
			}
			// Reserve before claiming: two concurrent passes can then never target
			// the same path, and the concurrency budget is exact.
			if !s.reserve(candidate.ID, capacity) {
				result.Skipped++
				continue
			}
			claimed, err := s.Paths.LeasePath(ctx, candidate.ID, owner, s.leaseTTLFor(s.LeaseTTL, auditID), []path.Status{path.StatusQueued}, owner)
			if err != nil {
				// Another scheduler won the race, or the path moved on. Both are
				// normal: the pass simply did not take it.
				s.unreserve(candidate.ID)
				result.Skipped++
				continue
			}
			s.markHeld(claimed.ID)
			budget--
			active++
			result.Dispatched++
			s.metrics().AddDispatched(1)

			wg.Add(1)
			go func(p path.Path) {
				defer wg.Done()
				defer s.unreserve(p.ID)
				if s.runDispatch(ctx, p) {
					failed.Add(1)
				}
			}(*claimed)
		}
	}
	wg.Wait()
	result.Failed = int(failed.Load())
	result.Held = s.heldCount()
	s.observeQueue(ids, now)
	return result, firstErr
}

// observeQueue publishes the queue shape after a pass has settled its work, so the
// depth and the oldest wait an operator reads are the ones the pass left behind.
func (s *Scheduler) observeQueue(ids []string, now time.Time) {
	depth, active := 0, 0
	var oldest time.Duration
	for _, auditID := range ids {
		d, a, aged := s.queueShape(auditID, now)
		depth += d
		active += a
		if aged > oldest {
			oldest = aged
		}
	}
	s.metrics().ObserveQueue(depth, active, oldest)
}

// runDispatch hands one claimed path to the dispatcher and settles it. It reports
// whether the dispatch failed.
func (s *Scheduler) runDispatch(ctx context.Context, claimed path.Path) bool {
	err := s.Agent.DispatchPath(ctx, claimed.ID)
	if err == nil {
		s.metrics().AddSucceeded()
		s.settleSuccess(claimed)
		return false
	}
	s.metrics().AddFailed()
	if ctx.Err() != nil {
		// The pass was cancelled: this is a shutdown, not a failed attempt. The
		// lease is released rather than deferred, so the work is immediately
		// available to whoever runs next.
		s.releaseLease(claimed.ID, "the scheduler stopped before the run finished")
		s.forget(claimed.ID)
		return true
	}
	s.deferRetry(claimed, err)
	return true
}

// settleSuccess completes a path the dispatcher left active. A dispatcher that
// settles the path itself (the runner does) leaves nothing to do here; a
// dispatcher that does not must not leave a lease behind, so the scheduler
// advances the path exactly as a successful run would.
func (s *Scheduler) settleSuccess(claimed path.Path) {
	defer s.forget(claimed.ID)
	current, _, err := s.Paths.Path(claimed.ID)
	if err != nil || current == nil {
		return
	}
	if !current.Status.Active() || (current.LeaseOwner != "" && current.LeaseOwner != s.owner()) {
		return
	}
	if _, err := s.Paths.TransitionOwned(claimed.ID, s.owner(), path.StatusHypothesisFormed, s.owner(),
		"the scheduled run finished and the path was settled by the scheduler"); err != nil {
		s.releaseLease(claimed.ID, "the run finished but the path could not be advanced")
	}
}

// deferRetry writes the durable retry schedule of a failed dispatch.
//
// path.Retryable is the single decision point: FAILED, INTERRUPTED and BLOCKED
// attempts may be retried until the path's own attempt ceiling, and a CANCELLED
// path never is. A path with attempts left is returned to QUEUED with a
// NextAttemptAt computed from the backoff policy; one at its ceiling is taken out
// of the queue as FAILED.
func (s *Scheduler) deferRetry(claimed path.Path, cause error) {
	defer s.forget(claimed.ID)
	current, _, err := s.Paths.Path(claimed.ID)
	if err != nil || current == nil {
		return
	}
	if current.Status == path.StatusCancelled || current.Status.Terminal() {
		// An operator cancelled the path while it ran. It is never retried, and
		// the lease (if this scheduler still held one) is given back.
		s.releaseLease(claimed.ID, "the path was cancelled while its attempt ran")
		return
	}
	max := s.maxAttempts(claimed)
	attempts := claimed.Attempts + 1
	if !path.Retryable(retryStatus(current.Status), claimed.Attempts, max) || attempts > max {
		s.finalizeFailure(claimed.ID, cause)
		return
	}
	next := s.backoff().NextAttemptAt(attempts, claimed.ID, s.now())
	reason := fmt.Sprintf("the scheduled attempt failed (attempt %d of %d); retry after %s",
		attempts, max, path.NowString(next))
	_, err = s.ownedTransition(claimed.ID, path.StatusQueued, path.TransitionRequest{
		ClearLease:        true,
		IncrementAttempts: true,
		LastError:         cause.Error(),
		NextAttemptAt:     path.NowString(next),
		Actor:             s.owner(),
		Reason:            reason,
		EventType:         path.EventPathStatusChange,
		Detail:            map[string]string{"next_attempt_at": path.NowString(next), "attempts": fmt.Sprint(attempts)},
	})
	if err != nil {
		// The deferral could not be written (the lease was taken by someone else,
		// or the path moved on). Make sure this scheduler leaves no lease behind.
		s.logger().Warn("scheduler could not defer a failed path",
			"path_id", claimed.ID, "error", err)
		s.releaseLease(claimed.ID, "the retry schedule could not be recorded")
		return
	}
	s.metrics().AddRetried()
}

// finalizeFailure takes a path that spent its attempts out of the queue.
func (s *Scheduler) finalizeFailure(pathID string, cause error) {
	if _, err := s.ownedTransition(pathID, path.StatusFailed, path.TransitionRequest{
		ClearLease:        true,
		IncrementAttempts: true,
		LastError:         cause.Error(),
		Actor:             s.owner(),
		Reason:            "the scheduled attempt failed and the path has spent its attempts",
		EventType:         path.EventPathStatusChange,
	}); err != nil {
		s.logger().Warn("scheduler could not fail a spent path", "path_id", pathID, "error", err)
		s.releaseLease(pathID, "the path spent its attempts but could not be failed")
	}
}

// ownedTransition applies a state change the scheduler owns. When the dispatcher
// already released the lease, the path is taken again first — QUEUED to ANALYZING —
// so the write is an owned transition rather than a blind one, and the state
// machine never sees an illegal same-status change.
func (s *Scheduler) ownedTransition(pathID string, to path.Status, req path.TransitionRequest) (*path.Path, error) {
	current, _, err := s.Paths.Path(pathID)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, path.ErrNotFound
	}
	if current.Status == path.StatusQueued {
		claimed, cerr := s.Paths.LeasePath(context.Background(), pathID, s.owner(), s.leaseTTLFor(s.LeaseTTL, current.AuditID),
			[]path.Status{path.StatusQueued}, s.owner())
		if cerr != nil {
			return nil, cerr
		}
		current = claimed
	}
	req.PathID = pathID
	req.To = to
	req.Owner = s.owner()
	req.LeaseEpoch = current.LeaseEpoch
	req.ExpectedVersion = current.Version
	return s.Paths.Store.Transition(req)
}

// releaseLease gives a path back to the queue if this scheduler still holds it.
// It never touches a path that belongs to another owner or a path that was already
// settled.
func (s *Scheduler) releaseLease(pathID, reason string) {
	current, _, err := s.Paths.Path(pathID)
	if err != nil || current == nil {
		return
	}
	if current.LeaseOwner != s.owner() {
		return
	}
	if _, err := s.Paths.Release(pathID, s.owner(), reason); err != nil {
		s.logger().Warn("scheduler could not release a lease", "path_id", pathID, "error", err)
	}
}

// Run ticks on the configured interval until ctx is done, then releases every
// lease it still holds and returns.
func (s *Scheduler) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.Paths == nil {
		return errors.New("schedule: the scheduler has no path service")
	}
	if s.Agent == nil {
		return errors.New("schedule: the scheduler has no dispatcher")
	}
	s.running.Store(true)
	// Stopping must not leave a lease to expire on its own, so the release ignores
	// the cancellation that ended the loop.
	defer s.releaseHeld()
	defer s.running.Store(false)

	ticker := time.NewTicker(s.interval())
	defer ticker.Stop()
	s.logger().Info("scheduler started",
		"owner", s.owner(), "interval", s.interval().String(),
		"max_concurrent", s.concurrency(), "audits", strings.Join(s.Audits, ","))

	for {
		if _, err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			s.logger().Error("scheduler tick failed", "error", err)
		}
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
			continue
		}
		break
	}
	s.logger().Info("scheduler stopped", "owner", s.owner(), "held", s.heldCount())
	return nil
}

// Reclaim performs one recovery sweep by hand and returns what it recovered.
func (s *Scheduler) Reclaim(limit int) ([]path.Path, error) {
	if s == nil || s.Paths == nil {
		return nil, errors.New("schedule: the scheduler has no path service")
	}
	if limit <= 0 {
		limit = reclaimLimit
	}
	recovered, err := s.Paths.ReclaimExpired(limit)
	if err != nil {
		return nil, err
	}
	s.metrics().AddReclaimed(len(recovered))
	for i := range recovered {
		s.forget(recovered[i].ID)
	}
	return recovered, nil
}

// auditsWithWork lists the audits that have due queued work, which is the "all
// audits" spelling of the configured audit set.
func (s *Scheduler) auditsWithWork(now string) ([]string, error) {
	audits, _, err := s.Paths.Audits(path.AuditQuery{Limit: 1000})
	if err != nil {
		return nil, fmt.Errorf("schedule: list audits: %w", err)
	}
	out := make([]string, 0, len(audits))
	for i := range audits {
		due, derr := s.Paths.Store.ListDuePaths(audits[i].ID, now, 1)
		if derr != nil {
			continue
		}
		if len(due) > 0 {
			out = append(out, audits[i].ID)
		}
	}
	return out, nil
}

// queueShape returns the queued depth, the active leases and the age of the oldest
// queued path of one audit. It is computed from the paths the scheduler actually
// read, which is why the newest information an operator gets is one tick old.
func (s *Scheduler) queueShape(auditID string, now time.Time) (depth, active int, oldest time.Duration) {
	queued, total, err := s.Paths.Paths(path.PathQuery{
		AuditID: auditID, Status: []path.Status{path.StatusQueued}, Sort: "created", Limit: 1,
	})
	if err == nil {
		depth = total
		if len(queued) > 0 {
			oldest = ageOf(queued[0].CreatedAt, now)
		}
	}
	_, activeTotal, err := s.Paths.Paths(path.PathQuery{
		AuditID: auditID,
		Status:  []path.Status{path.StatusAnalyzing, path.StatusLocalExploring, path.StatusVerifying},
		Limit:   1,
	})
	if err == nil {
		active = activeTotal
	}
	return depth, active, oldest
}

// ageOf is how long an RFC3339 timestamp has been waiting at `now`. An unreadable
// timestamp counts as zero rather than as an enormous age.
func ageOf(stamp string, now time.Time) time.Duration {
	if strings.TrimSpace(stamp) == "" {
		return 0
	}
	parsed, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return 0
	}
	if age := now.Sub(parsed); age > 0 {
		return age
	}
	return 0
}

// reserve takes a slot and the path id in the in-flight set, so two concurrent
// passes can neither exceed the budget nor target the same path. It reports
// whether the reservation was taken.
func (s *Scheduler) reserve(pathID string, capacity int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight == nil {
		s.inflight = map[string]bool{}
	}
	if s.inflight[pathID] || len(s.inflight) >= capacity {
		return false
	}
	s.inflight[pathID] = true
	return true
}

func (s *Scheduler) unreserve(pathID string) {
	s.mu.Lock()
	delete(s.inflight, pathID)
	s.mu.Unlock()
}

func (s *Scheduler) inflightCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.inflight)
}

func (s *Scheduler) markHeld(pathID string) {
	s.mu.Lock()
	if s.held == nil {
		s.held = map[string]bool{}
	}
	s.held[pathID] = true
	s.mu.Unlock()
}

func (s *Scheduler) forget(pathID string) {
	s.mu.Lock()
	delete(s.held, pathID)
	s.mu.Unlock()
}

func (s *Scheduler) heldCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.held)
}

// releaseHeld returns every lease this scheduler still holds after a stop. It is
// the difference between a clean shutdown and work that waits for a lease to
// expire.
func (s *Scheduler) releaseHeld() {
	if s == nil || s.Paths == nil {
		return
	}
	s.mu.Lock()
	ids := make([]string, 0, len(s.held))
	for id := range s.held {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.releaseLease(id, "the scheduler stopped and returned the lease")
		s.forget(id)
	}
}

// maxAttempts is the path's own ceiling, then the engine's documented default.
func (s *Scheduler) maxAttempts(p path.Path) int {
	if p.MaxAttempts > 0 {
		return p.MaxAttempts
	}
	return path.DefaultLimits().MaxAttempts
}

// retryStatus maps the status a failed path is in to the status path.Retryable
// understands. A path the dispatcher handed back FAILED says so; one it released
// to QUEUED is still a failed attempt; a CANCELLED path stays cancelled, which is
// what makes Retryable refuse it.
func retryStatus(status path.Status) path.Status {
	switch status {
	case path.StatusFailed, path.StatusInterrupted, path.StatusBlocked, path.StatusCancelled:
		return status
	default:
		return path.StatusFailed
	}
}

// leaseTTLFor prefers the configured TTL and otherwise asks the audit for its own,
// which is the documented per-audit lease.
func (s *Scheduler) leaseTTLFor(configured time.Duration, auditID string) time.Duration {
	if configured > 0 {
		return configured
	}
	if audit, err := s.Paths.Store.GetAudit(auditID); err == nil {
		return time.Duration(audit.Limits.Normalize().LeaseTTLSeconds) * time.Second
	}
	return time.Duration(path.DefaultLimits().LeaseTTLSeconds) * time.Second
}

func (s *Scheduler) now() time.Time {
	if s != nil && s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Scheduler) owner() string {
	if s != nil {
		if owner := strings.TrimSpace(s.Owner); owner != "" {
			return owner
		}
	}
	return defaultSchedulerOwner
}

func (s *Scheduler) interval() time.Duration {
	if s != nil && s.Interval > 0 {
		return s.Interval
	}
	return defaultSchedulerInterval
}

func (s *Scheduler) concurrency() int {
	if s != nil && s.MaxConcurrent > 0 {
		return s.MaxConcurrent
	}
	return path.DefaultLimits().MaxActiveLeases
}

func (s *Scheduler) backoff() path.Backoff {
	if s != nil && (s.Backoff.Base > 0 || s.Backoff.Factor > 0 || s.Backoff.Max > 0 || s.Backoff.Jitter > 0) {
		return s.Backoff.Normalize()
	}
	return path.DefaultBackoff()
}

func (s *Scheduler) logger() *slog.Logger {
	if s != nil && s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// metrics returns the metrics registry, creating one on first use so a scheduler
// built without one still reports.
func (s *Scheduler) metrics() *Metrics {
	if s == nil {
		return &Metrics{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Metrics == nil {
		if s.defaultMetrics == nil {
			s.defaultMetrics = &Metrics{}
		}
		return s.defaultMetrics
	}
	return s.Metrics
}
