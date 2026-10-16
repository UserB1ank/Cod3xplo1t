package schedule

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// The scheduler tests drive the real path state machine over an in-memory store
// and an injected clock. That combination is deliberate: the properties under test
// — a lease is the dispatch right, a deferral is durable, an expired lease is
// recoverable — are properties of the state changes, not of a mock, so a fake that
// accepted them would prove nothing.

var schedTestNow = time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)

// testClock is the injectable clock. It is safe to read from the scheduler's
// goroutines while a test advances it.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d)
	c.mu.Unlock()
}

// recordingDispatcher is a dispatcher that records every path it is handed.
type recordingDispatcher struct {
	mu    sync.Mutex
	calls []string
	// err is returned for every dispatch unless perPath names the path.
	err     error
	perPath map[string]error
	// onCall runs before the result is returned, so a test can mutate the path
	// while its attempt is "running".
	onCall func(pathID string)
	// delay widens the window a concurrent-tick test needs.
	delay time.Duration
}

func (d *recordingDispatcher) DispatchPath(ctx context.Context, pathID string) error {
	d.mu.Lock()
	d.calls = append(d.calls, pathID)
	err := d.err
	if d.perPath != nil {
		if specific, ok := d.perPath[pathID]; ok {
			err = specific
		}
	}
	onCall := d.onCall
	delay := d.delay
	d.mu.Unlock()

	if onCall != nil {
		onCall(pathID)
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (d *recordingDispatcher) count(pathID string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, call := range d.calls {
		if call == pathID {
			n++
		}
	}
	return n
}

func (d *recordingDispatcher) total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

// schedFixture is one scheduler over one audit and one in-memory store.
type schedFixture struct {
	t          *testing.T
	store      *storage.Memory
	svc        *path.Service
	clock      *testClock
	dispatcher *recordingDispatcher
	scheduler  *Scheduler
	metrics    *Metrics
	auditID    string
}

// schedPath is one queued path of the fixture audit, with a distinct signature so
// the store's exact-dedup invariant is satisfied.
func schedPath(auditID, pathID string) path.Path {
	return path.Path{
		ID: pathID, AuditID: auditID, SnapshotID: "snap-1",
		EntryNodeID: "entry-1", TargetNodeID: "sink-1", PathKind: "entry_to_sink",
		PathStatus: path.PathStaticallySupported, Status: path.StatusQueued,
		Signature: "sig-" + pathID, MaxAttempts: 3,
		CreatedAt: path.NowString(schedTestNow), UpdatedAt: path.NowString(schedTestNow),
	}
}

func newSchedFixture(t *testing.T, paths ...path.Path) *schedFixture {
	t.Helper()
	store := storage.NewMemory()
	clock := &testClock{at: schedTestNow}
	svc := &path.Service{Store: store, Now: clock.Now}
	auditID := "audit-1"
	if len(paths) > 0 {
		auditID = paths[0].AuditID
	}
	if err := store.CreateAudit(path.Audit{
		ID: auditID, SnapshotID: "snap-1", Status: path.AuditReady,
		Budget: path.DefaultBudget(), Limits: path.DefaultLimits(),
		ScoreVersion:   path.ScoreVersion,
		CountsByStatus: map[string]int{}, CountsByPathStatus: map[string]int{},
		CreatedAt: path.NowString(schedTestNow), UpdatedAt: path.NowString(schedTestNow), Version: 1,
	}); err != nil {
		t.Fatalf("CreateAudit: %v", err)
	}
	if len(paths) > 0 {
		if err := store.ReplacePaths(auditID, paths); err != nil {
			t.Fatalf("ReplacePaths: %v", err)
		}
	}
	dispatcher := &recordingDispatcher{}
	metrics := NewMetrics()
	scheduler := New(svc, dispatcher,
		WithOwner("scheduler-1"),
		WithAudits([]string{auditID}),
		WithMaxConcurrent(2),
		WithLeaseTTL(time.Minute),
		WithBackoff(path.Backoff{Base: time.Minute, Factor: 2, Max: time.Hour}),
		WithClock(clock.Now),
		WithMetrics(metrics),
	)
	return &schedFixture{
		t: t, store: store, svc: svc, clock: clock,
		dispatcher: dispatcher, scheduler: scheduler, metrics: metrics, auditID: auditID,
	}
}

func (f *schedFixture) path(pathID string) path.Path {
	f.t.Helper()
	p, err := f.store.GetPath(pathID)
	if err != nil {
		f.t.Fatalf("GetPath(%s): %v", pathID, err)
	}
	return *p
}

func (f *schedFixture) tick() TickResult {
	f.t.Helper()
	result, err := f.scheduler.Tick(context.Background())
	if err != nil {
		f.t.Fatalf("Tick: %v", err)
	}
	return result
}

// TestSchedulerDispatchesUpToTheConcurrencyBudget pins the budget: one pass hands
// out exactly MaxConcurrent paths, and no more, even when the queue is longer.
func TestSchedulerDispatchesUpToTheConcurrencyBudget(t *testing.T) {
	f := newSchedFixture(t,
		schedPath("audit-1", "path-1"),
		schedPath("audit-1", "path-2"),
		schedPath("audit-1", "path-3"),
		schedPath("audit-1", "path-4"),
	)
	f.scheduler.MaxConcurrent = 2

	result := f.tick()
	if result.Dispatched != 2 {
		t.Fatalf("dispatched = %d, want the concurrency budget of 2", result.Dispatched)
	}
	if result.Due != 2 {
		t.Errorf("due = %d, want the 2 paths the pass asked for", result.Due)
	}
	if got := f.dispatcher.total(); got != 2 {
		t.Fatalf("dispatcher calls = %d, want 2", got)
	}
	// Every dispatched path settled as a completed run, so nothing is left leased.
	if result.Held != 0 {
		t.Errorf("held = %d, want 0 after a settling pass", result.Held)
	}
	for _, id := range f.dispatcher.calls {
		if got := f.path(id).Status; got != path.StatusHypothesisFormed {
			t.Errorf("path %s status = %s, want HYPOTHESIS_FORMED", id, got)
		}
	}
}

// TestSchedulerSkipsAPathInBackoffUntilItsDueTime is the durable half of the retry
// policy: the deferral lives in the path document, and the injected clock is what
// makes it elapse.
func TestSchedulerSkipsAPathInBackoffUntilItsDueTime(t *testing.T) {
	f := newSchedFixture(t, schedPath("audit-1", "path-1"))
	f.dispatcher.err = errors.New("the adapter could not start")

	first := f.tick()
	if first.Dispatched != 1 || first.Failed != 1 {
		t.Fatalf("first tick = %+v, want 1 dispatched and 1 failed", first)
	}
	deferred := f.path("path-1")
	if deferred.Status != path.StatusQueued {
		t.Fatalf("path status after a failed attempt = %s, want QUEUED", deferred.Status)
	}
	if deferred.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", deferred.Attempts)
	}
	wantNext := path.NowString(schedTestNow.Add(time.Minute))
	if deferred.NextAttemptAt != wantNext {
		t.Fatalf("next attempt = %q, want %q (base delay of the first failure)", deferred.NextAttemptAt, wantNext)
	}
	if deferred.LeaseOwner != "" {
		t.Errorf("lease owner = %q, want the lease released while the path waits", deferred.LeaseOwner)
	}

	// Before the due time the path is not even a candidate.
	second := f.tick()
	if second.Dispatched != 0 {
		t.Fatalf("tick before the due time dispatched %d path(s), want 0", second.Dispatched)
	}
	if f.dispatcher.total() != 1 {
		t.Fatalf("dispatcher calls = %d, want the single first attempt", f.dispatcher.total())
	}

	// Once the due time passes, the path runs again.
	f.clock.Advance(61 * time.Second)
	third := f.tick()
	if third.Dispatched != 1 {
		t.Fatalf("tick after the due time dispatched %d path(s), want 1", third.Dispatched)
	}
	if attempts := f.path("path-1").Attempts; attempts != 2 {
		t.Errorf("attempts = %d, want 2 after the retry", attempts)
	}
}

// TestSchedulerFailedDispatchDefersWithBackoff pins the write itself: attempts are
// incremented and the next attempt is computed from the backoff policy.
func TestSchedulerFailedDispatchDefersWithBackoff(t *testing.T) {
	f := newSchedFixture(t, schedPath("audit-1", "path-1"))
	f.dispatcher.err = errors.New("adapter exploded")

	f.tick()
	p := f.path("path-1")
	if p.Attempts != 1 || p.LastError == "" {
		t.Fatalf("path = attempts %d, last error %q; want the failed attempt recorded", p.Attempts, p.LastError)
	}
	// The deterministic jitter-free policy means the due time is exactly base.
	if p.NextAttemptAt != path.NowString(schedTestNow.Add(time.Minute)) {
		t.Errorf("next attempt = %q, want now+1m", p.NextAttemptAt)
	}
	if got := f.metrics.Snapshot()["retried_total"]; got != int64(1) {
		t.Errorf("retried_total = %v, want 1", got)
	}
}

// TestSchedulerDoesNotRetryAPathAtItsAttemptCeiling is the bounded-retry rule: a
// path that already spent its attempts is never handed out again.
func TestSchedulerDoesNotRetryAPathAtItsAttemptCeiling(t *testing.T) {
	exhausted := schedPath("audit-1", "path-1")
	exhausted.Attempts = exhausted.MaxAttempts
	f := newSchedFixture(t, exhausted)

	result := f.tick()
	if result.Dispatched != 0 {
		t.Fatalf("dispatched = %d, want 0 for a path at its attempt ceiling", result.Dispatched)
	}
	if result.Skipped != 1 {
		t.Errorf("skipped = %d, want the spent path to be skipped", result.Skipped)
	}
	if f.dispatcher.total() != 0 {
		t.Fatalf("dispatcher calls = %d, want 0", f.dispatcher.total())
	}
	if got := f.path("path-1").Status; got != path.StatusQueued {
		t.Errorf("path status = %s, want it left untouched in QUEUED", got)
	}
}

// TestSchedulerNeverRetriesACancelledPath pins the other half of path.Retryable:
// an operator cancelled the path, so its failed attempt must not be deferred or
// requeued.
func TestSchedulerNeverRetriesACancelledPath(t *testing.T) {
	f := newSchedFixture(t, schedPath("audit-1", "path-1"))
	f.dispatcher.onCall = func(pathID string) {
		// The operator cancels the path while its attempt is running.
		if _, err := f.svc.Cancel(pathID, "operator", "cancelled during the run"); err != nil {
			t.Errorf("Cancel: %v", err)
		}
	}
	f.dispatcher.err = errors.New("the run failed after the cancellation")

	result := f.tick()
	if result.Dispatched != 1 || result.Failed != 1 {
		t.Fatalf("tick = %+v, want the attempt to have run and failed", result)
	}
	p := f.path("path-1")
	if p.Status != path.StatusCancelled {
		t.Fatalf("path status = %s, want CANCELLED", p.Status)
	}
	if p.Attempts != 0 {
		t.Errorf("attempts = %d, want 0: a cancelled path is never retried", p.Attempts)
	}
	if p.NextAttemptAt != "" {
		t.Errorf("next attempt = %q, want empty for a cancelled path", p.NextAttemptAt)
	}
	if got := f.metrics.Snapshot()["retried_total"]; got != int64(0) {
		t.Errorf("retried_total = %v, want 0", got)
	}
}

// TestSchedulerReclaimsACrashedWorkersLease is the crash-recovery case, named for
// it: a worker stopped renewing its lease, and the scheduler recovers the path and
// dispatches it again in the same pass.
func TestSchedulerReclaimsACrashedWorkersLease(t *testing.T) {
	crashed := schedPath("audit-1", "path-1")
	crashed.Status = path.StatusAnalyzing
	crashed.LeaseOwner = "worker-that-died"
	crashed.LeaseUntil = path.NowString(schedTestNow.Add(-time.Minute))
	f := newSchedFixture(t, crashed)

	result := f.tick()
	if result.Reclaimed != 1 {
		t.Fatalf("reclaimed = %d, want the expired lease recovered", result.Reclaimed)
	}
	if result.Dispatched != 1 {
		t.Fatalf("dispatched = %d, want the recovered path dispatched again", result.Dispatched)
	}
	if got := f.dispatcher.count("path-1"); got != 1 {
		t.Fatalf("dispatcher calls for the recovered path = %d, want 1", got)
	}
	p := f.path("path-1")
	if p.Status != path.StatusHypothesisFormed {
		t.Errorf("path status = %s, want it re-run and settled", p.Status)
	}
	if p.LeaseOwner != "" {
		t.Errorf("lease owner = %q, want the crashed worker's lease cleared", p.LeaseOwner)
	}
	if got := f.metrics.Snapshot()["reclaimed_total"]; got != int64(1) {
		t.Errorf("reclaimed_total = %v, want 1", got)
	}
}

// TestSchedulerRunStopsAndReleasesHeldLeases pins the shutdown contract: Run
// returns when its context is done and hands back the lease it still holds instead
// of leaving it to expire.
func TestSchedulerRunStopsAndReleasesHeldLeases(t *testing.T) {
	f := newSchedFixture(t, schedPath("audit-1", "path-1"))
	entered := make(chan struct{}, 1)
	f.dispatcher.onCall = func(string) {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	// The attempt blocks until the scheduler is cancelled.
	blocking := &blockingDispatcher{entered: entered}
	f.scheduler.Agent = blocking
	f.scheduler.Interval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.scheduler.Run(ctx) }()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("the scheduler never dispatched the path")
	}
	if !f.scheduler.IsRunning() {
		t.Error("IsRunning = false while Run is in progress")
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after its context was cancelled")
	}
	if f.scheduler.IsRunning() {
		t.Error("IsRunning = true after Run returned")
	}
	p := f.path("path-1")
	if p.Status != path.StatusQueued {
		t.Fatalf("path status after shutdown = %s, want QUEUED", p.Status)
	}
	if p.LeaseOwner != "" {
		t.Errorf("lease owner = %q, want the scheduler's lease released", p.LeaseOwner)
	}
	if p.Attempts != 0 {
		t.Errorf("attempts = %d, want 0: a cancelled pass is not a failed attempt", p.Attempts)
	}
}

// blockingDispatcher holds its attempt until its context is cancelled, which is
// what a shutdown test needs.
type blockingDispatcher struct {
	entered chan struct{}
}

func (d *blockingDispatcher) DispatchPath(ctx context.Context, pathID string) error {
	select {
	case d.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

// TestConcurrentTicksNeverDispatchTheSamePathTwice pins the lease as the dispatch
// right: several passes racing over one queue produce exactly one dispatch.
func TestConcurrentTicksNeverDispatchTheSamePathTwice(t *testing.T) {
	f := newSchedFixture(t, schedPath("audit-1", "path-1"))
	f.dispatcher.delay = 10 * time.Millisecond

	var wg sync.WaitGroup
	results := make([]TickResult, 8)
	for i := 0; i < len(results); i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			result, err := f.scheduler.Tick(context.Background())
			if err != nil {
				t.Errorf("concurrent Tick: %v", err)
				return
			}
			results[index] = result
		}(i)
	}
	wg.Wait()

	if got := f.dispatcher.count("path-1"); got != 1 {
		t.Fatalf("dispatcher calls for path-1 = %d, want exactly 1", got)
	}
	dispatched := 0
	for _, result := range results {
		dispatched += result.Dispatched
	}
	if dispatched != 1 {
		t.Fatalf("total dispatched = %d across concurrent ticks, want 1", dispatched)
	}
}

// TestSchedulerMetricsReflectTheCounts pins the metrics contract the API exposes.
func TestSchedulerMetricsReflectTheCounts(t *testing.T) {
	crashed := schedPath("audit-1", "path-3")
	crashed.Status = path.StatusAnalyzing
	crashed.LeaseOwner = "worker-that-died"
	crashed.LeaseUntil = path.NowString(schedTestNow.Add(-time.Minute))
	f := newSchedFixture(t,
		schedPath("audit-1", "path-1"),
		schedPath("audit-1", "path-2"),
		crashed,
	)
	f.dispatcher.err = errors.New("the adapter could not start")

	result := f.tick()
	if result.Reclaimed != 1 || result.Dispatched != 2 || result.Failed != 2 {
		t.Fatalf("tick = %+v, want 1 reclaimed, 2 dispatched and 2 failed", result)
	}
	snapshot := f.metrics.Snapshot()
	for _, key := range []string{
		"ticks", "dispatched_total", "succeeded_total", "failed_total", "retried_total",
		"reclaimed_total", "active_leases", "queue_depth", "oldest_queued_seconds",
		"last_tick_at", "last_tick_ms",
	} {
		if _, ok := snapshot[key]; !ok {
			t.Errorf("metrics snapshot is missing %q: %v", key, snapshot)
		}
	}
	if snapshot["ticks"] != int64(1) {
		t.Errorf("ticks = %v, want 1", snapshot["ticks"])
	}
	if snapshot["dispatched_total"] != int64(2) || snapshot["failed_total"] != int64(2) {
		t.Errorf("dispatched/failed = %v/%v, want 2/2", snapshot["dispatched_total"], snapshot["failed_total"])
	}
	if snapshot["retried_total"] != int64(2) {
		t.Errorf("retried_total = %v, want 2", snapshot["retried_total"])
	}
	// The two failed paths are back in the queue, deferred, and the reclaimed path
	// is queued as well: the depth reflects all three.
	if snapshot["queue_depth"] != 3 {
		t.Errorf("queue_depth = %v, want 3", snapshot["queue_depth"])
	}
	if snapshot["last_tick_at"] == nil {
		t.Error("last_tick_at = nil, want the tick timestamp")
	}
}

// TestSchedulerReclaimByHand checks the manual sweep used by POST
// /api/scheduler/reclaim and `scheduler reclaim`.
func TestSchedulerReclaimByHand(t *testing.T) {
	crashed := schedPath("audit-1", "path-1")
	crashed.Status = path.StatusAnalyzing
	crashed.LeaseOwner = "worker-that-died"
	crashed.LeaseUntil = path.NowString(schedTestNow.Add(-time.Minute))
	f := newSchedFixture(t, crashed)

	recovered, err := f.scheduler.Reclaim(10)
	if err != nil {
		t.Fatalf("Reclaim: %v", err)
	}
	if len(recovered) != 1 || recovered[0].ID != "path-1" {
		t.Fatalf("recovered = %+v, want path-1", recovered)
	}
	if got := f.path("path-1").Status; got != path.StatusQueued {
		t.Errorf("path status = %s, want QUEUED", got)
	}
	if got := f.metrics.Snapshot()["reclaimed_total"]; got != int64(1) {
		t.Errorf("reclaimed_total = %v, want 1", got)
	}
}

// TestSchedulerConfigurationDefaults pins the fallbacks so a zero-value scheduler
// is still a usable one.
func TestSchedulerConfigurationDefaults(t *testing.T) {
	f := newSchedFixture(t)
	s := &Scheduler{Paths: f.svc, Agent: f.dispatcher}
	if s.owner() != defaultSchedulerOwner {
		t.Errorf("owner = %q, want %q", s.owner(), defaultSchedulerOwner)
	}
	if s.interval() != defaultSchedulerInterval {
		t.Errorf("interval = %s, want %s", s.interval(), defaultSchedulerInterval)
	}
	if s.concurrency() != path.DefaultLimits().MaxActiveLeases {
		t.Errorf("concurrency = %d, want the engine ceiling", s.concurrency())
	}
	if got := s.backoff(); got != path.DefaultBackoff() {
		t.Errorf("backoff = %+v, want the documented default", got)
	}
	if _, err := s.Tick(context.Background()); err == nil {
		// A fixture audit with nothing due is not an error; the point here is only
		// that an explicitly unconfigured scheduler refuses, below.
		t.Log("an empty queue is not an error")
	}
	empty := &Scheduler{}
	if _, err := empty.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "path service") {
		t.Errorf("Tick without a path service = %v, want an error naming it", err)
	}
}
