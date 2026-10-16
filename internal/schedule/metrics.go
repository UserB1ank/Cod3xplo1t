// Package schedule is the P7 resident scheduler: the process that turns the path
// engine's durable queue into running agent work, bounded by leases, a concurrency
// budget and a durable retry schedule.
//
// The layer owns four things the rest of the system deliberately does not:
//
//   - a resident loop that ticks on an interval and stops cleanly, releasing every
//     lease it still holds;
//   - path-scoped dispatch, so the scheduler runs the path it chose instead of
//     asking the runner to choose again;
//   - the retry schedule: a failed dispatch is deferred by an exponential backoff
//     written into the path document, so a restart remembers it;
//   - the metrics an operator needs to see whether the queue is moving.
//
// Two invariants shape every line below. A path is only ever dispatched while this
// scheduler holds its lease — the claim is the dispatch right — and a cancelled
// path is never retried, because path.Retryable says so.
package schedule

import (
	"sync"
	"time"
)

// Metrics are the counters and gauges of the scheduling layer.
//
// They are the part of the design §14 measurement set this layer owns: how much
// work was handed to agents, how much succeeded, failed and was deferred, how
// much expired work was recovered, and whether the queue is draining (depth, and
// the age of the oldest queued path). Every field is updated under one mutex and
// read through Snapshot, so a scraper can never observe a half-updated pair.
type Metrics struct {
	mu sync.Mutex

	ticks      int64
	dispatched int64
	succeeded  int64
	failed     int64
	retried    int64
	reclaimed  int64

	activeLeases int
	queueDepth   int
	// oldestQueued is the age of the oldest queued path the scheduler saw on the
	// last tick. It is a duration rather than a timestamp because "how long has
	// this been waiting" is the number an operator acts on.
	oldestQueued time.Duration

	lastTickAt     time.Time
	lastTickMillis int64
}

// NewMetrics builds an empty metrics registry.
func NewMetrics() *Metrics { return &Metrics{} }

// Snapshot returns a stable JSON-shaped view of the metrics. It is a plain map so
// the REST layer can embed it without the schedule package depending on the API.
func (m *Metrics) Snapshot() map[string]any {
	if m == nil {
		return map[string]any{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]any{
		"ticks":                 m.ticks,
		"dispatched_total":      m.dispatched,
		"succeeded_total":       m.succeeded,
		"failed_total":          m.failed,
		"retried_total":         m.retried,
		"reclaimed_total":       m.reclaimed,
		"active_leases":         m.activeLeases,
		"queue_depth":           m.queueDepth,
		"oldest_queued_seconds": m.oldestQueued.Seconds(),
		"last_tick_ms":          m.lastTickMillis,
	}
	if m.lastTickAt.IsZero() {
		out["last_tick_at"] = nil
	} else {
		out["last_tick_at"] = m.lastTickAt.UTC().Format(time.RFC3339)
	}
	return out
}

// AddDispatched records work handed to the dispatcher.
func (m *Metrics) AddDispatched(n int) { m.add(&m.dispatched, int64(n)) }

// AddSucceeded records a dispatch that settled its path as completed.
func (m *Metrics) AddSucceeded() { m.add(&m.succeeded, 1) }

// AddFailed records a dispatch that returned an error.
func (m *Metrics) AddFailed() { m.add(&m.failed, 1) }

// AddRetried records a failed dispatch whose path was requeued with a durable
// next-attempt time.
func (m *Metrics) AddRetried() { m.add(&m.retried, 1) }

// AddReclaimed records leases recovered from workers that stopped renewing them.
func (m *Metrics) AddReclaimed(n int) { m.add(&m.reclaimed, int64(n)) }

// ObserveQueue records the queue shape seen on a tick: how many paths are queued,
// how many leases are active and how long the oldest queued path has waited.
func (m *Metrics) ObserveQueue(depth, activeLeases int, oldest time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queueDepth = depth
	m.activeLeases = activeLeases
	if oldest < 0 {
		oldest = 0
	}
	m.oldestQueued = oldest
}

// ObserveTick records one completed pass.
func (m *Metrics) ObserveTick(at time.Time, elapsed time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ticks++
	m.lastTickAt = at.UTC()
	m.lastTickMillis = elapsed.Milliseconds()
}

func (m *Metrics) add(field *int64, delta int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	*field += delta
	m.mu.Unlock()
}
