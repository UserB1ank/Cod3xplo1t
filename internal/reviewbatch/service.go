package reviewbatch

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

const (
	defaultMaxPaths        = 2000
	defaultInterval        = 250 * time.Millisecond
	defaultLeaseTTL        = 30 * time.Second
	defaultReclaimInterval = time.Second
)

// Manager executes fixed path sets through agent.Runner. It is deliberately
// separate from schedule.Scheduler: the scheduler serves the whole durable queue,
// while a review batch has an explicit operator-owned membership and lifecycle.
type Manager struct {
	Store Store
	Paths PathService
	Agent *agent.Runner
	Owner string
	Now   func() time.Time
	// Interval polls state between waves and gives a cancelled local run a
	// deterministic place to settle.
	Interval        time.Duration
	LeaseTTL        time.Duration
	ReclaimInterval time.Duration
	Logger          *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu          sync.Mutex
	active      map[string]int64
	wg          sync.WaitGroup
	monitorOnce sync.Once
	configMu    sync.Mutex
}

func New(store Store, paths PathService, runner *agent.Runner) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		Store: store, Paths: paths, Agent: runner,
		Owner: "review-batch-" + rand.Text(), Now: func() time.Time { return time.Now().UTC() },
		Interval: defaultInterval, LeaseTTL: defaultLeaseTTL, ReclaimInterval: defaultReclaimInterval,
		Logger: slog.Default(), ctx: ctx, cancel: cancel, active: map[string]int64{},
	}
}

func (m *Manager) Close() {
	if m == nil || m.cancel == nil {
		return
	}
	m.cancel()
	m.wg.Wait()
}

func (m *Manager) Start(ctx context.Context, projectID, auditID, createdBy string, maxConcurrent, maxPaths int) (View, error) {
	if err := m.ready(); err != nil {
		return View{}, err
	}
	auditID = strings.TrimSpace(auditID)
	if auditID == "" {
		return View{}, fmt.Errorf("%w: audit_id is required", ErrInvalid)
	}
	audit, err := m.Paths.Audit(auditID)
	if err != nil {
		return View{}, err
	}
	if audit.Status != path.AuditReady {
		return View{}, fmt.Errorf("%w: audit %s is %s", ErrInvalid, auditID, audit.Status)
	}
	if audit.Paused || audit.Archived {
		return View{}, fmt.Errorf("%w: audit %s is paused or archived", ErrConflict, auditID)
	}
	limits := audit.Limits.Normalize()
	if maxConcurrent < 0 {
		return View{}, fmt.Errorf("%w: max_concurrent must not be negative", ErrInvalid)
	}
	if maxConcurrent == 0 {
		maxConcurrent = limits.MaxActiveLeases
	}
	if maxConcurrent > limits.MaxActiveLeases {
		return View{}, fmt.Errorf("%w: max_concurrent %d exceeds audit limit %d", ErrInvalid, maxConcurrent, limits.MaxActiveLeases)
	}
	if maxPaths < 0 {
		return View{}, fmt.Errorf("%w: max_paths must not be negative", ErrInvalid)
	}
	if maxPaths == 0 || maxPaths > limits.MaxPaths {
		maxPaths = limits.MaxPaths
	}
	if maxPaths > defaultMaxPaths {
		maxPaths = defaultMaxPaths
	}
	pathIDs, err := m.queuedPathIDs(auditID, maxPaths)
	if err != nil {
		return View{}, err
	}
	if len(pathIDs) == 0 {
		return View{}, ErrNoWork
	}
	now := m.now()
	nowString := path.NowString(now)
	batch := Batch{
		ID: "review-batch-" + rand.Text(), ProjectID: strings.TrimSpace(projectID),
		SnapshotID: audit.SnapshotID, AuditID: audit.ID, State: StateRunning,
		PathIDs: pathIDs, MaxConcurrent: maxConcurrent,
		CreatedBy: strings.TrimSpace(createdBy), ExecutionOwner: m.Owner, LeaseEpoch: 1,
		HeartbeatAt: nowString, LeaseUntil: path.NowString(now.Add(m.leaseTTL())),
		CreatedAt: nowString, UpdatedAt: nowString, Version: 1,
	}
	if batch.ProjectID == "" || batch.SnapshotID == "" {
		return View{}, fmt.Errorf("%w: project and snapshot identity are required", ErrInvalid)
	}
	stored, err := m.Store.CreateReviewBatch(ctx, batch)
	if err != nil {
		return View{}, err
	}
	m.launch(stored)
	return m.view(ctx, stored)
}

func (m *Manager) Get(ctx context.Context, id string) (View, error) {
	if err := m.ready(); err != nil {
		return View{}, err
	}
	batch, err := m.Store.GetReviewBatch(ctx, strings.TrimSpace(id))
	if err != nil {
		return View{}, err
	}
	return m.view(ctx, *batch)
}

func (m *Manager) List(ctx context.Context, query Query) ([]View, int, error) {
	if err := m.ready(); err != nil {
		return nil, 0, err
	}
	batches, total, err := m.Store.ListReviewBatches(ctx, query)
	if err != nil {
		return nil, 0, err
	}
	views := make([]View, 0, len(batches))
	for _, batch := range batches {
		view, err := m.view(ctx, batch)
		if err != nil {
			return nil, 0, err
		}
		views = append(views, view)
	}
	return views, total, nil
}

func (m *Manager) Pause(ctx context.Context, id string, expectedVersion int64, actor, reason string) (View, error) {
	return m.control(ctx, id, expectedVersion, StatePaused, actor, reason)
}

func (m *Manager) Resume(ctx context.Context, id string, expectedVersion int64, actor, reason string) (View, error) {
	if err := m.ready(); err != nil {
		return View{}, err
	}
	now := m.now()
	batch, err := m.Store.ControlReviewBatch(ctx, ControlRequest{
		BatchID: strings.TrimSpace(id), ExpectedVersion: expectedVersion, Target: StateRunning,
		Actor: actor, Reason: strings.TrimSpace(reason), Owner: m.Owner,
		Now: path.NowString(now), LeaseUntil: path.NowString(now.Add(m.leaseTTL())),
	})
	if err != nil {
		return View{}, err
	}
	m.launch(*batch)
	return m.view(ctx, *batch)
}

func (m *Manager) Cancel(ctx context.Context, id string, expectedVersion int64, actor, reason string) (View, error) {
	return m.control(ctx, id, expectedVersion, StateCancelling, actor, reason)
}

func (m *Manager) Recover(ctx context.Context) error {
	if err := m.available(); err != nil {
		return err
	}
	m.monitorOnce.Do(func() {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.monitor()
		}()
	})
	return m.Reclaim(ctx)
}

// Reclaim claims recoverable batches whose owner lease expired. It is exported
// so tests and a process supervisor can force an immediate scan.
func (m *Manager) Reclaim(ctx context.Context) error {
	if err := m.available(); err != nil {
		return err
	}
	batches, err := m.Store.ListReclaimableReviewBatches(ctx, path.NowString(m.now()), 100)
	if err != nil {
		return err
	}
	for _, candidate := range batches {
		m.claimAndLaunch(ctx, candidate)
	}
	return nil
}

func (m *Manager) control(ctx context.Context, id string, expectedVersion int64, target State, actor, reason string) (View, error) {
	if err := m.ready(); err != nil {
		return View{}, err
	}
	batch, err := m.Store.ControlReviewBatch(ctx, ControlRequest{
		BatchID: strings.TrimSpace(id), ExpectedVersion: expectedVersion, Target: target,
		Actor: actor, Reason: strings.TrimSpace(reason), Owner: m.Owner, Now: path.NowString(m.now()),
	})
	if err != nil {
		return View{}, err
	}
	if target == StateCancelling {
		m.cancelLocalActive(*batch)
		m.launch(*batch)
	}
	return m.view(ctx, *batch)
}

func (m *Manager) view(ctx context.Context, batch Batch) (View, error) {
	progress := Progress{Total: len(batch.PathIDs)}
	paths := make([]PathProgress, 0, len(batch.PathIDs))
	for _, pathID := range batch.PathIDs {
		current, _, err := m.Paths.Path(pathID)
		if err != nil {
			return View{}, err
		}
		status := string(current.Status)
		paths = append(paths, PathProgress{PathID: pathID, Status: status})
		switch {
		case current.Status == path.StatusQueued:
			progress.Queued++
		case current.Status.Active():
			progress.Active++
		case current.Status == path.StatusHypothesisFormed || current.Status == path.StatusConcluded:
			progress.Reviewed++
		case current.Status == path.StatusBlocked:
			progress.Blocked++
		case current.Status == path.StatusPaused:
			progress.Paused++
		case current.Status == path.StatusCancelled:
			progress.Cancelled++
		default:
			progress.Failed++
		}
	}
	return View{Batch: batch, Progress: progress, Paths: paths}, nil
}

func (m *Manager) queuedPathIDs(auditID string, maxPaths int) ([]string, error) {
	out := make([]string, 0, min(maxPaths, 500))
	for offset := 0; len(out) < maxPaths; {
		limit := min(500, maxPaths-len(out))
		items, total, err := m.Paths.Paths(path.PathQuery{
			AuditID: auditID, Status: []path.Status{path.StatusQueued},
			Sort: "priority", Limit: limit, Offset: offset,
		})
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			out = append(out, item.ID)
			if len(out) == maxPaths {
				break
			}
		}
		offset += len(items)
		if len(items) == 0 || offset >= total {
			break
		}
	}
	return out, nil
}

func (m *Manager) monitor() {
	ticker := time.NewTicker(m.reclaimInterval())
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.Reclaim(m.ctx); err != nil && m.ctx.Err() == nil {
				m.Logger.Warn("review batch reclaim scan failed", "error", err)
			}
		}
	}
}

func (m *Manager) claimAndLaunch(ctx context.Context, candidate Batch) {
	if err := m.ready(); err != nil {
		return
	}
	now := m.now()
	claimed, err := m.Store.ClaimReviewBatch(ctx, ClaimRequest{
		BatchID: candidate.ID, Owner: m.Owner, Now: path.NowString(now),
		LeaseUntil: path.NowString(now.Add(m.leaseTTL())),
	})
	if err != nil {
		if !errors.Is(err, ErrConflict) {
			m.Logger.Warn("review batch could not be claimed", "batch_id", candidate.ID, "error", err)
		}
		return
	}
	m.launch(*claimed)
}

func (m *Manager) launch(batch Batch) {
	if batch.State != StateRunning && batch.State != StateCancelling {
		return
	}
	if batch.ExecutionOwner != m.Owner || batch.LeaseEpoch <= 0 {
		return
	}
	m.mu.Lock()
	if current := m.active[batch.ID]; current >= batch.LeaseEpoch {
		m.mu.Unlock()
		return
	}
	m.active[batch.ID] = batch.LeaseEpoch
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		defer func() {
			m.mu.Lock()
			if m.active[batch.ID] == batch.LeaseEpoch {
				delete(m.active, batch.ID)
			}
			m.mu.Unlock()
		}()
		m.runBatch(m.ctx, batch.ID, batch.ExecutionOwner, batch.LeaseEpoch)
	}()
}

func (m *Manager) runBatch(parent context.Context, id, owner string, epoch int64) {
	workCtx, cancelWork := context.WithCancel(parent)
	defer cancelWork()
	leaseCtx, stopHeartbeat := context.WithCancel(parent)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		if err := m.heartbeat(leaseCtx, id, owner, epoch); err != nil && leaseCtx.Err() == nil {
			m.Logger.Warn("review batch lease lost", "batch_id", id, "owner", owner, "epoch", epoch, "error", err)
			cancelWork()
		}
	}()
	defer func() {
		stopHeartbeat()
		<-heartbeatDone
	}()

	for {
		if workCtx.Err() != nil {
			return
		}
		batch, err := m.Store.GetReviewBatch(workCtx, id)
		if err != nil {
			m.Logger.Warn("review batch could not be read", "batch_id", id, "error", err)
			return
		}
		if batch.ExecutionOwner != owner || batch.LeaseEpoch != epoch {
			return
		}
		switch batch.State {
		case StatePaused, StateCancelled, StateCompleted, StateFailed:
			return
		case StateCancelling:
			m.cancelQueued(batch)
			m.cancelLocalActive(*batch)
			view, viewErr := m.view(workCtx, *batch)
			if viewErr != nil {
				m.fail(workCtx, *batch, owner, epoch, viewErr)
				return
			}
			if view.Progress.Active == 0 {
				if err := m.finish(workCtx, *batch, owner, epoch, StateCancelled, ""); err != nil {
					m.Logger.Warn("review batch cancellation could not be finalized", "batch_id", id, "error", err)
				}
				return
			}
			if !m.sleep(workCtx) {
				return
			}
			continue
		case StateRunning:
		default:
			m.fail(workCtx, *batch, owner, epoch, fmt.Errorf("unknown batch state %q", batch.State))
			return
		}

		view, err := m.view(workCtx, *batch)
		if err != nil {
			m.fail(workCtx, *batch, owner, epoch, err)
			return
		}
		if view.Progress.Queued == 0 && view.Progress.Active == 0 {
			if err := m.finish(workCtx, *batch, owner, epoch, StateCompleted, ""); err != nil {
				m.Logger.Warn("review batch completion could not be stored", "batch_id", id, "error", err)
			}
			return
		}
		slots := batch.MaxConcurrent - view.Progress.Active
		if slots <= 0 {
			if !m.sleep(workCtx) {
				return
			}
			continue
		}
		queued := make([]string, 0, slots)
		for _, item := range view.Paths {
			if item.Status == string(path.StatusQueued) {
				queued = append(queued, item.PathID)
				if len(queued) == slots {
					break
				}
			}
		}
		if len(queued) == 0 {
			if !m.sleep(workCtx) {
				return
			}
			continue
		}
		m.runWave(workCtx, *batch, owner, epoch, queued)
	}
}

func (m *Manager) heartbeat(ctx context.Context, id, owner string, epoch int64) error {
	ttl := m.leaseTTL()
	interval := ttl / 3
	if interval < 50*time.Millisecond {
		interval = 50 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			now := m.now()
			if _, err := m.Store.RenewReviewBatch(ctx, RenewRequest{
				BatchID: id, Owner: owner, Epoch: epoch,
				HeartbeatAt: path.NowString(now), LeaseUntil: path.NowString(now.Add(ttl)),
			}); err != nil {
				return err
			}
		}
	}
}

func (m *Manager) runWave(ctx context.Context, batch Batch, owner string, epoch int64, pathIDs []string) {
	var wg sync.WaitGroup
	for _, pathID := range pathIDs {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, err := m.Agent.RunPath(ctx, id, m.batchOwner(batch.ID, epoch), 0, m.Agent.Policy)
			if err != nil && ctx.Err() == nil {
				m.Logger.Warn("review path could not run", "batch_id", batch.ID, "path_id", id, "owner", owner, "error", err)
			}
		}(pathID)
	}
	wg.Wait()
}

func (m *Manager) cancelLocalActive(batch Batch) {
	for _, pathID := range batch.PathIDs {
		if current, _, err := m.Paths.Path(pathID); err == nil && current.Status.Active() {
			m.Agent.CancelPath(pathID)
		}
	}
}

func (m *Manager) cancelQueued(batch *Batch) {
	for _, pathID := range batch.PathIDs {
		current, _, err := m.Paths.Path(pathID)
		if err != nil || current.Status != path.StatusQueued && current.Status != path.StatusPaused {
			continue
		}
		if _, err := m.Paths.Cancel(pathID, m.batchOwner(batch.ID, batch.LeaseEpoch), "review batch cancelled"); err != nil && !errors.Is(err, path.ErrInvalidTransition) {
			m.Logger.Warn("review path could not be cancelled", "batch_id", batch.ID, "path_id", pathID, "error", err)
		}
	}
}

func (m *Manager) finish(ctx context.Context, batch Batch, owner string, epoch int64, state State, lastError string) error {
	latest, err := m.Store.GetReviewBatch(ctx, batch.ID)
	if err != nil {
		return err
	}
	finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err = m.Store.FinalizeReviewBatch(finalizeCtx, FinalizeRequest{
		BatchID: batch.ID, ExpectedVersion: latest.Version, Owner: owner, Epoch: epoch,
		State: state, LastError: strings.TrimSpace(lastError), Now: path.NowString(m.now()),
	})
	return err
}

func (m *Manager) fail(ctx context.Context, batch Batch, owner string, epoch int64, err error) {
	if finishErr := m.finish(ctx, batch, owner, epoch, StateFailed, err.Error()); finishErr != nil {
		m.Logger.Warn("review batch failure could not be stored", "batch_id", batch.ID, "error", finishErr)
	}
}

func (m *Manager) sleep(ctx context.Context) bool {
	interval := m.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (m *Manager) ready() error {
	if err := m.available(); err != nil {
		return err
	}
	if err := m.Agent.Ready(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func (m *Manager) available() error {
	if m == nil || m.Store == nil || m.Paths == nil || m.Agent == nil {
		return ErrUnavailable
	}
	return nil
}

func (m *Manager) batchOwner(id string, epoch int64) string {
	base := strings.TrimSpace(m.Owner)
	if base == "" {
		base = "review-batch"
	}
	return fmt.Sprintf("%s-%s-%d", base, id, epoch)
}

func (m *Manager) now() time.Time {
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	return now
}

func (m *Manager) leaseTTL() time.Duration {
	m.configMu.Lock()
	defer m.configMu.Unlock()
	if m.LeaseTTL <= 0 {
		return defaultLeaseTTL
	}
	return m.LeaseTTL
}

func (m *Manager) reclaimInterval() time.Duration {
	m.configMu.Lock()
	defer m.configMu.Unlock()
	if m.ReclaimInterval <= 0 {
		return defaultReclaimInterval
	}
	return m.ReclaimInterval
}

// SetLeasePolicy adjusts takeover timing for a deployment or deterministic
// integration test. It is safe to call while the reclaim monitor is running.
func (m *Manager) SetLeasePolicy(ttl, reclaim time.Duration) {
	m.configMu.Lock()
	defer m.configMu.Unlock()
	if ttl > 0 {
		m.LeaseTTL = ttl
	}
	if reclaim > 0 {
		m.ReclaimInterval = reclaim
	}
}
