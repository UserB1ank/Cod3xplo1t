package path

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Service is the orchestrator-facing API of the path engine: it creates audits,
// serves the queue, and owns the state changes a scheduler or an operator makes.
//
// It is deliberately the only writer. Everything that changes a path goes through
// a transition that the state machine accepts and that the store applies together
// with its event.
type Service struct {
	Store  Store
	Engine *Engine
	Now    func() time.Time
}

// NewService builds the audit service.
func NewService(store Store, engine *Engine) *Service {
	return &Service{
		Store:  store,
		Engine: engine,
		Now:    func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now()
}

// CreateAuditRequest is one audit request.
type CreateAuditRequest struct {
	SnapshotID  string
	Budget      Budget
	Limits      Limits
	Sensitivity map[string]float64
	// Force regenerates and rescores even when the audit already exists. The path
	// ids stay the same because they are derived from the attack surface, so a
	// forced run is comparable with the previous one.
	Force bool
}

// AuditResult is the outcome of an audit request.
type AuditResult struct {
	Audit Audit  `json:"audit"`
	Paths []Path `json:"paths"`
	// Replayed is true when an existing audit was returned instead of generating a
	// new one: the same request must not silently produce a second ranking.
	Replayed bool `json:"replayed"`
}

// ConfigHash covers everything that changes the produced path set.
func ConfigHash(snapshotID string, budget Budget, limits Limits, sensitivity map[string]float64) string {
	h := sha256.New()
	keys := make([]string, 0, len(sensitivity))
	for key := range sensitivity {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fields := []string{
		"codexploit/audit-config/v1", snapshotID,
		fmt.Sprint(budget.Normalize()), fmt.Sprint(limits.Normalize()), fmt.Sprint(ScoreVersion),
	}
	for _, key := range keys {
		fields = append(fields, key+"="+fmt.Sprintf("%.4f", sensitivity[key]))
	}
	for _, field := range fields {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// CreateAudit generates the candidate paths of a snapshot, ranks them, and stores
// the audit. Generation is all-or-nothing: the audit becomes READY only after its
// paths, features and events are written, so a crash leaves a GENERATING audit
// that a repeated request replaces.
func (s *Service) CreateAudit(ctx context.Context, req CreateAuditRequest) (*AuditResult, error) {
	if strings.TrimSpace(req.SnapshotID) == "" {
		return nil, fmt.Errorf("%w: snapshot id is required", ErrInvalidArgument)
	}
	budget := req.Budget.Normalize()
	limits := req.Limits.Normalize()
	configHash := ConfigHash(req.SnapshotID, budget, limits, req.Sensitivity)
	auditID := AuditID(req.SnapshotID, configHash)

	if existing, err := s.Store.GetAudit(auditID); err == nil && !req.Force {
		// Only a finished audit is replayed. A GENERATING or FAILED one is the trace
		// of an interrupted run, and answering it as a replay would hand back an
		// incomplete path set as if it were the result.
		if existing.Status == AuditReady {
			paths, _, err := s.Store.ListPaths(PathQuery{AuditID: auditID, Limit: limits.MaxPaths})
			if err != nil {
				return nil, err
			}
			SortByPriority(paths)
			return &AuditResult{Audit: *existing, Paths: paths, Replayed: true}, nil
		}
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	// Novelty is measured against work already scheduled for this snapshot, in
	// every audit: that is what keeps parallel audits from re-auditing one subgraph.
	covered, err := s.coverageOfSnapshot(req.SnapshotID, auditID)
	if err != nil {
		return nil, err
	}
	alreadyCovered := covered.Nodes()

	now := NowString(s.now())
	audit := Audit{
		ID: auditID, SnapshotID: req.SnapshotID, Status: AuditGenerating,
		Budget: budget, Limits: limits, ScoreVersion: ScoreVersion, ConfigHash: configHash,
		CountsByStatus: map[string]int{}, CountsByPathStatus: map[string]int{},
		Limitations: []string{},
		CreatedAt:   now, UpdatedAt: now, Version: 1,
	}
	if existing, err := s.Store.GetAudit(auditID); err == nil {
		audit.CreatedAt = existing.CreatedAt
		audit.Version = existing.Version + 1
	}
	if err := s.auditUpsert(audit, audit.Version-1); err != nil {
		return nil, err
	}

	result, err := s.Engine.Generate(ctx, req.SnapshotID, GenerateOptions{
		AuditID: auditID, Budget: budget, Limits: limits, Sensitivity: req.Sensitivity, AlreadyCovered: alreadyCovered,
	})
	if err != nil {
		audit.Status = AuditFailed
		audit.Limitations = append(audit.Limitations, "generation failed: "+err.Error())
		audit.UpdatedAt = NowString(s.now())
		_ = s.auditUpsert(audit, 0)
		return nil, err
	}
	audit.SCGVersion = result.SCGVersion
	audit.ASGVersion = result.ASGVersion
	audit.Coverage = result.Coverage
	audit.Limitations = append(audit.Limitations, result.Limitations...)

	// Score with the coverage snapshot taken before this audit, then cluster. The
	// score stays a pure function of the path and the prior coverage, so it can be
	// recomputed identically later (design §6.3: replayable ranking).
	// Scoring runs twice on purpose. The duplicate discount depends on cluster
	// membership, and membership is chosen by priority, so the first pass ranks
	// paths, clustering groups them, and the second pass applies the discount. That
	// keeps the stored score a pure function of the path, its cluster and the prior
	// coverage — which is what makes a later replay reproducible.
	scored := make([]Path, 0, len(result.Paths))
	for _, candidate := range result.Paths {
		candidate.AuditID = auditID
		candidate.Status = StatusQueued
		scored = append(scored, ScorePath(candidate, ScoreInput{
			Covered: covered, Sensitivity: req.Sensitivity, Now: now,
		}))
	}
	SortByPriority(scored)
	scored = ClusterPaths(scored)
	for i := range scored {
		scored[i] = ScorePath(scored[i], ScoreInput{
			Covered: covered, Sensitivity: req.Sensitivity, Now: now, ClusterSize: scored[i].Cluster.Size,
		})
	}
	SortByPriority(scored)

	// Feature snapshots are append-only: a forced rerun adds a version instead of
	// destroying the ranking it replaces.
	priorSeq, err := s.priorScoreSeqs(auditID)
	if err != nil {
		return nil, err
	}
	records := make([]FeatureRecord, 0, len(scored))
	for i := range scored {
		scored[i].ScoreSeq = priorSeq[scored[i].ID] + 1
		records = append(records, FeatureRecordOf(scored[i], scored[i].ScoreSeq))
	}

	seq, err := s.Store.NextEventSeq(auditID)
	if err != nil {
		return nil, err
	}
	nextSeq := func() int64 { value := seq; seq++; return value }
	events := make([]Event, 0, len(scored)+2)
	events = append(events, Event{
		AuditID: auditID, Seq: nextSeq(), Type: EventAuditCreated, Actor: "system",
		Reason:    "audit requested for snapshot " + req.SnapshotID,
		Detail:    map[string]string{"config_hash": configHash, "score_version": fmt.Sprint(ScoreVersion)},
		CreatedAt: now,
	})
	for _, p := range scored {
		events = append(events, Event{
			AuditID: auditID, PathID: p.ID, Seq: nextSeq(), Type: EventPathQueued,
			From: StatusDiscovered, To: StatusQueued, Actor: "system",
			Reason: "discovered and queued at generation",
			Detail: map[string]string{
				"path_status": string(p.PathStatus), "priority": fmt.Sprintf("%.4f", p.Score.Priority),
				"cluster": p.Cluster.ID,
			},
			CreatedAt: now,
		})
	}
	for i := range events {
		events[i].ID = EventID(events[i].AuditID, events[i].PathID, events[i].Seq)
	}

	if err := s.Store.ReplacePaths(auditID, scored); err != nil {
		return nil, err
	}
	if err := s.Store.AppendFeatures(records); err != nil {
		return nil, err
	}
	if err := s.Store.AppendEvents(events); err != nil {
		return nil, err
	}

	audit.PathCount = len(scored)
	audit.CountsByStatus = StatusCounts(scored)
	audit.CountsByPathStatus = PathStatusCounts(scored)
	clusters, largest, _ := ClusterSummary(scored)
	audit.Coverage.Clusters = clusters
	if largest > 1 {
		audit.Limitations = append(audit.Limitations,
			fmt.Sprintf("%d path cluster(s) were found; the largest holds %d similar paths, which stay separate because their branches differ", clusters, largest))
	}
	audit.Status = AuditReady
	audit.UpdatedAt = NowString(s.now())
	if err := s.auditUpsert(audit, 0); err != nil {
		return nil, err
	}
	readySeq := nextSeq()
	if err := s.Store.AppendEvents([]Event{{
		ID: EventID(auditID, "", readySeq), AuditID: auditID, Seq: readySeq, Type: EventAuditReady, Actor: "system",
		Reason: fmt.Sprintf("%d path(s) queued", len(scored)),
		Detail: map[string]string{
			"paths": fmt.Sprint(len(scored)), "clusters": fmt.Sprint(clusters),
			"truncated": fmt.Sprint(result.Coverage.Truncated),
		},
		CreatedAt: audit.UpdatedAt,
	}}); err != nil {
		return nil, err
	}
	return &AuditResult{Audit: audit, Paths: scored}, nil
}

// coverageOfSnapshot collects the attack-surface nodes already taken by scheduled
// paths of a snapshot. The audit being regenerated is excluded, because its own
// paths are about to be replaced.
func (s *Service) coverageOfSnapshot(snapshotID, excludeAuditID string) (*CoverageSet, error) {
	covered := NewCoverageSet()
	offset := 0
	for {
		paths, total, err := s.Store.ListPaths(PathQuery{SnapshotID: snapshotID, Limit: 1000, Offset: offset})
		if err != nil {
			return nil, err
		}
		for _, p := range paths {
			if p.AuditID == excludeAuditID {
				continue
			}
			if p.Status == StatusCancelled {
				continue
			}
			covered.Observe(p)
		}
		offset += len(paths)
		if len(paths) == 0 || offset >= total {
			break
		}
	}
	return covered, nil
}

// priorScoreSeqs returns the highest stored score sequence per path.
func (s *Service) priorScoreSeqs(auditID string) (map[string]int64, error) {
	out := map[string]int64{}
	paths, _, err := s.Store.ListPaths(PathQuery{AuditID: auditID, Limit: 10000})
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		out[p.ID] = p.ScoreSeq
	}
	return out, nil
}

// auditUpsert writes the audit row, creating it when needed.
func (s *Service) auditUpsert(audit Audit, expectedVersion int64) error {
	err := s.Store.UpdateAudit(audit, expectedVersion)
	if errors.Is(err, ErrNotFound) {
		return s.Store.CreateAudit(audit)
	}
	return err
}

// Audit returns one audit.
func (s *Service) Audit(auditID string) (*Audit, error) { return s.Store.GetAudit(auditID) }

// Audits lists audits.
func (s *Service) Audits(q AuditQuery) ([]Audit, int, error) { return s.Store.ListAudits(q) }

// Path returns one path with its score history.
func (s *Service) Path(pathID string) (*Path, []FeatureRecord, error) {
	p, err := s.Store.GetPath(pathID)
	if err != nil {
		return nil, nil, err
	}
	records, err := s.Store.ListFeatures(pathID, 50)
	if err != nil {
		return nil, nil, err
	}
	return p, records, nil
}

// Paths lists paths of an audit. When q.Sort is empty the queue order (priority)
// is used.
func (s *Service) Paths(q PathQuery) ([]Path, int, error) {
	if q.Sort == "" {
		q.Sort = "priority"
	}
	return s.Store.ListPaths(q)
}

// Events lists the audit event log.
func (s *Service) Events(q EventQuery) ([]Event, error) { return s.Store.ListEvents(q) }

// Order returns the scheduling order of the queue without claiming anything.
func (s *Service) Order(auditID string, limit int) (SchedulePlan, error) {
	audit, err := s.Store.GetAudit(auditID)
	if err != nil {
		return SchedulePlan{}, err
	}
	if limit <= 0 {
		limit = 200
	}
	queued, _, err := s.Store.ListPaths(PathQuery{AuditID: auditID, Status: []Status{StatusQueued}, Sort: "priority", Limit: limit})
	if err != nil {
		return SchedulePlan{}, err
	}
	coverage, err := s.auditCoverage(auditID)
	if err != nil {
		return SchedulePlan{}, err
	}
	return Plan(audit.Limits, coverage, queued), nil
}

// auditCoverage is the coverage of the work already dispatched in one audit.
func (s *Service) auditCoverage(auditID string) (*CoverageSet, error) {
	covered := NewCoverageSet()
	offset := 0
	for {
		paths, total, err := s.Store.ListPaths(PathQuery{AuditID: auditID, Limit: 1000, Offset: offset})
		if err != nil {
			return nil, err
		}
		for _, p := range paths {
			// Only dispatched work counts: a queued path has covered nothing yet.
			if p.Status == StatusQueued || p.Status == StatusDiscovered || p.Status == StatusCancelled {
				continue
			}
			covered.Observe(p)
		}
		offset += len(paths)
		if len(paths) == 0 || offset >= total {
			break
		}
	}
	return covered, nil
}

// Next returns the path a worker should take, without leasing it.
func (s *Service) Next(auditID string) (*Path, error) {
	audit, err := s.Store.GetAudit(auditID)
	if err != nil {
		return nil, err
	}
	// The picker works on a bounded window of the highest-priority queued paths. The
	// window is large enough that the exploration reserve still reaches low-priority
	// work, and bounded so a huge audit cannot make one scheduling decision cost a
	// full table scan.
	queued, _, err := s.Store.ListPaths(PathQuery{AuditID: auditID, Status: []Status{StatusQueued}, Sort: "priority", Limit: 2000})
	if err != nil {
		return nil, err
	}
	coverage, err := s.auditCoverage(auditID)
	if err != nil {
		return nil, err
	}
	picker := NewPicker(audit.Limits, coverage)
	pick, ok := picker.Next(Claimable(queued))
	if !ok {
		return nil, ErrNotFound
	}
	return &pick, nil
}

// Claim leases the next path to an owner until the lease expires. The active-lease
// ceiling is enforced here, because that is a property of the audit, not of one
// row: it is the design's "at most 4 active branches".
func (s *Service) Claim(ctx context.Context, auditID, owner string, ttl time.Duration) (*Path, error) {
	if strings.TrimSpace(owner) == "" {
		return nil, fmt.Errorf("%w: a lease needs an owner", ErrInvalidArgument)
	}
	audit, err := s.Store.GetAudit(auditID)
	if err != nil {
		return nil, err
	}
	active, err := s.activeLeases(auditID)
	if err != nil {
		return nil, err
	}
	if audit.Limits.MaxActiveLeases > 0 && active >= audit.Limits.MaxActiveLeases {
		return nil, fmt.Errorf("%w: %d active lease(s) of a maximum of %d in audit %s",
			ErrBudgetExceeded, active, audit.Limits.MaxActiveLeases, auditID)
	}
	if ttl <= 0 {
		ttl = time.Duration(audit.Limits.LeaseTTLSeconds) * time.Second
	}
	until := NowString(s.now().Add(ttl))
	// Bounded retries: a conflicting claim means another worker moved the same
	// path, which is normal, not exceptional.
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		next, err := s.Next(auditID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, ErrNotFound
			}
			return nil, err
		}
		claimed, err := s.Store.ClaimPath(next.ID, owner, until, []Status{StatusQueued}, owner)
		if err == nil {
			return claimed, nil
		}
		lastErr = err
		if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrLeaseHeld) && !errors.Is(err, ErrNotClaimable) {
			return nil, err
		}
	}
	return nil, lastErr
}

// activeLeases counts the paths of an audit currently held by a worker.
func (s *Service) activeLeases(auditID string) (int, error) {
	active := 0
	offset := 0
	for {
		paths, total, err := s.Store.ListPaths(PathQuery{AuditID: auditID, Limit: 1000, Offset: offset})
		if err != nil {
			return 0, err
		}
		for _, p := range paths {
			if p.Status.Active() {
				active++
			}
		}
		offset += len(paths)
		if len(paths) == 0 || offset >= total {
			break
		}
	}
	return active, nil
}

// Heartbeat extends a lease.
func (s *Service) Heartbeat(pathID, owner string, ttl time.Duration) (*Path, error) {
	p, err := s.Store.GetPath(pathID)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		audit, err := s.Store.GetAudit(p.AuditID)
		if err != nil {
			return nil, err
		}
		ttl = time.Duration(audit.Limits.LeaseTTLSeconds) * time.Second
	}
	return s.Store.RenewLease(pathID, owner, NowString(s.now().Add(ttl)), owner)
}

// Release returns a path to the queue without a verdict.
func (s *Service) Release(pathID, owner, reason string) (*Path, error) {
	return s.Store.ReleaseLease(pathID, owner, owner, reason)
}

// ReclaimExpired recovers paths whose lease expired, which is how a crashed
// worker's work returns to the queue.
func (s *Service) ReclaimExpired(limit int) ([]Path, error) {
	return s.Store.ReclaimExpired(NowString(s.now()), limit, "scheduler")
}

// Transition applies an operator or agent state change. The allowed sources are
// policy, not convenience: a paused path cannot be completed, and a concluded path
// cannot be re-analysed without a new audit.
func (s *Service) Transition(pathID string, to Status, actor, reason string) (*Path, error) {
	// The operator form: no owner, so the store performs no lease-ownership check.
	// Pausing, resuming or cancelling work someone else started is an operator
	// action, and refusing it because a worker holds the lease would make a stuck
	// path unrecoverable.
	return s.transition(pathID, "", to, actor, reason)
}

// TransitionOwned is the worker form: the caller must be the path's lease owner,
// and a foreign owner is refused with ErrLeaseHeld. A worker that advances or
// completes a path it does not hold is a scheduler bug, and the store is the only
// place that can refuse it atomically.
func (s *Service) TransitionOwned(pathID, owner string, to Status, actor, reason string) (*Path, error) {
	return s.transition(pathID, owner, to, actor, reason)
}

func (s *Service) transition(pathID, owner string, to Status, actor, reason string) (*Path, error) {
	current, err := s.Store.GetPath(pathID)
	if err != nil {
		return nil, err
	}
	if err := ValidateTransition(current.Status, to); err != nil {
		return nil, err
	}
	// Leaving the active states clears the lease, whichever state it is: the worker
	// must find out at its next heartbeat instead of continuing to spend budget on
	// a path that is no longer its own.
	return s.Store.Transition(TransitionRequest{
		PathID: pathID, To: to, Owner: owner, Actor: actor, Reason: reason,
		ClearLease: !to.Active(), EventType: EventPathStatusChange,
		ExpectedVersion: current.Version,
	})
}

// Pause stops work on a path.
func (s *Service) Pause(pathID, actor, reason string) (*Path, error) {
	return s.Transition(pathID, StatusPaused, actor, reason)
}

// Resume queues a paused path again.
func (s *Service) Resume(pathID, actor, reason string) (*Path, error) {
	return s.Transition(pathID, StatusQueued, actor, reason)
}

// Cancel removes a path from the queue for good.
func (s *Service) Cancel(pathID, actor, reason string) (*Path, error) {
	return s.Transition(pathID, StatusCancelled, actor, reason)
}

// Rescore recomputes the ranking of an audit from its stored paths and rewrites
// the scores. Recomputing must reproduce the stored numbers: the check is part of
// the method's contract, and a mismatch is reported instead of silently accepted
// (design §6.3, implementation guide §8.3 "可重放评分").
func (s *Service) Rescore(auditID string) (*Audit, error) {
	audit, err := s.Store.GetAudit(auditID)
	if err != nil {
		return nil, err
	}
	paths, _, err := s.Store.ListPaths(PathQuery{AuditID: auditID, Limit: 100000})
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return audit, nil
	}
	covered, err := s.coverageOfSnapshot(audit.SnapshotID, auditID)
	if err != nil {
		return nil, err
	}
	now := NowString(s.now())
	records := make([]FeatureRecord, 0, len(paths))
	drift := 0
	for i := range paths {
		before := paths[i].Score.Priority
		rescored := ScorePath(paths[i], ScoreInput{
			Covered: covered, Now: now, ClusterSize: paths[i].Cluster.Size,
		})
		if rescored.Score.Priority != before {
			drift++
		}
		rescored.ID = paths[i].ID
		rescored.ScoreSeq = paths[i].ScoreSeq + 1
		if err := s.Store.UpdatePath(rescored, 0); err != nil {
			return nil, err
		}
		records = append(records, FeatureRecordOf(rescored, rescored.ScoreSeq))
		paths[i] = rescored
	}
	if err := s.Store.AppendFeatures(records); err != nil {
		return nil, err
	}
	SortByPriority(paths)
	audit.CountsByStatus = StatusCounts(paths)
	audit.CountsByPathStatus = PathStatusCounts(paths)
	audit.UpdatedAt = now
	audit.Version++
	if drift > 0 {
		audit.Limitations = append(audit.Limitations, fmt.Sprintf(
			"%d path(s) changed priority when the ranking was replayed; the feature mapping changed without a score version bump", drift))
	}
	if err := s.Store.UpdateAudit(*audit, 0); err != nil {
		return nil, err
	}
	rescoreSeq, err := s.Store.NextEventSeq(auditID)
	if err != nil {
		return nil, err
	}
	if err := s.Store.AppendEvents([]Event{{
		ID: EventID(auditID, "", rescoreSeq), AuditID: auditID, Seq: rescoreSeq,
		Type: EventScoreRecomputed, Actor: "scheduler",
		Reason:    "ranking recomputed from stored paths",
		Detail:    map[string]string{"paths": fmt.Sprint(len(paths)), "priority_drift": fmt.Sprint(drift)},
		CreatedAt: now,
	}}); err != nil {
		return nil, err
	}
	return audit, nil
}
