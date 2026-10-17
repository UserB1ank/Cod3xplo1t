package path

// Store is the persistence contract of the path engine.
//
// It is declared here, next to the model, and implemented by the storage layer:
// the engine depends on the semantics of an audit, not on which database holds
// it. Every method that changes a path is required to be atomic with the event it
// appends (implementation guide §11) — a state that disagrees with its log is
// worse than a missing log.
type Store interface {
	// CreateAudit stores a new audit document.
	CreateAudit(audit Audit) error
	GetAudit(auditID string) (*Audit, error)
	ListAudits(q AuditQuery) ([]Audit, int, error)
	// UpdateAudit writes an audit with optimistic concurrency; expectedVersion 0
	// skips the check and preserves the current pin, archive, and category fields.
	UpdateAudit(audit Audit, expectedVersion int64) error

	// ReplacePaths replaces every path of an audit in one transaction. Generation
	// is a whole-document operation: a half-generated audit must never be visible.
	ReplacePaths(auditID string, paths []Path) error
	GetPath(pathID string) (*Path, error)
	ListPaths(q PathQuery) ([]Path, int, error)
	// ListDuePaths returns queued paths whose backoff has elapsed, oldest due time
	// first, so a scheduler cannot starve a path that keeps losing the race.
	ListDuePaths(auditID, now string, limit int) ([]Path, error)
	// UpdatePath writes one path with optimistic concurrency; expectedVersion 0
	// skips the check.
	UpdatePath(p Path, expectedVersion int64) error

	// AppendFeatures adds score snapshots. Features are append-only so a ranking
	// can be replayed and compared (design §6.3).
	AppendFeatures(records []FeatureRecord) error
	ListFeatures(pathID string, limit int) ([]FeatureRecord, error)

	// AppendEvents adds events to the audit log. Generation appends one event per
	// path, so the batch form is the one that matters.
	AppendEvents(events []Event) error
	ListEvents(q EventQuery) ([]Event, error)
	// NextEventSeq returns the next audit-scoped event sequence number. Events are
	// numbered per audit, not per path: a rerun appends, and appending must never
	// collide with what is already stored.
	NextEventSeq(auditID string) (int64, error)

	// Transition moves a path to a new status and appends the event in one
	// transaction. It validates the transition, the expected version and the lease
	// ownership, so no caller can write an illegal state directly.
	Transition(req TransitionRequest) (*Path, error)

	// ClaimPath leases a claimable path to an owner until the given time and moves
	// it to ANALYZING. It must be atomic: two workers may never win the same path,
	// and a lease may never be taken on a path whose status is not in `from`.
	// The audit's active-lease ceiling is checked in the same atomic operation.
	ClaimPath(pathID, owner, until string, from []Status, actor string) (*Path, error)
	// RenewLease extends a lease the owner still holds. It fails with
	// ErrLeaseExpired when the lease is gone and ErrLeaseHeld when someone else
	// holds it.
	RenewLease(pathID, owner, until, actor string) (*Path, error)
	// ReleaseLease returns a path to QUEUED and clears the lease, but only for the
	// owner that holds it.
	ReleaseLease(pathID, owner, actor, reason string) (*Path, error)
	// ReclaimExpired returns paths whose lease has expired, with no owner, to
	// QUEUED, appending the recovery event. It returns the recovered paths.
	ReclaimExpired(now string, limit int, actor string) ([]Path, error)

	// DeleteAuditsForSnapshot removes an audit and everything derived from it,
	// returning the number of audits removed.
	DeleteAuditsForSnapshot(snapshotID string) (int, error)
}

// TransitionRequest is one atomic state change plus its event.
type TransitionRequest struct {
	PathID string
	To     Status
	// ExpectedVersion of 0 skips the optimistic-concurrency check.
	ExpectedVersion int64
	// Owner is the lease owner making the change; it must match the stored lease
	// when the path is leased.
	Owner string
	// ClearLease releases the path; SetLeaseOwner and SetLeaseUntil acquire one.
	ClearLease    bool
	SetLeaseOwner string
	SetLeaseUntil string
	Actor         string
	Reason        string
	Detail        map[string]string
	EventType     string
	// Score and Features replace the stored score in the same transaction, which is
	// how a rescored path keeps its event and its score consistent.
	Score    *Score
	Features *Features
	// IncrementAttempts and LastError record a failed attempt.
	IncrementAttempts bool
	LastError         string
	// NextAttemptAt is when a failed path may run again. Empty clears it, which is
	// what a successful settlement and an operator resume do.
	NextAttemptAt string
}

// AuditQuery filters audit listings.
type AuditQuery struct {
	Search      string
	TaskState   string
	Category    string
	CategorySet bool
	Archived    *bool
	Organized   bool
	ProjectID   string
	SnapshotID  string
	Status      string
	Limit       int
	Offset      int
}

// PathQuery filters path listings.
type PathQuery struct {
	AuditID    string
	SnapshotID string
	Status     []Status
	PathStatus []PathStatus
	// EntryNodeID and TargetNodeID pin a path to one attack-surface element.
	EntryNodeID  string
	TargetNodeID string
	// MinPriority filters out paths the caller considers uninteresting.
	MinPriority float64
	// DueBefore restricts the answer to paths whose retry time has elapsed (empty
	// NextAttemptAt counts as due). It is how the scheduler asks "what may run now".
	DueBefore string
	// Sort is "priority" (default), "created" or "path_id".
	Sort   string
	Limit  int
	Offset int
}

// EventQuery filters the event log.
type EventQuery struct {
	AuditID string
	PathID  string
	// AfterSeq returns events strictly after a sequence number (audit-scoped),
	// which is how a client resumes a stream without replaying it.
	AfterSeq int64
	Limit    int
}

// FeatureRecord is one immutable score snapshot of a path.
type FeatureRecord struct {
	PathID       string             `json:"path_id"`
	AuditID      string             `json:"audit_id"`
	Seq          int64              `json:"seq"`
	ScoreVersion int                `json:"score_version"`
	Risk         float64            `json:"risk"`
	Support      float64            `json:"support"`
	Utility      float64            `json:"utility"`
	Priority     float64            `json:"priority"`
	Features     Features           `json:"features"`
	Weights      map[string]float64 `json:"weights"`
	Reasons      map[string]string  `json:"reasons,omitempty"`
	ComputedAt   string             `json:"computed_at"`
}
