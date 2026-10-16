package agent

// Store is the persistence contract of the agent runtime.
//
// It is declared next to the model and implemented by the storage layer, so the
// orchestrator depends on the shape of a run rather than on a database. Every
// mutating method that also writes an event must do both in one transaction: a run
// whose state disagrees with its log cannot be resumed or audited.
type Store interface {
	CreateRun(run Run) error
	GetRun(runID string) (*Run, error)
	ListRuns(q RunQuery) ([]Run, int, error)
	// UpdateRun writes a run with optimistic concurrency; expectedVersion 0 skips
	// the check.
	UpdateRun(run Run, expectedVersion int64) error

	// AppendRunEvents adds run events. Sequences are per run and must increase.
	//
	// The names are run-scoped on purpose: the audit log (path.Store) has its own
	// AppendEvents/ListEvents/NextEventSeq with different types, and Go does not
	// overload. Keeping both vocabularies distinct is also what makes a reader
	// certain which log they are looking at.
	AppendRunEvents(events []Event) error
	ListRunEvents(q EventQuery) ([]Event, error)
	// NextRunEventSeq returns the next sequence number of a run's event log.
	NextRunEventSeq(runID string) (int64, error)

	// SaveHypotheses upserts hypotheses by (path_id, digest) and appends the
	// hypothesis events in the same transaction.
	SaveHypotheses(hypotheses []Hypothesis) error
	ListHypotheses(q HypothesisQuery) ([]Hypothesis, int, error)
	GetHypothesis(hypothesisID string) (*Hypothesis, error)

	// DeleteRunsForSnapshot removes a snapshot's runs, events and hypotheses,
	// returning the number of runs removed.
	DeleteRunsForSnapshot(snapshotID string) (int, error)
}

// RunQuery filters run listings.
type RunQuery struct {
	PathID     string
	AuditID    string
	SnapshotID string
	Status     []RunStatus
	Limit      int
	Offset     int
}

// EventQuery filters run event listings.
type EventQuery struct {
	RunID    string
	PathID   string
	Types    []string
	AfterSeq int64
	Limit    int
}

// HypothesisQuery filters hypothesis listings.
type HypothesisQuery struct {
	PathID     string
	AuditID    string
	SnapshotID string
	RunID      string
	Status     []string
	// FindingCandidatesOnly restricts the answer to claims a verification phase
	// should look at.
	FindingCandidatesOnly bool
	Limit                 int
	Offset                int
}
