package verify

import "time"

// Store is the persistence contract of the verification layer.
//
// The names are verification-scoped for the same reason the agent log's are
// run-scoped: Go has no overloading, and `agent.Store` already owns plain
// CreateRun/GetRun/ListRuns/UpdateRun. Distinct names also mean a reader never has
// to guess which kind of run they hold.
//
// Evidence is append-only: the store refuses to replace an object, and a correction
// arrives as a new object that supersedes the old one.
type Store interface {
	CreateVerificationRun(run Run) error
	GetVerificationRun(runID string) (*Run, error)
	ListVerificationRuns(q RunQuery) ([]Run, int, error)
	// UpdateVerificationRun writes a run with optimistic concurrency;
	// expectedVersion 0 skips the check.
	UpdateVerificationRun(run Run, expectedVersion int64) error

	// AppendEvidence stores new evidence objects. Re-appending the same id with the
	// same content is a no-op; the same id with different content is a conflict,
	// because evidence that can be rewritten is not evidence.
	AppendEvidence(evidence []Evidence) error
	GetEvidence(evidenceID string) (*Evidence, error)
	ListEvidence(q EvidenceQuery) ([]Evidence, int, error)

	// UpsertFinding stores the verdict about a hypothesis, keyed by hypothesis id.
	UpsertFinding(finding Finding) error
	GetFinding(findingID string) (*Finding, error)
	ListFindings(q FindingQuery) ([]Finding, int, error)

	// DeleteVerificationForSnapshot removes a snapshot's runs, evidence and findings,
	// returning the number of runs removed.
	DeleteVerificationForSnapshot(snapshotID string) (int, error)
}

// RunQuery filters verification runs.
type RunQuery struct {
	HypothesisID string
	FindingID    string
	PathID       string
	AuditID      string
	SnapshotID   string
	Status       []VerificationStatus
	Outcome      []Outcome
	PlanHash     string
	Limit        int
	Offset       int
}

// EvidenceQuery filters evidence objects.
type EvidenceQuery struct {
	SnapshotID        string
	HypothesisID      string
	FindingID         string
	PathID            string
	VerificationRunID string
	Kinds             []EvidenceKind
	Limit             int
	Offset            int
}

// FindingQuery filters findings.
type FindingQuery struct {
	AuditID    string
	SnapshotID string
	PathID     string
	Status     []FindingStatus
	// ConclusiveOnly restricts the answer to findings verification has settled.
	ConclusiveOnly bool
	// CandidatesOnly restricts the answer to findings waiting for verification.
	CandidatesOnly bool
	Limit          int
	Offset         int
}

// nowUTC exists so the package's default clock is in one place for tests to inject
// around.
func nowUTC() time.Time { return time.Now().UTC() }
