package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

var (
	// ErrInvalid reports a malformed observation, audit or query.
	ErrInvalid = errors.New("findings: invalid observation, audit or query")
	// ErrConflict reports the same observation id or audit version with different
	// content, or a severity write that lost its CAS.
	ErrConflict = errors.New("findings: observation or severity version conflicts")
	// ErrNotFound reports a missing finding or observation.
	ErrNotFound = errors.New("findings: record not found")
)

// Observation is one producer's claim about one rule at one location. It is not
// a verdict: its status is candidate and it never changes a verification result.
type Observation struct {
	ID                 string               `json:"observation_id"`
	FindingID          string               `json:"finding_id"`
	Scope              artifact.Scope       `json:"scope"`
	TaskID             string               `json:"task_id,omitempty"`
	Producer           artifact.Producer    `json:"producer"`
	RuleID             string               `json:"rule_id"`
	RuleVersion        string               `json:"rule_version"`
	RuleFamily         string               `json:"rule_family"`
	Title              string               `json:"title"`
	SeverityHint       string               `json:"severity_hint,omitempty"`
	Status             verify.FindingStatus `json:"status"`
	File               string               `json:"file"`
	Line               int                  `json:"line"`
	EndLine            int                  `json:"end_line,omitempty"`
	EvidenceRefs       []string             `json:"evidence_refs"`
	Limitations        []string             `json:"limitations"`
	Fingerprint        string               `json:"fingerprint"`
	FingerprintVersion string               `json:"fingerprint_version"`
	CreatedAt          string               `json:"created_at"`
}

// Digest is the content identity used for idempotent replay. CreatedAt is part
// of the stored document but not of identity: a replay may arrive with a new
// clock and must still be a replay.
func (o Observation) Digest() string {
	copy := o
	copy.CreatedAt = ""
	raw, _ := json.Marshal(copy)
	sum := sha256.Sum256(append([]byte("codexploit/finding-observation\n"), raw...))
	return hex.EncodeToString(sum[:])
}

// SeverityAudit is one append-only assessment of a finding's severity.
type SeverityAudit struct {
	ID               string `json:"audit_id"`
	FindingID        string `json:"finding_id"`
	Version          int64  `json:"version"`
	PreviousSeverity string `json:"previous_severity,omitempty"`
	Severity         string `json:"severity"`
	Reason           string `json:"reason"`
	Actor            string `json:"actor"`
	CreatedAt        string `json:"created_at"`
}

// Group is one fingerprint group: the canonical finding plus every source that
// supports it and the severity assessment history.
type Group struct {
	Finding verify.Finding
	// Members are every finding that folded into this fallback fingerprint. A
	// plugin group has exactly one; verification findings may share a path/status.
	Members            []verify.Finding
	Fingerprint        string
	FingerprintVersion string
	Observations       []Observation
	SeverityAudit      []SeverityAudit
}

// ListQuery filters grouped findings. TaskID matches any source observation, not
// only the group's first task.
type ListQuery struct {
	ProjectID string
	TaskID    string
	Severity  string
	Status    verify.FindingStatus
	Limit     int
	Offset    int
}

// Counts separates candidate observations from confirmed verification results;
// summing them together would make a candidate look like a confirmed finding.
type Counts struct {
	Confirmed map[string]int `json:"confirmed"`
	Candidate map[string]int `json:"candidate"`
}

func NewCounts() Counts {
	return Counts{
		Confirmed: map[string]int{"high": 0, "medium": 0, "low": 0, "ungraded": 0},
		Candidate: map[string]int{"high": 0, "medium": 0, "low": 0, "ungraded": 0},
	}
}

func (c Counts) add(status verify.FindingStatus, severity string) {
	grade := severity
	if grade != "high" && grade != "medium" && grade != "low" {
		grade = "ungraded"
	}
	switch status {
	case verify.FindingConfirmed:
		c.Confirmed[grade]++
	case verify.FindingCandidate:
		c.Candidate[grade]++
	}
}

// ListResult is the bounded grouped listing.
type ListResult struct {
	Groups    []Group
	Total     int
	Counts    Counts
	Truncated bool
}

// ObservationStore is the persistence contract of the observation ledger and
// severity audits. The verification store still owns findings and evidence.
type ObservationStore interface {
	// UpsertFindingObservation stores one observation by id. A replay with the
	// same digest is a no-op; the same id with different content is a conflict.
	UpsertFindingObservation(Observation) (bool, error)
	GetFindingObservation(string) (*Observation, error)
	ListFindingObservations(findingID string) ([]Observation, error)
	ListFindingObservationsByProject(projectID string, limit, offset int) ([]Observation, int, error)
	ListFindingObservationsByTask(taskID string, limit, offset int) ([]Observation, int, error)
	ListFindingSeverityAudits(findingID string) ([]SeverityAudit, error)
	// SetFindingSeverityWithAudit updates the grade and appends its audit in one
	// atomic write, checking expectedVersion.
	SetFindingSeverityWithAudit(findingID, severity string, expectedVersion int64, audit SeverityAudit) error
}

// Store is everything the findings service needs from persistence.
type Store interface {
	verify.Store
	ObservationStore
}
