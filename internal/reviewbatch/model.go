// Package reviewbatch coordinates a durable batch of Audit paths through the
// existing Agent runner. It owns batch identity and control state; path leases,
// runs and hypotheses remain authoritative in the path and agent stores.
package reviewbatch

import (
	"context"
	"errors"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

var (
	ErrNotFound    = errors.New("review batch: not found")
	ErrConflict    = errors.New("review batch: version or active-audit conflict")
	ErrInvalid     = errors.New("review batch: invalid request")
	ErrNoWork      = errors.New("review batch: no queued paths")
	ErrUnavailable = errors.New("review batch: persistence unavailable")
)

// State is the durable control state of one review batch.
type State string

const (
	StateRunning    State = "RUNNING"
	StatePaused     State = "PAUSED"
	StateCancelling State = "CANCELLING"
	StateCancelled  State = "CANCELLED"
	StateCompleted  State = "COMPLETED"
	StateFailed     State = "FAILED"
)

func (s State) Terminal() bool {
	return s == StateCancelled || s == StateCompleted || s == StateFailed
}

func (s State) BlocksNewBatch() bool {
	return !s.Terminal()
}

func ValidState(s State) bool {
	switch s {
	case StateRunning, StatePaused, StateCancelling, StateCancelled, StateCompleted, StateFailed:
		return true
	default:
		return false
	}
}

// Batch is the durable identity of one operator-requested review run. PathIDs
// are fixed when the batch starts so later proposals cannot silently join it.
type Batch struct {
	ID             string   `json:"batch_id"`
	ProjectID      string   `json:"project_id"`
	SnapshotID     string   `json:"snapshot_id"`
	AuditID        string   `json:"audit_id"`
	State          State    `json:"state"`
	PathIDs        []string `json:"path_ids"`
	MaxConcurrent  int      `json:"max_concurrent"`
	CreatedBy      string   `json:"created_by"`
	Reason         string   `json:"reason,omitempty"`
	LastError      string   `json:"last_error,omitempty"`
	ExecutionOwner string   `json:"execution_owner,omitempty"`
	LeaseEpoch     int64    `json:"lease_epoch"`
	HeartbeatAt    string   `json:"heartbeat_at,omitempty"`
	LeaseUntil     string   `json:"lease_until,omitempty"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
	Version        int64    `json:"version"`
}

func (b Batch) Normalize() Batch {
	b.ID = strings.TrimSpace(b.ID)
	b.ProjectID = strings.TrimSpace(b.ProjectID)
	b.SnapshotID = strings.TrimSpace(b.SnapshotID)
	b.AuditID = strings.TrimSpace(b.AuditID)
	b.CreatedBy = strings.TrimSpace(b.CreatedBy)
	b.Reason = strings.TrimSpace(b.Reason)
	b.ExecutionOwner = strings.TrimSpace(b.ExecutionOwner)
	b.HeartbeatAt = strings.TrimSpace(b.HeartbeatAt)
	b.LeaseUntil = strings.TrimSpace(b.LeaseUntil)
	if b.PathIDs == nil {
		b.PathIDs = []string{}
	} else {
		b.PathIDs = append([]string(nil), b.PathIDs...)
	}
	return b
}

// Progress is derived from the current path documents. It is not a second
// scheduler ledger.
type Progress struct {
	Total     int `json:"total"`
	Queued    int `json:"queued"`
	Active    int `json:"active"`
	Reviewed  int `json:"reviewed"`
	Failed    int `json:"failed"`
	Cancelled int `json:"cancelled"`
	Blocked   int `json:"blocked"`
	Paused    int `json:"paused"`
}

type PathProgress struct {
	PathID string `json:"path_id"`
	Status string `json:"status"`
}

type View struct {
	Batch    Batch          `json:"batch"`
	Progress Progress       `json:"progress"`
	Paths    []PathProgress `json:"paths"`
}

type Query struct {
	ProjectID string
	AuditID   string
	State     State
	Limit     int
	Offset    int
}

type ClaimRequest struct {
	BatchID    string
	Owner      string
	Now        string
	LeaseUntil string
}

type RenewRequest struct {
	BatchID     string
	Owner       string
	Epoch       int64
	HeartbeatAt string
	LeaseUntil  string
}

type FinalizeRequest struct {
	BatchID         string
	ExpectedVersion int64
	Owner           string
	Epoch           int64
	State           State
	LastError       string
	Now             string
}

type ControlRequest struct {
	BatchID         string
	ExpectedVersion int64
	Target          State
	Actor           string
	Reason          string
	Owner           string
	Now             string
	LeaseUntil      string
}

type Store interface {
	CreateReviewBatch(context.Context, Batch) (Batch, error)
	GetReviewBatch(context.Context, string) (*Batch, error)
	ListReviewBatches(context.Context, Query) ([]Batch, int, error)
	ControlReviewBatch(context.Context, ControlRequest) (*Batch, error)
	ClaimReviewBatch(context.Context, ClaimRequest) (*Batch, error)
	RenewReviewBatch(context.Context, RenewRequest) (*Batch, error)
	FinalizeReviewBatch(context.Context, FinalizeRequest) (*Batch, error)
	ListReclaimableReviewBatches(context.Context, string, int) ([]Batch, error)
}

// PathService is the narrow path-engine surface used by the coordinator.
type PathService interface {
	Audit(string) (*path.Audit, error)
	Paths(path.PathQuery) ([]path.Path, int, error)
	Path(string) (*path.Path, []path.FeatureRecord, error)
	Cancel(string, string, string) (*path.Path, error)
}
