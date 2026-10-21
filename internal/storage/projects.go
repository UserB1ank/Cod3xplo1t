package storage

import (
	"context"
	"fmt"
	"time"
)

// Project input states. A new project starts by importing exactly one piece of
// source code; the input becomes ready only after its immutable snapshot exists.
// Projects created before this lifecycle have no input row and are reported as
// legacy, which keeps multi-source history readable without inventing a latest
// input for it.
const (
	ProjectInputImporting = "importing"
	ProjectInputReady     = "ready"
	ProjectInputFailed    = "failed"
	ProjectInputLegacy    = "legacy"
)

// ProjectDeletion states. The tombstone is written before any row is removed and
// is only marked completed after snapshots and project-scoped rows are gone. A
// pending tombstone is what makes a retried DELETE resume instead of starting a
// second cleanup.
const (
	ProjectDeletionPending   = "pending"
	ProjectDeletionCompleted = "completed"
)

// ProjectInputStaleAfter bounds how long an import may stay in flight without
// touching its record. The HTTP import deadline is two minutes, so a five-minute
// window cannot cut off a live upload while still letting a crashed dialog be
// retried or deleted.
const ProjectInputStaleAfter = 5 * time.Minute

// ErrProjectInputFixed reports an attempt to replace the one source a new
// project already has.
var ErrProjectInputFixed = fmt.Errorf("%w: the project already has a fixed source input", ErrConflict)

// ErrProjectImportInProgress reports a concurrent import for the same project.
var ErrProjectImportInProgress = fmt.Errorf("%w: a source import is already running for this project", ErrConflict)

// ProjectInput is the implicit audit input of a single-source project.
type ProjectInput struct {
	ProjectID      string    `json:"project_id"`
	State          string    `json:"state"`
	SourceID       string    `json:"source_id,omitempty"`
	SourceKind     string    `json:"source_kind,omitempty"`
	SourceName     string    `json:"source_name,omitempty"`
	SnapshotID     string    `json:"snapshot_id,omitempty"`
	Files          int       `json:"files"`
	Bytes          int64     `json:"bytes"`
	FailureCode    string    `json:"failure_code,omitempty"`
	FailureMessage string    `json:"failure_message,omitempty"`
	Version        int64     `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Stale reports whether an importing input has not been touched for the whole
// import window, which means its uploader is gone.
func (p ProjectInput) Stale(now time.Time) bool {
	return p.State == ProjectInputImporting && !p.UpdatedAt.IsZero() && now.Sub(p.UpdatedAt) > ProjectInputStaleAfter
}

// Effective returns the state a reader should see. A stale import is failed with
// an explicit interruption reason instead of "importing" forever; the stored row
// is not rewritten by a read, so a retry can still take the binding over.
func EffectiveProjectInput(input ProjectInput, now time.Time) ProjectInput {
	if input.Stale(now) {
		input.State = ProjectInputFailed
		input.FailureCode = "import_interrupted"
		input.FailureMessage = "源码导入已中断，未保存任何输入；可重试或删除项目。"
	}
	return input
}

// ProjectDeletion is the durable intent to remove a project.
type ProjectDeletion struct {
	ProjectID string    `json:"project_id"`
	State     string    `json:"state"`
	Failure   string    `json:"failure,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProjectRepository is the project lifecycle contract used by the API. It is
// separate from Store so a read-only or legacy store remains a valid Store,
// while a deployment that exposes project management must implement all of it.
type ProjectRepository interface {
	// CreateProject inserts a project and its importing input atomically.
	CreateProject(ctx context.Context, p Project) (Project, error)
	GetProjectInput(ctx context.Context, projectID string) (ProjectInput, error)
	ListProjectInputs(ctx context.Context) ([]ProjectInput, error)
	// BeginProjectInput binds or retakes the single source of a new project.
	BeginProjectInput(ctx context.Context, projectID, sourceID, sourceKind, sourceName string) (ProjectInput, error)
	CompleteProjectInput(ctx context.Context, projectID, sourceID, snapshotID string, files int, bytes int64) (ProjectInput, error)
	FailProjectInput(ctx context.Context, projectID, sourceID, code, message string) (ProjectInput, error)
	UpdateProjectDetails(ctx context.Context, id, name, description string, expectedVersion int64) (Project, error)
	// BeginProjectDeletion validates references, writes the tombstone and fences
	// every snapshot of the project before any filesystem cleanup starts.
	BeginProjectDeletion(ctx context.Context, id string) (ProjectDeletion, error)
	ProjectDeletion(ctx context.Context, id string) (ProjectDeletion, error)
	// FinishProjectDeletion removes remaining project-scoped rows and the project
	// row. It refuses while snapshots still exist.
	FinishProjectDeletion(ctx context.Context, id string) (ProjectDeletion, error)
}

// validateProjectDetails applies the public limits shared by the API and the
// store. Descriptions may be empty; names may not.
func validateProjectDetails(name, description string) error {
	if name == "" {
		return fmt.Errorf("%w: project name must not be empty", ErrConflict)
	}
	if len([]rune(name)) > 100 {
		return fmt.Errorf("%w: project name exceeds 100 characters", ErrConflict)
	}
	if len([]rune(description)) > 2000 {
		return fmt.Errorf("%w: project description exceeds 2000 characters", ErrConflict)
	}
	return nil
}

// inputImportingLocked returns a conflict when another source is actively being
// imported. The same source is allowed to retry, and a stale/failed attempt can
// be replaced.
func inputImportingLocked(input ProjectInput, sourceID string, now time.Time) error {
	if input.SourceID == sourceID {
		return nil
	}
	if input.SourceID != "" && input.State == ProjectInputImporting && !input.Stale(now) {
		return ErrProjectImportInProgress
	}
	return nil
}

// sameSource reports whether an input is already bound to a source.
func sameSource(input ProjectInput, sourceID string) bool {
	return input.SourceID != "" && input.SourceID == sourceID
}

var _ ProjectRepository = (*Memory)(nil)
var _ ProjectRepository = (*SQL)(nil)
