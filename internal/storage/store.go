// Package storage persists the P1 documents: projects, snapshots and analysis
// manifests. It is deliberately driver agnostic: the SQL implementation takes an
// already registered database/sql driver name and only rebinds placeholders per
// dialect, so switching from SQLite to PostgreSQL is a configuration change.
package storage

import (
	"context"
	"errors"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

// Errors returned by every Store implementation.
var (
	// ErrNotFound means the requested record does not exist.
	ErrNotFound = errors.New("storage: record not found")
	// ErrConflict means an immutable record already exists with different
	// content, or a unique key was violated.
	ErrConflict = errors.New("storage: conflicting record")
)

// Project is a repository the user asked Codexploit to audit.
type Project struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Source       string    `json:"source"`
	IdentityKind string    `json:"identity_kind"`
	Identity     string    `json:"identity"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Version      int64     `json:"version"`
}

// SnapshotRecord is the indexed view of a stored snapshot. The full snapshot
// metadata document stays in the store and is returned by GetSnapshot.
type SnapshotRecord struct {
	SnapshotID      string    `json:"snapshot_id"`
	ProjectID       string    `json:"project_id"`
	Commit          string    `json:"commit"`
	VCS             string    `json:"vcs"`
	WorktreeDirty   bool      `json:"worktree_dirty"`
	CreatedAt       time.Time `json:"created_at"`
	ManifestPresent bool      `json:"manifest_present"`
	AnalysisID      string    `json:"analysis_id,omitempty"`
}

// Store is the persistence contract used by the API and the CLI.
//
// Snapshots and manifests are immutable: writing the same document twice is a
// no-op, writing a different document under the same id is ErrConflict.
type Store interface {
	PutProject(ctx context.Context, p Project) error
	// EnsureProject creates missing metadata without changing an existing project.
	EnsureProject(ctx context.Context, p Project) error
	// RenameProject compares and advances the version atomically.
	RenameProject(ctx context.Context, id, name string, expectedVersion int64) (Project, error)
	GetProject(ctx context.Context, id string) (Project, error)
	ListProjects(ctx context.Context) ([]Project, error)

	PutSnapshot(ctx context.Context, projectID string, snap *repository.Snapshot) error
	GetSnapshot(ctx context.Context, id string) (*repository.Snapshot, error)
	ListSnapshots(ctx context.Context, projectID string) ([]SnapshotRecord, error)
	DeleteSnapshot(ctx context.Context, id string) error
	// BeginSnapshotDeletion refuses unfinished work and blocks new writes until
	// deletion completes. DeleteSnapshot retains a completed tombstone against
	// late writes; PutSnapshot can revive a materialized, matching snapshot.
	BeginSnapshotDeletion(ctx context.Context, id string) error
	SnapshotDeletionPending(ctx context.Context, id string) (bool, error)

	PutManifest(ctx context.Context, snapshotID string, m *analysis.Manifest) error
	GetManifest(ctx context.Context, snapshotID string) (*analysis.Manifest, error)

	Close() error
}
