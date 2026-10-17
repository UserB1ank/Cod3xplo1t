package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

// EnsureProject creates an implicit CLI project without overwriting a user's name.
func (m *Memory) EnsureProject(_ context.Context, p Project) error {
	if p.ID == "" {
		return fmt.Errorf("%w: project id is required", ErrConflict)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.projects[p.ID]; ok {
		return nil
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	p.UpdatedAt, p.Version = p.CreatedAt, 1
	m.projects[p.ID] = p
	return nil
}

func (s *SQL) EnsureProject(ctx context.Context, p Project) error {
	if p.ID == "" {
		return fmt.Errorf("%w: project id is required", ErrConflict)
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO projects
(id, name, source, identity_kind, identity, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`),
		p.ID, p.Name, p.Source, p.IdentityKind, p.Identity, formatTime(p.CreatedAt), formatTime(p.CreatedAt))
	return mapSQLError(err)
}

func (m *Memory) SnapshotDeletionPending(_ context.Context, id string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deleting[id], nil
}

func (s *SQL) SnapshotDeletionPending(ctx context.Context, id string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(*) FROM snapshot_deletions WHERE snapshot_id = ? AND completed = 0"), id).Scan(&count)
	return count != 0, mapSQLError(err)
}

func (m *Memory) snapshotWritableLocked(id string) error {
	if _, exists := m.deleting[id]; exists {
		return fmt.Errorf("%w: snapshot %s is being deleted; retry deletion", ErrConflict, id)
	}
	return nil
}

// A completed marker blocks late writes. Only registration of a materialized
// snapshot may clear it, with the filesystem check inside the storage lock.
func validateSnapshotRevival(snap *repository.Snapshot) error {
	if snap.Dir == "" {
		return fmt.Errorf("%w: recreating a deleted snapshot requires its materialized tree", ErrConflict)
	}
	actual, err := repository.LoadSnapshot(snap.Dir)
	if err != nil {
		return fmt.Errorf("%w: cannot register a deleted snapshot without its tree: %v", ErrConflict, err)
	}
	want, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	got, err := json.Marshal(actual)
	if err != nil {
		return err
	}
	if !sameDocument(want, got) {
		return fmt.Errorf("%w: snapshot metadata changed before registration", ErrConflict)
	}
	return nil
}

func (s *SQL) snapshotRegistrationTx(ctx context.Context, tx *sql.Tx, snap *repository.Snapshot) error {
	if _, err := tx.ExecContext(ctx, s.rebind("UPDATE snapshot_deletions SET created_at = created_at WHERE snapshot_id = ?"), snap.SnapshotID); err != nil {
		return mapSQLError(err)
	}
	var completed int
	err := tx.QueryRowContext(ctx, s.rebind("SELECT completed FROM snapshot_deletions WHERE snapshot_id = ?"), snap.SnapshotID).Scan(&completed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return mapSQLError(err)
	}
	if completed == 0 {
		return fmt.Errorf("%w: snapshot %s is being deleted; retry deletion", ErrConflict, snap.SnapshotID)
	}
	if err := validateSnapshotRevival(snap); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.rebind("DELETE FROM snapshot_deletions WHERE snapshot_id = ?"), snap.SnapshotID)
	return mapSQLError(err)
}

// snapshotWritableTx obtains the SQLite write lock before checking the marker.
// A deletion and a snapshot writer cannot both pass their checks and commit.
func (s *SQL) snapshotWritableTx(ctx context.Context, tx *sql.Tx, id string) error {
	if _, err := tx.ExecContext(ctx, s.rebind("UPDATE snapshot_deletions SET created_at = created_at WHERE snapshot_id = ?"), id); err != nil {
		return mapSQLError(err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, s.rebind("SELECT COUNT(*) FROM snapshot_deletions WHERE snapshot_id = ?"), id).Scan(&count); err != nil {
		return mapSQLError(err)
	}
	if count != 0 {
		return fmt.Errorf("%w: snapshot %s is being deleted; retry deletion", ErrConflict, id)
	}
	return nil
}

func (s *SQL) snapshotWrite(ctx context.Context, id string, write func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	if err := s.snapshotWritableTx(ctx, tx, id); err != nil {
		return err
	}
	if err := write(tx); err != nil {
		return err
	}
	return mapSQLError(tx.Commit())
}

// BeginSnapshotDeletion marks cleanup as pending. DeleteSnapshot completes the
// marker after filesystem cleanup; the tombstone then rejects late writes.
// Active work must be settled or reclaimed before deletion is attempted.
func (m *Memory) BeginSnapshotDeletion(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleting[id] {
		return nil
	}
	for _, doc := range m.audits {
		if doc.audit.SnapshotID != id {
			continue
		}
		for _, p := range doc.paths {
			if p.Status.Active() {
				return fmt.Errorf("%w: snapshot %s has active paths", ErrConflict, id)
			}
		}
	}
	for _, doc := range m.agentRuns {
		if doc.run.SnapshotID == id && !doc.run.Status.Terminal() {
			return fmt.Errorf("%w: snapshot %s has unfinished agent runs", ErrConflict, id)
		}
	}
	for _, run := range m.verificationRuns {
		if run.SnapshotID == id && !run.Status.Terminal() {
			return fmt.Errorf("%w: snapshot %s has unfinished verification runs", ErrConflict, id)
		}
	}
	for _, raw := range m.workflowRuns {
		var run workflow.Run
		if json.Unmarshal(raw, &run) != nil {
			return ErrConflict
		}
		if run.Scope.SnapshotID == id && !workflow.RunTerminal(run.Status) {
			return fmt.Errorf("%w: snapshot has unfinished workflow runs", ErrConflict)
		}
	}
	for _, raw := range m.pluginInvocations {
		var inv plugin.Invocation
		if json.Unmarshal(raw, &inv) != nil {
			return ErrConflict
		}
		if inv.Request.Scope.SnapshotID == id && !plugin.Terminal(inv.Status) {
			return fmt.Errorf("%w: snapshot has unfinished plugin invocations", ErrConflict)
		}
	}
	m.deleting[id] = true
	return nil
}

func (s *SQL) BeginSnapshotDeletion(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO snapshot_deletions(snapshot_id,created_at)
VALUES (?, ?) ON CONFLICT(snapshot_id) DO UPDATE SET completed = 0`), id, formatTime(time.Now().UTC())); err != nil {
		return mapSQLError(err)
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM workflow_runs WHERE snapshot_id=? AND status IN ('CREATED','RUNNING','PAUSING','PAUSED','CANCELLING')`,
		`SELECT COUNT(*) FROM plugin_invocations WHERE snapshot_id = ? AND status IN ('CREATED', 'RUNNING')`,
		`SELECT COUNT(*) FROM audit_paths WHERE snapshot_id = ? AND status IN ('ANALYZING','LOCAL_EXPLORING','VERIFYING')`,
		`SELECT COUNT(*) FROM agent_runs WHERE snapshot_id = ? AND status NOT IN ('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','BUDGET_EXCEEDED','INVALID_OUTPUT')`,
		`SELECT COUNT(*) FROM verification_runs WHERE snapshot_id = ? AND status NOT IN ('SUCCEEDED','FAILED','BLOCKED','CANCELLED','TIMED_OUT')`,
	} {
		var active int
		if err := tx.QueryRowContext(ctx, s.rebind(query), id).Scan(&active); err != nil {
			return mapSQLError(err)
		}
		if active != 0 {
			return fmt.Errorf("%w: snapshot %s has unfinished work; settle or reclaim it before deletion", ErrConflict, id)
		}
	}
	return mapSQLError(tx.Commit())
}
