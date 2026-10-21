package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CreateProject implements ProjectRepository.
func (s *SQL) CreateProject(ctx context.Context, p Project) (Project, error) {
	if p.ID == "" {
		return Project{}, fmt.Errorf("%w: project id is required", ErrConflict)
	}
	if err := validateProjectDetails(p.Name, p.Description); err != nil {
		return Project{}, err
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	p.Version = 1
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Project{}, mapSQLError(err)
	}
	defer tx.Rollback()
	var deleted int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM project_deletions WHERE project_id = ?`), p.ID).Scan(&deleted); err != nil {
		return Project{}, mapSQLError(err)
	}
	if deleted != 0 {
		return Project{}, fmt.Errorf("%w: project %s is being deleted", ErrConflict, p.ID)
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO projects
(id, name, description, source, identity_kind, identity, created_at, updated_at, version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`),
		p.ID, p.Name, p.Description, p.Source, p.IdentityKind, p.Identity, formatTime(p.CreatedAt), formatTime(p.UpdatedAt)); err != nil {
		return Project{}, mapSQLError(err)
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO project_inputs
(project_id, state, source_id, source_kind, source_name, snapshot_id, files, bytes,
 failure_code, failure_message, version, created_at, updated_at)
VALUES (?, ?, '', '', '', '', 0, 0, '', '', 1, ?, ?)`),
		p.ID, ProjectInputImporting, formatTime(p.CreatedAt), formatTime(p.UpdatedAt)); err != nil {
		return Project{}, mapSQLError(err)
	}
	if err := tx.Commit(); err != nil {
		return Project{}, mapSQLError(err)
	}
	return p, nil
}

// GetProjectInput implements ProjectRepository.
func (s *SQL) GetProjectInput(ctx context.Context, projectID string) (ProjectInput, error) {
	row := s.db.QueryRowContext(ctx, s.rebind(`SELECT project_id, state, source_id, source_kind, source_name,
snapshot_id, files, bytes, failure_code, failure_message, version, created_at, updated_at
FROM project_inputs WHERE project_id = ?`), projectID)
	return scanProjectInput(row.Scan)
}

// ListProjectInputs implements ProjectRepository.
func (s *SQL) ListProjectInputs(ctx context.Context) ([]ProjectInput, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT project_id, state, source_id, source_kind, source_name,
snapshot_id, files, bytes, failure_code, failure_message, version, created_at, updated_at
FROM project_inputs ORDER BY project_id`)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	out := []ProjectInput{}
	for rows.Next() {
		input, err := scanProjectInput(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, input)
	}
	return out, rows.Err()
}

func scanProjectInput(scan func(...any) error) (ProjectInput, error) {
	var input ProjectInput
	var created, updated string
	if err := scan(&input.ProjectID, &input.State, &input.SourceID, &input.SourceKind, &input.SourceName,
		&input.SnapshotID, &input.Files, &input.Bytes, &input.FailureCode, &input.FailureMessage,
		&input.Version, &created, &updated); err != nil {
		return ProjectInput{}, mapSQLError(err)
	}
	input.CreatedAt, input.UpdatedAt = parseStoredTime(created), parseStoredTime(updated)
	return input, nil
}

// BeginProjectInput implements ProjectRepository.
func (s *SQL) BeginProjectInput(ctx context.Context, projectID, sourceID, sourceKind, sourceName string) (ProjectInput, error) {
	if strings.TrimSpace(sourceID) == "" {
		return ProjectInput{}, fmt.Errorf("%w: source id is required", ErrConflict)
	}
	if err := s.projectWritable(ctx, projectID); err != nil {
		return ProjectInput{}, err
	}
	input, err := s.GetProjectInput(ctx, projectID)
	if err != nil {
		return ProjectInput{}, err
	}
	now := time.Now().UTC()
	switch input.State {
	case ProjectInputReady:
		if !sameSource(input, sourceID) {
			return ProjectInput{}, ErrProjectInputFixed
		}
		if _, err := s.db.ExecContext(ctx, s.rebind(`UPDATE project_inputs SET updated_at = ? WHERE project_id = ? AND version = ?`),
			formatTime(now), projectID, input.Version); err != nil {
			return ProjectInput{}, mapSQLError(err)
		}
		input.UpdatedAt = now
		return input, nil
	case ProjectInputImporting:
		if sameSource(input, sourceID) {
			if _, err := s.db.ExecContext(ctx, s.rebind(`UPDATE project_inputs SET updated_at = ? WHERE project_id = ? AND version = ?`),
				formatTime(now), projectID, input.Version); err != nil {
				return ProjectInput{}, mapSQLError(err)
			}
			input.UpdatedAt = now
			return input, nil
		}
		if err := inputImportingLocked(input, sourceID, now); err != nil {
			return ProjectInput{}, err
		}
	case ProjectInputFailed:
	default:
		return ProjectInput{}, fmt.Errorf("%w: unknown project input state %q", ErrConflict, input.State)
	}
	result, err := s.db.ExecContext(ctx, s.rebind(`UPDATE project_inputs SET
state = ?, source_id = ?, source_kind = ?, source_name = ?, snapshot_id = '', files = 0, bytes = 0,
failure_code = '', failure_message = '', version = version + 1, updated_at = ?
WHERE project_id = ? AND version = ?`),
		ProjectInputImporting, sourceID, sourceKind, sourceName, formatTime(now), projectID, input.Version)
	if err != nil {
		return ProjectInput{}, mapSQLError(err)
	}
	if n, err := result.RowsAffected(); err != nil {
		return ProjectInput{}, err
	} else if n == 0 {
		return ProjectInput{}, fmt.Errorf("%w: project input was changed by another writer", ErrConflict)
	}
	return s.GetProjectInput(ctx, projectID)
}

// CompleteProjectInput implements ProjectRepository.
func (s *SQL) CompleteProjectInput(ctx context.Context, projectID, sourceID, snapshotID string, files int, bytes int64) (ProjectInput, error) {
	if strings.TrimSpace(snapshotID) == "" {
		return ProjectInput{}, fmt.Errorf("%w: snapshot id is required", ErrConflict)
	}
	if err := s.projectWritable(ctx, projectID); err != nil {
		return ProjectInput{}, err
	}
	input, err := s.GetProjectInput(ctx, projectID)
	if err != nil {
		return ProjectInput{}, err
	}
	if input.State == ProjectInputReady {
		if sameSource(input, sourceID) && input.SnapshotID == snapshotID {
			return input, nil
		}
		return ProjectInput{}, ErrProjectInputFixed
	}
	if input.State != ProjectInputImporting || !sameSource(input, sourceID) {
		return ProjectInput{}, fmt.Errorf("%w: project input is not an import of this source", ErrConflict)
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, s.rebind(`UPDATE project_inputs SET
state = ?, snapshot_id = ?, files = ?, bytes = ?, failure_code = '', failure_message = '',
version = version + 1, updated_at = ?
WHERE project_id = ? AND version = ? AND state = ? AND source_id = ?`),
		ProjectInputReady, snapshotID, files, bytes, formatTime(now), projectID, input.Version, ProjectInputImporting, sourceID)
	if err != nil {
		return ProjectInput{}, mapSQLError(err)
	}
	if n, err := result.RowsAffected(); err != nil {
		return ProjectInput{}, err
	} else if n == 0 {
		return ProjectInput{}, fmt.Errorf("%w: project input was completed by another writer", ErrConflict)
	}
	return s.GetProjectInput(ctx, projectID)
}

// FailProjectInput implements ProjectRepository.
func (s *SQL) FailProjectInput(ctx context.Context, projectID, sourceID, code, message string) (ProjectInput, error) {
	if err := s.projectWritable(ctx, projectID); err != nil {
		return ProjectInput{}, err
	}
	input, err := s.GetProjectInput(ctx, projectID)
	if err != nil {
		return ProjectInput{}, err
	}
	if input.State != ProjectInputImporting || !sameSource(input, sourceID) {
		return input, nil
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, s.rebind(`UPDATE project_inputs SET
state = ?, failure_code = ?, failure_message = ?, version = version + 1, updated_at = ?
WHERE project_id = ? AND version = ? AND state = ? AND source_id = ?`),
		ProjectInputFailed, code, truncateMessage(message, 500), formatTime(now),
		projectID, input.Version, ProjectInputImporting, sourceID)
	if err != nil {
		return ProjectInput{}, mapSQLError(err)
	}
	if n, err := result.RowsAffected(); err != nil {
		return ProjectInput{}, err
	} else if n == 0 {
		// Another attempt changed the binding; report the current row so the
		// caller can decide, without overwriting the newer state.
		return s.GetProjectInput(ctx, projectID)
	}
	return s.GetProjectInput(ctx, projectID)
}

// UpdateProjectDetails implements ProjectRepository.
func (s *SQL) UpdateProjectDetails(ctx context.Context, id, name, description string, expectedVersion int64) (Project, error) {
	if err := validateProjectDetails(name, description); err != nil {
		return Project{}, err
	}
	var p Project
	var created, updated string
	err := s.db.QueryRowContext(ctx, s.rebind(`UPDATE projects SET name = ?, description = ?, updated_at = ?, version = version + 1
WHERE id = ? AND version = ? AND NOT EXISTS (SELECT 1 FROM project_deletions WHERE project_id = ?)
RETURNING id, name, description, source, identity_kind, identity, created_at, updated_at, version`),
		name, description, formatTime(time.Now().UTC()), id, expectedVersion, id).Scan(
		&p.ID, &p.Name, &p.Description, &p.Source, &p.IdentityKind, &p.Identity, &created, &updated, &p.Version)
	if errors.Is(err, sql.ErrNoRows) {
		if _, lookupErr := s.GetProject(ctx, id); lookupErr != nil {
			return Project{}, lookupErr
		}
		return Project{}, fmt.Errorf("%w: project %s was changed by another writer or is being deleted", ErrConflict, id)
	}
	if err != nil {
		return Project{}, mapSQLError(err)
	}
	p.CreatedAt, p.UpdatedAt = parseStoredTime(created), parseStoredTime(updated)
	return p, nil
}

// ProjectDeletion implements ProjectRepository.
func (s *SQL) ProjectDeletion(ctx context.Context, id string) (ProjectDeletion, error) {
	var deletion ProjectDeletion
	var created, updated string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT project_id, state, failure, created_at, updated_at
FROM project_deletions WHERE project_id = ?`), id).Scan(
		&deletion.ProjectID, &deletion.State, &deletion.Failure, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectDeletion{}, fmt.Errorf("%w: project deletion for %s", ErrNotFound, id)
	}
	if err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	deletion.CreatedAt, deletion.UpdatedAt = parseStoredTime(created), parseStoredTime(updated)
	return deletion, nil
}

// BeginProjectDeletion implements ProjectRepository.
func (s *SQL) BeginProjectDeletion(ctx context.Context, id string) (ProjectDeletion, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	defer tx.Rollback()
	if err := s.lockProjectTx(ctx, tx, id); err != nil {
		return ProjectDeletion{}, err
	}
	deletion, err := projectDeletionTx(ctx, s, tx, id)
	if err == nil {
		return deletion, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return ProjectDeletion{}, err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM projects WHERE id = ?`), id).Scan(&exists); err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	if exists == 0 {
		return ProjectDeletion{}, fmt.Errorf("%w: project %s", ErrNotFound, id)
	}
	if err := s.guardProjectDeletionTx(ctx, tx, id); err != nil {
		return ProjectDeletion{}, err
	}
	if err := s.purgeProjectAuxiliaryTx(ctx, tx, id); err != nil {
		return ProjectDeletion{}, err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO project_deletions(project_id, state, failure, created_at, updated_at)
VALUES (?, ?, '', ?, ?)`), id, ProjectDeletionPending, formatTime(now), formatTime(now)); err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	if err := fenceProjectSnapshotsTx(ctx, s, tx, id, now); err != nil {
		return ProjectDeletion{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	return ProjectDeletion{ProjectID: id, State: ProjectDeletionPending, CreatedAt: now, UpdatedAt: now}, nil
}

// FinishProjectDeletion implements ProjectRepository.
func (s *SQL) FinishProjectDeletion(ctx context.Context, id string) (ProjectDeletion, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	defer tx.Rollback()
	if err := s.lockProjectTx(ctx, tx, id); err != nil {
		return ProjectDeletion{}, err
	}
	deletion, err := projectDeletionTx(ctx, s, tx, id)
	if err != nil {
		return ProjectDeletion{}, err
	}
	if deletion.State == ProjectDeletionCompleted {
		return deletion, nil
	}
	var remaining int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM snapshots WHERE project_id = ?`), id).Scan(&remaining); err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	if remaining != 0 {
		return ProjectDeletion{}, fmt.Errorf("%w: project %s still has %d snapshot(s)", ErrConflict, id, remaining)
	}
	queries := []string{
		`DELETE FROM workflow_heads WHERE project_id = ?`,
		`DELETE FROM workflow_versions WHERE project_id = ?`,
		`DELETE FROM workflow_plans WHERE project_id = ?`,
		`DELETE FROM workflow_runs WHERE project_id = ?`,
		`DELETE FROM analysis_runs WHERE project_id = ?`,
		`DELETE FROM plugin_invocations WHERE project_id = ?`,
		`DELETE FROM knowledge_analysis_paths WHERE project_id = ?`,
		`DELETE FROM knowledge_analyses WHERE project_id = ?`,
		`DELETE FROM knowledge_outbox WHERE project_id = ?`,
		`DELETE FROM knowledge_revisions WHERE project_id = ?`,
		`DELETE FROM artifact_refs WHERE project_id = ?`,
		`DELETE FROM project_sources WHERE project_id = ?`,
		`DELETE FROM project_inputs WHERE project_id = ?`,
	}
	if s.postgres {
		// The lease tables are part of the PostgreSQL execution profile only; the
		// legacy SQLite schema has no owner/epoch bookkeeping to remove.
		queries = append([]string{
			`DELETE FROM workflow_node_claims WHERE run_id IN (SELECT run_id FROM workflow_runs WHERE project_id = ?)`,
			`DELETE FROM workflow_leases WHERE run_id IN (SELECT run_id FROM workflow_runs WHERE project_id = ?)`,
		}, queries...)
	}
	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, s.rebind(query), id); err != nil {
			return ProjectDeletion{}, mapSQLError(err)
		}
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM projects WHERE id = ?`), id); err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE project_deletions SET state = ?, failure = '', updated_at = ? WHERE project_id = ?`),
		ProjectDeletionCompleted, formatTime(now), id); err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	if err := tx.Commit(); err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	deletion.State = ProjectDeletionCompleted
	deletion.Failure = ""
	deletion.UpdatedAt = now
	return deletion, nil
}

func projectDeletionTx(ctx context.Context, s *SQL, tx *sql.Tx, id string) (ProjectDeletion, error) {
	var deletion ProjectDeletion
	var created, updated string
	err := tx.QueryRowContext(ctx, s.rebind(`SELECT project_id, state, failure, created_at, updated_at
FROM project_deletions WHERE project_id = ?`), id).Scan(
		&deletion.ProjectID, &deletion.State, &deletion.Failure, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectDeletion{}, fmt.Errorf("%w: project deletion for %s", ErrNotFound, id)
	}
	if err != nil {
		return ProjectDeletion{}, mapSQLError(err)
	}
	deletion.CreatedAt, deletion.UpdatedAt = parseStoredTime(created), parseStoredTime(updated)
	return deletion, nil
}

func (s *SQL) projectWritable(ctx context.Context, id string) error {
	var deleted int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM project_deletions WHERE project_id = ?`), id).Scan(&deleted); err != nil {
		return mapSQLError(err)
	}
	if deleted != 0 {
		return fmt.Errorf("%w: project %s is being deleted", ErrConflict, id)
	}
	return nil
}

func (s *SQL) lockProjectTx(ctx context.Context, tx *sql.Tx, id string) error {
	if !s.postgres {
		return nil
	}
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "project:"+id)
	return err
}

// guardProjectDeletionTx proves that no referenced work is still moving. A
// stale importing input is treated as interrupted so a crashed upload cannot
// block cleanup forever, while a live one is refused.
func (s *SQL) guardProjectDeletionTx(ctx context.Context, tx *sql.Tx, id string) error {
	var state, sourceID, updated string
	err := tx.QueryRowContext(ctx, s.rebind(`SELECT state, source_id, updated_at FROM project_inputs WHERE project_id = ?`), id).Scan(&state, &sourceID, &updated)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return mapSQLError(err)
	case state == ProjectInputImporting && sourceID != "" && time.Since(parseStoredTime(updated)) <= ProjectInputStaleAfter:
		return fmt.Errorf("%w: project %s is still importing its source", ErrConflict, id)
	}
	queries := []struct {
		query string
		args  []any
		why   string
	}{
		{`SELECT COUNT(*) FROM audit_paths WHERE snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?)
AND status IN ('DISCOVERED','QUEUED','ANALYZING','LOCAL_EXPLORING','HYPOTHESIS_FORMED','VERIFYING')`, []any{id}, "queued or running paths"},
		{`SELECT COUNT(*) FROM audits WHERE snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?)
AND status IN ('GENERATING','PAUSING','CANCELLING')`, []any{id}, "an unfinished analysis"},
		{`SELECT COUNT(*) FROM agent_runs WHERE snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?)
AND status NOT IN ('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','BUDGET_EXCEEDED','INVALID_OUTPUT')`, []any{id}, "unfinished agent runs"},
		{`SELECT COUNT(*) FROM verification_runs WHERE snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?)
AND status NOT IN ('SUCCEEDED','FAILED','BLOCKED','CANCELLED','TIMED_OUT')`, []any{id}, "unfinished verification runs"},
		{`SELECT COUNT(*) FROM workflow_runs WHERE project_id = ? AND status IN ('CREATED','RUNNING','PAUSING','PAUSED','CANCELLING')`, []any{id}, "unfinished workflow runs"},
		{`SELECT COUNT(*) FROM plugin_invocations WHERE project_id = ? AND status IN ('CREATED','RUNNING')`, []any{id}, "unfinished plugin invocations"},
		{`SELECT COUNT(*) FROM verification_plans WHERE project_id = ? AND state IN ('pending','approved')`, []any{id}, "a pending verification plan"},
		{`SELECT COUNT(*) FROM environment_leases WHERE project_id = ? AND state IN ('provisioning','ready','running')`, []any{id}, "an active verification environment"},
	}
	for _, check := range queries {
		var active int
		if err := tx.QueryRowContext(ctx, s.rebind(check.query), check.args...).Scan(&active); err != nil {
			return mapSQLError(err)
		}
		if active != 0 {
			return fmt.Errorf("%w: project %s has %s", ErrConflict, id, check.why)
		}
	}
	return nil
}

func (s *SQL) purgeProjectAuxiliaryTx(ctx context.Context, tx *sql.Tx, id string) error {
	for _, query := range []string{
		`DELETE FROM agent_checkpoint_resumes WHERE checkpoint_id IN (
SELECT checkpoint_id FROM agent_checkpoints WHERE snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?))`,
		`DELETE FROM agent_checkpoints WHERE snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?)
OR audit_id IN (SELECT audit_id FROM audits WHERE snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?))`,
		`DELETE FROM agent_budget_grants WHERE audit_id IN (
SELECT audit_id FROM audits WHERE snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?))`,
		`DELETE FROM agent_audit_budgets WHERE audit_id IN (
SELECT audit_id FROM audits WHERE snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?))`,
		`DELETE FROM finding_severity_audits WHERE finding_id IN (
SELECT finding_id FROM findings WHERE snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?))
OR finding_id IN (SELECT finding_id FROM finding_observations WHERE project_id = ?)`,
		`DELETE FROM finding_observations WHERE project_id = ?`,
		`DELETE FROM verification_plans WHERE project_id = ?`,
		`DELETE FROM environment_leases WHERE project_id = ?`,
	} {
		args := []any{id}
		if countArgs(query) > 1 {
			args = []any{id, id}
		}
		if _, err := tx.ExecContext(ctx, s.rebind(query), args...); err != nil {
			return mapSQLError(err)
		}
	}
	return nil
}

func fenceProjectSnapshotsTx(ctx context.Context, s *SQL, tx *sql.Tx, projectID string, now time.Time) error {
	rows, err := tx.QueryContext(ctx, s.rebind(`SELECT snapshot_id FROM snapshots WHERE project_id = ?`), projectID)
	if err != nil {
		return mapSQLError(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return mapSQLError(err)
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO snapshot_deletions(snapshot_id, created_at, completed)
VALUES (?, ?, 0) ON CONFLICT(snapshot_id) DO UPDATE SET completed = 0`), id, formatTime(now)); err != nil {
			return mapSQLError(err)
		}
	}
	return nil
}

func countArgs(query string) int {
	return strings.Count(query, "?")
}
