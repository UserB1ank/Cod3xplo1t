package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// UpsertFindingObservation implements findings.ObservationStore. The insert is
// guarded by the observation id and compared by content hash, so a replay with a
// fresh timestamp is a no-op and a changed claim under the same id is refused.
func (s *SQL) UpsertFindingObservation(o findings.Observation) (bool, error) {
	if err := validateFindingObservation(o); err != nil {
		return false, err
	}
	if o.CreatedAt == "" {
		o.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return false, findings.ErrInvalid
	}
	contentHash := o.Digest()
	inserted := false
	err = s.snapshotWrite(context.Background(), o.Scope.SnapshotID, func(tx *sql.Tx) error {
		ctx := context.Background()
		var snapshotID string
		err := tx.QueryRowContext(ctx, s.rebind("SELECT snapshot_id FROM findings WHERE finding_id = ?"+s.forUpdate()), o.FindingID).Scan(&snapshotID)
		if errors.Is(err, sql.ErrNoRows) {
			return findings.ErrNotFound
		}
		if err != nil {
			return mapVerifySQLError(err)
		}
		if snapshotID != o.Scope.SnapshotID {
			return findings.ErrConflict
		}
		result, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO finding_observations
			(observation_id, finding_id, project_id, snapshot_id, task_id, fingerprint, fingerprint_version, content_hash, observation_json, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (observation_id) DO NOTHING`),
			o.ID, o.FindingID, o.Scope.ProjectID, o.Scope.SnapshotID, o.TaskID, o.Fingerprint, o.FingerprintVersion, contentHash, string(raw), o.CreatedAt)
		if err != nil {
			return mapVerifySQLError(err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		var storedHash string
		if err := tx.QueryRowContext(ctx, s.rebind("SELECT content_hash FROM finding_observations WHERE observation_id = ?"), o.ID).Scan(&storedHash); err != nil {
			return mapVerifySQLError(err)
		}
		if storedHash != contentHash {
			return findings.ErrConflict
		}
		inserted = n == 1
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// GetFindingObservation implements findings.ObservationStore.
func (s *SQL) GetFindingObservation(id string) (*findings.Observation, error) {
	var raw string
	err := s.db.QueryRowContext(context.Background(), s.rebind("SELECT observation_json FROM finding_observations WHERE observation_id = ?"), id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, findings.ErrNotFound
	}
	if err != nil {
		return nil, mapSQLError(err)
	}
	var o findings.Observation
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		return nil, findings.ErrInvalid
	}
	return &o, nil
}

// ListFindingObservations implements findings.ObservationStore.
func (s *SQL) ListFindingObservations(findingID string) ([]findings.Observation, error) {
	rows, err := s.db.QueryContext(context.Background(), s.rebind("SELECT observation_json FROM finding_observations WHERE finding_id = ? ORDER BY created_at, observation_id"), findingID)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	return scanObservations(rows)
}

// ListFindingObservationsByProject implements findings.ObservationStore.
func (s *SQL) ListFindingObservationsByProject(projectID string, limit, offset int) ([]findings.Observation, int, error) {
	return s.listObservations("project_id = ?", projectID, limit, offset)
}

// ListFindingObservationsByTask implements findings.ObservationStore.
func (s *SQL) ListFindingObservationsByTask(taskID string, limit, offset int) ([]findings.Observation, int, error) {
	return s.listObservations("task_id = ?", taskID, limit, offset)
}

func (s *SQL) listObservations(filter string, value string, limit, offset int) ([]findings.Observation, int, error) {
	ctx := context.Background()
	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM finding_observations WHERE "+filter), value).Scan(&total); err != nil {
		return nil, 0, mapSQLError(err)
	}
	rows, err := s.db.QueryContext(ctx, s.rebind("SELECT observation_json FROM finding_observations WHERE "+filter+" ORDER BY created_at, observation_id LIMIT ? OFFSET ?"),
		value, normaliseLimit(limit, 100, 0), max(offset, 0))
	if err != nil {
		return nil, 0, mapSQLError(err)
	}
	defer rows.Close()
	items, err := scanObservations(rows)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func scanObservations(rows *sql.Rows) ([]findings.Observation, error) {
	out := []findings.Observation{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, mapSQLError(err)
		}
		var o findings.Observation
		if err := json.Unmarshal([]byte(raw), &o); err != nil {
			return nil, findings.ErrInvalid
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ListFindingSeverityAudits implements findings.ObservationStore.
func (s *SQL) ListFindingSeverityAudits(findingID string) ([]findings.SeverityAudit, error) {
	rows, err := s.db.QueryContext(context.Background(), s.rebind(`SELECT audit_id, finding_id, version, previous_severity, severity, reason, actor, created_at
		FROM finding_severity_audits WHERE finding_id = ? ORDER BY version, audit_id`), findingID)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	out := []findings.SeverityAudit{}
	for rows.Next() {
		var audit findings.SeverityAudit
		if err := rows.Scan(&audit.ID, &audit.FindingID, &audit.Version, &audit.PreviousSeverity, &audit.Severity, &audit.Reason, &audit.Actor, &audit.CreatedAt); err != nil {
			return nil, mapSQLError(err)
		}
		out = append(out, audit)
	}
	return out, rows.Err()
}

// SetFindingSeverityWithAudit implements findings.ObservationStore. The grade
// update and its audit row commit together, so an audit cannot claim a change
// the finding did not make.
func (s *SQL) SetFindingSeverityWithAudit(findingID, severity string, expectedVersion int64, audit findings.SeverityAudit) error {
	if !validGrade(severity) {
		return fmt.Errorf("%w: severity must be high, medium or low", verify.ErrInvalidArgument)
	}
	if err := validateSeverityAudit(audit); err != nil {
		return err
	}
	if audit.FindingID != findingID || audit.Severity != severity || audit.Version != expectedVersion+1 {
		return findings.ErrConflict
	}
	finding, err := s.GetFinding(findingID)
	if err != nil {
		return err
	}
	if audit.CreatedAt == "" {
		audit.CreatedAt = verifyNow()
	}
	audit.PreviousSeverity = finding.Severity
	return s.snapshotWrite(context.Background(), finding.SnapshotID, func(tx *sql.Tx) error {
		ctx := context.Background()
		result, err := tx.ExecContext(ctx, s.rebind("UPDATE findings SET severity = ?, version = version + 1, updated_at = ? WHERE finding_id = ? AND version = ?"),
			severity, audit.CreatedAt, findingID, expectedVersion)
		if err != nil {
			return mapVerifySQLError(err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return verify.ErrConflict
		}
		_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO finding_severity_audits
			(audit_id, finding_id, version, previous_severity, severity, reason, actor, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			audit.ID, findingID, audit.Version, audit.PreviousSeverity, severity, audit.Reason, audit.Actor, audit.CreatedAt)
		if err != nil {
			return findings.ErrConflict
		}
		return nil
	})
}

// deleteFindingRowsForSnapshot removes observations and audits before the
// findings rows they name. It runs inside the snapshot deletion transaction.
func (s *SQL) deleteFindingRowsForSnapshot(ctx context.Context, exec sqlExecer, snapshotID string) error {
	findingIDs := "SELECT finding_id FROM findings WHERE snapshot_id = ?"
	if _, err := exec.ExecContext(ctx, s.rebind("DELETE FROM finding_observations WHERE snapshot_id = ? OR finding_id IN ("+findingIDs+")"), snapshotID, snapshotID); err != nil {
		return mapSQLError(err)
	}
	if _, err := exec.ExecContext(ctx, s.rebind("DELETE FROM finding_severity_audits WHERE finding_id IN ("+findingIDs+")"), snapshotID); err != nil {
		return mapSQLError(err)
	}
	return nil
}
