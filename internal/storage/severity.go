package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func validGrade(grade string) bool { return grade == "high" || grade == "medium" || grade == "low" }

func (m *Memory) SetFindingSeverity(id, severity string, expectedVersion int64) error {
	if !validGrade(severity) {
		return fmt.Errorf("%w: severity must be high, medium or low", verify.ErrInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	finding, ok := m.findings[id]
	if !ok {
		return verify.ErrNotFound
	}
	if err := m.snapshotWritableLocked(finding.SnapshotID); err != nil {
		return err
	}
	if expectedVersion < 1 || finding.Version != expectedVersion {
		return verify.ErrConflict
	}
	finding.Severity, finding.UpdatedAt = severity, verifyNow()
	finding.Version++
	m.findings[id] = finding
	return nil
}

func (s *SQL) SetFindingSeverity(id, severity string, expectedVersion int64) error {
	if !validGrade(severity) {
		return fmt.Errorf("%w: severity must be high, medium or low", verify.ErrInvalidArgument)
	}
	if expectedVersion < 1 {
		return verify.ErrConflict
	}
	finding, err := s.GetFinding(id)
	if err != nil {
		return err
	}
	return s.snapshotWrite(context.Background(), finding.SnapshotID, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(context.Background(), s.rebind("UPDATE findings SET severity = ?, version = version + 1, updated_at = ? WHERE finding_id = ? AND version = ?"), severity, verifyNow(), id, expectedVersion)
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
		return nil
	})
}
