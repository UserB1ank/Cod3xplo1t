package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func (s *SQL) CreateSupervisorSession(ctx context.Context, session SupervisorSession) (SupervisorSession, error) {
	if session.ID == "" || session.ProjectID == "" || session.SnapshotID == "" {
		return SupervisorSession{}, fmt.Errorf("%w: supervisor session identity is incomplete", path.ErrInvalidArgument)
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(1) FROM projects WHERE id = ?`), session.ProjectID).Scan(&exists); err != nil {
		return SupervisorSession{}, mapSQLError(err)
	}
	if exists == 0 {
		return SupervisorSession{}, fmt.Errorf("%w: project %s", ErrNotFound, session.ProjectID)
	}
	session.Version = 1
	if session.Messages == nil {
		session.Messages = []SupervisorMessage{}
	}
	if session.Runs == nil {
		session.Runs = []SupervisorRun{}
	}
	if session.Events == nil {
		session.Events = []SupervisorEvent{}
	}
	raw, err := jsonString(session)
	if err != nil {
		return SupervisorSession{}, err
	}
	_, err = s.db.ExecContext(ctx, s.rebind(`INSERT INTO supervisor_sessions
(session_id, project_id, snapshot_id, title, state, document_json, created_at, updated_at, version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`),
		session.ID, session.ProjectID, session.SnapshotID, session.Title, session.State, raw, session.CreatedAt, session.UpdatedAt)
	if err != nil {
		return SupervisorSession{}, mapSQLError(err)
	}
	return session, nil
}

func (s *SQL) GetSupervisorSession(ctx context.Context, projectID, sessionID string) (SupervisorSession, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM supervisor_sessions WHERE project_id = ? AND session_id = ?`), projectID, sessionID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return SupervisorSession{}, fmt.Errorf("%w: supervisor session %s", ErrNotFound, sessionID)
	}
	if err != nil {
		return SupervisorSession{}, mapSQLError(err)
	}
	var session SupervisorSession
	if err := decodeJSON(raw, &session); err != nil {
		return SupervisorSession{}, err
	}
	return session, nil
}

func (s *SQL) ListSupervisorSessions(ctx context.Context, projectID string, limit int) ([]SupervisorSession, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: limit must be 1–100", path.ErrInvalidArgument)
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT document_json FROM supervisor_sessions WHERE project_id = ? ORDER BY created_at DESC, session_id DESC LIMIT ?`), projectID, limit)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	out := []SupervisorSession{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var session SupervisorSession
		if err := decodeJSON(raw, &session); err != nil {
			return nil, err
		}
		out = append(out, session)
	}
	return out, rows.Err()
}

func (s *SQL) SaveSupervisorSession(ctx context.Context, session SupervisorSession, expectedVersion int64) (SupervisorSession, error) {
	if expectedVersion <= 0 {
		return SupervisorSession{}, fmt.Errorf("%w: expected version is required", path.ErrInvalidArgument)
	}
	// The document carries the same version as the row. Advance it before
	// marshaling, otherwise a reload would return the old version and every
	// subsequent save would conflict.
	session.Version = expectedVersion + 1
	raw, err := jsonString(session)
	if err != nil {
		return SupervisorSession{}, err
	}
	res, err := s.db.ExecContext(ctx, s.rebind(`UPDATE supervisor_sessions
SET state = ?, document_json = ?, updated_at = ?, version = version + 1
WHERE session_id = ? AND project_id = ? AND version = ?`),
		session.State, raw, session.UpdatedAt, session.ID, session.ProjectID, expectedVersion)
	if err != nil {
		return SupervisorSession{}, mapSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return SupervisorSession{}, err
	}
	if affected == 0 {
		if _, getErr := s.GetSupervisorSession(ctx, session.ProjectID, session.ID); getErr != nil {
			return SupervisorSession{}, getErr
		}
		return SupervisorSession{}, fmt.Errorf("%w: supervisor session version", ErrConflict)
	}
	return session, nil
}
