package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

func (s *SQL) CreateSource(ctx context.Context, source SourceDefinition) error {
	source.Version = 1
	document, err := json.Marshal(source)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO project_sources (source_id, project_id, version, definition_json)
SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM projects WHERE id = ?)`), source.ID, source.ProjectID, source.Version, string(document), source.ProjectID)
	if err != nil {
		return mapSQLError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQL) RegisterSourceSnapshot(ctx context.Context, source SourceDefinition, snapshot *repository.Snapshot) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	// Always acquire the snapshot fence before the source row, including replay.
	// Deletion uses the same order when clearing a source's latest snapshot.
	if err := s.snapshotRegistrationTx(ctx, tx, snapshot); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, s.rebind(`UPDATE project_sources SET version = version WHERE source_id = ? AND project_id = ? AND version = ?`), source.ID, source.ProjectID, source.Version)
	if err != nil {
		return mapSQLError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	var document string
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT definition_json FROM project_sources WHERE source_id = ?`), source.ID).Scan(&document); err != nil {
		return mapSQLError(err)
	}
	var current SourceDefinition
	if err := json.Unmarshal([]byte(document), &current); err != nil {
		return err
	}
	var binding SourceSnapshot
	err = tx.QueryRowContext(ctx, s.rebind(`SELECT source_id, source_version FROM source_snapshots WHERE snapshot_id = ?`), snapshot.SnapshotID).Scan(&binding.SourceID, &binding.SourceVersion)
	if err == nil {
		if binding.SourceID != source.ID || binding.SourceVersion != source.Version {
			return ErrConflict
		}
		current.Snapshot, current.Files = snapshot.SnapshotID, snapshot.Stats.Files
		raw, err := json.Marshal(current)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE project_sources SET definition_json = ? WHERE source_id = ?`), string(raw), source.ID); err != nil {
			return mapSQLError(err)
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return mapSQLError(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	var priorProject, priorDocument string
	err = tx.QueryRowContext(ctx, s.rebind(`SELECT project_id, metadata_json FROM snapshots WHERE snapshot_id = ?`), snapshot.SnapshotID).Scan(&priorProject, &priorDocument)
	if err == nil {
		if priorProject != source.ProjectID || !sameDocument([]byte(priorDocument), raw) {
			return ErrConflict
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO snapshots (snapshot_id, project_id, commit_sha, vcs, worktree_dirty, created_at, metadata_json, manifest_json) VALUES (?, ?, ?, ?, 0, ?, ?, NULL)`), snapshot.SnapshotID, source.ProjectID, snapshot.Commit, snapshot.VCS, snapshot.CreatedAt, string(raw))
		if err != nil {
			return mapSQLError(err)
		}
	} else {
		return mapSQLError(err)
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO source_snapshots (snapshot_id, source_id, source_version) VALUES (?, ?, ?)`), snapshot.SnapshotID, source.ID, source.Version); err != nil {
		return mapSQLError(err)
	}
	current.Snapshot, current.Files, current.Revision = snapshot.SnapshotID, snapshot.Stats.Files, current.Revision+1
	raw, err = json.Marshal(current)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE project_sources SET definition_json = ? WHERE source_id = ?`), string(raw), source.ID); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

func (s *SQL) GetSourceSnapshot(ctx context.Context, id string) (SourceSnapshot, error) {
	var result SourceSnapshot
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT source_id, source_version FROM source_snapshots WHERE snapshot_id = ?`), id).Scan(&result.SourceID, &result.SourceVersion)
	return result, mapSQLError(err)
}

func (s *SQL) deleteSourceSnapshot(ctx context.Context, tx *sql.Tx, id string) error {
	var sourceID, document string
	err := tx.QueryRowContext(ctx, s.rebind(`SELECT p.source_id, p.definition_json FROM project_sources p JOIN source_snapshots b ON b.source_id = p.source_id WHERE b.snapshot_id = ?`), id).Scan(&sourceID, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return mapSQLError(err)
	}
	var source SourceDefinition
	if err := json.Unmarshal([]byte(document), &source); err != nil {
		return err
	}
	if source.Snapshot == id {
		source.Snapshot, source.Files = "", 0
		raw, err := json.Marshal(source)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE project_sources SET definition_json = ? WHERE source_id = ?`), string(raw), sourceID); err != nil {
			return mapSQLError(err)
		}
	}
	_, err = tx.ExecContext(ctx, s.rebind(`DELETE FROM source_snapshots WHERE snapshot_id = ?`), id)
	return mapSQLError(err)
}

func (s *SQL) GetSource(ctx context.Context, id string) (SourceDefinition, error) {
	var document string
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT definition_json FROM project_sources WHERE source_id = ?`), id).Scan(&document); err != nil {
		return SourceDefinition{}, mapSQLError(err)
	}
	var source SourceDefinition
	err := json.Unmarshal([]byte(document), &source)
	return source, err
}

func (s *SQL) ListSources(ctx context.Context, project, cursor string, limit int) ([]SourceDefinition, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT definition_json FROM project_sources WHERE project_id = ? AND source_id > ? ORDER BY source_id LIMIT ?`), project, cursor, limit)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	result := []SourceDefinition{}
	for rows.Next() {
		var document string
		if err := rows.Scan(&document); err != nil {
			return nil, err
		}
		var source SourceDefinition
		if err := json.Unmarshal([]byte(document), &source); err != nil {
			return nil, err
		}
		result = append(result, source)
	}
	return result, rows.Err()
}
