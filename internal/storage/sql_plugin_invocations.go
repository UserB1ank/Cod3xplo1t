package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func (s *SQL) RecoverInvocations(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE plugin_invocations SET version = version WHERE status IN ('CREATED','RUNNING')`); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT document_json FROM plugin_invocations WHERE status IN ('CREATED','RUNNING')`)
	if err != nil {
		return err
	}
	active := []plugin.Invocation{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var inv plugin.Invocation
		if err := json.Unmarshal([]byte(raw), &inv); err != nil {
			rows.Close()
			return err
		}
		active = append(active, inv)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, inv := range active {
		inv.Status = "FAILED"
		inv.ErrorCode = "host_restarted"
		inv.Version++
		inv.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		inv.Outputs = []artifact.Ref{}
		raw, err := json.Marshal(inv)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE plugin_invocations SET status = ?, version = ?, document_json = ? WHERE invocation_id = ?`), inv.Status, inv.Version, string(raw), inv.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQL) CreateInvocation(ctx context.Context, inv plugin.Invocation) (plugin.Invocation, bool, error) {
	created := false
	var result plugin.Invocation
	err := s.snapshotWrite(ctx, inv.Request.Scope.SnapshotID, func(tx *sql.Tx) error {
		scope, err := scanArtifactScope(tx.QueryRowContext(ctx, s.rebind(artifactScopeQuery), inv.Request.Scope.ProjectID, inv.Request.Scope.SnapshotID))
		if err != nil || scope != inv.Request.Scope {
			return plugin.ErrNotFound
		}
		var previous string
		err = tx.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM plugin_invocations WHERE invocation_id = ?`), inv.ID).Scan(&previous)
		if err == nil {
			if json.Unmarshal([]byte(previous), &result) != nil || result.RequestDigest != inv.RequestDigest {
				return plugin.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		raw, err := json.Marshal(inv)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO plugin_invocations (invocation_id,project_id,source_id,snapshot_id,version,status,document_json) VALUES (?,?,?,?,?,?,?)`), inv.ID, scope.ProjectID, scope.SourceID, scope.SnapshotID, inv.Version, inv.Status, string(raw))
		created = err == nil
		result = inv
		return err
	})
	return result, created, err
}
func (s *SQL) SaveInvocation(ctx context.Context, inv plugin.Invocation, expected int64) error {
	return s.snapshotWrite(ctx, inv.Request.Scope.SnapshotID, func(tx *sql.Tx) error {
		var raw string
		if err := tx.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM plugin_invocations WHERE invocation_id = ?`), inv.ID).Scan(&raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return plugin.ErrNotFound
			}
			return err
		}
		var prior plugin.Invocation
		if json.Unmarshal([]byte(raw), &prior) != nil {
			return plugin.ErrInvalid
		}
		if prior.Version != expected || inv.Version != expected+1 || prior.RequestDigest != inv.RequestDigest || !plugin.ValidTransition(prior.Status, inv.Status) {
			return plugin.ErrConflict
		}
		for _, ref := range inv.Outputs {
			if !plugin.PublishableOutput(inv, ref) {
				return plugin.ErrConflict
			}
			if ref.Scope != inv.Request.Scope || ref.Producer.InvocationID != inv.ID || ref.Validate() != nil {
				return plugin.ErrInvalid
			}
			encoded, err := json.Marshal(ref)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO artifact_refs (artifact_id,project_id,source_id,snapshot_id,ref_json) VALUES (?,?,?,?,?) ON CONFLICT (artifact_id) DO NOTHING`), ref.ID, ref.Scope.ProjectID, ref.Scope.SourceID, ref.Scope.SnapshotID, string(encoded))
			if err != nil {
				return err
			}
			var existing string
			if err := tx.QueryRowContext(ctx, s.rebind(`SELECT ref_json FROM artifact_refs WHERE artifact_id = ?`), ref.ID).Scan(&existing); err != nil {
				return err
			}
			var old artifact.Ref
			if json.Unmarshal([]byte(existing), &old) != nil || old != ref {
				return plugin.ErrConflict
			}
		}
		updated, err := json.Marshal(inv)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, s.rebind(`UPDATE plugin_invocations SET version = ?, status = ?, document_json = ? WHERE invocation_id = ? AND version = ?`), inv.Version, inv.Status, string(updated), inv.ID, expected)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return plugin.ErrConflict
		}
		return nil
	})
}
func (s *SQL) GetInvocation(ctx context.Context, scope artifact.Scope, id string) (plugin.Invocation, error) {
	actual, err := s.ArtifactScope(ctx, scope.ProjectID, scope.SnapshotID)
	if err != nil || actual != scope {
		return plugin.Invocation{}, plugin.ErrNotFound
	}
	var raw string
	err = s.db.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM plugin_invocations WHERE invocation_id = ? AND project_id = ? AND source_id = ? AND snapshot_id = ?`), id, scope.ProjectID, scope.SourceID, scope.SnapshotID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return plugin.Invocation{}, plugin.ErrNotFound
	}
	if err != nil {
		return plugin.Invocation{}, err
	}
	var inv plugin.Invocation
	err = json.Unmarshal([]byte(raw), &inv)
	return inv, err
}
func (s *SQL) ListInvocations(ctx context.Context, scope artifact.Scope, cursor string, limit int) ([]plugin.Invocation, error) {
	actual, err := s.ArtifactScope(ctx, scope.ProjectID, scope.SnapshotID)
	if err != nil || actual != scope {
		return nil, plugin.ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT document_json FROM plugin_invocations WHERE project_id = ? AND source_id = ? AND snapshot_id = ? AND invocation_id > ? ORDER BY invocation_id LIMIT ?`), scope.ProjectID, scope.SourceID, scope.SnapshotID, cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []plugin.Invocation{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var inv plugin.Invocation
		if err := json.Unmarshal([]byte(raw), &inv); err != nil {
			return nil, err
		}
		result = append(result, inv)
	}
	return result, rows.Err()
}
