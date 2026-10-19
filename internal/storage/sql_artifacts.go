package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

const artifactScopeQuery = `SELECT s.project_id, COALESCE(b.source_id, 'legacy-' || s.project_id), s.snapshot_id
FROM snapshots s LEFT JOIN source_snapshots b ON b.snapshot_id = s.snapshot_id
WHERE s.project_id = ? AND s.snapshot_id = ? AND NOT EXISTS (SELECT 1 FROM snapshot_deletions d WHERE d.snapshot_id = s.snapshot_id)`

func scanArtifactScope(row *sql.Row) (artifact.Scope, error) {
	var scope artifact.Scope
	err := row.Scan(&scope.ProjectID, &scope.SourceID, &scope.SnapshotID)
	if errors.Is(err, sql.ErrNoRows) {
		err = artifact.ErrNotFound
	}
	return scope, err
}

func (s *SQL) ArtifactScope(ctx context.Context, project, snapshot string) (artifact.Scope, error) {
	return scanArtifactScope(s.db.QueryRowContext(ctx, s.rebind(artifactScopeQuery), project, snapshot))
}

func (s *SQL) PublishArtifact(ctx context.Context, ref artifact.Ref) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	return s.snapshotWrite(ctx, ref.Scope.SnapshotID, func(tx *sql.Tx) error {
		if lease, ok := workflow.ContextLease(ctx); s.postgres && ok {
			if err := validateWorkflowLeaseTx(ctx, tx, lease.RunID); err != nil {
				return err
			}
		}
		scope, err := scanArtifactScope(tx.QueryRowContext(ctx, s.rebind(artifactScopeQuery), ref.Scope.ProjectID, ref.Scope.SnapshotID))
		if err != nil {
			return err
		}
		if scope != ref.Scope {
			return artifact.ErrNotFound
		}
		raw, err := json.Marshal(ref)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO artifact_refs (artifact_id,project_id,source_id,snapshot_id,ref_json) VALUES (?,?,?,?,?) ON CONFLICT (artifact_id) DO NOTHING`), ref.ID, scope.ProjectID, scope.SourceID, scope.SnapshotID, string(raw))
		if err != nil {
			return err
		}
		var previous string
		if err := tx.QueryRowContext(ctx, s.rebind(`SELECT ref_json FROM artifact_refs WHERE artifact_id = ?`), ref.ID).Scan(&previous); err != nil {
			return err
		}
		var prior artifact.Ref
		if json.Unmarshal([]byte(previous), &prior) != nil || prior != ref {
			return artifact.ErrConflict
		}
		return nil
	})
}

func (s *SQL) LookupArtifact(ctx context.Context, scope artifact.Scope, id string) (artifact.Ref, error) {
	actual, err := s.ArtifactScope(ctx, scope.ProjectID, scope.SnapshotID)
	if err != nil {
		return artifact.Ref{}, err
	}
	if actual != scope {
		return artifact.Ref{}, artifact.ErrNotFound
	}
	var raw string
	err = s.db.QueryRowContext(ctx, s.rebind(`SELECT ref_json FROM artifact_refs WHERE artifact_id = ? AND project_id = ? AND source_id = ? AND snapshot_id = ?`), id, scope.ProjectID, scope.SourceID, scope.SnapshotID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return artifact.Ref{}, artifact.ErrNotFound
	}
	if err != nil {
		return artifact.Ref{}, err
	}
	var ref artifact.Ref
	err = json.Unmarshal([]byte(raw), &ref)
	if err == nil && ref.Scope != scope {
		return artifact.Ref{}, artifact.ErrIntegrity
	}
	return ref, err
}

func (s *SQL) ListArtifacts(ctx context.Context, scope artifact.Scope, cursor string, limit int) ([]artifact.Ref, error) {
	actual, err := s.ArtifactScope(ctx, scope.ProjectID, scope.SnapshotID)
	if err != nil {
		return nil, err
	}
	if actual != scope {
		return nil, artifact.ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT ref_json FROM artifact_refs WHERE project_id = ? AND source_id = ? AND snapshot_id = ? AND artifact_id > ? ORDER BY artifact_id LIMIT ?`), scope.ProjectID, scope.SourceID, scope.SnapshotID, cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := []artifact.Ref{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var ref artifact.Ref
		if err := json.Unmarshal([]byte(raw), &ref); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}
