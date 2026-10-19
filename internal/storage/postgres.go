package storage

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"time"
)

func (s *SQL) lockSnapshotTx(ctx context.Context, tx *sql.Tx, id string) error {
	if !s.postgres {
		return nil
	}
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "snapshot:"+id)
	return err
}

func (s *SQL) deleteCatalogSnapshot(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.lockSnapshotTx(ctx, tx, id); err != nil {
		return err
	}
	for _, table := range []string{"workflow_node_claims", "workflow_leases"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE run_id IN (SELECT run_id FROM workflow_runs WHERE snapshot_id=$1)`, id); err != nil {
			return err
		}
	}
	for _, table := range []string{"workflow_runs", "workflow_plans"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE snapshot_id=$1`, id); err != nil {
			return err
		}
	}
	if _, err := s.deleteVerificationRowsForSnapshot(ctx, tx, id); err != nil {
		return err
	}
	if _, err := s.deleteAgentRowsForSnapshot(ctx, tx, id); err != nil {
		return err
	}
	if _, err := s.deleteAuditRowsForSnapshot(ctx, tx, id); err != nil {
		return err
	}
	for _, table := range []string{"knowledge_analysis_paths", "knowledge_analyses", "knowledge_revisions", "knowledge_outbox", "plugin_invocations", "analyses", "artifact_refs", "scg_modules", "scg_files", "scg_symbols", "scg_call_sites", "scg_edges", "graph_builds", "asg_nodes", "asg_edges", "asg_builds"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE snapshot_id=$1`, id); err != nil {
			return mapSQLError(err)
		}
	}
	if err := s.deleteSourceSnapshot(ctx, tx, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM snapshots WHERE snapshot_id=$1`, id)
	if err != nil {
		return mapSQLError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		var marked bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM snapshot_deletions WHERE snapshot_id=$1)`, id).Scan(&marked); err != nil {
			return err
		}
		if !marked {
			return ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE snapshot_deletions SET completed=1 WHERE snapshot_id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// The lock is acquired before CREATE TABLE and held on the same transaction
// connection throughout discovery, DDL and bookkeeping. Transaction-scoped
// locks also release automatically on cancellation or connection loss.
func (s *SQL) migratePostgres(ctx context.Context, files fs.FS) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(1129271877, 15)"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	names, err := fs.Glob(files, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		version := migrationVersion(name)
		var applied bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		for _, statement := range splitStatements(string(body)) {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migration %s failed: %w", name, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)`, version, formatTime(time.Now().UTC())); err != nil {
			return err
		}
	}
	return tx.Commit()
}
