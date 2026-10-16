package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

// SQL is a database/sql backed Store. The driver is chosen by the caller, so the
// same implementation serves SQLite (MVP default) and PostgreSQL.
type SQL struct {
	db       *sql.DB
	postgres bool
}

// OpenSQL opens a database and verifies connectivity. Driver names are matched
// loosely: anything containing "postgres", "pgx" or "pq" is treated as
// PostgreSQL, everything else uses question-mark placeholders.
func OpenSQL(ctx context.Context, driver, dsn string) (*SQL, error) {
	if strings.TrimSpace(driver) == "" {
		return nil, errors.New("storage: empty driver name")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", driver, err)
	}
	// A SQLite :memory: database is per connection, and P1 writes are short;
	// a single connection keeps behaviour predictable on every platform.
	if !isPostgresDriver(driver) {
		db.SetMaxOpenConns(1)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: connect %s: %w", driver, err)
	}
	return &SQL{db: db, postgres: isPostgresDriver(driver)}, nil
}

func isPostgresDriver(driver string) bool {
	d := strings.ToLower(driver)
	return strings.Contains(d, "postgres") || strings.Contains(d, "pgx") || d == "pq"
}

// DB exposes the underlying handle for callers that need their own statements.
func (s *SQL) DB() *sql.DB { return s.db }

// Close implements Store.
func (s *SQL) Close() error { return s.db.Close() }

// rebind converts question-mark placeholders to the dialect's syntax.
func (s *SQL) rebind(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// PutProject implements Store.
func (s *SQL) PutProject(ctx context.Context, p Project) error {
	if p.ID == "" {
		return fmt.Errorf("%w: project id is required", ErrConflict)
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.rebind(`
INSERT INTO projects (id, name, source, identity_kind, identity, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    name = excluded.name,
    source = excluded.source,
    identity_kind = excluded.identity_kind,
    identity = excluded.identity,
    updated_at = excluded.updated_at`),
		p.ID, p.Name, p.Source, p.IdentityKind, p.Identity, formatTime(p.CreatedAt), formatTime(p.UpdatedAt))
	if err != nil {
		return mapSQLError(err)
	}
	return nil
}

// GetProject implements Store.
func (s *SQL) GetProject(ctx context.Context, id string) (Project, error) {
	row := s.db.QueryRowContext(ctx, s.rebind(`
SELECT id, name, source, identity_kind, identity, created_at, updated_at FROM projects WHERE id = ?`), id)
	var p Project
	var created, updated string
	if err := row.Scan(&p.ID, &p.Name, &p.Source, &p.IdentityKind, &p.Identity, &created, &updated); err != nil {
		return Project{}, mapSQLError(err)
	}
	p.CreatedAt = parseStoredTime(created)
	p.UpdatedAt = parseStoredTime(updated)
	return p, nil
}

// ListProjects implements Store.
func (s *SQL) ListProjects(ctx context.Context) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, source, identity_kind, identity, created_at, updated_at FROM projects ORDER BY id`)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var p Project
		var created, updated string
		if err := rows.Scan(&p.ID, &p.Name, &p.Source, &p.IdentityKind, &p.Identity, &created, &updated); err != nil {
			return nil, err
		}
		p.CreatedAt = parseStoredTime(created)
		p.UpdatedAt = parseStoredTime(updated)
		out = append(out, p)
	}
	return out, rows.Err()
}

// PutSnapshot implements Store.
func (s *SQL) PutSnapshot(ctx context.Context, projectID string, snap *repository.Snapshot) error {
	if snap == nil || snap.SnapshotID == "" {
		return fmt.Errorf("%w: snapshot id is required", ErrConflict)
	}
	doc, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	created := parseStoredTime(snap.CreatedAt)
	if created.IsZero() {
		created = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()

	var existing string
	err = tx.QueryRowContext(ctx, s.rebind(`SELECT metadata_json FROM snapshots WHERE snapshot_id = ?`), snap.SnapshotID).Scan(&existing)
	switch {
	case err == nil:
		if !sameDocument([]byte(existing), doc) {
			return fmt.Errorf("%w: snapshot %s already exists with different content", ErrConflict, snap.SnapshotID)
		}
		return tx.Commit()
	case !errors.Is(err, sql.ErrNoRows):
		return mapSQLError(err)
	}

	var projectExists int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(1) FROM projects WHERE id = ?`), projectID).Scan(&projectExists); err != nil {
		return mapSQLError(err)
	}
	if projectExists == 0 {
		return fmt.Errorf("%w: project %s", ErrNotFound, projectID)
	}
	dirty := 0
	if snap.WorktreeDirty {
		dirty = 1
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`
INSERT INTO snapshots (snapshot_id, project_id, commit_sha, vcs, worktree_dirty, created_at, metadata_json, manifest_json)
VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`),
		snap.SnapshotID, projectID, snap.Commit, snap.VCS, dirty, formatTime(created), string(doc)); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

// GetSnapshot implements Store.
func (s *SQL) GetSnapshot(ctx context.Context, id string) (*repository.Snapshot, error) {
	var doc string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT metadata_json FROM snapshots WHERE snapshot_id = ?`), id).Scan(&doc)
	if err != nil {
		return nil, mapSQLError(err)
	}
	var snap repository.Snapshot
	if err := json.Unmarshal([]byte(doc), &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// ListSnapshots implements Store.
func (s *SQL) ListSnapshots(ctx context.Context, projectID string) ([]SnapshotRecord, error) {
	query := `
SELECT snapshot_id, project_id, commit_sha, vcs, worktree_dirty, created_at, manifest_json
FROM snapshots`
	args := []any{}
	if projectID != "" {
		query += ` WHERE project_id = ?`
		args = append(args, projectID)
	}
	query += ` ORDER BY created_at, snapshot_id`
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var out []SnapshotRecord
	for rows.Next() {
		var rec SnapshotRecord
		var dirty int
		var created string
		var manifest sql.NullString
		if err := rows.Scan(&rec.SnapshotID, &rec.ProjectID, &rec.Commit, &rec.VCS, &dirty, &created, &manifest); err != nil {
			return nil, err
		}
		rec.WorktreeDirty = dirty != 0
		rec.CreatedAt = parseStoredTime(created)
		if manifest.Valid && manifest.String != "" {
			rec.ManifestPresent = true
			var mf analysis.Manifest
			if err := json.Unmarshal([]byte(manifest.String), &mf); err == nil {
				rec.AnalysisID = mf.AnalysisID
			}
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// DeleteSnapshot implements Store.
func (s *SQL) DeleteSnapshot(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM analyses WHERE snapshot_id = ?`), id); err != nil {
		return mapSQLError(err)
	}
	// The graph belongs to the snapshot: leaving it behind would let a deleted
	// snapshot keep answering queries.
	for _, table := range []string{"scg_modules", "scg_files", "scg_symbols", "scg_call_sites", "scg_edges", "graph_builds"} {
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM `+table+` WHERE snapshot_id = ?`), id); err != nil {
			return mapSQLError(err)
		}
	}
	res, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM snapshots WHERE snapshot_id = ?`), id)
	if err != nil {
		return mapSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return mapSQLError(err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: snapshot %s", ErrNotFound, id)
	}
	return tx.Commit()
}

// PutManifest implements Store.
func (s *SQL) PutManifest(ctx context.Context, snapshotID string, mf *analysis.Manifest) error {
	if mf == nil {
		return fmt.Errorf("%w: nil manifest", ErrConflict)
	}
	doc, err := json.Marshal(mf)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()

	var existing sql.NullString
	err = tx.QueryRowContext(ctx, s.rebind(`SELECT manifest_json FROM snapshots WHERE snapshot_id = ?`), snapshotID).Scan(&existing)
	if err != nil {
		return mapSQLError(err)
	}
	if existing.Valid && existing.String != "" {
		if sameAnalysis([]byte(existing.String), doc) {
			// Same analysis identity: the stored manifest stays authoritative.
			return tx.Commit()
		}
		if !sameDocument([]byte(existing.String), doc) {
			var prev analysis.Manifest
			if err := json.Unmarshal([]byte(existing.String), &prev); err == nil && prev.AnalysisID != mf.AnalysisID {
				return fmt.Errorf("%w: snapshot %s already has analysis %s; re-analysis with a different rule set or configuration needs a new snapshot",
					ErrConflict, snapshotID, prev.AnalysisID)
			}
			return fmt.Errorf("%w: manifest for snapshot %s already exists with different content", ErrConflict, snapshotID)
		}
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE snapshots SET manifest_json = ? WHERE snapshot_id = ?`), string(doc), snapshotID); err != nil {
		return mapSQLError(err)
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`
INSERT INTO analyses (analysis_id, snapshot_id, engine, engine_version, ruleset_hash, config_hash, created_at, document_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (analysis_id) DO NOTHING`),
		mf.AnalysisID, snapshotID, mf.Engine.Name, mf.Engine.Version, mf.RulesetHash, mf.ConfigHash,
		formatTime(time.Now().UTC()), string(doc)); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

// GetManifest implements Store.
func (s *SQL) GetManifest(ctx context.Context, snapshotID string) (*analysis.Manifest, error) {
	var doc sql.NullString
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT manifest_json FROM snapshots WHERE snapshot_id = ?`), snapshotID).Scan(&doc); err != nil {
		return nil, mapSQLError(err)
	}
	if !doc.Valid || doc.String == "" {
		return nil, fmt.Errorf("%w: manifest for snapshot %s", ErrNotFound, snapshotID)
	}
	var mf analysis.Manifest
	if err := json.Unmarshal([]byte(doc.String), &mf); err != nil {
		return nil, err
	}
	return &mf, nil
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// mapSQLError translates driver errors into the storage error vocabulary where
// the meaning is unambiguous.
func mapSQLError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unique constraint") || strings.Contains(msg, "duplicate key") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	if strings.Contains(msg, "foreign key") {
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	return err
}
