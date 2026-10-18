package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// migrationTable records applied migrations so a rerun is a no-op.
const migrationTable = "schema_migrations"

// Migrate applies every *.sql file in fsys (sorted by file name) that has not
// been applied yet. Each file runs inside a transaction together with its
// bookkeeping row, so a failure leaves the schema at the previous version.
func (s *SQL) Migrate(ctx context.Context, fsys fs.FS) error {
	if fsys == nil {
		return errors.New("storage: nil migration filesystem")
	}
	if s.postgres {
		return s.migratePostgres(ctx, fsys)
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS `+migrationTable+` (
    version    TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
)`); err != nil {
		return mapSQLError(err)
	}
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		version := migrationVersion(name)
		applied, err := s.migrationApplied(ctx, version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		if err := s.applyMigration(ctx, version, string(body)); err != nil {
			return fmt.Errorf("storage: migration %s: %w", name, err)
		}
	}
	return nil
}

// migrationVersion is the sortable prefix of a migration file name.
func migrationVersion(name string) string {
	base := path.Base(name)
	if i := strings.Index(base, "_"); i > 0 {
		return base[:i]
	}
	return base
}

func (s *SQL) migrationApplied(ctx context.Context, version string) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(1) FROM `+migrationTable+` WHERE version = ?`), version).Scan(&count); err != nil {
		return false, mapSQLError(err)
	}
	return count > 0, nil
}

func (s *SQL) applyMigration(ctx context.Context, version, body string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	for _, stmt := range splitStatements(body) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("statement %q: %w", firstLine(stmt), err)
		}
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO `+migrationTable+` (version, applied_at) VALUES (?, ?)`),
		version, formatTime(time.Now().UTC())); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

// splitStatements splits a migration on semicolons, dropping empty statements
// and line comments. Migrations in this repository never contain semicolons
// inside string literals; the guard below makes that assumption explicit.
func splitStatements(body string) []string {
	var out []string
	var current strings.Builder
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")
		if strings.Contains(line, ";") {
			stmt := strings.TrimSpace(current.String())
			stmt = strings.TrimSuffix(stmt, ";")
			if strings.TrimSpace(stmt) != "" {
				out = append(out, stmt)
			}
			current.Reset()
		}
	}
	if rest := strings.TrimSpace(current.String()); rest != "" {
		out = append(out, rest)
	}
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 60 {
		return s[:60]
	}
	return s
}

// ErrNoMigrations reports an empty migration set, which is almost always a
// packaging mistake rather than a legitimate state.
var ErrNoMigrations = errors.New("storage: no migrations found")

// EnsureSchema applies the migration set and fails if it is empty.
func (s *SQL) EnsureSchema(ctx context.Context, fsys fs.FS) error {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return ErrNoMigrations
	}
	return s.Migrate(ctx, fsys)
}
