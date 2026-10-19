package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
)

// SettingsRepository returns the SQL model-settings store. The deployment
// profile decides whether it is used: PostgreSQL does, while SQLite and memory
// retain the workspace-file implementation.
func SettingsRepository(store Store) (llm.Repository, bool) {
	s, ok := store.(*SQL)
	if !ok {
		return nil, false
	}
	return newSQLSettings(s), true
}

type sqlSettings struct{ s *SQL }

func newSQLSettings(s *SQL) llm.Repository { return sqlSettings{s: s} }

func (r sqlSettings) LoadLLMSettings(ctx context.Context) ([]byte, int64, bool, error) {
	var ciphertext []byte
	var version int64
	err := r.s.db.QueryRowContext(ctx, `SELECT ciphertext, version FROM llm_settings WHERE singleton = 1`).Scan(&ciphertext, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, mapSQLError(err)
	}
	return append([]byte(nil), ciphertext...), version, true, nil
}

func (r sqlSettings) SaveLLMSettings(ctx context.Context, ciphertext []byte, expected int64) (int64, bool, error) {
	if len(ciphertext) == 0 {
		return 0, false, fmt.Errorf("%w: empty settings ciphertext", ErrConflict)
	}
	if expected < 0 {
		return 0, false, nil
	}
	now := time.Now().UTC().UnixMilli()
	var version int64
	var err error
	if expected == 0 {
		// The first write is exclusive: it only succeeds when no configuration
		// exists, so two instances cannot both initialize the row.
		err = r.s.db.QueryRowContext(ctx, r.s.rebind(`INSERT INTO llm_settings (singleton, ciphertext, version, updated_at)
VALUES (1, ?, 1, ?) ON CONFLICT (singleton) DO NOTHING RETURNING version`), ciphertext, now).Scan(&version)
	} else {
		err = r.s.db.QueryRowContext(ctx, r.s.rebind(`UPDATE llm_settings SET ciphertext = ?, version = version + 1, updated_at = ?
WHERE singleton = 1 AND version = ? RETURNING version`), ciphertext, now, expected).Scan(&version)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, mapSQLError(err)
	}
	return version, true, nil
}
