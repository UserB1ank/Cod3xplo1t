package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func (s *SQL) PutPlugin(ctx context.Context, record plugin.Record) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.rebind(`INSERT INTO plugin_versions (plugin_id,version,record_json) VALUES (?,?,?) ON CONFLICT (plugin_id,version) DO NOTHING`), record.Manifest.ID, record.Manifest.Version, string(raw))
	if err != nil {
		return err
	}
	prior, err := s.GetPlugin(ctx, record.Manifest.ID, record.Manifest.Version)
	if err != nil {
		return err
	}
	if prior.ManifestDigest != record.ManifestDigest || prior.PackageDigest != record.PackageDigest {
		return plugin.ErrConflict
	}
	return nil
}
func (s *SQL) GetPlugin(ctx context.Context, id, version string) (plugin.Record, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT record_json FROM plugin_versions WHERE plugin_id = ? AND version = ?`), id, version).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return plugin.Record{}, plugin.ErrNotFound
	}
	if err != nil {
		return plugin.Record{}, err
	}
	var record plugin.Record
	err = json.Unmarshal([]byte(raw), &record)
	return record, err
}
func (s *SQL) ListPlugins(ctx context.Context, cursor string, limit int) ([]plugin.Record, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT record_json FROM plugin_versions WHERE plugin_id || '@' || version > ? ORDER BY plugin_id || '@' || version LIMIT ?`), cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []plugin.Record{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var record plugin.Record
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}
