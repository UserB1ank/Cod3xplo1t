package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func releaseKey(r plugin.Release) string {
	return r.PluginID + "@" + r.PluginVersion + "/" + r.OS + "/" + r.Arch + "/" + r.BuildID
}

func (m *Memory) PutPluginRelease(ctx context.Context, release plugin.Release) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := releaseKey(release)
	if prior, ok := m.pluginReleases[key]; ok {
		if prior != release {
			return plugin.ErrConflict
		}
		return nil
	}
	if m.pluginReleases == nil {
		m.pluginReleases = map[string]plugin.Release{}
	}
	m.pluginReleases[key] = release
	return nil
}

func (m *Memory) ListPluginReleases(ctx context.Context, id, version string) ([]plugin.Release, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rows := []plugin.Release{}
	for _, row := range m.pluginReleases {
		if row.PluginID == id && row.PluginVersion == version {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return releaseKey(rows[i]) < releaseKey(rows[j]) })
	return rows, nil
}

func (m *Memory) SavePluginInstallation(ctx context.Context, next plugin.Installation, expected int64) (plugin.Installation, error) {
	if err := ctx.Err(); err != nil {
		return plugin.Installation{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var prior *plugin.Installation
	if raw, ok := m.pluginInstallations[next.ID]; ok {
		prior = &plugin.Installation{}
		if json.Unmarshal(raw, prior) != nil {
			return plugin.Installation{}, plugin.ErrInvalid
		}
	}
	if err := plugin.ValidInstallation(next, prior, expected); err != nil {
		return plugin.Installation{}, err
	}
	if prior != nil && prior.Installed && !next.Installed {
		for _, raw := range m.pluginInvocations {
			var inv plugin.Invocation
			if json.Unmarshal(raw, &inv) != nil {
				return plugin.Installation{}, plugin.ErrInvalid
			}
			if inv.Request.PluginID == next.Release.PluginID && inv.Request.PluginVersion == next.Release.PluginVersion && inv.Request.PackageDigest == next.Release.PackageDigest && !plugin.Terminal(inv.Status) {
				return plugin.Installation{}, plugin.ErrConflict
			}
		}
	}
	if m.pluginInstallations == nil {
		m.pluginInstallations = map[string][]byte{}
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return plugin.Installation{}, err
	}
	m.pluginInstallations[next.ID] = raw
	return next, nil
}

func (m *Memory) ListPluginInstallations(ctx context.Context) ([]plugin.Installation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rows := []plugin.Installation{}
	for _, raw := range m.pluginInstallations {
		var row plugin.Installation
		if json.Unmarshal(raw, &row) != nil {
			return nil, plugin.ErrInvalid
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}

func (s *SQL) PutPluginRelease(ctx context.Context, r plugin.Release) error {
	if !s.postgres {
		return plugin.ErrUnsupported
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO plugin_releases (plugin_id,version,os,arch,build_id,package_digest,record_json) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (plugin_id,version,os,arch,build_id) DO NOTHING`, r.PluginID, r.PluginVersion, r.OS, r.Arch, r.BuildID, r.PackageDigest, string(raw))
	if err != nil {
		return err
	}
	var prior string
	if err = s.db.QueryRowContext(ctx, `SELECT record_json FROM plugin_releases WHERE plugin_id=$1 AND version=$2 AND os=$3 AND arch=$4 AND build_id=$5`, r.PluginID, r.PluginVersion, r.OS, r.Arch, r.BuildID).Scan(&prior); err != nil {
		return err
	}
	var stored plugin.Release
	if json.Unmarshal([]byte(prior), &stored) != nil {
		return plugin.ErrInvalid
	}
	if stored != r {
		return plugin.ErrConflict
	}
	return nil
}

func (s *SQL) ListPluginReleases(ctx context.Context, id, version string) ([]plugin.Release, error) {
	if !s.postgres {
		return nil, plugin.ErrUnsupported
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record_json FROM plugin_releases WHERE plugin_id=$1 AND version=$2 ORDER BY os,arch`, id, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []plugin.Release{}
	for rows.Next() {
		var raw string
		var r plugin.Release
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *SQL) SavePluginInstallation(ctx context.Context, next plugin.Installation, expected int64) (plugin.Installation, error) {
	if !s.postgres {
		return plugin.Installation{}, plugin.ErrUnsupported
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return plugin.Installation{}, err
	}
	defer tx.Rollback()
	var raw string
	err = tx.QueryRowContext(ctx, `SELECT record_json FROM plugin_installations WHERE installation_id=$1 FOR UPDATE`, next.ID).Scan(&raw)
	var prior *plugin.Installation
	if err == nil {
		prior = &plugin.Installation{}
		err = json.Unmarshal([]byte(raw), prior)
	} else if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return plugin.Installation{}, err
	}
	if err = plugin.ValidInstallation(next, prior, expected); err != nil {
		return plugin.Installation{}, err
	}
	if prior != nil && prior.Installed && !next.Installed {
		var active bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM plugin_invocations WHERE status IN ('CREATED','RUNNING') AND document_json::jsonb->'request'->>'plugin_id'=$1 AND document_json::jsonb->'request'->>'plugin_version'=$2 AND document_json::jsonb->'request'->>'package_digest'=$3)`, next.Release.PluginID, next.Release.PluginVersion, next.Release.PackageDigest).Scan(&active)
		if err != nil {
			return plugin.Installation{}, err
		}
		if active {
			return plugin.Installation{}, plugin.ErrConflict
		}
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return plugin.Installation{}, err
	}
	var changed sql.Result
	if prior == nil {
		changed, err = tx.ExecContext(ctx, `INSERT INTO plugin_installations (installation_id,plugin_id,version,package_digest,worker_id,record_version,enabled,installed,record_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, next.ID, next.Release.PluginID, next.Release.PluginVersion, next.Release.PackageDigest, next.WorkerID, next.Version, next.Enabled, next.Installed, string(encoded))
	} else {
		changed, err = tx.ExecContext(ctx, `UPDATE plugin_installations SET record_version=$1,enabled=$2,installed=$3,record_json=$4 WHERE installation_id=$5 AND record_version=$6`, next.Version, next.Enabled, next.Installed, string(encoded), next.ID, expected)
	}
	if err != nil {
		return plugin.Installation{}, err
	}
	count, err := changed.RowsAffected()
	if err != nil {
		return plugin.Installation{}, err
	}
	if count != 1 {
		return plugin.Installation{}, plugin.ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return plugin.Installation{}, err
	}
	return next, nil
}

func (s *SQL) ListPluginInstallations(ctx context.Context) ([]plugin.Installation, error) {
	if !s.postgres {
		return nil, plugin.ErrUnsupported
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record_json FROM plugin_installations ORDER BY installation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []plugin.Installation{}
	for rows.Next() {
		var raw string
		var r plugin.Installation
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
