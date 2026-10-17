package storage

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func (m *Memory) PutPlugin(ctx context.Context, record plugin.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := record.Manifest.ID + "@" + record.Manifest.Version
	if raw, ok := m.plugins[key]; ok {
		var prior plugin.Record
		if json.Unmarshal(raw, &prior) != nil || prior.ManifestDigest != record.ManifestDigest || prior.PackageDigest != record.PackageDigest {
			return plugin.ErrConflict
		}
		return nil
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if m.plugins == nil {
		m.plugins = map[string][]byte{}
	}
	m.plugins[key] = raw
	return nil
}
func (m *Memory) GetPlugin(ctx context.Context, id, version string) (plugin.Record, error) {
	if err := ctx.Err(); err != nil {
		return plugin.Record{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	raw, ok := m.plugins[id+"@"+version]
	if !ok {
		return plugin.Record{}, plugin.ErrNotFound
	}
	var record plugin.Record
	err := json.Unmarshal(raw, &record)
	return record, err
}
func (m *Memory) ListPlugins(ctx context.Context, cursor string, limit int) ([]plugin.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := []string{}
	for key := range m.plugins {
		if key > cursor {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	rows := []plugin.Record{}
	for _, key := range keys {
		var record plugin.Record
		if err := json.Unmarshal(m.plugins[key], &record); err != nil {
			return nil, err
		}
		rows = append(rows, record)
	}
	return rows, nil
}
