package storage

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func (m *Memory) RecoverInvocations(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, raw := range m.pluginInvocations {
		var inv plugin.Invocation
		if err := json.Unmarshal(raw, &inv); err != nil {
			return err
		}
		if plugin.Terminal(inv.Status) {
			continue
		}
		inv.Status = "FAILED"
		inv.ErrorCode = "host_restarted"
		inv.Version++
		inv.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		inv.Outputs = []artifact.Ref{}
		updated, err := json.Marshal(inv)
		if err != nil {
			return err
		}
		m.pluginInvocations[id] = updated
	}
	return nil
}

func (m *Memory) CreateInvocation(ctx context.Context, inv plugin.Invocation) (plugin.Invocation, bool, error) {
	if err := ctx.Err(); err != nil {
		return plugin.Invocation{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.artifactScopeLocked(inv.Request.Scope) {
		return plugin.Invocation{}, false, plugin.ErrNotFound
	}
	if raw, ok := m.pluginInvocations[inv.ID]; ok {
		var prior plugin.Invocation
		if json.Unmarshal(raw, &prior) != nil || prior.RequestDigest != inv.RequestDigest {
			return plugin.Invocation{}, false, plugin.ErrConflict
		}
		return prior, false, nil
	}
	raw, err := json.Marshal(inv)
	if err != nil {
		return plugin.Invocation{}, false, err
	}
	if m.pluginInvocations == nil {
		m.pluginInvocations = map[string][]byte{}
	}
	m.pluginInvocations[inv.ID] = raw
	return inv, true, nil
}
func (m *Memory) SaveInvocation(ctx context.Context, inv plugin.Invocation, expected int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var prior plugin.Invocation
	raw, ok := m.pluginInvocations[inv.ID]
	if !ok || json.Unmarshal(raw, &prior) != nil || !m.artifactScopeLocked(inv.Request.Scope) {
		return plugin.ErrNotFound
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
		if old, ok := m.artifacts[ref.ID]; ok && old != ref {
			return plugin.ErrConflict
		}
	}
	data, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	for _, ref := range inv.Outputs {
		if m.artifacts == nil {
			m.artifacts = map[string]artifact.Ref{}
		}
		m.artifacts[ref.ID] = ref
	}
	m.pluginInvocations[inv.ID] = data
	return nil
}
func (m *Memory) GetInvocation(ctx context.Context, scope artifact.Scope, id string) (plugin.Invocation, error) {
	if err := ctx.Err(); err != nil {
		return plugin.Invocation{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var inv plugin.Invocation
	raw, ok := m.pluginInvocations[id]
	if !ok || json.Unmarshal(raw, &inv) != nil || inv.Request.Scope != scope || !m.artifactScopeLocked(scope) {
		return plugin.Invocation{}, plugin.ErrNotFound
	}
	return inv, nil
}
func (m *Memory) ListInvocations(ctx context.Context, scope artifact.Scope, cursor string, limit int) ([]plugin.Invocation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.artifactScopeLocked(scope) {
		return nil, plugin.ErrNotFound
	}
	rows := []plugin.Invocation{}
	for id, raw := range m.pluginInvocations {
		var inv plugin.Invocation
		if id > cursor && json.Unmarshal(raw, &inv) == nil && inv.Request.Scope == scope {
			rows = append(rows, inv)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}
