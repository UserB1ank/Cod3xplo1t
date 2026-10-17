package storage

import (
	"context"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

func (m *Memory) artifactScopeLocked(scope artifact.Scope) bool {
	snap, ok := m.snapshots[scope.SnapshotID]
	if !ok || snap.projectID != scope.ProjectID {
		return false
	}
	if _, deleted := m.deleting[scope.SnapshotID]; deleted {
		return false
	}
	if binding, ok := m.sourceSnapshots[scope.SnapshotID]; ok {
		return binding.SourceID == scope.SourceID
	}
	return scope.SourceID == "legacy-"+scope.ProjectID
}

func (m *Memory) ArtifactScope(ctx context.Context, project, snapshot string) (artifact.Scope, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Scope{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	scope := artifact.Scope{ProjectID: project, SourceID: "legacy-" + project, SnapshotID: snapshot}
	if binding, ok := m.sourceSnapshots[snapshot]; ok {
		scope.SourceID = binding.SourceID
	}
	if !m.artifactScopeLocked(scope) {
		return artifact.Scope{}, artifact.ErrNotFound
	}
	return scope, nil
}

func (m *Memory) ListArtifacts(ctx context.Context, scope artifact.Scope, cursor string, limit int) ([]artifact.Ref, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.artifactScopeLocked(scope) {
		return nil, artifact.ErrNotFound
	}
	refs := []artifact.Ref{}
	for _, ref := range m.artifacts {
		if ref.Scope == scope && ref.ID > cursor {
			refs = append(refs, ref)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	if len(refs) > limit {
		refs = refs[:limit]
	}
	return refs, nil
}

func (m *Memory) PublishArtifact(ctx context.Context, ref artifact.Ref) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.artifactScopeLocked(ref.Scope) {
		return artifact.ErrNotFound
	}
	if prior, ok := m.artifacts[ref.ID]; ok && prior != ref {
		return artifact.ErrConflict
	}
	if m.artifacts == nil {
		m.artifacts = map[string]artifact.Ref{}
	}
	m.artifacts[ref.ID] = ref
	return nil
}

func (m *Memory) LookupArtifact(ctx context.Context, scope artifact.Scope, id string) (artifact.Ref, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Ref{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	ref, ok := m.artifacts[id]
	if !ok || ref.Scope != scope || !m.artifactScopeLocked(scope) {
		return artifact.Ref{}, artifact.ErrNotFound
	}
	return ref, nil
}
