package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

// SourceDefinition records a versioned input owned by one project. Location is
// a logical container path, never the deployment's physical mount root.
type SourceDefinition struct {
	APIVersion string `json:"api_version"`
	ID         string `json:"id"`
	ProjectID  string `json:"project_id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Location   string `json:"location"`
	Ref        string `json:"ref"`
	Version    int64  `json:"version"`
	Snapshot   string `json:"snapshot,omitempty"`
	Files      int    `json:"files"`
	Revision   int    `json:"revision"`
}

type SourceSnapshot struct {
	SourceID      string `json:"source_id,omitempty"`
	SourceVersion int64  `json:"source_version,omitempty"`
}

// SourceRepository is separate from the legacy snapshot Store.
type SourceRepository interface {
	CreateSource(context.Context, SourceDefinition) error
	GetSource(context.Context, string) (SourceDefinition, error)
	ListSources(context.Context, string, string, int) ([]SourceDefinition, error)
	RegisterSourceSnapshot(context.Context, SourceDefinition, *repository.Snapshot) error
	GetSourceSnapshot(context.Context, string) (SourceSnapshot, error)
}

func (m *Memory) RegisterSourceSnapshot(_ context.Context, source SourceDefinition, snapshot *repository.Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.sources[source.ID]
	if !ok {
		return ErrNotFound
	}
	if current.Version != source.Version || current.ProjectID != source.ProjectID {
		return ErrConflict
	}
	if pending, deleted := m.deleting[snapshot.SnapshotID]; deleted {
		if pending {
			return ErrConflict
		}
		if err := validateSnapshotRevival(snapshot); err != nil {
			return err
		}
	}
	if prior, ok := m.sourceSnapshots[snapshot.SnapshotID]; ok {
		if prior.SourceID != source.ID || prior.SourceVersion != source.Version {
			return ErrConflict
		}
		current.Snapshot, current.Files = snapshot.SnapshotID, snapshot.Stats.Files
		m.sources[source.ID] = current
		return nil
	}
	document, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if prior, ok := m.snapshots[snapshot.SnapshotID]; ok && (prior.projectID != source.ProjectID || !sameDocument(prior.doc, document)) {
		return ErrConflict
	}
	m.snapshots[snapshot.SnapshotID] = memorySnapshot{projectID: source.ProjectID, doc: document, createdAt: parseStoredTime(snapshot.CreatedAt)}
	if m.sourceSnapshots == nil {
		m.sourceSnapshots = make(map[string]SourceSnapshot)
	}
	m.sourceSnapshots[snapshot.SnapshotID] = SourceSnapshot{SourceID: source.ID, SourceVersion: source.Version}
	current.Snapshot, current.Files, current.Revision = snapshot.SnapshotID, snapshot.Stats.Files, current.Revision+1
	m.sources[source.ID] = current
	delete(m.deleting, snapshot.SnapshotID)
	return nil
}

func (m *Memory) GetSourceSnapshot(_ context.Context, id string) (SourceSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, ok := m.sourceSnapshots[id]
	if !ok {
		return SourceSnapshot{}, ErrNotFound
	}
	return value, nil
}

func (m *Memory) CreateSource(_ context.Context, source SourceDefinition) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.projects[source.ProjectID]; !ok {
		return ErrNotFound
	}
	if _, ok := m.sources[source.ID]; ok {
		return fmt.Errorf("%w: source already exists", ErrConflict)
	}
	if m.sources == nil {
		m.sources = make(map[string]SourceDefinition)
	}
	source.Version = 1
	m.sources[source.ID] = source
	return nil
}

func (m *Memory) GetSource(_ context.Context, id string) (SourceDefinition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	source, ok := m.sources[id]
	if !ok {
		return SourceDefinition{}, ErrNotFound
	}
	return source, nil
}

func (m *Memory) ListSources(_ context.Context, project, cursor string, limit int) ([]SourceDefinition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := []SourceDefinition{}
	for _, source := range m.sources {
		if source.ProjectID == project && source.ID > cursor {
			result = append(result, source)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}
