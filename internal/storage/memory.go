package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

// Memory is an in-process Store. It keeps the same immutability semantics as the
// SQL implementation by storing serialised documents, which also makes it a
// faithful target for API tests and for `--db memory` runs.
type Memory struct {
	mu        sync.RWMutex
	projects  map[string]Project
	snapshots map[string]memorySnapshot
	manifests map[string][]byte
	analyses  map[string]string // analysis_id -> analysis document
	graphs    map[string]*memoryGraph
	// idempotency survives for the lifetime of the store, which is what makes a
	// retry after a restart safe when the store is a database.
	idempotency map[idempotencyKey]IdempotencyRecord
}

type memorySnapshot struct {
	projectID string
	doc       []byte
	createdAt time.Time
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		projects:    map[string]Project{},
		snapshots:   map[string]memorySnapshot{},
		manifests:   map[string][]byte{},
		analyses:    map[string]string{},
		graphs:      map[string]*memoryGraph{},
		idempotency: map[idempotencyKey]IdempotencyRecord{},
	}
}

// PutProject implements Store.
func (m *Memory) PutProject(_ context.Context, p Project) error {
	if p.ID == "" {
		return fmt.Errorf("%w: project id is required", ErrConflict)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.projects[p.ID]; ok && !existing.CreatedAt.IsZero() {
		p.CreatedAt = existing.CreatedAt
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	p.UpdatedAt = time.Now().UTC()
	m.projects[p.ID] = p
	return nil
}

// GetProject implements Store.
func (m *Memory) GetProject(_ context.Context, id string) (Project, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.projects[id]
	if !ok {
		return Project{}, fmt.Errorf("%w: project %s", ErrNotFound, id)
	}
	return p, nil
}

// ListProjects implements Store.
func (m *Memory) ListProjects(_ context.Context) ([]Project, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Project, 0, len(m.projects))
	for _, p := range m.projects {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// PutSnapshot implements Store.
func (m *Memory) PutSnapshot(_ context.Context, projectID string, snap *repository.Snapshot) error {
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.projects[projectID]; !ok {
		return fmt.Errorf("%w: project %s", ErrNotFound, projectID)
	}
	if existing, ok := m.snapshots[snap.SnapshotID]; ok {
		if !sameDocument(existing.doc, doc) {
			return fmt.Errorf("%w: snapshot %s already exists with different content", ErrConflict, snap.SnapshotID)
		}
		return nil
	}
	m.snapshots[snap.SnapshotID] = memorySnapshot{projectID: projectID, doc: doc, createdAt: created}
	return nil
}

// GetSnapshot implements Store. The returned snapshot carries no Dir: callers
// that need the frozen tree resolve it through the repository manager, so a
// stored document can never point at an arbitrary path.
func (m *Memory) GetSnapshot(_ context.Context, id string) (*repository.Snapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.snapshots[id]
	if !ok {
		return nil, fmt.Errorf("%w: snapshot %s", ErrNotFound, id)
	}
	var snap repository.Snapshot
	if err := json.Unmarshal(rec.doc, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// ListSnapshots implements Store.
func (m *Memory) ListSnapshots(_ context.Context, projectID string) ([]SnapshotRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []SnapshotRecord
	for id, rec := range m.snapshots {
		if projectID != "" && rec.projectID != projectID {
			continue
		}
		var snap repository.Snapshot
		if err := json.Unmarshal(rec.doc, &snap); err != nil {
			return nil, err
		}
		record := SnapshotRecord{
			SnapshotID:    id,
			ProjectID:     rec.projectID,
			Commit:        snap.Commit,
			VCS:           snap.VCS,
			WorktreeDirty: snap.WorktreeDirty,
			CreatedAt:     rec.createdAt,
		}
		if doc, ok := m.manifests[id]; ok {
			record.ManifestPresent = true
			var mf analysis.Manifest
			if err := json.Unmarshal(doc, &mf); err == nil {
				record.AnalysisID = mf.AnalysisID
			}
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].SnapshotID < out[j].SnapshotID
	})
	return out, nil
}

// DeleteSnapshot implements Store.
func (m *Memory) DeleteSnapshot(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.snapshots[id]; !ok {
		return fmt.Errorf("%w: snapshot %s", ErrNotFound, id)
	}
	delete(m.snapshots, id)
	delete(m.manifests, id)
	delete(m.graphs, id)
	return nil
}

// PutManifest implements Store. Manifests are immutable per snapshot: a second
// analysis with a different analysis id is a conflict, not an overwrite.
func (m *Memory) PutManifest(_ context.Context, snapshotID string, mf *analysis.Manifest) error {
	if mf == nil {
		return fmt.Errorf("%w: nil manifest", ErrConflict)
	}
	doc, err := json.Marshal(mf)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.snapshots[snapshotID]; !ok {
		return fmt.Errorf("%w: snapshot %s", ErrNotFound, snapshotID)
	}
	if existing, ok := m.manifests[snapshotID]; ok {
		if sameAnalysis(existing, doc) {
			// The same analysis ran again: keep the stored document, which is the
			// one the evidence points at.
			return nil
		}
		if !sameDocument(existing, doc) {
			var prev analysis.Manifest
			if err := json.Unmarshal(existing, &prev); err == nil && prev.AnalysisID != mf.AnalysisID {
				return fmt.Errorf("%w: snapshot %s already has analysis %s; re-analysis with a different rule set or configuration needs a new snapshot",
					ErrConflict, snapshotID, prev.AnalysisID)
			}
			return fmt.Errorf("%w: manifest for snapshot %s already exists with different content", ErrConflict, snapshotID)
		}
		return nil
	}
	m.manifests[snapshotID] = doc
	m.analyses[mf.AnalysisID] = string(doc)
	return nil
}

// GetManifest implements Store.
func (m *Memory) GetManifest(_ context.Context, snapshotID string) (*analysis.Manifest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.manifests[snapshotID]
	if !ok {
		return nil, fmt.Errorf("%w: manifest for snapshot %s", ErrNotFound, snapshotID)
	}
	var mf analysis.Manifest
	if err := json.Unmarshal(doc, &mf); err != nil {
		return nil, err
	}
	return &mf, nil
}

// Close implements Store.
func (m *Memory) Close() error { return nil }

// sameDocument compares two serialised documents, tolerating whitespace and key
// ordering differences.
func sameDocument(a, b []byte) bool {
	if string(a) == string(b) {
		return true
	}
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	ab, err1 := json.Marshal(av)
	bb, err2 := json.Marshal(bv)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ab) == string(bb)
}

// parseStoredTime accepts the RFC3339 timestamps written by the storage layer.
func parseStoredTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
