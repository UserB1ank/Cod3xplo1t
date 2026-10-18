package storage

import (
	"context"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/publication"
)

// knowledgeScopeState is the revision history of one project snapshot.
type knowledgeScopeState struct {
	revisions map[string]publication.RevisionDocument
	batches   map[string]publication.Revision
	head      string
	outbox    []publication.OutboxEvent
}

func knowledgeKey(scope publication.Scope) string {
	return scope.ProjectID + "\x00" + scope.SnapshotID
}

func (m *Memory) knowledgeState(scope publication.Scope) *knowledgeScopeState {
	if m.knowledge == nil {
		m.knowledge = map[string]*knowledgeScopeState{}
	}
	key := knowledgeKey(scope)
	state := m.knowledge[key]
	if state == nil {
		state = &knowledgeScopeState{
			revisions: map[string]publication.RevisionDocument{},
			batches:   map[string]publication.Revision{},
			head:      "rev-0",
		}
		m.knowledge[key] = state
	}
	return state
}

// knowledgeScopeWritable proves the snapshot belongs to the project and is not
// being retired, so a publication cannot cross scopes or resurrect a deleted one.
func (m *Memory) knowledgeScopeWritable(scope publication.Scope) bool {
	snapshot, ok := m.snapshots[scope.SnapshotID]
	if !ok || snapshot.projectID != scope.ProjectID {
		return false
	}
	if _, deleting := m.deleting[scope.SnapshotID]; deleting {
		return false
	}
	return true
}

func (m *Memory) KnowledgeHead(ctx context.Context, scope publication.Scope) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.knowledgeScopeWritable(scope) {
		return "", publication.ErrNotFound
	}
	if state := m.knowledge[knowledgeKey(scope)]; state != nil {
		return state.head, nil
	}
	return "rev-0", nil
}

func (m *Memory) KnowledgeBatch(ctx context.Context, scope publication.Scope, batchID string) (publication.Revision, error) {
	if err := ctx.Err(); err != nil {
		return publication.Revision{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if state := m.knowledge[knowledgeKey(scope)]; state != nil {
		if revision, ok := state.batches[batchID]; ok {
			return revision, nil
		}
	}
	return publication.Revision{}, publication.ErrNotFound
}

func (m *Memory) GetKnowledgeRevision(ctx context.Context, scope publication.Scope, revision string) (publication.RevisionDocument, error) {
	if err := ctx.Err(); err != nil {
		return publication.RevisionDocument{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.knowledgeScopeWritable(scope) {
		return publication.RevisionDocument{}, publication.ErrNotFound
	}
	if state := m.knowledge[knowledgeKey(scope)]; state != nil {
		if document, ok := state.revisions[revision]; ok {
			return cloneRevisionDocument(document), nil
		}
	}
	return publication.RevisionDocument{}, publication.ErrNotFound
}

func (m *Memory) ListKnowledgeRevisions(ctx context.Context, scope publication.Scope, limit int) ([]publication.Revision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.knowledgeScopeWritable(scope) {
		return nil, publication.ErrNotFound
	}
	state := m.knowledge[knowledgeKey(scope)]
	if state == nil {
		return []publication.Revision{}, nil
	}
	revisions := make([]publication.Revision, 0, len(state.revisions))
	for _, document := range state.revisions {
		revisions = append(revisions, document.Revision)
	}
	sort.Slice(revisions, func(i, j int) bool { return revisions[i].Number < revisions[j].Number })
	if limit > 0 && len(revisions) > limit {
		revisions = revisions[:limit]
	}
	return revisions, nil
}

func (m *Memory) ListKnowledgeOutbox(ctx context.Context, scope publication.Scope, limit int) ([]publication.OutboxEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	state := m.knowledge[knowledgeKey(scope)]
	if state == nil {
		return []publication.OutboxEvent{}, nil
	}
	events := append([]publication.OutboxEvent(nil), state.outbox...)
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

// PublishKnowledge commits the revision, its batch index and the outbox event
// as one unit and rejects a head that moved since the caller read it.
func (m *Memory) PublishKnowledge(ctx context.Context, expectedHead string, document publication.RevisionDocument, event publication.OutboxEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scope := document.Revision.Scope
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.knowledgeScopeWritable(scope) {
		return publication.ErrNotFound
	}
	state := m.knowledgeState(scope)
	head := state.head
	if head == "" {
		head = "rev-0"
	}
	if expectedHead != head {
		return publication.ErrVersionConflict
	}
	if _, exists := state.revisions[document.Revision.ID]; exists {
		return publication.ErrBatchConflict
	}
	if _, exists := state.batches[document.Revision.BatchID]; exists {
		return publication.ErrBatchConflict
	}
	if document.Analysis != nil && document.Analysis.Summary.ID != document.Revision.Producer.InvocationID {
		return publication.ErrInvalidBatch
	}
	if err := m.indexAnalysisLocked(scope, document.Analysis); err != nil {
		return err
	}
	state.revisions[document.Revision.ID] = cloneRevisionDocument(document)
	state.batches[document.Revision.BatchID] = document.Revision
	state.head = document.Revision.ID
	state.outbox = append(state.outbox, event)
	return nil
}

func cloneRevisionDocument(document publication.RevisionDocument) publication.RevisionDocument {
	clone := document
	clone.Analysis = nil
	clone.Facts = make([]publication.Fact, len(document.Facts))
	for i, fact := range document.Facts {
		clone.Facts[i] = fact
		clone.Facts[i].Observations = append([]publication.Observation(nil), fact.Observations...)
		if fact.Location != nil {
			location := *fact.Location
			clone.Facts[i].Location = &location
		}
	}
	clone.Edges = append([]publication.Edge(nil), document.Edges...)
	clone.Revision.Limitations = append([]string(nil), document.Revision.Limitations...)
	return clone
}
