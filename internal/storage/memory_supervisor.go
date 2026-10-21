package storage

import (
	"context"
	"fmt"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func (m *Memory) CreateSupervisorSession(_ context.Context, session SupervisorSession) (SupervisorSession, error) {
	if session.ID == "" || session.ProjectID == "" || session.SnapshotID == "" {
		return SupervisorSession{}, fmt.Errorf("%w: supervisor session identity is incomplete", path.ErrInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleting[session.ProjectID] {
		return SupervisorSession{}, fmt.Errorf("%w: project is being deleted", ErrConflict)
	}
	if _, ok := m.projects[session.ProjectID]; !ok {
		return SupervisorSession{}, fmt.Errorf("%w: project %s", ErrNotFound, session.ProjectID)
	}
	if _, exists := m.supervisorSessions[session.ID]; exists {
		return SupervisorSession{}, fmt.Errorf("%w: supervisor session %s", ErrConflict, session.ID)
	}
	session.Version = 1
	if session.Messages == nil {
		session.Messages = []SupervisorMessage{}
	}
	if session.Runs == nil {
		session.Runs = []SupervisorRun{}
	}
	if session.Events == nil {
		session.Events = []SupervisorEvent{}
	}
	m.supervisorSessions[session.ID] = session
	return cloneDocument(session)
}

func (m *Memory) GetSupervisorSession(_ context.Context, projectID, sessionID string) (SupervisorSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	session, ok := m.supervisorSessions[sessionID]
	if !ok || session.ProjectID != projectID {
		return SupervisorSession{}, fmt.Errorf("%w: supervisor session %s", ErrNotFound, sessionID)
	}
	return cloneDocument(session)
}

func (m *Memory) ListSupervisorSessions(_ context.Context, projectID string, limit int) ([]SupervisorSession, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: limit must be 1–100", path.ErrInvalidArgument)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []SupervisorSession{}
	for _, session := range m.supervisorSessions {
		if session.ProjectID != projectID {
			continue
		}
		cloned, err := cloneDocument(session)
		if err != nil {
			return nil, err
		}
		out = append(out, cloned)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) SaveSupervisorSession(_ context.Context, session SupervisorSession, expectedVersion int64) (SupervisorSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.supervisorSessions[session.ID]
	if !ok || existing.ProjectID != session.ProjectID {
		return SupervisorSession{}, fmt.Errorf("%w: supervisor session %s", ErrNotFound, session.ID)
	}
	if expectedVersion > 0 && existing.Version != expectedVersion {
		return SupervisorSession{}, fmt.Errorf("%w: supervisor session version", ErrConflict)
	}
	session.Version = existing.Version + 1
	session.CreatedAt = existing.CreatedAt
	m.supervisorSessions[session.ID] = session
	return cloneDocument(session)
}
