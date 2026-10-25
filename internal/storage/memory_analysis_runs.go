package storage

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func activeAnalysisState(state string) bool {
	switch state {
	case "QUEUED", "CREATED", "RUNNING", "PAUSED", "CANCELLING":
		return true
	default:
		return false
	}
}

func (m *Memory) CreateAnalysisRun(_ context.Context, run AnalysisRun, idempotencyKey string) (AnalysisRun, error) {
	if run.ID == "" || run.ProjectID == "" || run.WorkflowRunID == "" || run.PlanID == "" {
		return AnalysisRun{}, fmt.Errorf("%w: analysis run identity is incomplete", path.ErrInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleting[run.ProjectID] {
		return AnalysisRun{}, fmt.Errorf("%w: project %s is being deleted", ErrConflict, run.ProjectID)
	}
	if _, ok := m.projects[run.ProjectID]; !ok {
		return AnalysisRun{}, fmt.Errorf("%w: project %s", ErrNotFound, run.ProjectID)
	}
	if idempotencyKey != "" {
		for _, existing := range m.analysisRuns {
			if existing.ProjectID == run.ProjectID && existing.IdempotencyKey == idempotencyKey {
				return cloneDocument(existing)
			}
		}
	}
	for _, existing := range m.analysisRuns {
		if existing.ProjectID == run.ProjectID && activeAnalysisState(existing.State) {
			return AnalysisRun{}, fmt.Errorf("%w: project already has an active analysis run", ErrConflict)
		}
	}
	if _, exists := m.analysisRuns[run.ID]; exists {
		return AnalysisRun{}, fmt.Errorf("%w: analysis run %s", ErrConflict, run.ID)
	}
	run.IdempotencyKey = idempotencyKey
	run.Version = 1
	if run.Stages == nil {
		run.Stages = []AnalysisRunStage{}
	}
	copy, err := cloneDocument(run)
	if err != nil {
		return AnalysisRun{}, err
	}
	m.analysisRuns[run.ID] = copy
	return cloneDocument(run)
}

func (m *Memory) GetAnalysisRun(_ context.Context, projectID, analysisRunID string) (AnalysisRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	run, ok := m.analysisRuns[analysisRunID]
	if !ok || run.ProjectID != projectID {
		return AnalysisRun{}, fmt.Errorf("%w: analysis run %s", ErrNotFound, analysisRunID)
	}
	return cloneDocument(run)
}

func (m *Memory) GetAnalysisRunByIdempotency(_ context.Context, projectID, idempotencyKey string) (AnalysisRun, error) {
	if idempotencyKey == "" {
		return AnalysisRun{}, fmt.Errorf("%w: idempotency key is required", path.ErrInvalidArgument)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, run := range m.analysisRuns {
		if run.ProjectID == projectID && run.IdempotencyKey == idempotencyKey {
			return cloneDocument(run)
		}
	}
	return AnalysisRun{}, fmt.Errorf("%w: analysis run", ErrNotFound)
}

func (m *Memory) ListAnalysisRuns(_ context.Context, projectID string, limit int) ([]AnalysisRun, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: limit must be 1–100", path.ErrInvalidArgument)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []AnalysisRun{}
	for _, run := range m.analysisRuns {
		if run.ProjectID == projectID {
			cloned, err := cloneDocument(run)
			if err != nil {
				return nil, err
			}
			out = append(out, cloned)
		}
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

func (m *Memory) UpdateAnalysisRun(_ context.Context, run AnalysisRun) (AnalysisRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.analysisRuns[run.ID]
	if !ok || existing.ProjectID != run.ProjectID {
		return AnalysisRun{}, fmt.Errorf("%w: analysis run %s", ErrNotFound, run.ID)
	}
	if existing.Version != run.Version || !reflect.DeepEqual(existing.Engine, run.Engine) {
		return AnalysisRun{}, fmt.Errorf("%w: analysis run version", ErrConflict)
	}
	run.Version = existing.Version + 1
	run.CreatedAt = existing.CreatedAt
	copy, err := cloneDocument(run)
	if err != nil {
		return AnalysisRun{}, err
	}
	m.analysisRuns[run.ID] = copy
	return cloneDocument(run)
}

func (m *Memory) ActiveAnalysisRun(_ context.Context, projectID string) (AnalysisRun, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, run := range m.analysisRuns {
		if run.ProjectID == projectID && activeAnalysisState(run.State) {
			cloned, err := cloneDocument(run)
			return cloned, err == nil, err
		}
	}
	return AnalysisRun{}, false, nil
}
