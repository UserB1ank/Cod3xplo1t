package storage

import (
	"context"
	"errors"
	"slices"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

var ErrCategoryInUse = errors.New("remove category assignments before deleting a category")

type TaskCategories struct {
	Categories []string `json:"categories"`
	Version    int64    `json:"version"`
}

// TaskCategoryRepository owns a versioned project catalog. Assignment and
// removal checks share the storage transaction/lock with task updates.
type TaskCategoryRepository interface {
	GetTaskCategories(context.Context, string) (TaskCategories, error)
	SetTaskCategories(context.Context, string, []string, int64) (TaskCategories, error)
}

func (m *Memory) categoriesLocked(project string) TaskCategories {
	catalog, ok := m.taskCategories[project]
	if !ok {
		catalog = TaskCategories{Categories: []string{}, Version: 1}
	}
	catalog.Categories = append([]string{}, catalog.Categories...)
	return catalog
}

func (m *Memory) GetTaskCategories(_ context.Context, project string) (TaskCategories, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.projects[project]; !ok {
		return TaskCategories{}, ErrNotFound
	}
	return m.categoriesLocked(project), nil
}

func (m *Memory) SetTaskCategories(_ context.Context, project string, categories []string, version int64) (TaskCategories, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.projects[project]; !ok {
		return TaskCategories{}, ErrNotFound
	}
	current := m.categoriesLocked(project)
	if current.Version != version {
		return TaskCategories{}, ErrConflict
	}
	for _, doc := range m.audits {
		if m.snapshots[doc.audit.SnapshotID].projectID == project && doc.audit.Category != "" && !slices.Contains(categories, doc.audit.Category) {
			return TaskCategories{}, ErrCategoryInUse
		}
	}
	if m.taskCategories == nil {
		m.taskCategories = make(map[string]TaskCategories)
	}
	updated := TaskCategories{Categories: append([]string{}, categories...), Version: version + 1}
	m.taskCategories[project] = updated
	updated.Categories = append([]string{}, updated.Categories...)
	return updated, nil
}

func invalidTaskCategory() error { return path.ErrInvalidArgument }
