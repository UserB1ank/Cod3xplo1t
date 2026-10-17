package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func (s *Server) projectTask(w http.ResponseWriter, r *http.Request) (*path.Audit, bool) {
	if s.auditUnavailable(w) {
		return nil, false
	}
	if _, err := s.Store.GetProject(r.Context(), r.PathValue("id")); err != nil {
		writeStorageError(w, err)
		return nil, false
	}
	task, err := s.Audit.Audit(r.PathValue("taskID"))
	if err != nil {
		writeAuditError(w, err, "")
		return nil, false
	}
	snapshots, err := s.Store.ListSnapshots(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err)
		return nil, false
	}
	for _, snapshot := range snapshots {
		if snapshot.SnapshotID == task.SnapshotID {
			return task, true
		}
	}
	writeError(w, http.StatusNotFound, "not_found", errors.New("task does not belong to this project"))
	return nil, false
}

func (s *Server) handleOrganizeTask(w http.ResponseWriter, r *http.Request) {
	task, ok := s.projectTask(w, r)
	if !ok || !requireEntityVersion(w, r, taskETag(task)) {
		return
	}
	var request struct {
		Pinned   *bool   `json:"pinned"`
		Archived *bool   `json:"archived"`
		Category *string `json:"category"`
	}
	if !s.decode(w, r, &request) {
		return
	}
	if request.Pinned == nil && request.Archived == nil && request.Category == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("choose a task property to update"))
		return
	}
	version := task.Version
	if request.Pinned != nil {
		task.Pinned = *request.Pinned
	}
	if request.Archived != nil {
		task.Archived = *request.Archived
	}
	if request.Category != nil {
		task.Category = strings.TrimSpace(*request.Category)
	}
	task.UpdatedAt, task.Version = path.NowString(time.Now().UTC()), version+1
	if err := s.Store.UpdateAudit(*task, version); err != nil {
		if errors.Is(err, path.ErrTaskActive) || errors.Is(err, path.ErrTaskArchived) {
			writeError(w, http.StatusConflict, "task_not_idle", err)
		} else if errors.Is(err, path.ErrConflict) {
			writeError(w, http.StatusPreconditionFailed, "precondition_failed", err)
		} else {
			writeAuditError(w, err, "")
		}
		return
	}
	w.Header().Set("ETag", taskETag(task))
	writeJSON(w, http.StatusOK, task)
}

func categoriesETag(project string, catalog storage.TaskCategories) string {
	return fmt.Sprintf(`"task-categories-%s-v%d"`, project, catalog.Version)
}

func (s *Server) handleTaskCategories(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("id")
	repo, ok := s.Store.(storage.TaskCategoryRepository)
	if !ok {
		writeError(w, http.StatusNotImplemented, "categories_unavailable", errors.New("task categories are unavailable"))
		return
	}
	catalog, err := repo.GetTaskCategories(r.Context(), project)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if r.Method == http.MethodPut {
		if !requireEntityVersion(w, r, categoriesETag(project, catalog)) {
			return
		}
		var request struct {
			Categories []string `json:"categories"`
		}
		if !s.decode(w, r, &request) {
			return
		}
		seen := map[string]bool{}
		if request.Categories == nil || len(request.Categories) > 32 {
			writeError(w, 400, "invalid_request", errors.New("categories must be an array of at most 32 names"))
			return
		}
		for i, category := range request.Categories {
			category = strings.TrimSpace(category)
			key := strings.ToLower(category)
			if category == "" || len([]rune(category)) > 30 || seen[key] {
				writeError(w, 400, "invalid_request", errors.New("category names must be unique and contain 1–30 characters"))
				return
			}
			seen[key], request.Categories[i] = true, category
		}
		catalog, err = repo.SetTaskCategories(r.Context(), project, request.Categories, catalog.Version)
		if err != nil {
			if errors.Is(err, storage.ErrConflict) {
				writeError(w, 412, "precondition_failed", err)
			} else if errors.Is(err, storage.ErrCategoryInUse) {
				writeError(w, 409, "category_in_use", err)
			} else {
				writeStorageError(w, err)
			}
			return
		}
	}
	w.Header().Set("ETag", categoriesETag(project, catalog))
	writeJSON(w, http.StatusOK, catalog)
}
