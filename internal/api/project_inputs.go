package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/lifecycle"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

type projectInputResponse struct {
	APIVersion string               `json:"api_version"`
	Input      storage.ProjectInput `json:"input"`
}

type projectDirectoryEntry struct {
	Project    storage.Project       `json:"project"`
	AuditInput *storage.ProjectInput `json:"audit_input,omitempty"`
}

// projectInput returns the stored lifecycle of a new project, or a synthesized
// legacy value for a project that predates single-source audits. Reads never
// create an input row.
func (s *Server) projectInput(ctx context.Context, projectID string) (storage.ProjectInput, error) {
	input, err := s.Store.GetProjectInput(ctx, projectID)
	if errors.Is(err, storage.ErrNotFound) {
		return storage.ProjectInput{ProjectID: projectID, State: storage.ProjectInputLegacy}, nil
	}
	if err != nil {
		return storage.ProjectInput{}, err
	}
	return storage.EffectiveProjectInput(input, time.Now().UTC()), nil
}

// bindProjectInput binds the first source of a new project and rejects a second
// one while the first is still being imported or already ready. It returns false
// for a legacy project, whose multi-source history is intentionally untouched.
func (s *Server) bindProjectInput(ctx context.Context, projectID, sourceID, kind, name string) (storage.ProjectInput, bool, error) {
	if _, err := s.Store.GetProjectInput(ctx, projectID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return storage.ProjectInput{ProjectID: projectID, State: storage.ProjectInputLegacy}, false, nil
		}
		return storage.ProjectInput{}, true, err
	}
	bound, err := s.Store.BeginProjectInput(ctx, projectID, sourceID, kind, name)
	return bound, true, err
}

func (s *Server) completeProjectInput(ctx context.Context, projectID, sourceID string, snapshotID string, files int, bytes int64) error {
	_, err := s.Store.CompleteProjectInput(ctx, projectID, sourceID, snapshotID, files, bytes)
	if errors.Is(err, storage.ErrNotFound) {
		return nil // legacy project: no implicit input to complete
	}
	return err
}

// failProjectInput records a real import failure. It deliberately uses a fresh
// context because the request may already be cancelled, and it ignores a missing
// input so legacy callers keep their old behaviour.
func (s *Server) failProjectInput(projectID, sourceID, code string, cause error) {
	if sourceID == "" {
		return
	}
	message := "源码导入失败"
	if cause != nil && strings.TrimSpace(cause.Error()) != "" {
		message = cause.Error()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 5*time.Second)
	defer cancel()
	if _, err := s.Store.FailProjectInput(ctx, projectID, sourceID, code, message); err != nil && !errors.Is(err, storage.ErrNotFound) {
		s.Logger.Warn("project input failure was not recorded", "project", projectID, "error", err)
	}
}

func writeProjectInputError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrProjectInputFixed):
		writeError(w, http.StatusConflict, "input_fixed", err)
	case errors.Is(err, storage.ErrProjectImportInProgress):
		writeError(w, http.StatusConflict, "import_in_progress", err)
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err)
	default:
		writeStorageError(w, err)
	}
}

// handleProjectDirectory is the versioned project list used by the management
// surface. It carries the real input state, not an inferred one.
func (s *Server) handleProjectDirectory(w http.ResponseWriter, r *http.Request) {
	projects, err := s.Store.ListProjects(r.Context())
	if err != nil {
		writeStorageError(w, err)
		return
	}
	inputs, err := s.Store.ListProjectInputs(r.Context())
	if err != nil {
		writeStorageError(w, err)
		return
	}
	now := time.Now().UTC()
	byProject := make(map[string]storage.ProjectInput, len(inputs))
	for _, input := range inputs {
		byProject[input.ProjectID] = storage.EffectiveProjectInput(input, now)
	}
	entries := make([]projectDirectoryEntry, 0, len(projects))
	for _, project := range projects {
		entry := projectDirectoryEntry{Project: project}
		if input, ok := byProject[project.ID]; ok {
			value := input
			entry.AuditInput = &value
		}
		entries = append(entries, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_version": "codexploit/v1",
		"projects":    entries,
	})
}

// handleGetProjectInput returns the single-source import state. A legacy project
// answers with state=legacy instead of pretending it has a latest input.
func (s *Server) handleGetProjectInput(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	input, err := s.projectInput(r.Context(), projectID)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if input.State != storage.ProjectInputLegacy {
		w.Header().Set("ETag", projectInputETag(input))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, projectInputResponse{APIVersion: "codexploit/v1", Input: input})
}

func projectInputETag(input storage.ProjectInput) string {
	return fmt.Sprintf(`"project-input-%s-v%d"`, input.ProjectID, input.Version)
}

// handleDeleteProject removes a project through the recoverable lifecycle. The
// response is only 204 after the tombstone is completed; an active reference or
// an in-flight import is a conflict the caller can resolve and retry.
func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	if s.Manager == nil {
		writeError(w, http.StatusNotImplemented, "project_storage_unavailable",
			errors.New("project filesystem storage is unavailable"))
		return
	}
	projects := lifecycle.NewProjects(s.Store, s.Manager)
	if err := projects.Delete(r.Context(), r.PathValue("projectID")); err != nil {
		switch {
		case errors.Is(err, storage.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", err)
		case errors.Is(err, storage.ErrConflict):
			writeError(w, http.StatusConflict, "project_active_work", err)
		default:
			writeStorageError(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
