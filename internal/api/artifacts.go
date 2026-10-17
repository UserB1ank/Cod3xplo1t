package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

func writeArtifactError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, artifact.ErrNotFound):
		writeError(w, 404, "artifact_not_found", artifact.ErrNotFound)
	case errors.Is(err, artifact.ErrConflict):
		writeError(w, 409, "artifact_conflict", artifact.ErrConflict)
	case errors.Is(err, artifact.ErrIntegrity):
		writeError(w, 409, "artifact_integrity", artifact.ErrIntegrity)
	case errors.Is(err, artifact.ErrBudget):
		writeError(w, 413, "artifact_budget", artifact.ErrBudget)
	case errors.Is(err, artifact.ErrInvalid):
		writeError(w, 400, "invalid_request", artifact.ErrInvalid)
	default:
		writeError(w, 503, "artifacts_unavailable", errors.New("artifact storage is unavailable"))
	}
}

func (s *Server) snapshotArtifactScope(w http.ResponseWriter, r *http.Request) (artifact.Scope, bool) {
	index, ok := s.Store.(artifact.Index)
	if !ok || s.Artifacts == nil {
		writeError(w, 501, "artifacts_unavailable", errors.New("artifact storage is unavailable"))
		return artifact.Scope{}, false
	}
	scope, err := index.ArtifactScope(r.Context(), r.PathValue("projectID"), r.PathValue("snapshotID"))
	if err != nil {
		writeArtifactError(w, err)
		return artifact.Scope{}, false
	}
	return scope, true
}

func (s *Server) publishSourceArtifacts(ctx context.Context, project string, snap *repository.Snapshot) error {
	index, ok := s.Store.(artifact.Index)
	if !ok || s.Artifacts == nil {
		return artifact.ErrNotFound
	}
	scope, err := index.ArtifactScope(ctx, project, snap.SnapshotID)
	if err != nil {
		return err
	}
	return artifact.PublishSnapshot(ctx, s.Artifacts, scope, snap)
}

func (s *Server) handleSnapshotArtifacts(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.snapshotArtifactScope(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		snap, err := s.Manager.Load(scope.SnapshotID)
		if err != nil {
			writeArtifactError(w, artifact.ErrNotFound)
			return
		}
		if err := artifact.PublishSnapshot(r.Context(), s.Artifacts, scope, snap); err != nil {
			writeArtifactError(w, err)
			return
		}
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writeArtifactError(w, artifact.ErrInvalid)
			return
		}
		limit = n
	}
	refs, err := s.Artifacts.List(r.Context(), scope, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeArtifactError(w, err)
		return
	}
	next := ""
	if len(refs) == limit {
		next = refs[len(refs)-1].ID
	}
	writeJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "artifacts": refs, "next_cursor": next})
}

func (s *Server) handleReadArtifact(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.snapshotArtifactScope(w, r)
	if !ok {
		return
	}
	budget := int64(64 << 20)
	if raw := r.URL.Query().Get("max_bytes"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 || n > artifact.MaxBytes {
			writeArtifactError(w, artifact.ErrInvalid)
			return
		}
		budget = n
	}
	reader, ref, err := s.Artifacts.Open(r.Context(), scope, r.PathValue("artifactID"), budget)
	if err != nil {
		writeArtifactError(w, err)
		return
	}
	defer reader.Close()
	w.Header().Set("ETag", `"sha256-`+ref.SHA256+`"`)
	if !strings.HasSuffix(r.URL.Path, "/content") {
		writeJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "artifact": ref, "availability": "verified"})
		return
	}
	w.Header().Set("Content-Type", ref.MediaType)
	w.Header().Set("Content-Length", strconv.FormatInt(ref.Bytes, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, ref.ID))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, no-store")
	if _, err := io.Copy(w, reader); err != nil {
		panic(http.ErrAbortHandler)
	}
}
