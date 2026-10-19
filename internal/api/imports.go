package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/sourceimport"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func (s *Server) handleImportSource(w http.ResponseWriter, r *http.Request) {
	project, id := r.PathValue("projectID"), r.PathValue("sourceID")
	if _, err := s.Store.GetProject(r.Context(), project); err != nil {
		writeStorageError(w, err)
		return
	}
	repo, ok := s.sourceRepository(w)
	if !ok {
		return
	}
	name, format := strings.TrimSpace(r.URL.Query().Get("name")), r.URL.Query().Get("format")
	definition := createSourceRequest{APIVersion: "codexploit/v1", ID: id, ProjectID: project, Name: name, Kind: "local_folder", Location: "/repos/import", Ref: ""}
	if !s.validateSourceRequest(w, definition) {
		return
	}
	select {
	case s.sourceImports <- struct{}{}:
		defer func() { <-s.sourceImports }()
	default:
		writeError(w, 429, "import_busy", errors.New("已有源码正在上传，请稍后重试"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	upload, err := sourceimport.Extract(ctx, r.Body, format)
	if err != nil {
		status, code := 400, "invalid_import"
		if errors.Is(err, sourceimport.ErrBudget) {
			status, code = 413, "import_budget"
		}
		if !errors.Is(err, sourceimport.ErrInvalid) && !errors.Is(err, sourceimport.ErrBudget) {
			err = errors.New("源码上传未完成，请重试")
		}
		writeError(w, status, code, err)
		return
	}
	defer upload.Close()
	source := storage.SourceDefinition{APIVersion: "codexploit/v1", ID: id, ProjectID: project, Name: name, Kind: "uploaded_archive", Location: "upload:" + upload.Report.SHA256, Version: 1, Import: &upload.Report}
	if err := repo.CreateSource(ctx, source); err != nil {
		prior, readErr := repo.GetSource(ctx, id)
		if !errors.Is(err, storage.ErrConflict) || readErr != nil || prior.ProjectID != project || prior.Kind != source.Kind || prior.Location != source.Location {
			writeStorageError(w, err)
			return
		}
		source = prior
	}
	root, err := os.OpenRoot(upload.Tree)
	if err != nil {
		writeError(w, 503, "import_unavailable", errors.New("源码暂存不可用，请重新上传"))
		return
	}
	defer root.Close()
	snapshot, err := s.Manager.Create(ctx, repository.Source{Raw: "/uploaded", Kind: repository.KindDir, Files: root.FS(), NameOverride: fmt.Sprintf("projects/%s/sources/%s/v1", project, id)})
	if err != nil {
		s.writeSourceError(w, err)
		return
	}
	request := captureSourceRequest{ProjectID: project, SourceVersion: 1}
	request.BuildGraph, request.BuildASG = r.URL.Query().Get("build_graph") == "true", r.URL.Query().Get("build_asg") == "true"
	s.finishSourceCapture(w, r.WithContext(ctx), repo, source, snapshot, request)
}
