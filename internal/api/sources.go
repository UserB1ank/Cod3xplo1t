package api

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func (s *Server) handleCreateSourceProject(w http.ResponseWriter, r *http.Request) {
	var request struct {
		APIVersion string `json:"api_version"`
		Name       string `json:"name"`
	}
	if !s.decode(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.APIVersion != "codexploit/v1" || request.Name == "" || len([]rune(request.Name)) > 100 {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("codexploit/v1 and a project name of 1–100 characters are required"))
		return
	}
	id := "proj-" + rand.Text()
	if err := s.Store.PutProject(r.Context(), storage.Project{ID: id, Name: request.Name, IdentityKind: "project", Identity: id}); err != nil {
		writeStorageError(w, err)
		return
	}
	project, err := s.Store.GetProject(r.Context(), id)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	w.Header().Set("ETag", projectETag(project))
	writeJSON(w, http.StatusCreated, projectResponse{Project: project})
}

func WithLocalSourceRoot(root string) Option { return func(s *Server) { s.LocalSourceRoot = root } }

type captureSourceRequest struct {
	ProjectID     string `json:"project_id"`
	SourceVersion int64  `json:"source_version"`
	createSnapshotRequest
}

func (s *Server) handleCaptureSource(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.sourceRepository(w)
	if !ok {
		return
	}
	source, err := repo.GetSource(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	var request captureSourceRequest
	if !s.decode(w, r, &request) {
		return
	}
	if request.ProjectID != source.ProjectID {
		writeError(w, http.StatusBadRequest, "invalid_scope", errors.New("source belongs to a different project"))
		return
	}
	if request.SourceVersion != source.Version {
		writeError(w, http.StatusPreconditionFailed, "precondition_failed", errors.New("source definition has changed"))
		return
	}
	if request.Ref != "" || source.Kind != "local_folder" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("folder captures do not accept a Git ref"))
		return
	}
	rootPath := s.LocalSourceRoot
	if rootPath == "" {
		rootPath = "/repos"
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "source_mount_unavailable", errors.New("the source mount is unavailable"))
		return
	}
	defer root.Close()
	directory, err := root.OpenRoot(strings.TrimPrefix(source.Location, "/repos/"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_source_path", errors.New("source directory is missing or outside the registered mount"))
		return
	}
	defer directory.Close()
	snapshot, err := s.Manager.Create(r.Context(), repository.Source{Raw: source.Location, Kind: repository.KindDir, Files: directory.FS(), NameOverride: fmt.Sprintf("projects/%s/sources/%s/v%d", source.ProjectID, source.ID, source.Version)})
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if err := repo.RegisterSourceSnapshot(r.Context(), source, snapshot); err != nil {
		writeStorageError(w, err)
		return
	}
	response := snapshotResponse{Snapshot: summaryOf(snapshot, source.ProjectID)}
	response.Snapshot.SourceSnapshot = storage.SourceSnapshot{SourceID: source.ID, SourceVersion: source.Version}
	if !request.SkipAnalysis {
		manifest, err := s.Analyzer.Analyze(r.Context(), snapshot)
		if err != nil {
			writeStorageError(w, err)
			return
		}
		if err := s.persistManifest(r.Context(), snapshot, manifest); err != nil {
			writeStorageError(w, err)
			return
		}
		response.Manifest = manifestSummaryOf(manifest)
	}
	if request.BuildGraph {
		if s.Builder == nil {
			writeError(w, http.StatusNotImplemented, "graph_unavailable", errors.New("graph builder is unavailable"))
			return
		}
		graph, err := s.Builder.Build(r.Context(), snapshot)
		if err != nil {
			writeStorageError(w, err)
			return
		}
		if err := s.Store.ReplaceGraph(r.Context(), snapshot.SnapshotID, graph); err != nil {
			writeStorageError(w, err)
			return
		}
		if err := s.persistGraphArtifact(snapshot, graph); err != nil {
			writeStorageError(w, err)
			return
		}
		response.Graph = graph.Summarize()
	}
	if request.BuildASG {
		summary, _, ok := s.buildASG(w, r, snapshot.SnapshotID, false)
		if !ok {
			return
		}
		response.ASG = summary
	}
	writeJSON(w, http.StatusCreated, response)
}

var localSourceSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	raw, err := contracts.Files.ReadFile("source.schema.json")
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return schema.Resolve(nil)
})

type createSourceRequest struct {
	APIVersion string `json:"api_version"`
	ID         string `json:"id"`
	ProjectID  string `json:"project_id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Location   string `json:"location"`
	Ref        string `json:"ref"`
}

func sourceETag(source storage.SourceDefinition) string {
	return fmt.Sprintf(`"source-%s-v%d"`, source.ID, source.Version)
}

func (s *Server) sourceRepository(w http.ResponseWriter) (storage.SourceRepository, bool) {
	repo, ok := s.Store.(storage.SourceRepository)
	if !ok {
		writeError(w, http.StatusNotImplemented, "sources_unavailable", errors.New("source storage is unavailable"))
	}
	return repo, ok
}

func (s *Server) handleCreateSource(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("id")
	if _, err := s.Store.GetProject(r.Context(), project); err != nil {
		writeStorageError(w, err)
		return
	}
	repo, ok := s.sourceRepository(w)
	if !ok {
		return
	}
	var request createSourceRequest
	if !s.decode(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.ProjectID != project {
		writeError(w, http.StatusBadRequest, "invalid_scope", errors.New("source belongs to a different project"))
		return
	}
	schema, err := localSourceSchema()
	if err != nil {
		writeStorageError(w, err)
		return
	}
	raw, _ := json.Marshal(request)
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		writeStorageError(w, err)
		return
	}
	if err := schema.Validate(value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if request.Kind != "local_folder" {
		writeError(w, http.StatusNotImplemented, "unsupported_source", errors.New("only local_folder sources are implemented"))
		return
	}
	source := storage.SourceDefinition{APIVersion: request.APIVersion, ID: request.ID, ProjectID: project, Name: request.Name, Kind: request.Kind, Location: request.Location, Ref: request.Ref, Version: 1}
	if err := repo.CreateSource(r.Context(), source); err != nil {
		writeStorageError(w, err)
		return
	}
	w.Header().Set("ETag", sourceETag(source))
	writeJSON(w, http.StatusCreated, map[string]any{"source": source})
}

func (s *Server) handleListSources(w http.ResponseWriter, r *http.Request) {
	project, err := s.Store.GetProject(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	repo, ok := s.sourceRepository(w)
	if !ok {
		return
	}
	limit := min(200, pageLimit(r.URL.Query().Get("limit")))
	sources, err := repo.ListSources(r.Context(), project.ID, r.URL.Query().Get("cursor"), limit+1)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	cursor := ""
	if len(sources) > limit {
		sources = sources[:limit]
		cursor = sources[len(sources)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": sources, "next_cursor": cursor, "legacy_source": project.Source})
}
