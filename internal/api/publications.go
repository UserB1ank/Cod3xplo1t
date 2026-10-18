package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"

	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
)

// publicationSchema validates the publication receipt against the public
// contract, so the response cannot drift from the published schema.
var publicationSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	raw, err := contracts.Files.ReadFile("publication.schema.json")
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return schema.Resolve(nil)
})

func writePublicationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, publication.ErrVersionConflict):
		writeError(w, http.StatusConflict, "version_conflict", publication.ErrVersionConflict)
	case errors.Is(err, publication.ErrBatchConflict):
		writeError(w, http.StatusConflict, "batch_conflict", publication.ErrBatchConflict)
	case errors.Is(err, publication.ErrOrphanEdge), errors.Is(err, publication.ErrInvalidBatch):
		writeError(w, http.StatusBadRequest, "invalid_batch", err)
	case errors.Is(err, publication.ErrNotFound), errors.Is(err, plugin.ErrNotFound):
		writeError(w, http.StatusNotFound, "knowledge_not_found", publication.ErrNotFound)
	default:
		writeStorageError(w, err)
	}
}

// handlePublishKnowledge turns one invocation's standard result into an
// immutable revision. The invocation is the producer, so the batch cannot name
// facts it did not generate.
func (s *Server) handlePublishKnowledge(w http.ResponseWriter, r *http.Request) {
	if s.Plugins == nil || s.Publications == nil {
		writeError(w, http.StatusNotImplemented, "publications_unavailable", errors.New("knowledge publications are unavailable"))
		return
	}
	var request struct {
		APIVersion   string `json:"api_version"`
		SnapshotID   string `json:"snapshot_id"`
		InvocationID string `json:"invocation_id"`
		TaskID       string `json:"task_id"`
		BatchID      string `json:"batch_id"`
		BaseRevision string `json:"base_revision"`
	}
	if !s.decode(w, r, &request) {
		return
	}
	request.SnapshotID = strings.TrimSpace(request.SnapshotID)
	request.InvocationID = strings.TrimSpace(request.InvocationID)
	request.BatchID = strings.TrimSpace(request.BatchID)
	request.TaskID = strings.TrimSpace(request.TaskID)
	if request.APIVersion != "codexploit/v1" || request.SnapshotID == "" || request.InvocationID == "" || request.BatchID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("codexploit/v1, snapshot_id, invocation_id and batch_id are required"))
		return
	}
	index, ok := s.Store.(artifact.Index)
	if !ok {
		writeError(w, http.StatusNotImplemented, "publications_unavailable", errors.New("artifact scope is unavailable"))
		return
	}
	scope, err := index.ArtifactScope(r.Context(), r.PathValue("projectID"), request.SnapshotID)
	if err != nil {
		writePublicationError(w, publication.ErrNotFound)
		return
	}
	invocation, err := s.Plugins.GetStatus(r.Context(), scope, request.InvocationID)
	if err != nil {
		writePublicationError(w, err)
		return
	}
	if invocation.Status != "SUCCEEDED" && invocation.Status != "PARTIAL" {
		writeError(w, http.StatusConflict, "invocation_not_complete", errors.New("only a completed invocation can be published"))
		return
	}
	if request.TaskID != "" {
		if s.Audit == nil {
			writeError(w, http.StatusNotImplemented, "tasks_unavailable", errors.New("the path engine is unavailable"))
			return
		}
		task, err := s.Audit.Audit(request.TaskID)
		if err != nil || task == nil || task.SnapshotID != scope.SnapshotID {
			writeError(w, http.StatusNotFound, "task_not_found", errors.New("the task does not belong to this snapshot"))
			return
		}
	}
	document, err := s.Plugins.Result(r.Context(), scope, request.InvocationID, 8<<20)
	if err != nil {
		writePublicationError(w, err)
		return
	}
	batch, omittedEdges := publication.BatchFromDiscovery(
		request.BatchID,
		publication.Scope{ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID},
		artifact.Producer{
			PluginID:      invocation.Request.PluginID,
			PluginVersion: invocation.Request.PluginVersion,
			InvocationID:  invocation.ID,
			TaskID:        request.TaskID,
			ConfigDigest:  invocation.ConfigDigest,
		},
		document,
		request.BaseRevision,
		"security",
	)
	if omittedEdges > 0 {
		batch.Limitations = append(batch.Limitations, fmt.Sprintf("%d cross-layer edge(s) were omitted because their endpoints are not attack-surface facts in this batch", omittedEdges))
	}
	batch.Analysis, err = s.publicationAnalysis(r.Context(), document)
	if err != nil {
		writePublicationError(w, err)
		return
	}
	revision, err := s.Publications.Publish(r.Context(), batch)
	if err != nil {
		writePublicationError(w, err)
		return
	}
	if s.Findings != nil && len(document.Candidates) > 0 {
		producer := artifact.Producer{
			PluginID:      invocation.Request.PluginID,
			PluginVersion: invocation.Request.PluginVersion,
			InvocationID:  invocation.ID,
			TaskID:        request.TaskID,
			ConfigDigest:  invocation.ConfigDigest,
		}
		if _, err := s.Findings.RecordCandidates(r.Context(), scope, request.TaskID, producer, document.Candidates); err != nil {
			writeFindingsError(w, err)
			return
		}
	}
	view, err := publication.NewView(batch.Scope, revision.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	receipt := map[string]any{
		"api_version": "codexploit/v1",
		"publication": map[string]any{
			"status":   "published",
			"revision": revision.ID,
			"digest":   revision.Digest,
			"facts":    len(batch.Facts),
			"edges":    len(batch.Edges),
			"view":     view,
		},
	}
	schema, err := publicationSchema()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "contract_unavailable", err)
		return
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	if err := schema.Validate(value); err != nil {
		writeError(w, http.StatusInternalServerError, "contract_violation", err)
		return
	}
	writeJSON(w, http.StatusCreated, receipt)
}

// revisionStore resolves the publication store or reports the feature missing.
func (s *Server) revisionStore(w http.ResponseWriter) (publication.Store, bool) {
	store, ok := s.Store.(publication.Store)
	if !ok {
		writeError(w, http.StatusNotImplemented, "publications_unavailable", errors.New("knowledge publications are unavailable"))
		return nil, false
	}
	return store, true
}

func revisionPage(r *http.Request) (offset, limit int, ok bool) {
	limit = 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			return 0, 0, false
		}
		limit = value
	}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		decoded, err := decodeRevisionCursor(raw)
		if err != nil {
			return 0, 0, false
		}
		offset = decoded
	}
	return offset, limit, true
}

func decodeRevisionCursor(cursor string) (int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(string(raw), "o:") {
		return 0, errors.New("invalid revision cursor")
	}
	value, err := strconv.Atoi(strings.TrimPrefix(string(raw), "o:"))
	if err != nil || value < 0 {
		return 0, errors.New("invalid revision cursor")
	}
	return value, nil
}

// handleKnowledgeRevisionFacts reads one published revision. It never resolves
// "latest": the view id names the revision, so a newer publication cannot
// change what an in-flight reader sees.
func (s *Server) handleKnowledgeRevisionFacts(w http.ResponseWriter, r *http.Request) {
	store, ok := s.revisionStore(w)
	if !ok {
		return
	}
	scope, revision, err := publication.ParseView(r.PathValue("viewID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", publication.ErrInvalidView)
		return
	}
	if scope.ProjectID != r.PathValue("projectID") {
		writeError(w, http.StatusNotFound, "knowledge_not_found", publication.ErrNotFound)
		return
	}
	if requested := r.URL.Query().Get("snapshot_id"); requested != "" && requested != scope.SnapshotID {
		writeError(w, http.StatusNotFound, "knowledge_not_found", publication.ErrNotFound)
		return
	}
	offset, limit, ok := revisionPage(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("limit or cursor is invalid"))
		return
	}
	document, err := store.GetKnowledgeRevision(r.Context(), scope, revision)
	if err != nil {
		writePublicationError(w, err)
		return
	}
	facts := document.Facts
	if offset > len(facts) {
		offset = len(facts)
	}
	end := offset + limit
	if end > len(facts) {
		end = len(facts)
	}
	next := ""
	if end < len(facts) {
		next = base64.RawURLEncoding.EncodeToString([]byte("o:" + strconv.Itoa(end)))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_version": "codexploit/v1",
		"revision":    document.Revision,
		"facts":       facts[offset:end],
		"next_cursor": next,
	})
}

// handleListKnowledgeRevisions lists the immutable versions of one snapshot so
// the workbench can choose a version instead of always reading the newest one.
func (s *Server) handleListKnowledgeRevisions(w http.ResponseWriter, r *http.Request) {
	store, ok := s.revisionStore(w)
	if !ok {
		return
	}
	snapshotID := strings.TrimSpace(r.URL.Query().Get("snapshot_id"))
	if snapshotID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("snapshot_id is required"))
		return
	}
	offset, limit, valid := revisionPage(r)
	if !valid {
		writeError(w, 400, "invalid_request", errors.New("limit or cursor is invalid"))
		return
	}
	if r.URL.Query().Get("limit") == "" {
		limit = 100
	}
	if offset > 10000 {
		writeError(w, 413, "knowledge_directory_budget", errors.New("revision directory offset exceeds 10000"))
		return
	}
	scope := publication.Scope{ProjectID: r.PathValue("projectID"), SnapshotID: snapshotID}
	head, err := store.KnowledgeHead(r.Context(), scope)
	if err != nil {
		writePublicationError(w, err)
		return
	}
	revisions, err := store.ListKnowledgeRevisions(r.Context(), scope, offset+limit+1)
	if err != nil {
		writePublicationError(w, err)
		return
	}
	if offset > len(revisions) {
		offset = len(revisions)
	}
	end := offset + limit
	if end > len(revisions) {
		end = len(revisions)
	}
	next := ""
	if end < len(revisions) {
		next = base64.RawURLEncoding.EncodeToString([]byte("o:" + strconv.Itoa(end)))
	}
	revisions = revisions[offset:end]
	type revisionView struct {
		publication.Revision
		View publication.View `json:"view"`
	}
	items := make([]revisionView, 0, len(revisions))
	for _, revision := range revisions {
		view, err := publication.NewView(scope, revision.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", err)
			return
		}
		items = append(items, revisionView{Revision: revision, View: view})
	}
	writeKnowledgeDirectory(w, map[string]any{"api_version": "codexploit/v1", "head_revision": head, "revisions": items, "next_cursor": next})
}
