package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/reviewbatch"
)

var reviewBatchSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	load := func(name string) (*jsonschema.Schema, error) {
		raw, err := contracts.Files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var schema jsonschema.Schema
		if err := json.Unmarshal(raw, &schema); err != nil {
			return nil, err
		}
		return &schema, nil
	}
	schema, err := load("review-batch.schema.json")
	if err != nil {
		return nil, err
	}
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
		if uri.Scheme != "https" || uri.Host != "codexploit.invalid" || path.Dir(uri.Path) != "/contracts/v1" {
			return nil, errors.New("review batch schema dependency is outside contracts/v1")
		}
		return load(path.Base(uri.Path))
	}})
})

func writeReviewBatchJSON(w http.ResponseWriter, status int, document any) {
	schema, err := reviewBatchSchema()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "contract_unavailable", err)
		return
	}
	raw, err := json.Marshal(document)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	var value any
	if json.Unmarshal(raw, &value) != nil || schema.Validate(value) != nil {
		writeError(w, http.StatusInternalServerError, "contract_violation", errors.New("review batch response does not satisfy the public contract"))
		return
	}
	writeJSON(w, status, document)
}

func WithReviewBatches(manager *reviewbatch.Manager) Option {
	return func(s *Server) { s.ReviewBatches = manager }
}

type startReviewBatchRequest struct {
	APIVersion    string `json:"api_version"`
	AuditID       string `json:"audit_id"`
	MaxConcurrent int    `json:"max_concurrent,omitempty"`
	MaxPaths      int    `json:"max_paths,omitempty"`
}

type reviewBatchControlRequest struct {
	Reason string `json:"reason,omitempty"`
}

func (s *Server) reviewBatchUnavailable(w http.ResponseWriter) bool {
	if s.ReviewBatches == nil {
		writeError(w, http.StatusNotImplemented, "review_batches_unavailable",
			errors.New("this deployment has no durable review-batch coordinator"))
		return true
	}
	return false
}

func reviewBatchDocument(view reviewbatch.View) map[string]any {
	return map[string]any{
		"api_version": "codexploit/v1",
		"batch":       view.Batch,
		"progress":    view.Progress,
		"paths":       view.Paths,
	}
}

func reviewBatchETag(view reviewbatch.View) string {
	return fmt.Sprintf(`"review-batch-%s-v%d"`, view.Batch.ID, view.Batch.Version)
}

func (s *Server) handleStartReviewBatch(w http.ResponseWriter, r *http.Request) {
	if s.reviewBatchUnavailable(w) {
		return
	}
	projectID := r.PathValue("projectID")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	var req startReviewBatchRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.APIVersion != "codexploit/v1" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("api_version must be codexploit/v1"))
		return
	}
	audit, err := s.Audit.Audit(strings.TrimSpace(req.AuditID))
	if err != nil {
		writeAuditError(w, err, req.AuditID)
		return
	}
	if !s.projectOwnsSnapshot(r, projectID, audit.SnapshotID) {
		writeError(w, http.StatusNotFound, "not_found", errors.New("audit does not belong to this project"))
		return
	}
	view, err := s.ReviewBatches.Start(r.Context(), projectID, audit.ID, principalName(r), req.MaxConcurrent, req.MaxPaths)
	if err != nil {
		writeReviewBatchError(w, err)
		return
	}
	w.Header().Set("ETag", reviewBatchETag(view))
	writeReviewBatchJSON(w, http.StatusCreated, reviewBatchDocument(view))
}

func (s *Server) handleListReviewBatches(w http.ResponseWriter, r *http.Request) {
	if s.reviewBatchUnavailable(w) {
		return
	}
	projectID := r.PathValue("projectID")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	query := reviewbatch.Query{
		ProjectID: projectID,
		AuditID:   strings.TrimSpace(r.URL.Query().Get("audit_id")),
		Limit:     pageLimit(r.URL.Query().Get("limit")),
		Offset:    max(0, queryInt(r.URL.Query().Get("offset"), 0)),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("state")); raw != "" {
		query.State = reviewbatch.State(raw)
		if !reviewbatch.ValidState(query.State) {
			writeError(w, http.StatusBadRequest, "invalid_request", fmt.Errorf("unknown review batch state %q", raw))
			return
		}
	}
	views, total, err := s.ReviewBatches.List(r.Context(), query)
	if err != nil {
		writeReviewBatchError(w, err)
		return
	}
	documents := make([]map[string]any, 0, len(views))
	for _, view := range views {
		documents = append(documents, reviewBatchDocument(view))
	}
	writeReviewBatchJSON(w, http.StatusOK, map[string]any{
		"api_version": "codexploit/v1",
		"batches":     documents,
		"total":       total,
	})
}

func (s *Server) handleGetReviewBatch(w http.ResponseWriter, r *http.Request) {
	if s.reviewBatchUnavailable(w) {
		return
	}
	view, err := s.ReviewBatches.Get(r.Context(), r.PathValue("batchID"))
	if err != nil {
		writeReviewBatchError(w, err)
		return
	}
	if !s.projectOwnsSnapshot(r, r.PathValue("projectID"), view.Batch.SnapshotID) {
		writeReviewBatchError(w, reviewbatch.ErrNotFound)
		return
	}
	w.Header().Set("ETag", reviewBatchETag(view))
	writeReviewBatchJSON(w, http.StatusOK, reviewBatchDocument(view))
}

func (s *Server) handleReviewBatchControl(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.reviewBatchUnavailable(w) {
			return
		}
		projectID, batchID := r.PathValue("projectID"), r.PathValue("batchID")
		current, err := s.ReviewBatches.Get(r.Context(), batchID)
		if err != nil {
			writeReviewBatchError(w, err)
			return
		}
		if !s.projectOwnsSnapshot(r, projectID, current.Batch.SnapshotID) {
			writeReviewBatchError(w, reviewbatch.ErrNotFound)
			return
		}
		if !requireEntityVersion(w, r, reviewBatchETag(current)) {
			return
		}
		var req reviewBatchControlRequest
		if !s.decode(w, r, &req) {
			return
		}
		actor := principalName(r)
		var view reviewbatch.View
		switch action {
		case "pause":
			view, err = s.ReviewBatches.Pause(r.Context(), batchID, current.Batch.Version, actor, req.Reason)
		case "resume":
			view, err = s.ReviewBatches.Resume(r.Context(), batchID, current.Batch.Version, actor, req.Reason)
		case "cancel":
			view, err = s.ReviewBatches.Cancel(r.Context(), batchID, current.Batch.Version, actor, req.Reason)
		default:
			writeError(w, http.StatusNotFound, "not_found", errors.New("unknown review batch action"))
			return
		}
		if err != nil {
			writeReviewBatchError(w, err)
			return
		}
		w.Header().Set("ETag", reviewBatchETag(view))
		writeReviewBatchJSON(w, http.StatusOK, reviewBatchDocument(view))
	}
}

func (s *Server) projectOwnsSnapshot(r *http.Request, projectID, snapshotID string) bool {
	snapshots, err := s.Store.ListSnapshots(r.Context(), projectID)
	if err != nil {
		return false
	}
	for _, snapshot := range snapshots {
		if snapshot.SnapshotID == snapshotID {
			return true
		}
	}
	return false
}

func writeReviewBatchError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, reviewbatch.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err)
	case errors.Is(err, reviewbatch.ErrConflict):
		writeError(w, http.StatusConflict, "review_batch_conflict", err)
	case errors.Is(err, reviewbatch.ErrNoWork):
		writeError(w, http.StatusConflict, "no_queued_paths", err)
	case errors.Is(err, reviewbatch.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_request", err)
	case errors.Is(err, reviewbatch.ErrUnavailable):
		writeError(w, http.StatusNotImplemented, "review_batches_unavailable", err)
	default:
		writeStorageError(w, err)
	}
}
