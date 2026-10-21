package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/supervisor"
)

func WithSupervisor(service *supervisor.Service) Option {
	return func(s *Server) { s.Supervisor = service }
}

func (s *Server) supervisorAvailable(w http.ResponseWriter) bool {
	if s.Supervisor == nil {
		writeError(w, http.StatusNotImplemented, "supervisor_unavailable", errors.New("the project supervisor is not configured"))
		return false
	}
	return true
}

func writeSupervisorError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, supervisor.ErrUnavailable):
		writeError(w, http.StatusConflict, "agent_unavailable", err)
	case errors.Is(err, supervisor.ErrConflict), errors.Is(err, storage.ErrConflict):
		writeError(w, http.StatusConflict, "supervisor_conflict", err)
	case errors.Is(err, supervisor.ErrNotFound), errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "supervisor_not_found", err)
	case errors.Is(err, supervisor.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_request", err)
	default:
		writeError(w, http.StatusServiceUnavailable, "supervisor_unavailable", errors.New("supervisor operation failed"))
	}
}

func (s *Server) projectSupervisorInput(w http.ResponseWriter, r *http.Request) (string, bool) {
	projectID := r.PathValue("projectID")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return "", false
	}
	input, err := s.Store.GetProjectInput(r.Context(), projectID)
	if err != nil || input.State != storage.ProjectInputReady || input.SnapshotID == "" {
		writeError(w, http.StatusConflict, "analysis_input_unavailable", errors.New("the project source input must be ready before a conversation"))
		return "", false
	}
	return input.SnapshotID, true
}

func (s *Server) handleListSupervisorSessions(w http.ResponseWriter, r *http.Request) {
	if !s.supervisorAvailable(w) {
		return
	}
	projectID := r.PathValue("projectID")
	if _, ok := s.projectSupervisorInput(w, r); !ok {
		return
	}
	sessions, err := s.Supervisor.List(r.Context(), projectID, 20)
	if err != nil {
		writeSupervisorError(w, err)
		return
	}
	reason := ""
	if readyErr := s.Supervisor.Ready(); readyErr != nil {
		reason = readyErr.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "sessions": sessions, "available": reason == "", "reason": reason})
}

type createSupervisorSessionRequest struct {
	APIVersion string `json:"api_version"`
	Title      string `json:"title"`
}

func (s *Server) handleCreateSupervisorSession(w http.ResponseWriter, r *http.Request) {
	if !s.supervisorAvailable(w) {
		return
	}
	snapshotID, ok := s.projectSupervisorInput(w, r)
	if !ok {
		return
	}
	var req createSupervisorSessionRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.APIVersion != "codexploit/v1" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("api_version must be codexploit/v1"))
		return
	}
	if readyErr := s.Supervisor.Ready(); readyErr != nil {
		writeSupervisorError(w, readyErr)
		return
	}
	session, err := s.Supervisor.EnsureSession(r.Context(), r.PathValue("projectID"), snapshotID, req.Title)
	if err != nil {
		writeSupervisorError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+session.ID+`-`+strconv.FormatInt(session.Version, 10)+`"`)
	writeJSON(w, http.StatusCreated, map[string]any{"api_version": "codexploit/v1", "session": session})
}

func (s *Server) handleGetSupervisorSession(w http.ResponseWriter, r *http.Request) {
	if !s.supervisorAvailable(w) {
		return
	}
	session, err := s.Supervisor.Get(r.Context(), r.PathValue("projectID"), r.PathValue("sessionID"))
	if err != nil {
		writeSupervisorError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+session.ID+`-`+strconv.FormatInt(session.Version, 10)+`"`)
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "session": session})
}

func (s *Server) handleSupervisorMessages(w http.ResponseWriter, r *http.Request) {
	if !s.supervisorAvailable(w) {
		return
	}
	session, err := s.Supervisor.Get(r.Context(), r.PathValue("projectID"), r.PathValue("sessionID"))
	if err != nil {
		writeSupervisorError(w, err)
		return
	}
	after := int64(0)
	if raw := r.URL.Query().Get("after_seq"); raw != "" {
		after, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", errors.New("after_seq must be an integer"))
			return
		}
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			writeError(w, http.StatusBadRequest, "invalid_request", errors.New("limit must be 1–200"))
			return
		}
	}
	messages := []storage.SupervisorMessage{}
	for _, message := range session.Messages {
		if message.Seq > after {
			messages = append(messages, message)
		}
		if len(messages) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "messages": messages})
}

type supervisorMessageRequest struct {
	APIVersion      string `json:"api_version"`
	Content         string `json:"content"`
	ClientMessageID string `json:"client_message_id"`
}

func (s *Server) handlePostSupervisorMessage(w http.ResponseWriter, r *http.Request) {
	if !s.supervisorAvailable(w) {
		return
	}
	var req supervisorMessageRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.APIVersion != "codexploit/v1" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("api_version must be codexploit/v1"))
		return
	}
	message, run, err := s.Supervisor.Send(r.Context(), r.PathValue("projectID"), r.PathValue("sessionID"), req.Content, req.ClientMessageID)
	if err != nil {
		writeSupervisorError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"api_version": "codexploit/v1", "message": message, "run": run})
}

func (s *Server) handleSupervisorEvents(w http.ResponseWriter, r *http.Request) {
	if !s.supervisorAvailable(w) {
		return
	}
	session, err := s.Supervisor.Get(r.Context(), r.PathValue("projectID"), r.PathValue("sessionID"))
	if err != nil {
		writeSupervisorError(w, err)
		return
	}
	after := int64(0)
	if raw := r.URL.Query().Get("after_seq"); raw != "" {
		after, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", errors.New("after_seq must be an integer"))
			return
		}
	}
	events := []storage.SupervisorEvent{}
	next := after
	for _, event := range session.Events {
		if event.Seq > after {
			events = append(events, event)
			next = event.Seq
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "events": events, "next_seq": next})
}

func (s *Server) handleGetSupervisorRun(w http.ResponseWriter, r *http.Request) {
	if !s.supervisorAvailable(w) {
		return
	}
	session, err := s.Supervisor.Get(r.Context(), r.PathValue("projectID"), r.PathValue("sessionID"))
	if err != nil {
		writeSupervisorError(w, err)
		return
	}
	for _, run := range session.Runs {
		if run.ID == r.PathValue("runID") {
			writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "run": run})
			return
		}
	}
	writeSupervisorError(w, supervisor.ErrNotFound)
}

type cancelSupervisorRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleCancelSupervisorRun(w http.ResponseWriter, r *http.Request) {
	if !s.supervisorAvailable(w) {
		return
	}
	var req cancelSupervisorRequest
	if !s.decode(w, r, &req) {
		return
	}
	run, err := s.Supervisor.Cancel(r.Context(), r.PathValue("projectID"), r.PathValue("sessionID"), r.PathValue("runID"), strings.TrimSpace(req.Reason))
	if err != nil {
		writeSupervisorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "run": run})
}
