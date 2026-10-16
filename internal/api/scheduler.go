package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/schedule"
)

// The scheduler surface is the smallest operator surface in the API: read what the
// resident scheduler is doing, run one pass by hand, or sweep expired leases. It
// exists because P7's failure mode is silence — a scheduler that is not running,
// or one whose queue is not draining, looks exactly like a quiet system.

// WithScheduler attaches the P7 resident scheduler, which enables the scheduler
// routes. Without it those routes answer 501, because a deployment that never
// scheduled anything must not look like one whose queue happens to be empty.
func WithScheduler(s *schedule.Scheduler) Option {
	return func(server *Server) { server.Scheduler = s }
}

// schedulerUnavailable mirrors auditUnavailable: a server without the scheduler
// says "not configured" instead of answering with zeros that read like a healthy
// idle loop.
func (s *Server) schedulerUnavailable(w http.ResponseWriter) bool {
	if s.Scheduler == nil {
		writeError(w, http.StatusNotImplemented, "scheduler_unavailable",
			errors.New("this server was started without the scheduler; start it with --scheduler"))
		return true
	}
	return false
}

// --- GET /api/scheduler ------------------------------------------------------

// handleSchedulerStatus answers GET /api/scheduler with the metrics snapshot and
// whether the resident loop is running.
func (s *Server) handleSchedulerStatus(w http.ResponseWriter, r *http.Request) {
	if s.schedulerUnavailable(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.Scheduler.Snapshot())
}

// --- POST /api/scheduler/tick ------------------------------------------------

// schedulerTickRequest is the optional body of the manual tick. Both fields are
// overrides of this pass only: the resident scheduler's configuration is not
// rewritten by an operator call.
type schedulerTickRequest struct {
	Audits      []string `json:"audits"`
	Concurrency int      `json:"concurrency"`
}

// handleSchedulerTick answers POST /api/scheduler/tick: one scheduling pass,
// synchronous, with the pass's own summary in the body.
//
// The route needs write capability and an idempotency key like every other write:
// a pass claims leases and spends an audit's budget, so replaying it must not run
// it twice.
func (s *Server) handleSchedulerTick(w http.ResponseWriter, r *http.Request) {
	if s.schedulerUnavailable(w) {
		return
	}
	var req schedulerTickRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.Concurrency < 0 {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Errorf("concurrency must not be negative (got %d)", req.Concurrency))
		return
	}
	for _, id := range req.Audits {
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", errors.New("an audit id must not be empty"))
			return
		}
	}
	result, err := s.Scheduler.TickScoped(r.Context(), req.Audits, req.Concurrency)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// --- POST /api/scheduler/reclaim ---------------------------------------------

// schedulerReclaimRequest is the optional body of the manual sweep.
type schedulerReclaimRequest struct {
	Limit int `json:"limit"`
}

// handleSchedulerReclaim answers POST /api/scheduler/reclaim: one recovery sweep
// of expired leases, which is what an operator runs after killing a worker.
func (s *Server) handleSchedulerReclaim(w http.ResponseWriter, r *http.Request) {
	if s.schedulerUnavailable(w) {
		return
	}
	var req schedulerReclaimRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.Limit < 0 {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Errorf("limit must not be negative (got %d)", req.Limit))
		return
	}
	recovered, err := s.Scheduler.Reclaim(req.Limit)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if recovered == nil {
		recovered = []path.Path{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"recovered": recovered,
		"count":     len(recovered),
	})
}
