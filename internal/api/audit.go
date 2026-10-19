package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// defaultAuditPageSize matches the queue-oriented defaults of the engine: a
// caller that names no limit gets a reviewable page, not the whole table.
const defaultAuditPageSize = 200

// maxAuditPageSize bounds every page. The audit table can hold thousands of
// paths, and an unbounded answer would be the largest response the API serves.
const maxAuditPageSize = 1000

// WithAudit attaches the path engine, which enables the audit and path routes.
func WithAudit(svc *path.Service) Option { return func(s *Server) { s.Audit = svc } }

// auditUnavailable mirrors asgUnavailable: a server without the path engine must
// say "not configured" rather than answer as if the audit were missing.
func (s *Server) auditUnavailable(w http.ResponseWriter) bool {
	if s.Audit == nil {
		writeError(w, http.StatusNotImplemented, "audit_unavailable",
			errors.New("this server was started without the audit (path) service"))
		return true
	}
	return false
}

// --- POST /api/audits -------------------------------------------------------

// createAuditRequest is the audit request. Budget and Limits are the engine's own
// documents so the wire format and the stored configuration cannot drift.
type createAuditRequest struct {
	SnapshotID  string             `json:"snapshot_id"`
	Force       bool               `json:"force"`
	Budget      path.Budget        `json:"budget"`
	Limits      path.Limits        `json:"limits"`
	Sensitivity map[string]float64 `json:"sensitivity"`
}

// auditResponse is the answer to an audit request: the audit, how many paths it
// queued, and whether the request was replayed instead of recomputed.
type auditResponse struct {
	Audit     *path.Audit `json:"audit"`
	PathCount int         `json:"path_count"`
	Replayed  bool        `json:"replayed"`
}

func (s *Server) handleCreateAudit(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	var req createAuditRequest
	if !s.decode(w, r, &req) {
		return
	}
	snapshotID := strings.TrimSpace(req.SnapshotID)
	if snapshotID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("snapshot_id is required"))
		return
	}
	if err := validateAuditRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	// The engine reports "no such snapshot" and "snapshot has no attack surface"
	// with the same sentinel, so the snapshot record is consulted first: the two
	// are different operator actions and must not share a status code.
	if _, err := s.Store.GetSnapshot(r.Context(), snapshotID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found",
				fmt.Errorf("snapshot %s does not exist; freeze it first with POST /api/projects/{id}/snapshots", snapshotID))
			return
		}
		writeStorageError(w, err)
		return
	}
	result, err := s.Audit.CreateAudit(r.Context(), path.CreateAuditRequest{
		SnapshotID:  snapshotID,
		Force:       req.Force,
		Budget:      req.Budget,
		Limits:      req.Limits,
		Sensitivity: req.Sensitivity,
	})
	if err != nil {
		writeAuditError(w, err, snapshotID)
		return
	}
	// A replay is not a creation: 200 tells a script that no new ranking was
	// produced, while the body still carries the audit to work with.
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, auditResponse{Audit: &result.Audit, PathCount: result.Audit.PathCount, Replayed: result.Replayed})
}

// validateAuditRequest rejects a body the engine would silently normalise. A
// negative bound or a sensitivity outside [0,1] is a client mistake, and
// accepting it would make the stored configuration disagree with the request.
func validateAuditRequest(req createAuditRequest) error {
	bounds := []struct {
		name  string
		value int
	}{
		{"budget.max_depth", req.Budget.MaxDepth},
		{"budget.max_branches", req.Budget.MaxBranches},
		{"budget.max_tool_calls", req.Budget.MaxToolCalls},
		{"limits.max_entries", req.Limits.MaxEntries},
		{"limits.max_sinks_per_entry", req.Limits.MaxSinksPerEntry},
		{"limits.max_chains_per_pair", req.Limits.MaxChainsPerPair},
		{"limits.max_paths", req.Limits.MaxPaths},
		{"limits.max_active_leases", req.Limits.MaxActiveLeases},
		{"limits.max_attempts", req.Limits.MaxAttempts},
		{"limits.chain_query_budget", req.Limits.ChainQueryBudget},
		{"limits.lease_ttl_seconds", req.Limits.LeaseTTLSeconds},
	}
	for _, bound := range bounds {
		if bound.value < 0 {
			return fmt.Errorf("%s must not be negative (got %d)", bound.name, bound.value)
		}
	}
	if req.Limits.ExplorationFraction < 0 {
		return fmt.Errorf("limits.exploration_fraction must not be negative (got %v)", req.Limits.ExplorationFraction)
	}
	keys := make([]string, 0, len(req.Sensitivity))
	for key := range req.Sensitivity {
		keys = append(keys, key)
	}
	// Sorted so the same bad body always produces the same message.
	sort.Strings(keys)
	for _, key := range keys {
		if strings.TrimSpace(key) == "" {
			return errors.New("sensitivity keys must not be empty")
		}
		if value := req.Sensitivity[key]; value < 0 || value > 1 {
			return fmt.Errorf("sensitivity[%s] must be in [0,1] (got %v)", key, value)
		}
	}
	return nil
}

// --- reads ------------------------------------------------------------------

// handleListAudits answers GET /api/audits.
func (s *Server) handleListAudits(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	q := r.URL.Query()
	status := strings.TrimSpace(q.Get("status"))
	if status != "" && !validAuditStatus(status) {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Errorf("unknown audit status %q; valid statuses are %s", status, strings.Join(auditStatusNames(), ", ")))
		return
	}
	audits, total, err := s.Audit.Audits(path.AuditQuery{
		SnapshotID: strings.TrimSpace(q.Get("snapshot_id")),
		Status:     status,
		Limit:      pageLimit(q.Get("limit")),
		Offset:     queryInt(q.Get("offset"), 0),
	})
	if err != nil {
		writeAuditError(w, err, "")
		return
	}
	if audits == nil {
		audits = []path.Audit{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"audits": audits, "total": total})
}

// handleGetAudit answers GET /api/audits/{id}.
func (s *Server) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	audit, err := s.Audit.Audit(r.PathValue("id"))
	if err != nil {
		writeAuditError(w, err, r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, audit)
}

// handleAuditPaths answers GET /api/audits/{id}/paths. The page is ordered by
// the queue unless the caller asks for a different sort, so the default answer is
// exactly the order a scheduler would serve.
func (s *Server) handleAuditPaths(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	if _, err := s.Audit.Audit(id); err != nil {
		writeAuditError(w, err, id)
		return
	}
	q := r.URL.Query()
	statuses, err := parsePathStatuses(q.Get("status"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	pathStatuses, err := parsePathStatusClasses(q.Get("path_status"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	sortKey, err := parsePathSort(q.Get("sort"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	minPriority := 0.0
	if raw := strings.TrimSpace(q.Get("min_priority")); raw != "" {
		minPriority, err = strconv.ParseFloat(raw, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request",
				fmt.Errorf("min_priority must be a number: %w", err))
			return
		}
	}
	paths, total, err := s.Audit.Paths(path.PathQuery{
		AuditID:      id,
		Status:       statuses,
		PathStatus:   pathStatuses,
		EntryNodeID:  strings.TrimSpace(q.Get("entry")),
		TargetNodeID: strings.TrimSpace(q.Get("target")),
		MinPriority:  minPriority,
		Sort:         sortKey,
		Limit:        pageLimit(q.Get("limit")),
		Offset:       queryInt(q.Get("offset"), 0),
	})
	if err != nil {
		writeAuditError(w, err, id)
		return
	}
	if paths == nil {
		paths = []path.Path{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"audit_id":         id,
		"paths":            paths,
		"total":            total,
		"objective_counts": path.ObjectiveCounts(paths),
	})
}

// auditEventPage is a bounded page of the event log. Streaming is deliberately
// not offered here; the WebUI phase owns the transport, and after_seq makes a
// poll a resumable cursor in the meantime.
type auditEventPage struct {
	AuditID      string       `json:"audit_id"`
	Events       []path.Event `json:"events"`
	Total        int          `json:"total"`
	NextAfterSeq int64        `json:"next_after_seq"`
}

// handleAuditEvents answers GET /api/audits/{id}/events.
func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	if _, err := s.Audit.Audit(id); err != nil {
		writeAuditError(w, err, id)
		return
	}
	q := r.URL.Query()
	afterSeq := int64(0)
	if raw := strings.TrimSpace(q.Get("after_seq")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			writeError(w, http.StatusBadRequest, "invalid_request",
				fmt.Errorf("after_seq must be a non-negative integer (got %q)", raw))
			return
		}
		afterSeq = value
	}
	events, err := s.Audit.Events(path.EventQuery{
		AuditID:  id,
		PathID:   strings.TrimSpace(q.Get("path_id")),
		AfterSeq: afterSeq,
		Limit:    pageLimit(q.Get("limit")),
	})
	if err != nil {
		writeAuditError(w, err, id)
		return
	}
	if events == nil {
		events = []path.Event{}
	}
	next := afterSeq
	for _, event := range events {
		if event.Seq > next {
			next = event.Seq
		}
	}
	writeJSON(w, http.StatusOK, auditEventPage{AuditID: id, Events: events, Total: len(events), NextAfterSeq: next})
}

// handleAuditNext answers GET /api/audits/{id}/next. It answers a question, it
// does not take a lease: two callers asking "what next" must see the same answer
// until someone actually claims it.
func (s *Server) handleAuditNext(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	if _, err := s.Audit.Audit(id); err != nil {
		writeAuditError(w, err, id)
		return
	}
	next, err := s.Audit.Next(id)
	if err != nil {
		if errors.Is(err, path.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found",
				fmt.Errorf("audit %s has no queued path to serve", id))
			return
		}
		writeAuditError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit_id": id, "path": next, "leased": false})
}

// pathDetailResponse is one path with the history that makes its ranking
// reviewable: the score snapshots and the events of that path.
type pathDetailResponse struct {
	Path     *path.Path           `json:"path"`
	Features []path.FeatureRecord `json:"features"`
	Events   []path.Event         `json:"events"`
}

// handleGetPath answers GET /api/paths/{id}.
func (s *Server) handleGetPath(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	p, features, err := s.Audit.Path(id)
	if err != nil {
		writeAuditError(w, err, id)
		return
	}
	events, err := s.Audit.Events(path.EventQuery{AuditID: p.AuditID, PathID: id, Limit: maxAuditPageSize})
	if err != nil {
		writeAuditError(w, err, id)
		return
	}
	if features == nil {
		features = []path.FeatureRecord{}
	}
	if events == nil {
		events = []path.Event{}
	}
	w.Header().Set("ETag", pathETag(p))
	writeJSON(w, http.StatusOK, pathDetailResponse{Path: p, Features: features, Events: events})
}

// --- path lifecycle ---------------------------------------------------------

// pathActionRequest is the body shared by pause, resume and cancel.
type pathActionRequest struct {
	Reason string `json:"reason"`
}

// handlePathTransition builds the handler for POST /api/paths/{id}/{action}.
func (s *Server) handlePathTransition(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.auditUnavailable(w) {
			return
		}
		id := r.PathValue("id")
		current, _, err := s.Audit.Path(id)
		if err != nil {
			writeAuditError(w, err, id)
			return
		}
		// The precondition is checked before the body is read, exactly like the
		// project rename: a caller that never read the path must not be able to
		// overwrite a decision it did not see.
		if !requirePathVersion(w, r, current) {
			return
		}
		var req pathActionRequest
		if !s.decode(w, r, &req) {
			return
		}
		actor := principalName(r)
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = fmt.Sprintf("%s requested by %s", action, actor)
		}
		var updated *path.Path
		switch action {
		case "pause":
			updated, err = s.Audit.Pause(id, actor, reason)
		case "resume":
			updated, err = s.Audit.Resume(id, actor, reason)
		case "cancel":
			updated, err = s.Audit.Cancel(id, actor, reason)
		default:
			writeError(w, http.StatusNotImplemented, "invalid_request", fmt.Errorf("unknown path action %q", action))
			return
		}
		if err != nil {
			writeAuditError(w, err, id)
			return
		}
		w.Header().Set("ETag", pathETag(updated))
		writeJSON(w, http.StatusOK, updated)
	}
}

// claimPathRequest is the body of POST /api/paths/{id}/claim.
type claimPathRequest struct {
	Owner      string `json:"owner"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// handleClaimAudit answers POST /api/audits/{id}/claim: lease the next path of an
// audit's queue.
//
// The route is audit-scoped because the decision is: the ceiling on active leases
// is a property of the audit, and the scheduler picks by marginal coverage over
// the whole queue, not per row. The path in the answer is the one actually leased.
func (s *Server) handleClaimAudit(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	auditID := r.PathValue("id")
	if _, err := s.Audit.Audit(auditID); err != nil {
		writeAuditError(w, err, auditID)
		return
	}
	s.claim(w, r, auditID, auditID)
}

// handleClaimPath answers POST /api/paths/{id}/claim, which is the same operation
// reached through a path: the path only identifies the audit whose queue is leased.
// It is kept because a worker that holds a path id should not have to look up its
// audit first, but it is not the canonical spelling — the leased path may differ
// from the id in the URL, which is exactly why the audit route exists.
func (s *Server) handleClaimPath(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	current, _, err := s.Audit.Path(id)
	if err != nil {
		writeAuditError(w, err, id)
		return
	}
	s.claim(w, r, current.AuditID, id)
}

// claim performs the lease itself, so both routes share one implementation.
func (s *Server) claim(w http.ResponseWriter, r *http.Request, auditID, requestedFrom string) {
	var req claimPathRequest
	if !s.decode(w, r, &req) {
		return
	}
	owner := strings.TrimSpace(req.Owner)
	if owner == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("owner is required to claim a path"))
		return
	}
	if req.TTLSeconds < 0 {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Errorf("ttl_seconds must not be negative (got %d)", req.TTLSeconds))
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	leased, err := s.Audit.Claim(r.Context(), auditID, owner, ttl)
	if err != nil {
		if errors.Is(err, path.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found",
				fmt.Errorf("audit %s has no queued path to claim (requested from %s)", auditID, requestedFrom))
			return
		}
		writeAuditError(w, err, auditID)
		return
	}
	w.Header().Set("ETag", pathETag(leased))
	writeJSON(w, http.StatusOK, leased)
}

// heartbeatRequest is the body of POST /api/paths/{id}/heartbeat.
type heartbeatRequest struct {
	LeaseEpoch int64  `json:"lease_epoch"`
	Owner      string `json:"owner"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// handleHeartbeat answers POST /api/paths/{id}/heartbeat.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	var req heartbeatRequest
	if !s.decode(w, r, &req) {
		return
	}
	owner := strings.TrimSpace(req.Owner)
	if owner == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("owner is required to renew a lease"))
		return
	}
	if req.TTLSeconds < 0 {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Errorf("ttl_seconds must not be negative (got %d)", req.TTLSeconds))
		return
	}
	if storage.IsPostgres(s.Store) && req.LeaseEpoch <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("lease_epoch from the claim response is required"))
		return
	}
	var updated *path.Path
	var err error
	if storage.IsPostgres(s.Store) || req.LeaseEpoch > 0 {
		updated, err = s.Audit.HeartbeatEpoch(r.Context(), id, owner, req.LeaseEpoch, time.Duration(req.TTLSeconds)*time.Second)
	} else {
		updated, err = s.Audit.Heartbeat(id, owner, time.Duration(req.TTLSeconds)*time.Second)
	}
	if err != nil {
		writeAuditError(w, err, id)
		return
	}
	w.Header().Set("ETag", pathETag(updated))
	writeJSON(w, http.StatusOK, updated)
}

// releasePathRequest is the body of POST /api/paths/{id}/release.
type releasePathRequest struct {
	LeaseEpoch int64  `json:"lease_epoch"`
	Owner      string `json:"owner"`
	Reason     string `json:"reason"`
}

// handleReleasePath answers POST /api/paths/{id}/release: the work goes back to
// the queue without a verdict, which is what a worker that cannot continue does.
func (s *Server) handleReleasePath(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	var req releasePathRequest
	if !s.decode(w, r, &req) {
		return
	}
	owner := strings.TrimSpace(req.Owner)
	if owner == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("owner is required to release a lease"))
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "released by " + owner
	}
	if storage.IsPostgres(s.Store) && req.LeaseEpoch <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("lease_epoch from the claim response is required"))
		return
	}
	var updated *path.Path
	var err error
	if storage.IsPostgres(s.Store) || req.LeaseEpoch > 0 {
		updated, err = s.Audit.ReleaseEpoch(r.Context(), id, owner, req.LeaseEpoch, reason)
	} else {
		updated, err = s.Audit.Release(id, owner, reason)
	}
	if err != nil {
		writeAuditError(w, err, id)
		return
	}
	w.Header().Set("ETag", pathETag(updated))
	writeJSON(w, http.StatusOK, updated)
}

// reclaimRequest is the body of POST /api/audits/{id}/reclaim-expired.
type reclaimRequest struct {
	Limit int `json:"limit"`
}

// handleReclaimExpired answers POST /api/audits/{id}/reclaim-expired. The engine's
// sweep is store-wide, so the answer reports the paths of this audit and the
// total the sweep recovered rather than pretending the two are the same.
func (s *Server) handleReclaimExpired(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	if _, err := s.Audit.Audit(id); err != nil {
		writeAuditError(w, err, id)
		return
	}
	var req reclaimRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.Limit < 0 {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Errorf("limit must not be negative (got %d)", req.Limit))
		return
	}
	limit := req.Limit
	if limit == 0 {
		limit = 10
	}
	recovered, err := s.Audit.ReclaimExpired(limit)
	if err != nil {
		writeAuditError(w, err, id)
		return
	}
	owned := make([]path.Path, 0, len(recovered))
	for _, p := range recovered {
		if p.AuditID == id {
			owned = append(owned, p)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"audit_id": id, "recovered": owned, "count": len(owned), "recovered_total": len(recovered),
	})
}

// handleRescore answers POST /api/audits/{id}/rescore.
func (s *Server) handleRescore(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	audit, err := s.Audit.Rescore(id)
	if err != nil {
		writeAuditError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": audit})
}

// --- helpers ----------------------------------------------------------------

// pathETag is a strong validator over the path's optimistic-concurrency counter
// and its status, which is exactly the question If-Match asks: did the caller
// read the state it is about to change?
func pathETag(p *path.Path) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s", p.ID, p.Version, p.Status)))
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}

// requirePathVersion enforces the If-Match precondition on a path mutation,
// mirroring handlePatchProject: 428 when the header is missing, 412 when it names
// a version the path no longer has.
func requirePathVersion(w http.ResponseWriter, r *http.Request, current *path.Path) bool {
	etag := pathETag(current)
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	if ifMatch == "" {
		writeError(w, http.StatusPreconditionRequired, "precondition_required",
			fmt.Errorf("path %s requires If-Match with the ETag of the path you read (current ETag %s); read it with GET /api/paths/%s",
				current.ID, etag, current.ID))
		return false
	}
	if !etagMatches(ifMatch, etag) {
		writeError(w, http.StatusPreconditionFailed, "precondition_failed",
			fmt.Errorf("path %s is at version %d (ETag %s), not %s; re-read it with GET /api/paths/%s",
				current.ID, current.Version, etag, ifMatch, current.ID))
		return false
	}
	return true
}

// principalName is the actor recorded on an operator action.
func principalName(r *http.Request) string {
	if principal, ok := PrincipalFrom(r.Context()); ok && principal.Name != "" {
		return principal.Name
	}
	return "operator"
}

// pageLimit bounds a page size: a missing limit takes the default, an oversized
// one is capped rather than refused, and a negative one is a caller mistake.
func pageLimit(raw string) int {
	limit := queryInt(raw, defaultAuditPageSize)
	if limit <= 0 {
		return defaultAuditPageSize
	}
	if limit > maxAuditPageSize {
		return maxAuditPageSize
	}
	return limit
}

// writeAuditError maps the path engine's sentinels onto the API's error
// vocabulary. The codes are distinct on purpose: "you lost the race"
// (lease_held) is a different operator action from "your lease is gone"
// (lease_expired), "the path is gone" (not_found) and "the state machine refuses"
// (invalid_transition).
func writeAuditError(w http.ResponseWriter, err error, id string) {
	switch {
	case errors.Is(err, path.ErrTaskArchived):
		writeError(w, http.StatusConflict, "task_archived", err)
	case errors.Is(err, path.ErrTaskActive):
		writeError(w, http.StatusConflict, "task_not_idle", err)
	case err == nil:
		return
	case errors.Is(err, path.ErrNoASG):
		writeError(w, http.StatusConflict, "asg_missing", fmt.Errorf(
			"snapshot %s has no attack surface; build it first with POST /api/snapshots/%s/asg: %w",
			id, id, err))
	case errors.Is(err, path.ErrNotFound), errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err)
	case errors.Is(err, path.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, "invalid_request", err)
	case errors.Is(err, path.ErrInvalidTransition):
		// The engine's message carries the legal target statuses, which is what
		// turns a refusal into a fix.
		writeError(w, http.StatusConflict, "invalid_transition", err)
	case errors.Is(err, path.ErrConflict):
		writeError(w, http.StatusConflict, "version_conflict", err)
	case errors.Is(err, path.ErrLeaseHeld):
		writeError(w, http.StatusConflict, "lease_held", err)
	case errors.Is(err, path.ErrLeaseExpired):
		writeError(w, http.StatusConflict, "lease_expired", err)
	case errors.Is(err, path.ErrNotClaimable):
		writeError(w, http.StatusConflict, "not_claimable", err)
	case errors.Is(err, path.ErrBudgetExceeded):
		writeError(w, http.StatusConflict, "budget_exceeded", err)
	default:
		writeStorageError(w, err)
	}
}

// parsePathStatuses validates a comma-separated lifecycle status filter, so a
// typo is a 400 instead of a silently empty queue.
func parsePathStatuses(value string) ([]path.Status, error) {
	parts := commaList(value)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]path.Status, 0, len(parts))
	for _, part := range parts {
		status := path.Status(part)
		if !path.ValidStatus(status) {
			return nil, fmt.Errorf("unknown status %q; valid statuses are %s", part, strings.Join(statusNames(), ", "))
		}
		out = append(out, status)
	}
	return out, nil
}

// parsePathStatusClasses validates the evidence-class filter.
func parsePathStatusClasses(value string) ([]path.PathStatus, error) {
	parts := commaList(value)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]path.PathStatus, 0, len(parts))
	for _, part := range parts {
		status := path.PathStatus(part)
		if !path.ValidPathStatus(status) {
			return nil, fmt.Errorf("unknown path_status %q; valid values are %s", part, strings.Join(pathStatusNames(), ", "))
		}
		out = append(out, status)
	}
	return out, nil
}

// parsePathSort validates the order the caller asked for.
func parsePathSort(value string) (string, error) {
	switch strings.TrimSpace(value) {
	case "", "priority", "created", "path_id":
		return strings.TrimSpace(value), nil
	default:
		return "", fmt.Errorf("unknown sort %q; valid values are priority, created, path_id", value)
	}
}

func validAuditStatus(value string) bool {
	switch value {
	case path.AuditGenerating, path.AuditReady, path.AuditFailed:
		return true
	default:
		return false
	}
}

func auditStatusNames() []string {
	return []string{path.AuditGenerating, path.AuditReady, path.AuditFailed}
}

func statusNames() []string {
	statuses := path.AllStatuses()
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}

func pathStatusNames() []string {
	statuses := path.AllPathStatuses()
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}
