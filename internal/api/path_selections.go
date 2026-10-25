package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// pathSelectionRequest is the bounded selection of existing candidate paths
// that should become independently controlled Agent subtasks.
type pathSelectionRequest struct {
	APIVersion string   `json:"api_version"`
	PathIDs    []string `json:"path_ids"`
}

type selectedPath struct {
	SelectionID   string `json:"selection_id"`
	ProjectID     string `json:"project_id"`
	SnapshotID    string `json:"snapshot_id"`
	AuditID       string `json:"audit_id"`
	PathID        string `json:"path_id"`
	RunID         string `json:"run_id,omitempty"`
	State         string `json:"state"`
	Source        string `json:"source"`
	Reused        bool   `json:"reused"`
	EntrySubject  string `json:"entry_subject,omitempty"`
	TargetSubject string `json:"target_subject,omitempty"`
	TargetKind    string `json:"target_kind,omitempty"`
}

func selectionID(projectID, pathID string) string {
	sum := sha256.Sum256([]byte("codexploit/path-selection/v1\x00" + projectID + "\x00" + pathID))
	return "selection-" + hex.EncodeToString(sum[:16])
}

// handleSelectPaths starts one run per explicitly selected path. Selection is
// keyed by the canonical path ID, never by a title: two paths with the same
// display text remain two independently controllable subtasks. Repeating the
// request returns the run already recorded for that path.
func (s *Server) handleSelectPaths(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	if s.auditUnavailable(w) {
		return
	}
	projectID := r.PathValue("projectID")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	if s.Agent.Ready() != nil {
		writeError(w, http.StatusConflict, "agent_unavailable", errors.New("agent assistance is not configured for this deployment"))
		return
	}
	var req pathSelectionRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.APIVersion != "codexploit/v1" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("api_version must be codexploit/v1"))
		return
	}
	if len(req.PathIDs) == 0 || len(req.PathIDs) > 5 {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("select between 1 and 5 path ids"))
		return
	}
	seen := map[string]bool{}
	for _, id := range req.PathIDs {
		if id == "" || seen[id] {
			writeError(w, http.StatusBadRequest, "invalid_request", errors.New("path ids must be unique and non-empty"))
			return
		}
		seen[id] = true
	}
	snapshots, err := s.Store.ListSnapshots(r.Context(), projectID)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	owned := map[string]bool{}
	for _, snapshot := range snapshots {
		owned[snapshot.SnapshotID] = true
	}
	// Validate the whole selection before starting any run; a bad path must not
	// leave earlier paths running under a failed request.
	selected := make([]path.Path, 0, len(req.PathIDs))
	for _, id := range req.PathIDs {
		p, _, err := s.Audit.Path(id)
		if err != nil {
			writeAuditError(w, err, id)
			return
		}
		if !owned[p.SnapshotID] {
			writeError(w, http.StatusNotFound, "path_not_found", errors.New("path does not belong to this project"))
			return
		}
		selected = append(selected, *p)
	}
	selections := make([]selectedPath, 0, len(selected))
	anyReused := false
	for _, p := range selected {
		entry := selectedPath{SelectionID: selectionID(projectID, p.ID), ProjectID: projectID, SnapshotID: p.SnapshotID, AuditID: p.AuditID, PathID: p.ID, Source: "agent", State: string(p.Status), EntrySubject: p.EntrySubject, TargetSubject: p.TargetSubject, TargetKind: p.TargetKind}
		// A path that already ran is the same subtask: return its existing run
		// rather than starting a duplicate one. Failed runs can be retried through
		// the run's own retry endpoint.
		if runs, _, err := s.Agent.Store.ListRuns(agent.RunQuery{PathID: p.ID, Limit: 100}); err == nil {
			for _, run := range runs {
				if run.AuditID == p.AuditID {
					entry.RunID, entry.State, entry.Reused = run.ID, string(run.Status), true
					anyReused = true
					break
				}
			}
		}
		if entry.RunID == "" {
			run, err := s.Agent.RunPath(r.Context(), p.ID, "path-selection", 0, s.Agent.Policy)
			if err != nil {
				if errors.Is(err, path.ErrNotClaimable) {
					writeError(w, http.StatusConflict, "path_not_selectable", fmt.Errorf("path %s is no longer queued for a new run", p.ID))
					return
				}
				writeAgentError(w, err, p.AuditID)
				return
			}
			entry.RunID, entry.State = run.ID, string(run.Status)
		}
		selections = append(selections, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "selections": selections, "reused": anyReused})
}

// handleListPathSelections returns the existing run mapping for one path or for
// every run in the project's snapshot. It is a read projection over AgentRun;
// no second scheduling database is created.
func (s *Server) handleListPathSelections(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	projectID := r.PathValue("projectID")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	pathID := strings.TrimSpace(r.URL.Query().Get("path_id"))
	snapshots, err := s.Store.ListSnapshots(r.Context(), projectID)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	// Scope before paging: unrelated projects must not consume this page.
	const budget = 10000
	runs := []agent.Run{}
	truncated := false
	for _, snapshot := range snapshots {
		for offset := 0; ; {
			limit := min(500, budget-len(runs))
			if limit == 0 {
				truncated = true
				break
			}
			page, total, err := s.Agent.Store.ListRuns(agent.RunQuery{SnapshotID: snapshot.SnapshotID, PathID: pathID, Limit: limit, Offset: offset})
			if err != nil {
				writeAgentError(w, err, "")
				return
			}
			runs = append(runs, page...)
			offset += len(page)
			if offset >= total || len(page) == 0 {
				break
			}
		}
		if truncated {
			break
		}
	}
	// Resume creates a new run; expose its state without rewriting the history.
	byPath := map[string]selectedPath{}
	for _, run := range runs {
		if run.AuditID == "" || run.PathID == "" {
			continue
		}
		byPath[run.PathID] = selectedPath{
			SelectionID: selectionID(projectID, run.PathID), ProjectID: projectID,
			SnapshotID: run.SnapshotID, AuditID: run.AuditID, PathID: run.PathID,
			RunID: run.ID, State: string(run.Status), Source: "agent", Reused: true,
		}
	}
	// The subtask list needs a human-recognisable object without turning the
	// run ledger into a second path directory. Path metadata is read from the
	// same audit service that owns it.
	pathDetails := map[string]*path.Path{}
	if s.Audit != nil {
		for id := range byPath {
			if p, _, err := s.Audit.Path(id); err == nil {
				pathDetails[id] = p
			}
		}
	}
	for id, selection := range byPath {
		if p := pathDetails[id]; p != nil {
			selection.EntrySubject, selection.TargetSubject, selection.TargetKind = p.EntrySubject, p.TargetSubject, p.TargetKind
			byPath[id] = selection
		}
	}
	selections := make([]selectedPath, 0, len(byPath))
	for _, selection := range byPath {
		selections = append(selections, selection)
	}
	sort.Slice(selections, func(i, j int) bool { return selections[i].PathID < selections[j].PathID })
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "selections": selections, "truncated": truncated})
}
