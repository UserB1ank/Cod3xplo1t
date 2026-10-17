package api

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	ready := s.Agent != nil
	if ready && s.LLMSettings != nil {
		ready = s.Agent.Ready() == nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": p.Name, "role": p.Capabilities.String(), "can_write": p.Capabilities.Allows(CapWrite), "features": map[string]bool{"agent": ready, "llm_settings": s.LLMSettings != nil, "verification": s.Verifier != nil && s.VerifyPlanner != nil, "scheduler": s.Scheduler != nil, "network": s.AllowNetwork}})
}

type taskRequest struct {
	SourceID   string      `json:"source_id"`
	Name       string      `json:"name"`
	Objective  string      `json:"objective"`
	SnapshotID string      `json:"snapshot_id"`
	Scope      []string    `json:"scope"`
	Budget     path.Budget `json:"budget"`
	Limits     path.Limits `json:"limits"`
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	projectID := r.PathValue("id")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	var req taskRequest
	if !s.decode(w, r, &req) {
		return
	}
	req.Name, req.Objective = strings.TrimSpace(req.Name), strings.TrimSpace(req.Objective)
	if req.Name == "" || len([]rune(req.Name)) > 120 || req.Objective == "" || len([]rune(req.Objective)) > 2000 || len(req.Scope) > 32 {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("name (1–120 characters), objective (1–2000 characters) and at most 32 scope prefixes are required"))
		return
	}
	if err := validateAuditRequest(createAuditRequest{Budget: req.Budget, Limits: req.Limits}); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if req.Budget.MaxDepth > 10 || req.Budget.MaxBranches > 32 || req.Budget.MaxToolCalls > 200 || req.Limits.MaxPaths > 2000 || req.Limits.MaxActiveLeases > 16 || req.Limits.MaxEntries > 2000 || req.Limits.MaxSinksPerEntry > 200 || req.Limits.ChainQueryBudget > 2000 || req.Limits.MaxAttempts > 10 || req.Limits.LeaseTTLSeconds > 3600 {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("task limits exceed the bounded workbench policy"))
		return
	}
	for i, scope := range req.Scope {
		scope = strings.Trim(strings.TrimSpace(scope), "/")
		if scope == "" || len(scope) > 512 || strings.ContainsAny(scope, "\\:\x00") || strings.HasPrefix(req.Scope[i], "/") {
			writeError(w, http.StatusBadRequest, "invalid_request", errors.New("scope must contain repository-relative paths"))
			return
		}
		for _, segment := range strings.Split(scope, "/") {
			if segment == ".." || segment == "" {
				writeError(w, http.StatusBadRequest, "invalid_request", errors.New("scope cannot escape the repository"))
				return
			}
		}
		req.Scope[i] = scope
	}
	snapshots, err := s.Store.ListSnapshots(r.Context(), projectID)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if req.SnapshotID == "" && len(snapshots) > 0 {
		req.SnapshotID = snapshots[len(snapshots)-1].SnapshotID
	}
	belongs := false
	for _, snapshot := range snapshots {
		if snapshot.SnapshotID == req.SnapshotID {
			belongs = true
			break
		}
	}
	if !belongs {
		writeError(w, http.StatusBadRequest, "invalid_snapshot", errors.New("choose a snapshot owned by this project"))
		return
	}
	binding, err := s.snapshotSource(r.Context(), req.SnapshotID)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if req.SourceID != "" && req.SourceID != binding.SourceID {
		writeError(w, http.StatusBadRequest, "invalid_source", errors.New("snapshot does not belong to the selected source"))
		return
	}
	result, err := s.Audit.CreateAudit(r.Context(), path.CreateAuditRequest{TaskKey: rand.Text(), Name: req.Name, Objective: req.Objective, Scope: req.Scope, SnapshotID: req.SnapshotID, Budget: req.Budget, Limits: req.Limits})
	if err != nil {
		writeAuditError(w, err, req.SnapshotID)
		return
	}
	w.Header().Set("ETag", taskETag(&result.Audit))
	writeJSON(w, http.StatusCreated, map[string]any{"task": sourceTask{Audit: result.Audit, SourceSnapshot: binding}, "project_id": projectID})
}

type sourceTask struct {
	path.Audit
	storage.SourceSnapshot
	ETag               string `json:"etag,omitempty"`
	CanArchive         bool   `json:"can_archive"`
	ArchiveBlockReason string `json:"archive_block_reason,omitempty"`
}

func (s *Server) taskViews(ctx context.Context, tasks []path.Audit) ([]sourceTask, error) {
	ids := make([]string, len(tasks))
	for i, task := range tasks {
		ids[i] = task.ID
	}
	activities := map[string]storage.TaskActivity{}
	if reader, ok := s.Store.(storage.TaskActivityReader); ok {
		var err error
		activities, err = reader.TaskActivities(ctx, ids)
		if err != nil {
			return nil, err
		}
	}
	result := make([]sourceTask, 0, len(tasks))
	for _, task := range tasks {
		binding, err := s.snapshotSource(ctx, task.SnapshotID)
		if err != nil {
			return nil, err
		}
		activity, known := activities[task.ID]
		if known {
			task.CountsByStatus = activity.Counts
		}
		view := sourceTask{Audit: task, SourceSnapshot: binding, ETag: taskETag(&task), CanArchive: known && task.Paused && !task.Archived}
		switch {
		case !known:
			view.ArchiveBlockReason = "Task activity is unavailable"
		case task.Archived:
			view.ArchiveBlockReason = "Restore the archived task first"
		case !task.Paused:
			view.ArchiveBlockReason = "Pause scheduling before archiving"
		case activity.ActiveRuns:
			view.ArchiveBlockReason = "Wait for unfinished agent or verification runs"
		}
		for _, status := range []path.Status{path.StatusAnalyzing, path.StatusLocalExploring, path.StatusVerifying} {
			if activity.Counts[string(status)] > 0 {
				view.ArchiveBlockReason = "Wait for active paths to finish"
			}
		}
		if view.ArchiveBlockReason != "" {
			view.CanArchive = false
		}
		result = append(result, view)
	}
	return result, nil
}

func (s *Server) snapshotSource(ctx context.Context, id string) (storage.SourceSnapshot, error) {
	if sources, ok := s.Store.(storage.SourceRepository); ok {
		binding, err := sources.GetSourceSnapshot(ctx, id)
		if !errors.Is(err, storage.ErrNotFound) {
			return binding, err
		}
	}
	return storage.SourceSnapshot{}, nil
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	projectID := r.PathValue("id")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	values := r.URL.Query()
	query := path.AuditQuery{ProjectID: projectID, Limit: pageLimit(values.Get("limit")), Offset: max(0, queryInt(values.Get("offset"), 0)), Search: strings.TrimSpace(values.Get("q")), TaskState: values.Get("state"), Category: values.Get("category"), CategorySet: values.Has("category"), Organized: values.Get("sort") == "organized"}
	validState := query.TaskState == ""
	for _, state := range []string{"ARCHIVED", "FAILED", "RUNNING", "PAUSED", "EMPTY", "QUEUED", "BLOCKED", "CONCLUDED"} {
		if query.TaskState == state {
			validState = true
		}
	}
	if !validState || len([]rune(query.Search)) > 200 || len([]rune(query.Category)) > 30 || (values.Get("sort") != "" && !query.Organized) {
		writeError(w, 400, "invalid_request", errors.New("invalid task filter"))
		return
	}
	if values.Has("archived") {
		archived, err := strconv.ParseBool(values.Get("archived"))
		if err != nil {
			writeError(w, 400, "invalid_request", errors.New("archived must be true or false"))
			return
		}
		query.Archived = &archived
	}
	tasks, total, err := s.Audit.Audits(query)
	if err != nil {
		writeAuditError(w, err, "")
		return
	}
	result, err := s.taskViews(r.Context(), tasks)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": result, "total": total, "project_id": projectID})
}

func taskETag(task *path.Audit) string { return fmt.Sprintf(`"task-%s-v%d"`, task.ID, task.Version) }

func (s *Server) handleGetTask(w http.ResponseWriter, r *http.Request) {
	if s.auditUnavailable(w) {
		return
	}
	task, err := s.Audit.Audit(r.PathValue("id"))
	if err != nil {
		writeAuditError(w, err, "")
		return
	}
	w.Header().Set("ETag", taskETag(task))
	views, err := s.taskViews(r.Context(), []path.Audit{*task})
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, views[0])
}

func (s *Server) handlePauseTask(paused bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.auditUnavailable(w) {
			return
		}
		task, err := s.Audit.Audit(r.PathValue("id"))
		if err != nil {
			writeAuditError(w, err, "")
			return
		}
		if !requireEntityVersion(w, r, taskETag(task)) {
			return
		}
		var body struct{}
		if !s.decode(w, r, &body) {
			return
		}
		version := task.Version
		task.Paused, task.UpdatedAt = paused, path.NowString(time.Now().UTC())
		task.Version++
		if err := s.Store.UpdateAudit(*task, version); err != nil {
			if errors.Is(err, path.ErrTaskArchived) {
				writeError(w, http.StatusConflict, "task_archived", err)
			} else if errors.Is(err, path.ErrConflict) {
				writeError(w, http.StatusPreconditionFailed, "precondition_failed", err)
			} else {
				writeAuditError(w, err, "")
			}
			return
		}
		s.Logger.Info("task scheduling changed", "task", task.ID, "paused", paused, "actor", principalName(r))
		w.Header().Set("ETag", taskETag(task))
		writeJSON(w, http.StatusOK, task)
	}
}

func requireEntityVersion(w http.ResponseWriter, r *http.Request, current string) bool {
	value := strings.TrimSpace(r.Header.Get("If-Match"))
	if value == "" {
		writeError(w, http.StatusPreconditionRequired, "precondition_required", errors.New("read this object and supply its ETag in If-Match"))
		return false
	}
	if !etagMatches(value, current) {
		writeError(w, http.StatusPreconditionFailed, "precondition_failed", errors.New("the object has changed; refresh and retry"))
		return false
	}
	return true
}

type findingSource struct {
	TaskID    string `json:"task_id"`
	FindingID string `json:"finding_id"`
}
type projectFinding struct {
	verify.Finding
	Sources []findingSource `json:"sources"`
}

// Project knowledge reads use the store even if execution adapters are disabled.
// Aggregation is bounded and reports truncation rather than hiding partial data.
func (s *Server) handleProjectFindings(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	groups := map[string]*projectFinding{}
	truncated := false
	for offset := 0; ; offset += 500 {
		if err := r.Context().Err(); err != nil {
			return
		}
		items, total, err := s.Store.ListFindings(verify.FindingQuery{ProjectID: projectID, AuditID: r.URL.Query().Get("task_id"), Limit: 500, Offset: offset})
		if err != nil {
			writeVerifyError(w, err, "")
			return
		}
		for _, item := range items {
			item.Severity = verify.NormalizeSeverity(item.Severity)
			key := item.ID
			if p, err := s.Store.GetPath(item.PathID); err == nil && p.Signature != "" {
				key = item.SnapshotID + "\x00" + p.Signature + "\x00" + strings.ToLower(strings.TrimSpace(item.Title)) + "\x00" + string(item.Status)
			}
			group := groups[key]
			if group == nil {
				group = &projectFinding{Finding: item, Sources: []findingSource{}}
				groups[key] = group
			}
			group.Sources = append(group.Sources, findingSource{TaskID: item.AuditID, FindingID: item.ID})
			if gradeOrder(item.Severity) < gradeOrder(group.Severity) {
				group.Finding = item
			}
		}
		if offset+len(items) >= total || len(items) == 0 {
			break
		}
		if offset+len(items) >= 10000 {
			truncated = true
			break
		}
	}
	findings := make([]projectFinding, 0, len(groups))
	counts := map[string]int{"high": 0, "medium": 0, "low": 0, "ungraded": 0}
	for _, group := range groups {
		sort.Slice(group.Sources, func(i, j int) bool { return group.Sources[i].FindingID < group.Sources[j].FindingID })
		findings = append(findings, *group)
		if group.Status == verify.FindingConfirmed {
			grade := group.Severity
			if grade == "" {
				grade = "ungraded"
			}
			counts[grade]++
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if gradeOrder(findings[i].Severity) != gradeOrder(findings[j].Severity) {
			return gradeOrder(findings[i].Severity) < gradeOrder(findings[j].Severity)
		}
		return findings[i].ID < findings[j].ID
	})
	severity, status := r.URL.Query().Get("severity"), r.URL.Query().Get("status")
	filtered := make([]projectFinding, 0, len(findings))
	for _, finding := range findings {
		if severity != "" && finding.Severity != severity {
			continue
		}
		if status != "" && string(finding.Status) != status {
			continue
		}
		filtered = append(filtered, finding)
	}
	offset := max(0, queryInt(r.URL.Query().Get("offset"), 0))
	end := min(len(filtered), offset+pageLimit(r.URL.Query().Get("limit")))
	offset = min(offset, end)
	writeJSON(w, http.StatusOK, map[string]any{"findings": filtered[offset:end], "total": len(filtered), "counts": counts, "truncated": truncated})
}

func gradeOrder(grade string) int {
	switch grade {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

func (s *Server) handleKnowledgeFinding(w http.ResponseWriter, r *http.Request) {
	finding, err := s.Store.GetFinding(r.PathValue("id"))
	if err != nil {
		writeVerifyError(w, err, "")
		return
	}
	grouped, err := s.groupFindingEvidence(finding)
	if err != nil {
		writeVerifyError(w, err, "")
		return
	}
	runs, _, err := s.Store.ListVerificationRuns(verify.RunQuery{FindingID: finding.ID, Limit: maxVerificationPageSize})
	if err != nil {
		writeVerifyError(w, err, "")
		return
	}
	if runs == nil {
		runs = []verify.Run{}
	}
	finding.Severity = verify.NormalizeSeverity(finding.Severity)
	w.Header().Set("ETag", findingETag(finding))
	writeJSON(w, http.StatusOK, findingDetail{Finding: *finding, Evidence: grouped, Verifications: runs})
}

func findingETag(finding *verify.Finding) string {
	return fmt.Sprintf(`"finding-%s-v%d"`, finding.ID, finding.Version)
}

func (s *Server) handleGradeFinding(w http.ResponseWriter, r *http.Request) {
	finding, err := s.Store.GetFinding(r.PathValue("id"))
	if err != nil {
		writeVerifyError(w, err, "")
		return
	}
	if !requireEntityVersion(w, r, findingETag(finding)) {
		return
	}
	var req struct {
		Severity string `json:"severity"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.Severity != "high" && req.Severity != "medium" && req.Severity != "low" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("severity must be high, medium or low"))
		return
	}
	if err := s.Store.SetFindingSeverity(finding.ID, req.Severity, finding.Version); err != nil {
		if errors.Is(err, verify.ErrConflict) {
			writeError(w, http.StatusPreconditionFailed, "precondition_failed", err)
		} else {
			writeVerifyError(w, err, "")
		}
		return
	}
	s.Logger.Info("finding graded", "finding", finding.ID, "severity", req.Severity, "actor", principalName(r))
	updated, err := s.Store.GetFinding(finding.ID)
	if err != nil {
		writeVerifyError(w, err, "")
		return
	}
	w.Header().Set("ETag", findingETag(updated))
	writeJSON(w, http.StatusOK, updated)
}
