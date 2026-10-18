package api

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	ready := s.Agent != nil
	if ready && s.LLMSettings != nil {
		ready = s.Agent.Ready() == nil
	}
	features := storage.StorageCapabilities(s.Store)
	features["agent"], features["llm_settings"], features["verification"], features["scheduler"], features["network"] = ready, s.LLMSettings != nil, s.Verifier != nil && s.VerifyPlanner != nil, s.Scheduler != nil, s.AllowNetwork
	features["storage_postgres"] = storage.LimitedPostgres(s.Store)
	_, features["storage_memory"] = s.Store.(*storage.Memory)
	writeJSON(w, http.StatusOK, map[string]any{"name": p.Name, "role": p.Capabilities.String(), "can_write": p.Capabilities.Allows(CapWrite), "features": features})
}

type taskRequest struct {
	AcceptPartialNodes []string    `json:"accept_partial_nodes,omitempty"`
	WorkflowPlanID     string      `json:"workflow_plan_id,omitempty"`
	AnalyzeCandidates  bool        `json:"analyze_candidates"`
	SourceID           string      `json:"source_id"`
	Name               string      `json:"name"`
	Objective          string      `json:"objective"`
	SnapshotID         string      `json:"snapshot_id"`
	Scope              []string    `json:"scope"`
	Budget             path.Budget `json:"budget"`
	Limits             path.Limits `json:"limits"`
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
	if req.WorkflowPlanID != "" {
		if s.WorkflowRunner == nil {
			writeWorkflowError(w, errors.New("runner unavailable"))
			return
		}
		run, err := s.WorkflowRunner.Start(r.Context(), workflow.StartRequest{ProjectID: projectID, SnapshotID: req.SnapshotID, PlanID: req.WorkflowPlanID, Task: workflow.TaskDefinition{Name: req.Name, Objective: req.Objective, Scope: req.Scope, Budget: req.Budget, Limits: req.Limits}, AcceptPartialNodes: req.AcceptPartialNodes, AnalyzeCandidates: req.AnalyzeCandidates})
		if err != nil {
			writeWorkflowError(w, err)
			return
		}
		task, err := s.Audit.Audit(run.TaskID)
		if err != nil {
			writeAuditError(w, err, req.SnapshotID)
			return
		}
		w.Header().Set("ETag", taskETag(task))
		writeJSON(w, 201, map[string]any{"task": sourceTask{Audit: *task, SourceSnapshot: binding}, "project_id": projectID, "workflow_run": run})
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
	WorkflowRunID  string `json:"workflow_run_id,omitempty"`
	WorkflowPlanID string `json:"workflow_plan_id,omitempty"`
	WorkflowStatus string `json:"workflow_status,omitempty"`
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
		view := sourceTask{WorkflowRunID: activity.WorkflowRunID, WorkflowPlanID: activity.WorkflowPlanID, WorkflowStatus: activity.WorkflowStatus, Audit: task, SourceSnapshot: binding, ETag: taskETag(&task), CanArchive: known && task.Paused && !task.Archived}
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
		if reader, ok := s.Store.(storage.TaskActivityReader); ok {
			activities, err := reader.TaskActivities(r.Context(), []string{task.ID})
			if err != nil {
				writeStorageError(w, err)
				return
			}
			activity := activities[task.ID]
			if activity.WorkflowRunID != "" && (activity.WorkflowStatus == "CREATED" || activity.WorkflowStatus == "RUNNING") {
				writeError(w, 409, "workflow_managed", errors.New("active workflow tasks require workflow controls; legacy scheduling pause does not pause a workflow"))
				return
			}
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
	TaskID        string               `json:"task_id"`
	FindingID     string               `json:"finding_id"`
	ObservationID string               `json:"observation_id,omitempty"`
	Producer      *artifact.Producer   `json:"producer,omitempty"`
	RuleID        string               `json:"rule_id,omitempty"`
	RuleVersion   string               `json:"rule_version,omitempty"`
	RuleFamily    string               `json:"rule_family,omitempty"`
	Title         string               `json:"title,omitempty"`
	SeverityHint  string               `json:"severity_hint,omitempty"`
	Status        verify.FindingStatus `json:"status,omitempty"`
	File          string               `json:"file,omitempty"`
	Line          int                  `json:"line,omitempty"`
	EndLine       int                  `json:"end_line,omitempty"`
	EvidenceRefs  []string             `json:"evidence_refs"`
	Limitations   []string             `json:"limitations"`
	CreatedAt     string               `json:"created_at,omitempty"`
}
type projectFinding struct {
	verify.Finding
	Fingerprint        string                   `json:"fingerprint"`
	FingerprintVersion string                   `json:"fingerprint_version"`
	Sources            []findingSource          `json:"sources"`
	SeverityAudit      []findings.SeverityAudit `json:"severity_audit"`
}

// Project knowledge reads use the store even if execution adapters are disabled.
// Aggregation is bounded and reports truncation rather than hiding partial data.
func (s *Server) handleProjectFindings(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	if s.Findings == nil {
		writeError(w, http.StatusNotImplemented, "findings_unavailable", errors.New("the findings service is unavailable"))
		return
	}
	query := r.URL.Query()
	severity := strings.TrimSpace(query.Get("severity"))
	if severity != "" && severity != "high" && severity != "medium" && severity != "low" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("severity must be high, medium or low"))
		return
	}
	var status verify.FindingStatus
	if raw := strings.TrimSpace(query.Get("status")); raw != "" {
		status = verify.FindingStatus(raw)
		if !verify.ValidFindingStatus(status) {
			writeError(w, http.StatusBadRequest, "invalid_request", errors.New("unknown finding status"))
			return
		}
	}
	limit := pageLimit(query.Get("limit"))
	offset := max(0, queryInt(query.Get("offset"), 0))
	result, err := s.Findings.List(r.Context(), findings.ListQuery{
		ProjectID: projectID,
		TaskID:    strings.TrimSpace(query.Get("task_id")),
		Severity:  severity,
		Status:    status,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		writeFindingsError(w, err)
		return
	}
	items := make([]projectFinding, 0, len(result.Groups))
	for _, group := range result.Groups {
		items = append(items, projectFindingFromGroup(group))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings":         items,
		"total":            result.Total,
		"counts":           result.Counts.Confirmed,
		"confirmed_counts": result.Counts.Confirmed,
		"candidate_counts": result.Counts.Candidate,
		"truncated":        result.Truncated,
	})
}

func projectFindingFromGroup(group findings.Group) projectFinding {
	finding := group.Finding
	finding.Severity = verify.NormalizeSeverity(finding.Severity)
	item := projectFinding{
		Finding:            finding,
		Fingerprint:        group.Fingerprint,
		FingerprintVersion: group.FingerprintVersion,
		Sources:            []findingSource{},
		SeverityAudit:      group.SeverityAudit,
	}
	if item.SeverityAudit == nil {
		item.SeverityAudit = []findings.SeverityAudit{}
	}
	if len(group.Observations) == 0 {
		members := group.Members
		if len(members) == 0 {
			members = []verify.Finding{finding}
		}
		for _, member := range members {
			item.Sources = append(item.Sources, findingSource{
				TaskID: member.AuditID, FindingID: member.ID, Status: member.Status,
				EvidenceRefs: []string{}, Limitations: []string{},
			})
		}
		return item
	}
	for _, observation := range group.Observations {
		producer := observation.Producer
		item.Sources = append(item.Sources, findingSource{
			TaskID: observation.TaskID, FindingID: observation.FindingID,
			ObservationID: observation.ID, Producer: &producer,
			RuleID: observation.RuleID, RuleVersion: observation.RuleVersion, RuleFamily: observation.RuleFamily,
			Title: observation.Title, SeverityHint: observation.SeverityHint, Status: observation.Status,
			File: observation.File, Line: observation.Line, EndLine: observation.EndLine,
			EvidenceRefs: nonNilStrings(observation.EvidenceRefs),
			Limitations:  nonNilStrings(observation.Limitations),
			CreatedAt:    observation.CreatedAt,
		})
	}
	return item
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func writeFindingsError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, findings.ErrInvalid), errors.Is(err, verify.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, "invalid_request", err)
	case errors.Is(err, findings.ErrConflict), errors.Is(err, verify.ErrConflict):
		writeError(w, http.StatusPreconditionFailed, "precondition_failed", err)
	case errors.Is(err, findings.ErrNotFound), errors.Is(err, verify.ErrNotFound):
		writeError(w, http.StatusNotFound, "finding_not_found", err)
	default:
		writeError(w, http.StatusServiceUnavailable, "findings_unavailable", err)
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
	detail := findingDetail{Finding: *finding, Evidence: grouped, Verifications: runs, Sources: []findingSource{}, SeverityAudit: []findings.SeverityAudit{}}
	if s.Findings != nil {
		group, err := s.Findings.Get(r.Context(), finding.ID)
		if err != nil {
			writeFindingsError(w, err)
			return
		}
		item := projectFindingFromGroup(group)
		detail.Finding = item.Finding
		detail.Fingerprint, detail.FingerprintVersion = item.Fingerprint, item.FingerprintVersion
		detail.Sources, detail.SeverityAudit = item.Sources, item.SeverityAudit
	} else {
		detail.Finding.Severity = verify.NormalizeSeverity(detail.Finding.Severity)
	}
	w.Header().Set("ETag", findingETag(&detail.Finding))
	writeJSON(w, http.StatusOK, detail)
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
		Reason   string `json:"reason"`
	}
	if !s.decode(w, r, &req) {
		return
	}
	if req.Severity != "high" && req.Severity != "medium" && req.Severity != "low" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("severity must be high, medium or low"))
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if s.Findings != nil {
		if reason == "" {
			reason = "legacy severity request without a reason"
		}
		group, err := s.Findings.AssessSeverity(r.Context(), finding.ID, req.Severity, reason, principalName(r), finding.Version)
		if err != nil {
			writeFindingsError(w, err)
			return
		}
		s.Logger.Info("finding graded", "finding", finding.ID, "severity", req.Severity, "actor", principalName(r))
		w.Header().Set("ETag", findingETag(&group.Finding))
		writeJSON(w, http.StatusOK, group.Finding)
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
