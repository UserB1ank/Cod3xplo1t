package api

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"encoding/json"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"

	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

type analysisRunStartRequest struct {
	APIVersion         string `json:"api_version"`
	IdempotencyKey     string `json:"idempotency_key,omitempty"`
	AgentAssisted      bool   `json:"agent_assisted"`
	Runtime            string `json:"runtime,omitempty"`
	Frontend           string `json:"frontend,omitempty"`
	ConfirmSourceBytes int64  `json:"confirm_source_bytes,omitempty"`
}

type analysisStageDefinition struct {
	Key           string
	Label         string
	NodeID        string
	PluginID      string
	PluginVersion string
}

var analysisStageDefinitions = []analysisStageDefinition{
	{Key: "parse", Label: "代码图谱", NodeID: "parse", PluginID: workflow.DefaultEnginePluginID, PluginVersion: workflow.DefaultEnginePluginVersion},
	{Key: "semantic", Label: "安全语义与攻击面", NodeID: "semantic", PluginID: workflow.DefaultEnginePluginID, PluginVersion: workflow.DefaultEnginePluginVersion},
	{Key: "paths", Label: "候选路径", NodeID: "paths", PluginID: workflow.DefaultEnginePluginID, PluginVersion: workflow.DefaultEnginePluginVersion},
	{Key: "enhance", Label: "路径筛选与评分", NodeID: "enhance", PluginID: workflow.DefaultEnginePluginID, PluginVersion: workflow.DefaultEnginePluginVersion},
	{Key: "publish", Label: "共享知识发布", NodeID: "$publish", PluginID: "codexploit.workflow"},
	{Key: "analyze", Label: "Agent 辅助分析", NodeID: "$analyze", PluginID: "codexploit.workflow"},
}

func analysisTerminal(state string) bool {
	switch state {
	case "SUCCEEDED", "PARTIAL", "FAILED", "CANCELLED":
		return true
	default:
		return false
	}
}

func analysisRunState(status string) string {
	switch status {
	case "CREATED":
		return "QUEUED"
	case "RUNNING":
		return "RUNNING"
	case "PAUSING", "PAUSED":
		return "PAUSED"
	case "CANCELLING":
		return "CANCELLING"
	case "SUCCEEDED":
		return "SUCCEEDED"
	case "PARTIAL":
		return "PARTIAL"
	case "FAILED":
		return "FAILED"
	case "CANCELLED":
		return "CANCELLED"
	default:
		return "FAILED"
	}
}

func writeAnalysisError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "analysis_run_not_found", errors.New("analysis run not found"))
	case errors.Is(err, storage.ErrConflict):
		writeError(w, http.StatusConflict, "analysis_conflict", err)
	case errors.Is(err, path.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, "invalid_analysis", err)
	case errors.Is(err, agentUnavailableError{}):
		writeError(w, http.StatusConflict, "agent_unavailable", err)
	case errors.Is(err, workflow.ErrRuntimeUnavailable):
		writeError(w, http.StatusConflict, "agent_unavailable", err)
	case errors.Is(err, workflow.ErrInvalid):
		writeError(w, http.StatusBadRequest, "analysis_invalid", err)
	default:
		writeWorkflowError(w, err)
	}
}

type agentUnavailableError struct{ reason string }

func (e agentUnavailableError) Error() string {
	if e.reason != "" {
		return "Agent assistance is unavailable: " + e.reason
	}
	return "Agent assistance is unavailable"
}
func (e agentUnavailableError) Is(target error) bool {
	_, ok := target.(agentUnavailableError)
	return ok
}

func (s *Server) handleStartAnalysisRun(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	if s.Workflows == nil || s.WorkflowCompiler == nil || s.WorkflowRunner == nil {
		writeError(w, http.StatusServiceUnavailable, "analysis_unavailable", errors.New("workflow services are unavailable"))
		return
	}
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	var req analysisRunStartRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.APIVersion != "codexploit/v1" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("api_version must be codexploit/v1"))
		return
	}
	frontend, err := normalizeAnalysisFrontend(req.Frontend)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_frontend", err)
		return
	}
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	}
	if len(req.IdempotencyKey) > 160 {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("idempotency key is too long"))
		return
	}
	if req.IdempotencyKey != "" {
		if existing, err := s.Store.GetAnalysisRunByIdempotency(r.Context(), projectID, req.IdempotencyKey); err == nil {
			existing, syncErr := s.syncAnalysisRun(r.Context(), existing)
			if syncErr != nil {
				writeAnalysisError(w, syncErr)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "analysis_run": existing, "reused": true})
			return
		} else if !errors.Is(err, storage.ErrNotFound) {
			writeAnalysisError(w, err)
			return
		}
	}
	if active, ok, err := s.Store.ActiveAnalysisRun(r.Context(), projectID); err != nil {
		writeAnalysisError(w, err)
		return
	} else if ok {
		active, err = s.syncAnalysisRun(r.Context(), active)
		if err != nil {
			writeAnalysisError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "analysis_run": active, "reused": true})
		return
	}
	input, err := s.Store.GetProjectInput(r.Context(), projectID)
	if err != nil || input.State != storage.ProjectInputReady || input.SnapshotID == "" {
		writeError(w, http.StatusConflict, "analysis_input_unavailable", errors.New("the project source input must be ready before analysis"))
		return
	}
	if _, err := s.Store.GetSnapshot(r.Context(), input.SnapshotID); err != nil {
		writeError(w, http.StatusConflict, "analysis_input_unavailable", errors.New("the project input snapshot is unavailable"))
		return
	}
	root, err := s.analysisRoot(r.Context(), projectID, input.SnapshotID)
	if errors.Is(err, artifact.ErrBudget) {
		writeError(w, http.StatusRequestEntityTooLarge, "source_size_limit", errors.New("源码文件总大小超过部署上限 8 GiB，请缩小导入范围"))
		return
	}
	if err != nil {
		writeError(w, http.StatusConflict, "analysis_input_unavailable", errors.New("the read-only project source directory is unavailable"))
		return
	}
	if root.Bytes > artifact.SourceWarningBytes && req.ConfirmSourceBytes != root.Bytes {
		writeJSON(w, http.StatusConflict, map[string]any{"api_version": "codexploit/v1", "code": "source_size_confirmation_required", "error": fmt.Sprintf("源码文件总大小为 %d 字节，超过 500 MiB，确认是否继续图谱化？", root.Bytes), "source_bytes": root.Bytes, "threshold_bytes": artifact.SourceWarningBytes})
		return
	}
	runtimeName := strings.TrimSpace(req.Runtime)
	if req.AgentAssisted {
		if s.Agent == nil || s.Agent.Ready() != nil {
			writeError(w, http.StatusConflict, "agent_unavailable", agentUnavailableError{reason: "configure a working Agent model first"})
			return
		}
		if runtimeName != "" {
			info, ok := s.runtimeInfo(runtimeName)
			if !ok || !info.Ready {
				writeError(w, http.StatusConflict, "agent_unavailable", agentUnavailableError{reason: "the selected runtime is not ready"})
				return
			}
			runtimeName = info.Name
		}
	}
	engine, err := s.analysisEngineStatus(r.Context())
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	if !engine.Ready {
		writeError(w, http.StatusServiceUnavailable, "analysis_engine_unavailable", errors.New(engine.Reason))
		return
	}
	spec := s.analysisProvider().Workflow()
	if frontend != "" {
		spec, err = analysisWorkflowForFrontend(spec, frontend)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_frontend", err)
			return
		}
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	expected := ""
	entries, listErr := s.Workflows.List(r.Context(), projectID, spec.ID+"@", 1)
	if listErr != nil {
		writeWorkflowError(w, listErr)
		return
	}
	for _, entry := range entries {
		if entry.Spec.ID == spec.ID {
			expected = entry.HeadDigest
			break
		}
	}
	if _, err := s.Workflows.Save(r.Context(), projectID, raw, expected); err != nil {
		writeWorkflowError(w, err)
		return
	}
	plan, err := s.WorkflowCompiler.Compile(r.Context(), projectID, spec.ID, spec.Version, workflow.CompileRequest{
		APIVersion: "codexploit/v1", SnapshotID: input.SnapshotID, Inputs: []string{root.ID}, Language: analysisLanguageForFrontend(spec, frontend), MaxInputBytes: max(artifact.SourceWarningBytes, root.Bytes),
	})
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	accepted := []string{"parse", "semantic", "paths", "enhance", "$publish"}
	if req.AgentAssisted {
		accepted = append(accepted, "$analyze")
	}
	run, err := s.WorkflowRunner.Start(r.Context(), workflow.StartRequest{
		ProjectID: projectID, SnapshotID: input.SnapshotID, PlanID: plan.ID,
		Task:               workflow.TaskDefinition{Name: "图谱化分析", Objective: "执行固定四阶段图谱化分析并发布候选路径"},
		AcceptPartialNodes: accepted, AnalyzeCandidates: req.AgentAssisted, Runtime: runtimeName,
	})
	if err != nil {
		writeWorkflowError(w, err)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record := storage.AnalysisRun{
		ID: "analysis-" + rand.Text(), ProjectID: projectID, SnapshotID: input.SnapshotID,
		TaskID: run.TaskID, WorkflowRunID: run.ID, PlanID: plan.ID, PlanDigest: plan.Digest,
		WorkflowID: spec.ID, WorkflowVersion: spec.Version, Engine: &engine.Pin,
		State: "QUEUED", AgentAssisted: req.AgentAssisted, CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	created, err := s.Store.CreateAnalysisRun(r.Context(), record, req.IdempotencyKey)
	if err != nil {
		_, _ = s.WorkflowRunner.Cancel(r.Context(), projectID, run.ID)
		if errors.Is(err, storage.ErrConflict) {
			if active, ok, activeErr := s.Store.ActiveAnalysisRun(r.Context(), projectID); activeErr == nil && ok {
				active, activeErr = s.syncAnalysisRun(r.Context(), active)
				if activeErr == nil {
					writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "analysis_run": active, "reused": true})
					return
				}
			}
		}
		writeAnalysisError(w, err)
		return
	}
	if created.ID != record.ID {
		_, _ = s.WorkflowRunner.Cancel(r.Context(), projectID, run.ID)
		created, err = s.syncAnalysisRun(r.Context(), created)
		if err != nil {
			writeAnalysisError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "analysis_run": created, "reused": true})
		return
	}
	created, err = s.syncAnalysisRun(r.Context(), created)
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"api_version": "codexploit/v1", "analysis_run": created, "reused": false})
}

func (s *Server) analysisRoot(ctx context.Context, projectID, snapshotID string) (artifact.Ref, error) {
	binding, err := s.snapshotSource(ctx, snapshotID)
	if err != nil {
		return artifact.Ref{}, err
	}
	scope := artifact.Scope{ProjectID: projectID, SourceID: binding.SourceID, SnapshotID: snapshotID}
	if s.analysisProvider().Workflow().Nodes[0].PluginID == workflow.DefaultEnginePluginID {
		directories, ok := s.Artifacts.(artifact.DirectoryStore)
		if !ok {
			return artifact.Ref{}, artifact.ErrNotFound
		}
		return directories.SourceDirectoryRef(ctx, scope)
	}
	// Historical adapters still require an archive; only explicit legacy
	// execution creates it. Formal project analysis uses directories above.
	source, loadErr := s.Manager.Load(snapshotID)
	if loadErr == nil {
		if err := artifact.PublishSnapshot(ctx, s.Artifacts, scope, source); err != nil {
			return artifact.Ref{}, err
		}
	}
	refs, err := s.Artifacts.List(ctx, scope, "", 100)
	if err != nil {
		return artifact.Ref{}, err
	}
	for _, ref := range refs {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			return ref, nil
		}
	}
	return artifact.Ref{}, storage.ErrNotFound
}

func (s *Server) handleListAnalysisRuns(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writeError(w, http.StatusBadRequest, "invalid_request", errors.New("limit must be 1–100"))
			return
		}
		limit = n
	}
	runs, err := s.Store.ListAnalysisRuns(r.Context(), projectID, limit)
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	for i := range runs {
		if analysisTerminal(runs[i].State) {
			continue
		}
		synced, syncErr := s.syncAnalysisRun(r.Context(), runs[i])
		if syncErr == nil {
			runs[i] = synced
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "analysis_runs": runs})
}

func (s *Server) handleGetAnalysisRun(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	run, err := s.Store.GetAnalysisRun(r.Context(), projectID, r.PathValue("analysisRunID"))
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	run, err = s.syncAnalysisRun(r.Context(), run)
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%s-%d"`, run.ID, run.Version))
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "analysis_run": run})
}

func (s *Server) handleCancelAnalysisRun(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	run, err := s.Store.GetAnalysisRun(r.Context(), projectID, r.PathValue("analysisRunID"))
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	if analysisTerminal(run.State) {
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "analysis_run": run})
		return
	}
	if s.WorkflowRunner == nil {
		writeError(w, http.StatusServiceUnavailable, "analysis_unavailable", errors.New("workflow runner is unavailable"))
		return
	}
	if _, err := s.WorkflowRunner.Cancel(r.Context(), projectID, run.WorkflowRunID); err != nil {
		writeWorkflowError(w, err)
		return
	}
	run, err = s.syncAnalysisRun(r.Context(), run)
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "codexploit/v1", "analysis_run": run})
}

func (s *Server) syncAnalysisRun(ctx context.Context, run storage.AnalysisRun) (storage.AnalysisRun, error) {
	if analysisTerminal(run.State) || s.WorkflowRunner == nil {
		return run, nil
	}
	workflowRun, err := s.WorkflowRunner.Get(ctx, run.ProjectID, run.WorkflowRunID)
	if err != nil {
		return run, err
	}
	next := run
	next.State = analysisRunState(workflowRun.Status)
	next.Stages = analysisStages(workflowRun)
	if next.Stages == nil {
		next.Stages = []storage.AnalysisRunStage{}
	}
	if s.WorkflowCompiler != nil {
		if plan, planErr := s.WorkflowCompiler.Get(ctx, run.ProjectID, run.PlanID); planErr == nil {
			applyPlanVersions(next.Stages, plan)
		}
	}
	taskFound := false
	if s.Audit != nil {
		if task, taskErr := s.Audit.Audit(run.TaskID); taskErr == nil {
			taskFound = true
			next.Coverage = task.Coverage
			if next.Coverage.TruncationReasons == nil {
				next.Coverage.TruncationReasons = []string{}
			}
			next.Limitations = append([]string{}, task.Limitations...)
			if next.Limitations == nil {
				next.Limitations = []string{}
			}
			next.PathCount = task.PathCount
			if (next.State == "SUCCEEDED" || next.State == "PARTIAL") && task.Status != path.AuditReady {
				next.State = "RUNNING"
			}
		}
	}
	next.Knowledge = []storage.AnalysisKnowledge{}
	seenKnowledge := map[string]bool{}
	for _, stage := range next.Stages {
		if stage.ErrorCode != "" && next.FailureCode == "" {
			next.FailureCode = stage.ErrorCode
			next.FailureMessage = stage.Note
		}
		for _, pin := range stage.Knowledge {
			if !seenKnowledge[pin.Revision] {
				seenKnowledge[pin.Revision] = true
				next.Knowledge = append(next.Knowledge, pin)
			}
		}
	}
	if (next.State == "SUCCEEDED" || next.State == "PARTIAL") && !taskFound {
		next.State = "FAILED"
		next.FailureCode = "analysis_task_unavailable"
		next.FailureMessage = "The workflow finished but its analysis task is unavailable"
	}
	if next.State == "SUCCEEDED" {
		published := false
		for _, stage := range next.Stages {
			if stage.Key == "publish" && stage.Status == "SUCCEEDED" {
				published = true
			}
		}
		if !published {
			next.State = "PARTIAL"
			next.FailureCode = "publish_incomplete"
			next.Limitations = append(next.Limitations, "The analysis completed without a successful shared knowledge publication")
		}
	}
	if next.State == "FAILED" && next.FailureCode == "" {
		next.FailureCode = "workflow_failed"
		next.FailureMessage = "The default analysis workflow did not complete"
	}
	if reflect.DeepEqual(run, next) {
		return run, nil
	}
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	updated, err := s.Store.UpdateAnalysisRun(ctx, next)
	if errors.Is(err, storage.ErrConflict) {
		return s.Store.GetAnalysisRun(ctx, run.ProjectID, run.ID)
	}
	return updated, err
}

func analysisStages(run workflow.Run) []storage.AnalysisRunStage {
	stages := make([]storage.AnalysisRunStage, 0, len(analysisStageDefinitions))
	for _, def := range analysisStageDefinitions {
		if def.Key == "analyze" && !run.AnalyzeCandidates {
			continue
		}
		stage := storage.AnalysisRunStage{Key: def.Key, Label: def.Label, NodeID: def.NodeID, PluginID: def.PluginID, PluginVersion: def.PluginVersion, Status: "PENDING"}
		for _, node := range run.Nodes {
			if node.NodeID != def.NodeID {
				continue
			}
			stage.Status = node.Status
			stage.InvocationID = node.InvocationID
			stage.Inputs = append([]artifact.Ref{}, node.Inputs...)
			stage.Outputs = append([]artifact.Ref{}, node.Outputs...)
			stage.ErrorCode = node.ErrorCode
			stage.Note = node.Note
			stage.AgentRunIDs = append([]string{}, node.AgentRunIDs...)
			stage.StartedAt = node.StartedAt
			stage.FinishedAt = node.FinishedAt
			for _, pin := range node.Knowledge {
				stage.Knowledge = append(stage.Knowledge, storage.AnalysisKnowledge{Revision: pin.Revision, Digest: pin.Digest})
			}
			break
		}
		stages = append(stages, stage)
	}
	return stages
}

func applyPlanVersions(stages []storage.AnalysisRunStage, plan workflow.Plan) {
	byID := map[string]workflow.CompiledNode{}
	for _, node := range plan.Nodes {
		byID[node.ID] = node
	}
	for i := range stages {
		if node, ok := byID[stages[i].NodeID]; ok {
			stages[i].OperationID = node.OperationID
			stages[i].PluginID = node.PluginID
			stages[i].PluginVersion = node.PluginVersion
		}
	}
}
