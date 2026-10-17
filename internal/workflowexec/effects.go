// Package workflowexec binds workflow effects to real publication and Agent services.
package workflowexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	audit "github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

type pathReport struct {
	report     *plugin.NativeReport
	artifactID string
}

type Effects struct {
	Store       storage.FullStore
	Host        *plugin.Host
	Artifacts   artifact.Store
	Manager     *repository.Manager
	Agent       *agent.Runner
	Findings    *findings.Service
	enabled     bool
	native      *plugin.NativeReport
	pathReports []pathReport
	origins     []map[string]string
	truncated   bool
	knowledge   []workflow.KnowledgePin
}

func (e *Effects) Bind(_ context.Context, enabled bool) (workflow.Effects, workflow.ModelPin, error) {
	copy := *e
	copy.enabled = enabled
	copy.native = nil
	copy.pathReports = nil
	copy.origins = nil
	copy.truncated = false
	copy.knowledge = nil
	pin := workflow.ModelPin{Runtime: "disabled", RuntimeVersion: "1", ConfigVersion: "not_applicable"}
	if !enabled {
		return &copy, pin, nil
	}
	if e.Agent == nil || e.Agent.Ready() != nil {
		return nil, pin, workflow.ErrRuntimeUnavailable
	}
	frozen := *e.Agent
	caps := frozen.Runtime.Capabilities()
	pin.Runtime = caps.Name
	pin.RuntimeVersion = caps.Version
	if model, ok := frozen.Runtime.(*agent.ModelRuntime); ok {
		runtime, metadata, err := model.Freeze()
		if err != nil {
			return nil, pin, workflow.ErrRuntimeUnavailable
		}
		frozen.Runtime = runtime
		pin.ConfigVersion = metadata.Version
		pin.Model = metadata.Model
	}
	copy.Agent = &frozen
	return &copy, pin, nil
}
func (e *Effects) Execute(ctx context.Context, run workflow.Run, plan workflow.Plan, node workflow.NodeRun) (workflow.NodeResult, error) {
	if node.Kind == "knowledge_publish" {
		return e.publish(ctx, run, plan, node)
	}
	if !e.enabled {
		return workflow.NodeResult{Status: "SKIPPED", Note: "Candidate runtime analysis was not requested"}, nil
	}
	if e.native == nil || e.native.Paths == nil || len(e.native.Paths.Paths) == 0 {
		return workflow.NodeResult{Status: "SKIPPED", Note: "No candidate paths were produced"}, nil
	}
	return e.analyze(ctx, run, plan, node)
}
func (e *Effects) publish(ctx context.Context, run workflow.Run, plan workflow.Plan, node workflow.NodeRun) (workflow.NodeResult, error) {
	store, ok := e.Store.(publication.Store)
	if !ok {
		return workflow.NodeResult{}, workflow.ErrInvalid
	}
	publisher := publication.NewPublisher(store)
	result := workflow.NodeResult{Status: "SUCCEEDED", Knowledge: []workflow.KnowledgePin{}}
	for _, nr := range run.Nodes {
		if nr.Kind != "plugin" || (nr.Status != "SUCCEEDED" && nr.Status != "PARTIAL") {
			continue
		}
		inv, err := e.Host.GetStatus(ctx, run.Scope, nr.InvocationID)
		if err != nil {
			return result, err
		}
		if inv.Request.PluginID == plugin.BuiltinID {
			continue
		}
		document, err := e.Host.Result(ctx, run.Scope, inv.ID, 8<<20)
		if err != nil {
			return result, err
		}
		batch, omitted := publication.BatchFromDiscovery(
			"batch-"+run.ID+"-"+nr.NodeID,
			publication.Scope{ProjectID: run.Scope.ProjectID, SnapshotID: run.Scope.SnapshotID},
			artifact.Producer{PluginID: inv.Request.PluginID, PluginVersion: inv.Request.PluginVersion, InvocationID: inv.ID, TaskID: run.TaskID, ConfigDigest: inv.ConfigDigest},
			document,
			"",
			"security",
		)
		if omitted > 0 {
			batch.Limitations = append(batch.Limitations, fmt.Sprintf("%d cross-layer edges omitted because endpoints are outside this batch", omitted))
		}
		var revision *publication.Revision
		for attempt := 0; attempt < 5; attempt++ {
			batch.BaseRevision, err = store.KnowledgeHead(ctx, batch.Scope)
			if err != nil {
				return result, err
			}
			revision, err = publisher.Publish(ctx, batch)
			if !errors.Is(err, publication.ErrVersionConflict) {
				break
			}
		}
		if err != nil {
			return result, err
		}
		if e.Findings != nil && len(document.Candidates) > 0 {
			producer := artifact.Producer{PluginID: inv.Request.PluginID, PluginVersion: inv.Request.PluginVersion, InvocationID: inv.ID, TaskID: run.TaskID, ConfigDigest: inv.ConfigDigest}
			if _, err := e.Findings.RecordCandidates(ctx, run.Scope, run.TaskID, producer, document.Candidates); err != nil {
				return result, err
			}
		}
		result.Knowledge = append(result.Knowledge, workflow.KnowledgePin{Revision: revision.ID, Digest: revision.Digest})
		for _, ref := range nr.Outputs {
			if ref.SchemaID != "codexploit/builtin-native/v1" {
				continue
			}
			reader, _, err := e.Artifacts.Open(ctx, run.Scope, ref.ID, 8<<20)
			if err != nil {
				return result, err
			}
			raw, err := io.ReadAll(io.LimitReader(reader, 8<<20))
			reader.Close()
			if err != nil {
				return result, err
			}
			var native plugin.NativeReport
			if json.Unmarshal(raw, &native) != nil || native.Scope != run.Scope {
				return result, workflow.ErrInvalid
			}
			if native.Paths != nil {
				e.pathReports = append(e.pathReports, pathReport{&native, ref.ID})
			}
			if e.native == nil || (e.native.Paths == nil && native.Paths != nil) {
				e.native = &native
			}
		}
	}
	if len(result.Knowledge) == 0 {
		return workflow.NodeResult{Status: "SKIPPED", Note: "No normalized security or path results to publish"}, nil
	}
	e.knowledge = result.Knowledge
	if e.native != nil {
		if err := e.materialize(ctx, run); err != nil {
			return result, err
		}
	}
	ref, err := e.output(ctx, run, node, "knowledge.view", "codexploit/knowledge-revisions/v1", map[string]any{"api_version": "codexploit/v1", "scope": run.Scope, "plan_digest": plan.Digest, "revisions": result.Knowledge, "path_origins": e.origins})
	if err != nil {
		return result, err
	}
	result.Outputs = []artifact.Ref{ref}
	if e.truncated {
		result.Status = "PARTIAL"
		result.Note = "Task candidate path limit truncated the merged results"
	}
	return result, nil
}
func (e *Effects) output(ctx context.Context, run workflow.Run, node workflow.NodeRun, kind, schema string, value any) (artifact.Ref, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return artifact.Ref{}, err
	}
	ref := artifact.Ref{ID: "artifact-" + node.ID, Kind: kind, Scope: run.Scope, SHA256: workflow.Digest(raw), Bytes: int64(len(raw)), MediaType: "application/json", SchemaID: schema, Producer: artifact.Producer{PluginID: "builtin.workflow", PluginVersion: "1.0.0", InvocationID: node.ID, TaskID: run.TaskID, ConfigDigest: workflow.Digest([]byte("workflow-effects/v1"))}}
	return e.Artifacts.Put(ctx, ref, bytes.NewReader(raw), 4<<20)
}
func (e *Effects) materialize(ctx context.Context, run workflow.Run) error {
	if e.native.Graph == nil || e.native.Surface == nil {
		return workflow.ErrInvalid
	}
	summary, err := e.Store.GraphSummary(ctx, run.Scope.SnapshotID)
	if errors.Is(err, storage.ErrNotFound) {
		if err := e.Store.ReplaceGraph(ctx, run.Scope.SnapshotID, e.native.Graph); err != nil {
			return err
		}
		summary = e.native.Graph.Summarize()
	} else if err != nil {
		return err
	}
	if summary.GraphVersion != e.native.Graph.GraphVersion {
		return workflow.ErrConflict
	}
	if _, err := e.Store.ASGSummary(ctx, run.Scope.SnapshotID); errors.Is(err, storage.ErrNotFound) {
		if err := e.Store.ReplaceASG(ctx, run.Scope.SnapshotID, e.native.Surface); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if e.native.Paths == nil {
		return nil
	}
	task, err := e.Store.GetAudit(run.TaskID)
	if err != nil {
		return err
	}
	paths := []audit.Path{}
	seen := map[string]bool{}
	for _, source := range e.pathReports {
		if source.report.Graph == nil || source.report.Surface == nil || source.report.Graph.GraphVersion != e.native.Graph.GraphVersion || source.report.Surface.ASGVersion != e.native.Surface.ASGVersion {
			return workflow.ErrInvalid
		}
		for _, candidate := range source.report.Paths.Paths {

			entryFile, targetFile := "", ""
			if len(candidate.Steps) > 0 {
				entryFile = candidate.Steps[0].File
				targetFile = candidate.Steps[len(candidate.Steps)-1].File
			}
			if !audit.InScope(entryFile, task.Scope) || !audit.InScope(targetFile, task.Scope) {
				continue
			}
			original := candidate.ID
			candidate.ID = audit.PathID(task.ID, candidate.SnapshotID, candidate.EntryNodeID, candidate.TargetNodeID, candidate.SCGRefs, candidate.PathKind)
			if !seen[candidate.ID] && len(paths) >= task.Limits.MaxPaths {
				e.truncated = true
				continue
			}
			e.origins = append(e.origins, map[string]string{"task_path_id": candidate.ID, "native_path_id": original, "native_artifact_id": source.artifactID})
			if seen[candidate.ID] {
				continue
			}
			seen[candidate.ID] = true
			candidate.AuditID = task.ID
			candidate.Status = audit.StatusQueued
			candidate.Budget = task.Budget
			candidate.Objectives = append([]string{task.Objective}, candidate.Objectives...)
			candidate = audit.ScorePath(candidate, audit.ScoreInput{Now: run.UpdatedAt})
			candidate.ScoreSeq = 1
			paths = append(paths, candidate)
		}
	}
	paths = audit.ClusterPaths(paths)
	audit.SortByPriority(paths)
	if err := e.Store.ReplacePaths(task.ID, paths); err != nil {
		return err
	}
	features := []audit.FeatureRecord{}
	events := []audit.Event{}
	seq, err := e.Store.NextEventSeq(task.ID)
	if err != nil {
		return err
	}
	for _, p := range paths {
		features = append(features, audit.FeatureRecordOf(p, 1))
		events = append(events, audit.Event{ID: audit.EventID(task.ID, p.ID, seq), AuditID: task.ID, PathID: p.ID, Seq: seq, Type: audit.EventPathQueued, Actor: "workflow", Reason: "candidate path from fixed workflow input", CreatedAt: run.UpdatedAt, Detail: map[string]string{"workflow_run_id": run.ID, "plan_digest": run.PlanDigest}})
		seq++
	}
	if err := e.Store.AppendFeatures(features); err != nil {
		return err
	}
	if err := e.Store.AppendEvents(events); err != nil {
		return err
	}
	task.PathCount = len(paths)
	task.SCGVersion = e.native.Paths.SCGVersion
	task.ASGVersion = e.native.Paths.ASGVersion
	task.Coverage = e.native.Paths.Coverage
	task.Coverage.PathsEmitted = len(paths)
	if e.truncated {
		task.Coverage.Truncated = true
		task.Coverage.TruncationReasons = append(task.Coverage.TruncationReasons, "task candidate path limit truncated merged reports")
	}
	for _, source := range e.pathReports {
		if source.report.Paths.Coverage.Truncated {
			task.Coverage.Truncated = true
		}
		task.Limitations = append(task.Limitations, source.report.Paths.Limitations...)
	}
	if len(e.pathReports) > 1 {
		task.Limitations = append(task.Limitations, "Source/sink coverage counters describe the primary native report; task paths merge and deduplicate all path reports, whose individual coverage remains in original artifacts")
	}
	task.CountsByStatus = audit.StatusCounts(paths)
	task.CountsByPathStatus = audit.PathStatusCounts(paths)
	task.Limitations = append(task.Limitations, e.native.Paths.Limitations...)
	task.UpdatedAt = run.UpdatedAt
	return e.Store.UpdateAudit(*task, 0)
}
func (e *Effects) analyze(ctx context.Context, run workflow.Run, plan workflow.Plan, node workflow.NodeRun) (workflow.NodeResult, error) {
	memory := storage.NewMemory()
	if err := memory.ReplaceGraph(ctx, run.Scope.SnapshotID, e.native.Graph); err != nil {
		return workflow.NodeResult{}, err
	}
	if err := memory.ReplaceASG(ctx, run.Scope.SnapshotID, e.native.Surface); err != nil {
		return workflow.NodeResult{}, err
	}
	code := graph.NewService(memory, e.Manager)
	surface := graph.NewASGService(memory, code)
	facts := graph.NewPathFacts(code, surface, e.Store)
	paths := audit.NewService(e.Store, audit.NewEngine(facts, facts))
	runner := *e.Agent
	task, err := e.Store.GetAudit(run.TaskID)
	if err != nil {
		return workflow.NodeResult{}, err
	}
	runner.Policy.MaxToolCalls = min(runner.Policy.MaxToolCalls, task.Budget.MaxToolCalls)
	runner.Policy.MaxHops = min(runner.Policy.MaxHops, task.Budget.MaxDepth)
	runner.Policy.MaxBranches = min(runner.Policy.MaxBranches, task.Budget.MaxBranches)

	registry := agent.NewRegistry()
	graph.RegisterAgentTools(registry, code, surface, paths, e.Store)
	runner.Registry = registry
	runner.Tasks = graph.NewAgentFacts(code, surface, agent.BuildOptions{AllowedTools: runner.Policy.AllowedTools})
	runner.Paths = graph.NewAgentCoordinator(paths, "workflow-"+run.ID)
	candidates, total, err := e.Store.ListPaths(audit.PathQuery{AuditID: run.TaskID, Limit: 10, Sort: "priority"})
	if err != nil {
		return workflow.NodeResult{}, err
	}
	result := workflow.NodeResult{Status: "SUCCEEDED", AgentRunIDs: []string{}, Knowledge: e.knowledge}
	for _, candidate := range candidates {
		outcome, err := runner.RunPath(ctx, candidate.ID, "workflow-"+run.ID, time.Minute, runner.Policy)
		if outcome != nil {
			result.AgentRunIDs = append(result.AgentRunIDs, outcome.ID)
		}
		if err != nil {
			return result, err
		}
		if outcome == nil || outcome.Status != agent.RunSucceeded {
			result.Status = "FAILED"
			result.ErrorCode = "candidate_runtime_failed"
			return result, workflow.ErrInvalid
		}
	}
	if total > len(candidates) {
		result.Status = "PARTIAL"
		result.Note = "Candidate runtime is bounded to ten paths per workflow run"
	}
	ref, err := e.output(ctx, run, node, "report.document", "codexploit/workflow-analysis/v1", map[string]any{"api_version": "codexploit/v1", "workflow_run_id": run.ID, "task_id": run.TaskID, "plan_digest": plan.Digest, "model": run.Model, "knowledge": e.knowledge, "agent_run_ids": result.AgentRunIDs, "paths_total": total, "paths_analyzed": len(candidates)})
	if err != nil {
		return result, err
	}
	result.Outputs = []artifact.Ref{ref}
	return result, nil
}
