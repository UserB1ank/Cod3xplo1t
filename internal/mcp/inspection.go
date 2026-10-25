package mcp

import (
	"context"
	"errors"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

type scopedArtifacts interface {
	ArtifactScope(context.Context, string, string) (artifact.Scope, error)
	ListArtifacts(context.Context, artifact.Scope, string, int) ([]artifact.Ref, error)
}

func artifactSummary(refs []artifact.Ref) []map[string]any {
	out := []map[string]any{}
	for _, r := range refs {
		out = append(out, map[string]any{"id": r.ID, "kind": r.Kind, "bytes": r.Bytes, "sha256": r.SHA256, "plugin_id": r.Producer.PluginID, "plugin_version": r.Producer.PluginVersion, "operation_id": r.Producer.OperationID})
	}
	return out
}
func analysisSummary(run storage.AnalysisRun) map[string]any {
	stages := []map[string]any{}
	for _, s := range run.Stages {
		stages = append(stages, map[string]any{"key": s.Key, "status": s.Status, "error_code": s.ErrorCode, "invocation_id": s.InvocationID, "operation_id": s.OperationID, "inputs": artifactSummary(s.Inputs), "outputs": artifactSummary(s.Outputs)})
	}
	return map[string]any{"analysis_run_id": run.ID, "snapshot_id": run.SnapshotID, "workflow_run_id": run.WorkflowRunID, "task_id": run.TaskID, "state": run.State, "failure_code": run.FailureCode, "engine": run.Engine, "stages": stages, "path_count": run.PathCount, "coverage": run.Coverage, "knowledge": run.Knowledge, "created_at": run.CreatedAt}
}
func (p projectReader) operations(ctx context.Context, in inspectInput, out map[string]any) error {
	limit := in.Limit
	if limit < 1 || limit > 20 {
		limit = 10
	}
	if in.Offset < 0 || in.Offset > 1000000 || len(in.ID) > 256 || len(in.Cursor) > 256 {
		return coded(CodeInvalidArgument, errors.New("invalid inspection page"))
	}
	out["read_only"] = true
	switch in.Section {
	case "system":
		out["storage"] = storage.ProbeStatus(ctx, p.store)
		out["capabilities"] = []string{"source", "analysis", "workflow", "plugins", "invocations", "tasks", "paths", "agent_runs", "findings", "reports", "artifacts"}
		out["execution_access"] = "This inspection tool is read-only. Authenticated supervisors discover project read/write operations through list_project_operations and project_api when registered. Global settings and arbitrary shell are outside project scope."
	case "workflow":
		repo, ok := p.store.(workflow.RunRepository)
		if !ok {
			return coded("unsupported", errors.New("workflow catalog unavailable"))
		}
		ids := []string{}
		if in.ID != "" {
			ids = append(ids, in.ID)
		} else {
			runs, err := p.store.ListAnalysisRuns(ctx, p.project, limit)
			if err != nil {
				return err
			}
			for _, r := range runs {
				if r.SnapshotID == p.snapshot {
					ids = append(ids, r.WorkflowRunID)
				}
			}
			out["limited"] = len(runs) == limit
		}
		rows := []map[string]any{}
		for _, id := range ids {
			r, err := repo.GetWorkflowRun(ctx, p.project, id)
			if errors.Is(err, workflow.ErrNotFound) || errors.Is(err, storage.ErrNotFound) {
				rows = append(rows, map[string]any{"workflow_run_id": id, "state": "missing"})
				continue
			}
			if err != nil {
				return err
			}
			if r.Scope.SnapshotID != p.snapshot {
				return coded(CodeNotFound, errors.New("workflow outside bound source"))
			}
			nodes := []map[string]any{}
			for _, n := range r.Nodes {
				nodes = append(nodes, map[string]any{"node_id": n.NodeID, "status": n.Status, "error_code": n.ErrorCode, "invocation_id": n.InvocationID, "attempt": n.Attempt, "outputs": artifactSummary(n.Outputs)})
			}
			events := r.Events
			if len(events) > 20 {
				events = events[len(events)-20:]
				out["events_truncated"] = true
			}
			rows = append(rows, map[string]any{"workflow_run_id": r.ID, "status": r.Status, "plan_id": r.PlanID, "nodes": nodes, "events": events})
		}
		out["runs"] = rows
	case "plugins":
		repo, ok := p.store.(plugin.CatalogRepository)
		if !ok {
			return coded("unsupported", errors.New("plugin catalog unavailable"))
		}
		rows, err := repo.ListPlugins(ctx, in.Cursor, limit)
		if p.catalog != nil {
			rows, err = p.catalog.List(ctx, in.Cursor, limit)
		}
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for _, r := range rows {
			item := map[string]any{"id": r.Manifest.ID, "version": r.Manifest.Version, "package_digest": r.PackageDigest, "stages": r.Stages, "languages": r.Manifest.Languages}
			if p.catalog != nil {
				item["installed"] = r.Installed
				item["executable"] = r.Executable
			} else {
				item["availability"] = "worker_unbound"
			}
			if r.Installation != nil {
				item["enabled"] = r.Installation.Enabled
				item["integrity"] = r.Installation.Integrity
				item["probe"] = r.Installation.Probe
			}
			items = append(items, item)
		}
		out["plugins"] = items
		if len(rows) == limit {
			out["next_cursor"] = rows[len(rows)-1].Manifest.ID + "@" + rows[len(rows)-1].Manifest.Version
		}
	case "invocations", "reports", "artifacts":
		repo, ok := p.store.(scopedArtifacts)
		if !ok {
			return coded("unsupported", errors.New("artifact catalog unavailable"))
		}
		scope, err := repo.ArtifactScope(ctx, p.project, p.snapshot)
		if err != nil {
			return err
		}
		if in.Section == "artifacts" {
			refs, err := repo.ListArtifacts(ctx, scope, in.Cursor, limit)
			if err != nil {
				return err
			}
			out["artifacts"] = artifactSummary(refs)
			if len(refs) == limit {
				out["next_cursor"] = refs[len(refs)-1].ID
			}
			break
		}
		invs, ok := p.store.(plugin.Repository)
		if !ok {
			return coded("unsupported", errors.New("invocation catalog unavailable"))
		}
		var rows []plugin.Invocation
		if in.ID != "" {
			r, err := invs.GetInvocation(ctx, scope, in.ID)
			if err != nil {
				return coded(CodeNotFound, errors.New("invocation absent in project source"))
			}
			rows = []plugin.Invocation{r}
		} else {
			rows, err = invs.ListInvocations(ctx, scope, in.Cursor, limit)
			if err != nil {
				return err
			}
			if len(rows) == limit {
				out["next_cursor"] = rows[len(rows)-1].ID
			}
		}
		items := []map[string]any{}
		for _, r := range rows {
			if in.Section == "reports" && r.Request.PluginID != "builtin.reporter" {
				continue
			}
			items = append(items, map[string]any{"invocation_id": r.ID, "plugin_id": r.Request.PluginID, "plugin_version": r.Request.PluginVersion, "operation_id": r.Request.OperationID, "status": r.Status, "error_code": r.ErrorCode, "coverage": r.Coverage, "stage_coverage": r.StageCoverage, "outputs": artifactSummary(r.Outputs), "created_at": r.CreatedAt})
		}
		out[in.Section] = items
		out["scanned_items"] = len(rows)
	case "tasks":
		rows, total, err := p.store.ListAudits(path.AuditQuery{ProjectID: p.project, SnapshotID: p.snapshot, Limit: limit, Offset: in.Offset})
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for _, r := range rows {
			items = append(items, map[string]any{"task_id": r.ID, "name": r.Name, "status": r.Status, "paused": r.Paused, "archived": r.Archived, "path_count": r.PathCount, "counts_by_status": r.CountsByStatus})
		}
		out["tasks"] = items
		out["total"] = total
		out["next_offset"] = in.Offset + len(rows)
	case "paths":
		rows, total, err := p.store.ListPaths(path.PathQuery{SnapshotID: p.snapshot, Limit: limit, Offset: in.Offset})
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for _, r := range rows {
			items = append(items, map[string]any{"path_id": r.ID, "task_id": r.AuditID, "status": r.Status, "path_kind": r.PathKind, "priority": r.Score.Priority, "selection": r.Selection})
		}
		out["paths"] = items
		out["total"] = total
		out["next_offset"] = in.Offset + len(rows)
	case "agent_runs":
		rows, total, err := p.store.ListRuns(agent.RunQuery{SnapshotID: p.snapshot, Limit: limit, Offset: in.Offset})
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for _, r := range rows {
			items = append(items, map[string]any{"run_id": r.ID, "path_id": r.PathID, "status": r.Status, "runtime": r.Runtime, "stop_reason": r.StopReason})
		}
		out["runs"] = items
		out["total"] = total
		out["next_offset"] = in.Offset + len(rows)
	case "findings":
		rows, total, err := p.store.ListFindings(verify.FindingQuery{ProjectID: p.project, SnapshotID: p.snapshot, Limit: limit, Offset: in.Offset})
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for _, r := range rows {
			items = append(items, map[string]any{"finding_id": r.ID, "path_id": r.PathID, "title": r.Title, "status": r.Status, "severity": r.Severity, "supporting_evidence": r.Supporting, "contradicting_evidence": r.Contradicting, "inconclusive_evidence": r.Inconclusive})
		}
		out["findings"] = items
		out["total"] = total
		out["next_offset"] = in.Offset + len(rows)
	default:
		return coded(CodeInvalidArgument, errors.New("unknown project inspection section"))
	}
	return nil
}
