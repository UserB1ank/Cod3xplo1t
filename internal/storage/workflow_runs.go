package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	audit "github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func workflowTask(run workflow.Run, definition workflow.TaskDefinition) audit.Audit {
	return audit.Audit{ID: run.TaskID, Name: definition.Name, Objective: definition.Objective, Scope: definition.Scope, SnapshotID: run.Scope.SnapshotID, Status: audit.AuditGenerating, Budget: definition.Budget.Normalize(), Limits: definition.Limits.Normalize(), ConfigHash: run.PlanDigest, ScoreVersion: audit.ScoreVersion, CountsByStatus: map[string]int{}, CountsByPathStatus: map[string]int{}, Limitations: []string{}, CreatedAt: run.CreatedAt, UpdatedAt: run.CreatedAt, Version: 1}
}
func (m *Memory) CreateWorkflowRun(ctx context.Context, run workflow.Run, definition workflow.TaskDefinition) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(run)
	if err != nil {
		return err
	}
	task, err := cloneDocument(workflowTask(run, definition))
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.artifactScopeLocked(run.Scope) {
		return workflow.ErrNotFound
	}
	if _, ok := m.audits[run.TaskID]; ok {
		return workflow.ErrConflict
	}
	if m.workflowRuns == nil {
		m.workflowRuns = map[string][]byte{}
	}
	if _, ok := m.workflowRuns[run.ID]; ok {
		return workflow.ErrConflict
	}
	m.workflowRuns[run.ID] = raw
	m.audits[run.TaskID] = newAuditDocument(task)
	return nil
}
func (m *Memory) SaveWorkflowRun(ctx context.Context, run workflow.Run, expected int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(run)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.artifactScopeLocked(run.Scope) {
		return workflow.ErrNotFound
	}
	priorRaw, ok := m.workflowRuns[run.ID]
	if !ok {
		return workflow.ErrNotFound
	}
	var prior workflow.Run
	if err := json.Unmarshal(priorRaw, &prior); err != nil {
		return err
	}
	if !validWorkflowUpdate(prior, run, expected) {
		return workflow.ErrConflict
	}
	m.workflowRuns[run.ID] = raw
	if workflow.RunTerminal(run.Status) {
		if doc := m.audits[run.TaskID]; doc != nil {
			doc.audit.Status = audit.AuditReady
			if run.Status != "SUCCEEDED" && run.Status != "PARTIAL" {
				doc.audit.Status = audit.AuditFailed
			}
			doc.audit.Version++
			doc.audit.UpdatedAt = run.UpdatedAt
		}
	}
	return nil
}
func (m *Memory) ListRecoverableWorkflowRuns(ctx context.Context) ([]workflow.Run, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	runs := []workflow.Run{}
	for _, raw := range m.workflowRuns {
		var run workflow.Run
		if err := json.Unmarshal(raw, &run); err != nil {
			continue
		}
		if workflow.RunTerminal(run.Status) || !m.artifactScopeLocked(run.Scope) {
			continue
		}
		runs = append(runs, run)
	}
	return runs, nil
}
func (m *Memory) GetWorkflowRun(ctx context.Context, project, id string) (workflow.Run, error) {
	if err := ctx.Err(); err != nil {
		return workflow.Run{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var run workflow.Run
	raw, ok := m.workflowRuns[id]
	if !ok {
		return run, workflow.ErrNotFound
	}
	if err := json.Unmarshal(raw, &run); err != nil {
		return run, err
	}
	if run.Scope.ProjectID != project || !m.artifactScopeLocked(run.Scope) {
		return workflow.Run{}, workflow.ErrNotFound
	}
	return run, nil
}
func (s *SQL) CreateWorkflowRun(ctx context.Context, run workflow.Run, definition workflow.TaskDefinition) error {
	raw, err := json.Marshal(run)
	if err != nil {
		return err
	}
	values, err := auditWriteValues(workflowTask(run, definition))
	if err != nil {
		return err
	}
	return s.snapshotWrite(ctx, run.Scope.SnapshotID, func(tx *sql.Tx) error {
		scope, err := scanArtifactScope(tx.QueryRowContext(ctx, s.rebind(artifactScopeQuery), run.Scope.ProjectID, run.Scope.SnapshotID))
		if err != nil || scope != run.Scope {
			return workflow.ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO audits ("+strings.Join(auditColumnNames, ",")+") VALUES ("+placeholders(len(values))+")"), values...); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO workflow_runs(run_id,project_id,snapshot_id,task_id,plan_id,status,version,document_json) VALUES(?,?,?,?,?,?,?,?)`), run.ID, run.Scope.ProjectID, run.Scope.SnapshotID, run.TaskID, run.PlanID, run.Status, run.Version, string(raw))
		return err
	})
}
func (s *SQL) SaveWorkflowRun(ctx context.Context, run workflow.Run, expected int64) error {
	raw, err := json.Marshal(run)
	if err != nil {
		return err
	}
	return s.snapshotWrite(ctx, run.Scope.SnapshotID, func(tx *sql.Tx) error {
		var priorRaw string
		if err := tx.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM workflow_runs WHERE run_id=?`), run.ID).Scan(&priorRaw); err != nil {
			return err
		}
		var prior workflow.Run
		if err := json.Unmarshal([]byte(priorRaw), &prior); err != nil {
			return err
		}
		if !validWorkflowUpdate(prior, run, expected) {
			return workflow.ErrConflict
		}
		result, err := tx.ExecContext(ctx, s.rebind(`UPDATE workflow_runs SET status=?,version=?,document_json=? WHERE run_id=? AND project_id=? AND snapshot_id=? AND task_id=? AND plan_id=? AND version=?`), run.Status, run.Version, string(raw), run.ID, run.Scope.ProjectID, run.Scope.SnapshotID, run.TaskID, run.PlanID, expected)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 || run.Version != expected+1 {
			return workflow.ErrConflict
		}
		if workflow.RunTerminal(run.Status) {
			status := audit.AuditReady
			if run.Status != "SUCCEEDED" && run.Status != "PARTIAL" {
				status = audit.AuditFailed
			}
			_, err = tx.ExecContext(ctx, s.rebind(`UPDATE audits SET status=?,version=version+1,updated_at=? WHERE audit_id=?`), status, run.UpdatedAt, run.TaskID)
			if err != nil {
				return err
			}
		}

		return nil
	})
}
func (s *SQL) ListRecoverableWorkflowRuns(ctx context.Context) ([]workflow.Run, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT r.document_json FROM workflow_runs r
WHERE r.status IN ('CREATED','RUNNING','PAUSING','PAUSED','CANCELLING')
  AND NOT EXISTS (SELECT 1 FROM snapshot_deletions d WHERE d.snapshot_id = r.snapshot_id)`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := []workflow.Run{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var run workflow.Run
		if err := json.Unmarshal([]byte(raw), &run); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}
func (s *SQL) GetWorkflowRun(ctx context.Context, project, id string) (workflow.Run, error) {
	var raw string
	var run workflow.Run
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM workflow_runs r WHERE r.project_id=? AND r.run_id=? AND NOT EXISTS(SELECT 1 FROM snapshot_deletions d WHERE d.snapshot_id=r.snapshot_id)`), project, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return run, workflow.ErrNotFound
	}
	if err != nil {
		return run, err
	}
	err = json.Unmarshal([]byte(raw), &run)
	return run, err
}

// Every state write extends the event history and preserves the fixed run identity.
func validWorkflowUpdate(prior, next workflow.Run, expected int64) bool {
	if prior.Version != expected || next.Version != expected+1 || workflow.RunTerminal(prior.Status) || prior.ID != next.ID || prior.Scope != next.Scope || prior.TaskID != next.TaskID || prior.PlanID != next.PlanID || prior.PlanDigest != next.PlanDigest || prior.CreatedAt != next.CreatedAt || prior.Model != next.Model || prior.RunnerVersion != next.RunnerVersion || prior.MaxParallel != next.MaxParallel || prior.MaxAttempts != next.MaxAttempts || prior.RetryOf != next.RetryOf || prior.AnalyzeCandidates != next.AnalyzeCandidates || len(prior.Nodes) != len(next.Nodes) || len(next.Events) != len(prior.Events)+1 {
		return false
	}
	oldTask, _ := json.Marshal(prior.Task)
	newTask, _ := json.Marshal(next.Task)
	oldPolicy, _ := json.Marshal(prior.AcceptPartialNodes)
	newPolicy, _ := json.Marshal(next.AcceptPartialNodes)
	if string(oldTask) != string(newTask) || string(oldPolicy) != string(newPolicy) {
		return false
	}
	for i, event := range prior.Events {
		if event != next.Events[i] {
			return false
		}
	}
	last := next.Events[len(next.Events)-1]
	if last.Seq != int64(len(next.Events)) || last.CreatedAt != next.UpdatedAt {
		return false
	}
	for i, node := range prior.Nodes {
		updated := next.Nodes[i]
		if node.ID != updated.ID || node.NodeID != updated.NodeID || node.Kind != updated.Kind {
			return false
		}
		if node.Status != "PENDING" && node.Status != "RUNNING" {
			old, _ := json.Marshal(node)
			current, _ := json.Marshal(updated)
			if string(old) != string(current) {
				return false
			}
		}
	}
	return true
}
