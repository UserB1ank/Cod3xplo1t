package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

type workflowHead struct{ Digest, Version string }

func workflowKey(project, id, version string) string { return project + "/" + id + "/" + version }
func (m *Memory) SaveWorkflow(_ context.Context, r workflow.Record, expected string) (workflow.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.projects[r.ProjectID]; !ok {
		return workflow.Record{}, workflow.ErrNotFound
	}
	if m.workflows == nil {
		m.workflows = map[string][]byte{}
		m.workflowHeads = map[string]workflowHead{}
	}
	key := workflowKey(r.ProjectID, r.Spec.ID, r.Spec.Version)
	if raw, ok := m.workflows[key]; ok {
		var prior workflow.Record
		_ = json.Unmarshal(raw, &prior)
		if prior.Digest != r.Digest {
			return workflow.Record{}, workflow.ErrConflict
		}
		return prior, nil
	}
	head := workflowKey(r.ProjectID, r.Spec.ID, "")
	if m.workflowHeads[head].Digest != expected || !workflow.VersionAfter(r.Spec.Version, m.workflowHeads[head].Version) {
		return workflow.Record{}, workflow.ErrConflict
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return workflow.Record{}, err
	}
	m.workflows[key] = raw
	m.workflowHeads[head] = workflowHead{r.Digest, r.Spec.Version}
	return r, nil
}
func (m *Memory) GetWorkflow(_ context.Context, project, id, version string) (workflow.Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var r workflow.Record
	raw, ok := m.workflows[workflowKey(project, id, version)]
	if !ok {
		return r, workflow.ErrNotFound
	}
	err := json.Unmarshal(raw, &r)
	return r, err
}
func (s *SQL) SaveWorkflow(ctx context.Context, r workflow.Record, expected string) (workflow.Record, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return workflow.Record{}, err
	}
	defer tx.Rollback()
	// Acquire the project row before comparing the head, including the first write.
	result, err := tx.ExecContext(ctx, s.rebind(`UPDATE projects SET name=name WHERE id=?`), r.ProjectID)
	if err != nil {
		return workflow.Record{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return workflow.Record{}, err
	}
	if n == 0 {
		return workflow.Record{}, workflow.ErrNotFound
	}
	var priorRaw string
	err = tx.QueryRowContext(ctx, s.rebind(`SELECT record_json FROM workflow_versions WHERE project_id=? AND workflow_id=? AND version=?`), r.ProjectID, r.Spec.ID, r.Spec.Version).Scan(&priorRaw)
	if err == nil {
		var prior workflow.Record
		if err = json.Unmarshal([]byte(priorRaw), &prior); err != nil {
			return workflow.Record{}, err
		}
		if prior.Digest != r.Digest {
			return workflow.Record{}, workflow.ErrConflict
		}
		return prior, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return workflow.Record{}, err
	}
	var head, version string
	err = tx.QueryRowContext(ctx, s.rebind(`SELECT digest,version FROM workflow_heads WHERE project_id=? AND workflow_id=?`), r.ProjectID, r.Spec.ID).Scan(&head, &version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return workflow.Record{}, err
	}
	if head != expected || !workflow.VersionAfter(r.Spec.Version, version) {
		return workflow.Record{}, workflow.ErrConflict
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return workflow.Record{}, err
	}
	_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO workflow_versions(project_id,workflow_id,version,digest,record_json) VALUES(?,?,?,?,?)`), r.ProjectID, r.Spec.ID, r.Spec.Version, r.Digest, string(raw))
	if err != nil {
		return workflow.Record{}, err
	}
	_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO workflow_heads(project_id,workflow_id,digest,version) VALUES(?,?,?,?) ON CONFLICT(project_id,workflow_id) DO UPDATE SET digest=excluded.digest,version=excluded.version`), r.ProjectID, r.Spec.ID, r.Digest, r.Spec.Version)
	if err != nil {
		return workflow.Record{}, err
	}
	return r, tx.Commit()
}
func (s *SQL) GetWorkflow(ctx context.Context, project, id, version string) (workflow.Record, error) {
	var raw string
	var r workflow.Record
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT record_json FROM workflow_versions WHERE project_id=? AND workflow_id=? AND version=?`), project, id, version).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return r, workflow.ErrNotFound
	}
	if err != nil {
		return r, err
	}
	err = json.Unmarshal([]byte(raw), &r)
	return r, err
}

func (m *Memory) PutWorkflowPlan(_ context.Context, p workflow.Plan) (workflow.Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.artifactScopeLocked(p.Scope) {
		return workflow.Plan{}, workflow.ErrNotFound
	}
	if m.workflowPlans == nil {
		m.workflowPlans = map[string][]byte{}
	}
	if raw, ok := m.workflowPlans[p.ID]; ok {
		var prior workflow.Plan
		err := json.Unmarshal(raw, &prior)
		if err != nil {
			return workflow.Plan{}, err
		}
		if prior.Digest != p.Digest {
			return workflow.Plan{}, workflow.ErrConflict
		}
		return prior, nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return workflow.Plan{}, err
	}
	m.workflowPlans[p.ID] = raw
	return p, nil
}
func (m *Memory) GetWorkflowPlan(_ context.Context, project, id string) (workflow.Plan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var p workflow.Plan
	raw, ok := m.workflowPlans[id]
	if !ok {
		return p, workflow.ErrNotFound
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if p.Scope.ProjectID != project || !m.artifactScopeLocked(p.Scope) {
		return workflow.Plan{}, workflow.ErrNotFound
	}
	return p, nil
}
func (s *SQL) PutWorkflowPlan(ctx context.Context, p workflow.Plan) (workflow.Plan, error) {
	var result workflow.Plan
	err := s.snapshotWrite(ctx, p.Scope.SnapshotID, func(tx *sql.Tx) error {
		scope, err := scanArtifactScope(tx.QueryRowContext(ctx, s.rebind(artifactScopeQuery), p.Scope.ProjectID, p.Scope.SnapshotID))
		if err != nil || scope != p.Scope {
			return workflow.ErrNotFound
		}
		var raw string
		err = tx.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM workflow_plans WHERE plan_id=?`), p.ID).Scan(&raw)
		if err == nil {
			if err = json.Unmarshal([]byte(raw), &result); err != nil {
				return err
			}
			if result.Digest != p.Digest {
				return workflow.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		doc, err := json.Marshal(p)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO workflow_plans(plan_id,project_id,snapshot_id,document_json) VALUES(?,?,?,?)`), p.ID, p.Scope.ProjectID, p.Scope.SnapshotID, string(doc))
		result = p
		return err
	})
	return result, err
}
func (s *SQL) GetWorkflowPlan(ctx context.Context, project, id string) (workflow.Plan, error) {
	var p workflow.Plan
	var raw string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM workflow_plans p WHERE p.project_id=? AND p.plan_id=? AND EXISTS(SELECT 1 FROM snapshots s WHERE s.snapshot_id=p.snapshot_id AND s.project_id=p.project_id) AND NOT EXISTS(SELECT 1 FROM snapshot_deletions d WHERE d.snapshot_id=p.snapshot_id)`), project, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return p, workflow.ErrNotFound
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal([]byte(raw), &p)
	return p, err
}

func (m *Memory) ListWorkflows(_ context.Context, project, cursor string, limit int) ([]workflow.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.projects[project]; !ok {
		return nil, workflow.ErrNotFound
	}
	rows := []workflow.Entry{}
	for _, raw := range m.workflows {
		var r workflow.Record
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		if r.ProjectID == project && r.Spec.ID+"@"+r.Spec.Version > cursor {
			rows = append(rows, workflow.Entry{Record: r, HeadDigest: m.workflowHeads[workflowKey(project, r.Spec.ID, "")].Digest})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Spec.ID+"@"+rows[i].Spec.Version < rows[j].Spec.ID+"@"+rows[j].Spec.Version
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}
func (s *SQL) ListWorkflows(ctx context.Context, project, cursor string, limit int) ([]workflow.Entry, error) {
	if _, err := s.GetProject(ctx, project); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, workflow.ErrNotFound
		}
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT v.record_json,h.digest FROM workflow_versions v JOIN workflow_heads h ON v.project_id=h.project_id AND v.workflow_id=h.workflow_id WHERE v.project_id=? AND v.workflow_id || '@' || v.version > ? ORDER BY v.workflow_id || '@' || v.version LIMIT ?`), project, cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []workflow.Entry{}
	for rows.Next() {
		var raw string
		var r workflow.Entry
		if err := rows.Scan(&raw, &r.HeadDigest); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &r.Record); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (m *Memory) ListWorkflowPlans(_ context.Context, project, snapshot, cursor string, limit int) ([]workflow.Plan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := []workflow.Plan{}
	for _, raw := range m.workflowPlans {
		var p workflow.Plan
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		if p.Scope.ProjectID == project && p.Scope.SnapshotID == snapshot && p.ID > cursor && m.artifactScopeLocked(p.Scope) {
			result = append(result, p)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}
func (s *SQL) ListWorkflowPlans(ctx context.Context, project, snapshot, cursor string, limit int) ([]workflow.Plan, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT document_json FROM workflow_plans p WHERE project_id=? AND snapshot_id=? AND plan_id>? AND NOT EXISTS(SELECT 1 FROM snapshot_deletions d WHERE d.snapshot_id=p.snapshot_id) ORDER BY plan_id LIMIT ?`), project, snapshot, cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []workflow.Plan{}
	for rows.Next() {
		var raw string
		var p workflow.Plan
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}
