package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func (s *SQL) PutPlan(ctx context.Context, record verify.PlanRecord, expectedVersion int64) (verify.PlanRecord, error) {
	planJSON, err := json.Marshal(record.Plan)
	if err != nil {
		return verify.PlanRecord{}, err
	}
	approvalJSON := ""
	if record.Approval != nil {
		raw, err := json.Marshal(record.Approval)
		if err != nil {
			return verify.PlanRecord{}, err
		}
		approvalJSON = string(raw)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if expectedVersion == 0 {
		if record.CreatedAt == "" {
			record.CreatedAt = now
		}
		result, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO verification_plans (plan_id,project_id,state,plan_json,approval_json,version,created_at,updated_at) VALUES (?,?,?,?,?,1,?,?) ON CONFLICT (plan_id) DO NOTHING`),
			record.Plan.ID, record.Plan.ProjectID, string(record.State), string(planJSON), approvalJSON, record.CreatedAt, now)
		if err != nil {
			return verify.PlanRecord{}, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return verify.PlanRecord{}, err
		}
		if affected == 0 {
			return verify.PlanRecord{}, verify.ErrPlanConflict
		}
		record.Version, record.UpdatedAt = 1, now
		return record, nil
	}
	result, err := s.db.ExecContext(ctx, s.rebind(`UPDATE verification_plans SET state=?,plan_json=?,approval_json=?,version=?,updated_at=? WHERE plan_id=? AND project_id=? AND version=?`),
		string(record.State), string(planJSON), approvalJSON, expectedVersion+1, now, record.Plan.ID, record.Plan.ProjectID, expectedVersion)
	if err != nil {
		return verify.PlanRecord{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return verify.PlanRecord{}, err
	}
	if affected == 0 {
		return verify.PlanRecord{}, verify.ErrPlanConflict
	}
	record.Version, record.UpdatedAt = expectedVersion+1, now
	return record, nil
}

func (s *SQL) GetPlan(ctx context.Context, projectID, planID string) (verify.PlanRecord, error) {
	var state, planJSON, approvalJSON, createdAt, updatedAt string
	var version int64
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT state,plan_json,approval_json,version,created_at,updated_at FROM verification_plans WHERE plan_id=? AND project_id=?`), planID, projectID).
		Scan(&state, &planJSON, &approvalJSON, &version, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return verify.PlanRecord{}, verify.ErrPlanNotFound
	}
	if err != nil {
		return verify.PlanRecord{}, err
	}
	return decodePlanRecord(state, planJSON, approvalJSON, version, createdAt, updatedAt)
}

func (s *SQL) ListPlans(ctx context.Context, projectID, state string, limit, offset int) ([]verify.PlanRecord, int, error) {
	if limit < 1 || limit > 200 || offset < 0 {
		return nil, 0, verify.ErrPlanInvalid
	}
	where := "project_id=?"
	args := []any{projectID}
	if state != "" {
		where += " AND state=?"
		args = append(args, state)
	}
	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM verification_plans WHERE "+where), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := s.rebind("SELECT state,plan_json,approval_json,version,created_at,updated_at FROM verification_plans WHERE " + where + " ORDER BY created_at DESC, plan_id ASC LIMIT ? OFFSET ?")
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []verify.PlanRecord{}
	for rows.Next() {
		var recordState, planJSON, approvalJSON, createdAt, updatedAt string
		var version int64
		if err := rows.Scan(&recordState, &planJSON, &approvalJSON, &version, &createdAt, &updatedAt); err != nil {
			return nil, 0, err
		}
		record, err := decodePlanRecord(recordState, planJSON, approvalJSON, version, createdAt, updatedAt)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, record)
	}
	return result, total, rows.Err()
}

func decodePlanRecord(state, planJSON, approvalJSON string, version int64, createdAt, updatedAt string) (verify.PlanRecord, error) {
	var plan verify.ExecutionPlan
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
		return verify.PlanRecord{}, err
	}
	record := verify.PlanRecord{Plan: plan, State: verify.PlanState(state), Version: version, CreatedAt: createdAt, UpdatedAt: updatedAt}
	if approvalJSON != "" {
		var approval verify.PlanApproval
		if err := json.Unmarshal([]byte(approvalJSON), &approval); err != nil {
			return verify.PlanRecord{}, err
		}
		record.Approval = &approval
	}
	return record, nil
}
