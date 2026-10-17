package storage

import (
	"context"
	"database/sql"
	"errors"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

type TaskActivity struct {
	Counts     map[string]int
	ActiveRuns bool
}

type TaskActivityReader interface {
	TaskActivities(context.Context, []string) (map[string]TaskActivity, error)
}

func (m *Memory) taskActivityLocked(id string) TaskActivity {
	activity := TaskActivity{Counts: map[string]int{}}
	if doc, ok := m.audits[id]; ok {
		for _, p := range doc.paths {
			activity.Counts[string(p.Status)]++
		}
	}
	for _, doc := range m.agentRuns {
		if doc.run.AuditID == id && !doc.run.Status.Terminal() {
			activity.ActiveRuns = true
		}
	}
	for _, run := range m.verificationRuns {
		if run.AuditID == id && !run.Status.Terminal() {
			activity.ActiveRuns = true
		}
	}
	return activity
}

func (m *Memory) TaskActivities(_ context.Context, ids []string) (map[string]TaskActivity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]TaskActivity, len(ids))
	for _, id := range ids {
		result[id] = m.taskActivityLocked(id)
	}
	return result, nil
}

const terminalAgentStates = "'SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','BUDGET_EXCEEDED','INVALID_OUTPUT'"
const terminalVerificationStates = "'SUCCEEDED','FAILED','BLOCKED','CANCELLED','TIMED_OUT'"

func (s *SQL) TaskActivities(ctx context.Context, ids []string) (map[string]TaskActivity, error) {
	result := make(map[string]TaskActivity, len(ids))
	if len(ids) == 0 {
		return result, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
		result[id] = TaskActivity{Counts: map[string]int{}}
	}
	rows, err := s.db.QueryContext(ctx, s.rebind("SELECT audit_id,status,COUNT(*) FROM audit_paths WHERE audit_id IN ("+placeholders(len(ids))+") GROUP BY audit_id,status"), args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, status string
		var count int
		if err := rows.Scan(&id, &status, &count); err != nil {
			rows.Close()
			return nil, err
		}
		result[id].Counts[status] = count
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	query := "SELECT audit_id FROM agent_runs WHERE audit_id IN (" + placeholders(len(ids)) + ") AND status NOT IN (" + terminalAgentStates + ") UNION SELECT audit_id FROM verification_runs WHERE audit_id IN (" + placeholders(len(ids)) + ") AND status NOT IN (" + terminalVerificationStates + ")"
	args = append(args, args...)
	rows, err = s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		activity := result[id]
		activity.ActiveRuns = true
		result[id] = activity
	}
	return result, rows.Err()
}

func (s *SQL) taskHasRunsTx(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var count int
	query := "SELECT (SELECT COUNT(*) FROM agent_runs WHERE audit_id = ? AND status NOT IN (" + terminalAgentStates + ")) + (SELECT COUNT(*) FROM verification_runs WHERE audit_id = ? AND status NOT IN (" + terminalVerificationStates + "))"
	err := tx.QueryRowContext(ctx, s.rebind(query), id, id).Scan(&count)
	return count > 0, err
}

func (s *SQL) taskRunAllowedTx(ctx context.Context, tx *sql.Tx, id string) error {
	if _, err := tx.ExecContext(ctx, s.rebind("UPDATE audits SET version = version WHERE audit_id = ?"), id); err != nil {
		return err
	}
	var archived bool
	err := tx.QueryRowContext(ctx, s.rebind("SELECT task_archived FROM audits WHERE audit_id = ?"), id).Scan(&archived)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if archived {
		return path.ErrTaskArchived
	}
	return nil
}
