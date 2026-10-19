package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

// GetAuditBudget implements agent.Store. A missing ledger is the documented
// default, not an error: the row appears when the first reservation is made.
func (s *SQL) GetAuditBudget(auditID string) (*agent.AuditBudget, error) {
	row := s.db.QueryRowContext(context.Background(), s.rebind(
		`SELECT limit_tokens, reserved_tokens, used_tokens, version, updated_at FROM agent_audit_budgets WHERE audit_id = ?`), auditID)
	var budget agent.AuditBudget
	if err := row.Scan(&budget.LimitTokens, &budget.ReservedTokens, &budget.UsedTokens, &budget.Version, &budget.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return &agent.AuditBudget{AuditID: auditID, LimitTokens: agent.DefaultAuditTokenBudget, Version: 1}, nil
		}
		return nil, mapAgentSQLError(err)
	}
	budget.AuditID = auditID
	return &budget, nil
}

// ReserveAuditTokens implements agent.Store. The conditional UPDATE is the CAS:
// across instances only reservations that still fit are accepted.
func (s *SQL) ReserveAuditTokens(auditID string, tokens int) (*agent.AuditBudget, error) {
	if tokens <= 0 {
		return nil, fmt.Errorf("%w: a reservation must be positive", agent.ErrInvalidArgument)
	}
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, s.rebind(
		`INSERT INTO agent_audit_budgets (audit_id, limit_tokens, reserved_tokens, used_tokens, version, updated_at)
		 VALUES (?, ?, 0, 0, 1, ?) ON CONFLICT (audit_id) DO NOTHING`), auditID, agent.DefaultAuditTokenBudget, agentNow()); err != nil {
		return nil, mapAgentSQLError(err)
	}
	result, err := s.db.ExecContext(ctx, s.rebind(
		`UPDATE agent_audit_budgets SET reserved_tokens = reserved_tokens + ?, version = version + 1, updated_at = ?
		 WHERE audit_id = ? AND reserved_tokens + used_tokens + ? <= limit_tokens`), tokens, agentNow(), auditID, tokens)
	if err != nil {
		return nil, mapAgentSQLError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, fmt.Errorf("%w: the audit budget cannot reserve %d token(s)", agent.ErrBudgetExhausted, tokens)
	}
	return s.GetAuditBudget(auditID)
}

// SettleAuditTokens implements agent.Store: a reservation becomes real usage or
// is released. A replay is harmless because the caller passes the reservation
// once; the ledger never goes below zero.
func (s *SQL) SettleAuditTokens(auditID string, reserved, used int) error {
	if reserved < 0 || used < 0 {
		return fmt.Errorf("%w: usage cannot be negative", agent.ErrInvalidArgument)
	}
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, s.rebind(
		`INSERT INTO agent_audit_budgets (audit_id, limit_tokens, reserved_tokens, used_tokens, version, updated_at)
		 VALUES (?, ?, 0, 0, 1, ?) ON CONFLICT (audit_id) DO NOTHING`), auditID, agent.DefaultAuditTokenBudget, agentNow()); err != nil {
		return mapAgentSQLError(err)
	}
	_, err := s.db.ExecContext(ctx, s.rebind(
		`UPDATE agent_audit_budgets SET
			reserved_tokens = CASE WHEN reserved_tokens >= ? THEN reserved_tokens - ? ELSE 0 END,
			used_tokens = used_tokens + ?, version = version + 1, updated_at = ?
		 WHERE audit_id = ?`), reserved, reserved, used, agentNow(), auditID)
	return mapAgentSQLError(err)
}

// GrantAuditTokens implements agent.Store. The version guard is the CAS; an
// approved grant raises the ceiling, a rejected one only records the decision.
func (s *SQL) GrantAuditTokens(grant agent.BudgetGrant, expectedVersion int64) (*agent.AuditBudget, error) {
	if err := agent.ValidateBudgetGrant(grant); err != nil {
		return nil, err
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapAgentSQLError(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, s.rebind(
		`INSERT INTO agent_audit_budgets (audit_id, limit_tokens, reserved_tokens, used_tokens, version, updated_at)
		 VALUES (?, ?, 0, 0, 1, ?) ON CONFLICT (audit_id) DO NOTHING`), grant.AuditID, agent.DefaultAuditTokenBudget, agentNow()); err != nil {
		return nil, mapAgentSQLError(err)
	}
	var limit int
	var version int64
	query := `SELECT limit_tokens, version FROM agent_audit_budgets WHERE audit_id = ?`
	if s.postgres {
		query += ` FOR UPDATE`
	}
	if err := tx.QueryRowContext(ctx, s.rebind(query), grant.AuditID).Scan(&limit, &version); err != nil {
		return nil, mapAgentSQLError(err)
	}
	if expectedVersion != 0 && version != expectedVersion {
		return nil, fmt.Errorf("%w: the budget is at version %d", agent.ErrConflict, version)
	}
	if grant.Decision == agent.GrantApproved {
		limit += grant.Tokens
	}
	grant.Version = version + 1
	if grant.DecidedAt == "" {
		grant.DecidedAt = agentNow()
	}
	if _, err := tx.ExecContext(ctx, s.rebind(
		`UPDATE agent_audit_budgets SET limit_tokens = ?, version = version + 1, updated_at = ? WHERE audit_id = ?`),
		limit, agentNow(), grant.AuditID); err != nil {
		return nil, mapAgentSQLError(err)
	}
	if _, err := tx.ExecContext(ctx, s.rebind(
		`INSERT INTO agent_budget_grants (grant_id, audit_id, run_id, tokens, reason, requested_by, decision, decided_by, created_at, decided_at, version)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		grant.ID, grant.AuditID, grant.RunID, grant.Tokens, grant.Reason, grant.RequestedBy,
		grant.Decision, grant.DecidedBy, grant.CreatedAt, grant.DecidedAt, grant.Version); err != nil {
		return nil, mapAgentSQLError(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, mapAgentSQLError(err)
	}
	return s.GetAuditBudget(grant.AuditID)
}

// ListBudgetGrants implements agent.Store.
func (s *SQL) ListBudgetGrants(auditID string) ([]agent.BudgetGrant, error) {
	rows, err := s.db.QueryContext(context.Background(), s.rebind(
		`SELECT grant_id, audit_id, run_id, tokens, reason, requested_by, decision, decided_by, created_at, decided_at, version
		 FROM agent_budget_grants WHERE audit_id = ? ORDER BY created_at, grant_id`), auditID)
	if err != nil {
		return nil, mapAgentSQLError(err)
	}
	defer rows.Close()
	var out []agent.BudgetGrant
	for rows.Next() {
		var grant agent.BudgetGrant
		if err := rows.Scan(&grant.ID, &grant.AuditID, &grant.RunID, &grant.Tokens, &grant.Reason,
			&grant.RequestedBy, &grant.Decision, &grant.DecidedBy, &grant.CreatedAt, &grant.DecidedAt, &grant.Version); err != nil {
			return nil, err
		}
		out = append(out, grant)
	}
	return out, rows.Err()
}
