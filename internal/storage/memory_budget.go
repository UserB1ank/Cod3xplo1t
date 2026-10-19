package storage

import (
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

// auditBudgetLocked returns the ledger of an audit, creating the default row on
// first use. The caller holds the lock.
func (m *Memory) auditBudgetLocked(auditID string) *agent.AuditBudget {
	budget, ok := m.auditBudgets[auditID]
	if !ok {
		budget = &agent.AuditBudget{AuditID: auditID, LimitTokens: agent.DefaultAuditTokenBudget, Version: 1, UpdatedAt: agentNow()}
		m.auditBudgets[auditID] = budget
	}
	return budget
}

func (m *Memory) GetAuditBudget(auditID string) (*agent.AuditBudget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if budget, ok := m.auditBudgets[auditID]; ok {
		copied := *budget
		return &copied, nil
	}
	return &agent.AuditBudget{AuditID: auditID, LimitTokens: agent.DefaultAuditTokenBudget, Version: 1}, nil
}

func (m *Memory) ReserveAuditTokens(auditID string, tokens int) (*agent.AuditBudget, error) {
	if tokens <= 0 {
		return nil, fmt.Errorf("%w: a reservation must be positive", agent.ErrInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	budget := m.auditBudgetLocked(auditID)
	if budget.Available() < tokens {
		return nil, fmt.Errorf("%w: the audit budget has %d token(s) left, %d requested", agent.ErrBudgetExhausted, budget.Available(), tokens)
	}
	budget.ReservedTokens += tokens
	budget.Version++
	budget.UpdatedAt = agentNow()
	copied := *budget
	return &copied, nil
}

func (m *Memory) SettleAuditTokens(auditID string, reserved, used int) error {
	if reserved < 0 || used < 0 {
		return fmt.Errorf("%w: usage cannot be negative", agent.ErrInvalidArgument)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	budget := m.auditBudgetLocked(auditID)
	budget.ReservedTokens -= reserved
	if budget.ReservedTokens < 0 {
		budget.ReservedTokens = 0
	}
	budget.UsedTokens += used
	budget.Version++
	budget.UpdatedAt = agentNow()
	return nil
}

func (m *Memory) GrantAuditTokens(grant agent.BudgetGrant, expectedVersion int64) (*agent.AuditBudget, error) {
	if err := agent.ValidateBudgetGrant(grant); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	budget := m.auditBudgetLocked(grant.AuditID)
	if expectedVersion != 0 && budget.Version != expectedVersion {
		return nil, fmt.Errorf("%w: the budget is at version %d", agent.ErrConflict, budget.Version)
	}
	if grant.Decision == agent.GrantApproved {
		budget.LimitTokens += grant.Tokens
	}
	budget.Version++
	budget.UpdatedAt = agentNow()
	grant.Version = budget.Version
	if grant.DecidedAt == "" {
		grant.DecidedAt = agentNow()
	}
	m.budgetGrants[grant.AuditID] = append(m.budgetGrants[grant.AuditID], grant)
	copied := *budget
	return &copied, nil
}

func (m *Memory) ListBudgetGrants(auditID string) ([]agent.BudgetGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]agent.BudgetGrant(nil), m.budgetGrants[auditID]...), nil
}
