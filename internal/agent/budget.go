package agent

import "fmt"

// DefaultAuditTokenBudget is the audit-level ceiling for deployments that did not
// configure one. A run's hard limit never exceeds what the audit ledger can give.
const DefaultAuditTokenBudget = 60000

// AuditBudget is the audit-level token ledger shared by every run of the task.
// Reserved is money promised to an in-flight request; Used is real usage already
// reported. A new request may start only while Used+Reserved stays under Limit.
type AuditBudget struct {
	AuditID        string `json:"audit_id"`
	LimitTokens    int    `json:"limit_tokens"`
	ReservedTokens int    `json:"reserved_tokens"`
	UsedTokens     int    `json:"used_tokens"`
	Version        int64  `json:"version"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

// Available is what the audit can still promise without exceeding its ceiling.
func (b AuditBudget) Available() int {
	left := b.LimitTokens - b.UsedTokens - b.ReservedTokens
	if left < 0 {
		return 0
	}
	return left
}

// BudgetGrant is one approved or rejected addition to the audit ceiling. Grants
// are append-only; the decision is what moves the ledger.
type BudgetGrant struct {
	ID          string `json:"grant_id"`
	AuditID     string `json:"audit_id"`
	RunID       string `json:"run_id,omitempty"`
	Tokens      int    `json:"tokens"`
	Reason      string `json:"reason"`
	RequestedBy string `json:"requested_by"`
	Decision    string `json:"decision"`
	DecidedBy   string `json:"decided_by"`
	CreatedAt   string `json:"created_at"`
	DecidedAt   string `json:"decided_at,omitempty"`
	Version     int64  `json:"version"`
}

const (
	GrantApproved = "approved"
	GrantRejected = "rejected"
)

// ValidateBudgetGrant checks a requested addition before it can be stored.
func ValidateBudgetGrant(grant BudgetGrant) error {
	if grant.ID == "" || grant.AuditID == "" {
		return fmt.Errorf("%w: a grant needs an id and an audit", ErrInvalidArgument)
	}
	if grant.Tokens <= 0 || grant.Tokens > 10_000_000 {
		return fmt.Errorf("%w: a grant must add between 1 and 10,000,000 tokens", ErrInvalidArgument)
	}
	if grant.Decision != GrantApproved && grant.Decision != GrantRejected {
		return fmt.Errorf("%w: a decision must be approved or rejected", ErrInvalidArgument)
	}
	return nil
}
