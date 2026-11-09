package supervisor

import (
	"context"
	"fmt"
	"math"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

type auditBudgetStore interface {
	GetAuditBudget(string) (*agent.AuditBudget, error)
	ReserveAuditTokens(string, int) (*agent.AuditBudget, error)
	SettleAuditTokens(string, int, int) error
	GrantAuditTokens(agent.BudgetGrant, int64) (*agent.AuditBudget, error)
	ListBudgetGrants(string) ([]agent.BudgetGrant, error)
}

func (s *Service) budgetStore() (auditBudgetStore, error) {
	store, ok := s.Store.(auditBudgetStore)
	if !ok {
		return nil, fmt.Errorf("%w: token budget persistence is unavailable", ErrUnavailable)
	}
	return store, nil
}

func (s *Service) budgetScope(ctx context.Context, projectID, snapshotID string) (string, error) {
	if store, ok := s.Store.(path.Store); ok {
		audits, _, err := store.ListAudits(path.AuditQuery{SnapshotID: snapshotID, Limit: 1})
		if err != nil {
			return "", err
		}
		if len(audits) > 0 && audits[0].ID != "" {
			return audits[0].ID, nil
		}
	}
	return fmt.Sprintf("supervisor-budget:%s:%s", projectID, snapshotID), nil
}

func (s *Service) Budget(ctx context.Context, projectID, sessionID string) (*agent.AuditBudget, []agent.BudgetGrant, error) {
	store, err := s.budgetStore()
	if err != nil {
		return nil, nil, err
	}
	session, err := s.Store.GetSupervisorSession(ctx, projectID, sessionID)
	if err != nil {
		return nil, nil, err
	}
	auditID := session.AuditID
	if auditID == "" {
		auditID, err = s.budgetScope(ctx, projectID, session.SnapshotID)
		if err != nil {
			return nil, nil, err
		}
	}
	budget, err := store.GetAuditBudget(auditID)
	if err != nil {
		return nil, nil, err
	}
	grants, err := store.ListBudgetGrants(auditID)
	if err != nil {
		return nil, nil, err
	}
	return budget, grants, nil
}

func (s *Service) GrantBudget(ctx context.Context, projectID, sessionID string, grant agent.BudgetGrant, expectedVersion int64) (*agent.AuditBudget, agent.BudgetGrant, error) {
	store, err := s.budgetStore()
	if err != nil {
		return nil, agent.BudgetGrant{}, err
	}
	session, err := s.Store.GetSupervisorSession(ctx, projectID, sessionID)
	if err != nil {
		return nil, agent.BudgetGrant{}, err
	}
	auditID := session.AuditID
	if auditID == "" {
		auditID, err = s.budgetScope(ctx, projectID, session.SnapshotID)
		if err != nil {
			return nil, agent.BudgetGrant{}, err
		}
	}
	grant.AuditID = auditID
	budget, err := store.GrantAuditTokens(grant, expectedVersion)
	if err != nil {
		return nil, agent.BudgetGrant{}, err
	}
	return budget, grant, nil
}

type softBudgetNotice struct {
	Percent int
	AtRound int
	Text    string
}

func softBudgetNotices(maxRounds int) []softBudgetNotice {
	if maxRounds <= 1 {
		return nil
	}
	percents := []int{80, 90, 95}
	notices := make([]softBudgetNotice, 0, len(percents))
	seen := map[int]bool{}
	for _, percent := range percents {
		at := int(math.Ceil(float64(maxRounds) * float64(percent) / 100))
		if at <= 0 || at >= maxRounds || seen[at] {
			continue
		}
		seen[at] = true
		notices = append(notices, softBudgetNotice{
			Percent: percent,
			AtRound: at,
			Text:    budgetNoticeText(percent, at, maxRounds),
		})
	}
	return notices
}

func budgetNoticeText(percent, rounds, limit int) string {
	switch percent {
	case 80:
		return fmt.Sprintf("预算提示：普通模型轮次已使用 %d/%d。优先固定已有证据、停止低价值扩展，并准备可提交的当前结论。", rounds, limit)
	case 90:
		return fmt.Sprintf("预算提示：普通模型轮次已使用 %d/%d。现在整理当前结果、未完成项和下一步；不要开始新的高成本调查。", rounds, limit)
	default:
		return fmt.Sprintf("预算提示：普通模型轮次已使用 %d/%d。停止新的探索性工具调用，准备提交当前结论或明确剩余阻断。", rounds, limit)
	}
}

func appendSoftBudgetNotice(messages []llm.Message, notice softBudgetNotice) []llm.Message {
	return append(messages, llm.Message{Role: "system", Content: notice.Text})
}
