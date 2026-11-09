package supervisor

import (
	"fmt"
	"math"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
)

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
