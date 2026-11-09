package supervisor

import (
	"context"
	"fmt"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func (s *Service) recoverExpiredRuns(ctx context.Context, session storage.SupervisorSession) bool {
	now := time.Now().UTC()
	recovered := false
	for i := range session.Runs {
		run := session.Runs[i]
		if !active(run.Status) || run.LeaseUntil == "" {
			continue
		}
		lease, err := time.Parse(time.RFC3339Nano, run.LeaseUntil)
		if err != nil || lease.After(now) {
			continue
		}
		checkpoint := buildCheckpoint(
			session, run, StopRecovery, run.ModelTurns, run.ToolCalls,
			run.InputTokens, run.OutputTokens,
			"the execution host stopped before the run reached a terminal state",
		)
		nextEpoch := run.LeaseEpoch + 1
		if nextEpoch < 1 {
			nextEpoch = 1
		}
		s.finishRun(finishOptions{
			projectID: session.ProjectID, sessionID: session.ID, runID: run.ID,
			owner: s.executionOwner, epoch: nextEpoch, allowExpired: true,
			status: RunPaused, code: StopRecovery, stopReason: StopRecovery,
			message:      "execution lease expired before the run finished",
			terminalText: recoveryTemplate(), messageKind: "paused",
			finalizerSource: "template", input: run.InputTokens, output: run.OutputTokens,
			rounds: run.ModelTurns, tools: run.ToolCalls, checkpoint: checkpoint,
		})
		recovered = true
	}
	return recovered
}

func recoveryTemplate() string {
	return fmt.Sprintf(
		"本次运行的执行宿主已中断（%s）。已把运行恢复为 PAUSED 并保留已有消息、工具结果与预算计数；审计任务尚未完成，需要发送新的继续请求。",
		StopRecovery,
	)
}
