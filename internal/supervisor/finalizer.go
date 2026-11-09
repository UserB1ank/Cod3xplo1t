package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

const finalizerPrompt = `You are finalizing one bounded project-supervisor run.
Return only a concise user-facing status in Simplified Chinese unless the supplied
facts explicitly identify another user language.
Use only the JSON facts supplied by the host. Do not add facts, evidence, IDs,
vulnerability verdicts, tool calls or follow-up work that is not present.
State the stop reason, rounds used, tool calls used and whether the run can
continue. Do not state saved result counts unless they are present in the facts.
The run is not an audit completion merely because it stopped.`

func (s *Service) finalizeBoundary(
	ctx context.Context,
	cfg llm.Config,
	run storage.SupervisorRun,
	stopReason string,
	rounds, tools, input, output int,
) (text, source string, finalizerInput, finalizerOutput int) {
	facts := map[string]any{
		"run_id":        run.ID,
		"status":        RunPaused,
		"stop_reason":   stopReason,
		"rounds_used":   rounds,
		"tools_used":    tools,
		"input_tokens":  input,
		"output_tokens": output,
		"can_continue":  true,
		"next_step":     "call the continue endpoint for this run",
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		return pauseTemplate(stopReason, rounds, tools), "template", 0, 0
	}
	timeout := s.FinalizerTimeout
	if timeout <= 0 {
		timeout = finalizerTimeout
	}
	if cfg.MaxOutputTokens <= 0 || cfg.MaxOutputTokens > 1024 {
		cfg.MaxOutputTokens = 1024
	}
	finalizerCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	completion, err := llm.Complete(finalizerCtx, cfg, []llm.Message{
		{Role: "system", Content: finalizerPrompt},
		{Role: "user", Content: string(raw)},
	}, nil, "")
	if err != nil {
		return pauseTemplate(stopReason, rounds, tools), "template", 0, 0
	}
	finalizerInput, finalizerOutput = completion.InputTokens, completion.OutputTokens
	text = strings.TrimSpace(completion.Message.Content)
	if len(completion.Message.Calls) > 0 || text == "" || len(text) > 4000 {
		return pauseTemplate(stopReason, rounds, tools), "template", finalizerInput, finalizerOutput
	}
	return text, "model", finalizerInput, finalizerOutput
}

func (s *Service) pauseAtBoundary(
	ctx context.Context,
	cfg llm.Config,
	session storage.SupervisorSession,
	run storage.SupervisorRun,
	stopReason string,
	rounds, tools, input, output int,
	detail string,
) {
	if latest, err := s.Store.GetSupervisorSession(ctx, session.ProjectID, session.ID); err == nil {
		// Boundary facts must come from the committed transcript, not the
		// snapshot captured before the model and tools advanced it.
		session = latest
	}
	_ = s.updateRun(ctx, session.ProjectID, session.ID, run, func(value *storage.SupervisorRun) {
		value.Status = RunFinalizing
		value.StopReason = stopReason
		value.Checkpoint = buildCheckpoint(session, run, stopReason, rounds, tools, input, output, detail)
		value.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		value.Version++
	})
	text, source, finalizerInput, finalizerOutput := s.finalizeBoundary(
		ctx, cfg, run, stopReason, rounds, tools, input, output,
	)
	s.finishRun(finishOptions{
		projectID: session.ProjectID, sessionID: session.ID, runID: run.ID,
		owner: run.ExecutionOwner, epoch: run.LeaseEpoch,
		status: RunPaused, code: stopReason, stopReason: stopReason,
		message: detail, terminalText: text, messageKind: "paused", finalizerSource: source,
		input: input + finalizerInput, output: output + finalizerOutput,
		rounds: rounds, tools: tools,
	})
}

func pauseTemplate(stopReason string, rounds, tools int) string {
	if stopReason == StopToolLimit {
		return fmt.Sprintf(
			"本次运行已达到单片段工具调用上限（%d 次），已保存当前运行记录并暂停。模型轮次 %d，运行状态为 PAUSED；尚未完成审计任务，需要发送新的继续请求。",
			tools, rounds,
		)
	}
	if stopReason == StopTimeLimit {
		return fmt.Sprintf(
			"本次运行已达到单片段时间上限，已保存当前运行记录并暂停。模型轮次 %d，工具调用 %d。运行状态为 PAUSED；尚未完成审计任务，需要发送新的继续请求。",
			rounds, tools,
		)
	}
	if stopReason == StopStuck {
		return fmt.Sprintf(
			"本次运行检测到重复且无进展的工具错误，已暂停。模型轮次 %d，工具调用 %d。运行状态为 PAUSED；请修正工具参数或指定新的调查目标后继续。",
			rounds, tools,
		)
	}
	return fmt.Sprintf(
		"本次运行已达到单片段轮次上限（%d/%d），已保存当前运行记录并暂停。模型轮次 %d，工具调用 %d。运行状态为 PAUSED，尚未完成审计任务，需要发送新的继续请求。",
		rounds, rounds, rounds, tools,
	)
}

func failureTemplate(code, message string) string {
	reason := strings.TrimSpace(message)
	if reason == "" {
		reason = code
	}
	if len(reason) > 600 {
		reason = reason[:600]
	}
	return fmt.Sprintf("本次运行未能完成（%s）：%s。已保留运行记录和工具结果，审计任务尚未完成。", code, reason)
}

func cancelledTemplate() string {
	return "本次运行已由操作者取消。已保留取消前的运行记录和工具结果，审计任务尚未完成。"
}

type finishOptions struct {
	projectID       string
	sessionID       string
	runID           string
	owner           string
	epoch           int64
	allowExpired    bool
	status          string
	code            string
	stopReason      string
	message         string
	terminalText    string
	messageKind     string
	finalizerSource string
	input           int
	output          int
	rounds          int
	tools           int
	checkpoint      *storage.SupervisorCheckpoint
}
