import type {
  SupervisorCall,
  SupervisorMessage,
  SupervisorRun,
  SupervisorSession,
} from "./types.ts";

export type AgentConversationEntry =
  | {
      kind: "message";
      message: SupervisorMessage;
    }
  | {
      kind: "tool-activity";
      messageID: string;
      runID?: string;
      calls: SupervisorCall[];
      results: SupervisorMessage[];
    }
  | {
      kind: "tool-result";
      message: SupervisorMessage;
    }
  | {
      kind: "empty-message";
      message: SupervisorMessage;
    };

export interface TerminalRunFallback {
  run: SupervisorRun;
  message: string;
}

export function continuableRun(
  session: Pick<SupervisorSession, "runs">,
): SupervisorRun | undefined {
  if (session.runs.some((run) => run.status === "RUNNING" || run.status === "FINALIZING"))
    return undefined;
  const run = session.runs[session.runs.length - 1];
  if (
    !run ||
    (run.status !== "PAUSED" && run.status !== "PARTIAL") ||
    !run.user_message_id
  )
    return undefined;
  return run;
}

export function terminalRunFallback(
  session: Pick<SupervisorSession, "messages" | "runs">,
): TerminalRunFallback | undefined {
  const run = session.runs[session.runs.length - 1];
  if (!run || !["PAUSED", "PARTIAL", "FAILED", "CANCELLED"].includes(run.status))
    return undefined;
  const hasVisibleText = session.messages.some(
    (message) =>
      message.run_id === run.run_id &&
      message.role === "assistant" &&
      !!message.content.trim(),
  );
  if (hasVisibleText) return undefined;
  const reason =
    run.stop_reason ||
    run.error_code ||
    run.error ||
    "运行未记录停止原因";
  const reasonLabel =
    {
      round_limit: "模型轮次上限",
      tool_limit: "工具调用上限",
      time_limit: "运行时间上限",
      stuck: "重复无进展工具调用",
      recovery: "执行宿主已中断",
      global_budget: "审计级 token 预算耗尽",
      user_cancelled: "用户取消",
      model_error: "模型调用失败",
      internal_error: "内部错误",
    }[reason] || reason;
  const counts = `${run.model_turns ?? "未记录"} 轮，${run.tool_calls ?? "未记录"} 次工具调用`;
  switch (run.status) {
    case "PAUSED":
      return {
        run,
        message: `本次运行已暂停（${reasonLabel}）。已记录 ${counts}；审计任务尚未完成。`,
      };
    case "PARTIAL":
      return {
        run,
        message: `本次运行仅部分完成（${reasonLabel}）。已记录 ${counts}；未完成部分仍需继续处理。`,
      };
    case "CANCELLED":
      return {
        run,
        message: `本次运行已取消（${reasonLabel}）。已记录 ${counts}；取消不代表审计任务完成。`,
      };
    default:
      return {
        run,
        message: `本次运行失败（${reasonLabel}）。已记录 ${counts}；失败原因不能作为安全结论。`,
      };
  }
}

export function projectAgentConversation(
  session: Pick<SupervisorSession, "messages">,
): AgentConversationEntry[] {
  const conversation: AgentConversationEntry[] = [];
  const activeToolActivity = new Map<
    string,
    Extract<AgentConversationEntry, { kind: "tool-activity" }>
  >();

  for (const message of session.messages) {
    if (message.role === "tool") {
      const active = message.run_id
        ? activeToolActivity.get(message.run_id)
        : undefined;
      if (active) {
        active.results.push(message);
        continue;
      }
      conversation.push({ kind: "tool-result", message });
      continue;
    }
    if (message.role === "assistant" && message.calls?.length) {
      const hasContent = !!message.content.trim();
      if (hasContent) {
        if (message.run_id) {
          activeToolActivity.delete(message.run_id);
        }
        conversation.push({ kind: "message", message });
      }
      const active = message.run_id
        ? !hasContent
          ? activeToolActivity.get(message.run_id)
          : undefined
        : undefined;
      if (active) {
        active.calls.push(...message.calls);
        continue;
      }
      const activity: AgentConversationEntry = {
        kind: "tool-activity",
        messageID: message.message_id,
        runID: message.run_id,
        calls: [...message.calls],
        results: [],
      };
      conversation.push(activity);
      if (message.run_id) {
        activeToolActivity.set(message.run_id, activity);
      }
      continue;
    }
    if (message.role === "assistant" && !message.content.trim()) {
      if (message.run_id) {
        activeToolActivity.delete(message.run_id);
      }
      conversation.push({ kind: "empty-message", message });
      continue;
    }
    if (message.run_id) {
      activeToolActivity.delete(message.run_id);
    }
    conversation.push({ kind: "message", message });
  }
  return conversation;
}
