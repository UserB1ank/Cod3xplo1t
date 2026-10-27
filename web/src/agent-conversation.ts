import type {
  SupervisorCall,
  SupervisorMessage,
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
