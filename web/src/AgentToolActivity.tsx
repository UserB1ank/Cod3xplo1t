import { Wrench } from "lucide-react";
import type { SupervisorCall } from "./types.ts";

export function AgentToolActivity({
  calls,
  current = false,
  compact = false,
}: {
  calls: SupervisorCall[];
  current?: boolean;
  compact?: boolean;
}) {
  return (
    <details
      className={`agent-tool-activity ${compact ? "compact" : ""}`.trim()}
    >
      <summary>
        <Wrench size={compact ? 12 : 14} />
        <strong>{current ? "本轮工具活动" : "历史工具活动"}</strong>
        <span>{calls.length} 次调用</span>
      </summary>
      <div className="agent-tool-activity-calls">
        {calls.map((call) => (
          <code key={call.call_id}>{call.name}</code>
        ))}
      </div>
    </details>
  );
}
