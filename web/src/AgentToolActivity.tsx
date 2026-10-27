import { Wrench } from "lucide-react";
import type { ReactNode } from "react";
import type { SupervisorCall } from "./types.ts";
import { toolDisplayName } from "./agent-tool-label.ts";

export function AgentToolActivity({
  calls,
  current = false,
  compact = false,
  resultCount,
  children,
}: {
  calls: SupervisorCall[];
  current?: boolean;
  compact?: boolean;
  resultCount?: number;
  children?: ReactNode;
}) {
  return (
    <details
      className={`agent-tool-activity ${compact ? "compact" : ""}`.trim()}
    >
      <summary>
        <Wrench size={compact ? 12 : 14} />
        <strong>{current ? "本轮工具活动" : "历史工具活动"}</strong>
        <span>{calls.length} 次调用</span>
        {!!resultCount && <span>{resultCount} 条结果</span>}
      </summary>
      <div className="agent-tool-activity-calls">
        {calls.map((call) => (
          <div key={call.call_id}>
            <code>{toolDisplayName(call.name)}</code>
            <small>{call.name}</small>
          </div>
        ))}
      </div>
      {children && (
        <div className="agent-tool-activity-results">{children}</div>
      )}
    </details>
  );
}
