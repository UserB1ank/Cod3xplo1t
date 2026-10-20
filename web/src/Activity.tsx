import { useEffect, useState } from "react";
import { ApiClient } from "./api";
import { Badge, EmptyState, Failure, Modal, Panel } from "./components";
import { EventFeed } from "./EventFeed";
import { shortId } from "./domain";
import type { ActivityEntry, ProjectActivity } from "./types";

const stages: Record<string, { label: string; status: string }> = {
  analyzing: { label: "分析中", status: "RUNNING" },
  verifying: { label: "验证中", status: "RUNNING" },
  workflow: { label: "工作流执行中", status: "RUNNING" },
  paused: { label: "已暂停", status: "PAUSED" },
};

function elapsed(ms: number) {
  if (!ms || ms < 0) return "—";
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} 分 ${seconds % 60} 秒`;
}

// ProjectActivity answers "what is running in this project right now": the active
// tasks, each run's stage, the queue behind it, and a direct view of the agent log.
// It polls independently so the task list itself stays fast.
export function ProjectActivity({
  api,
  projectID,
  onOpenTask,
}: {
  api: ApiClient;
  projectID: string;
  onOpenTask: (id: string) => void;
}) {
  const [data, setData] = useState<ProjectActivity>();
  const [error, setError] = useState("");
  const [log, setLog] = useState<ActivityEntry>();
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => {
      if (!document.hidden) setTick((n) => n + 1);
    }, 5000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    api
      .get<ProjectActivity>(
        `/projects/${encodeURIComponent(projectID)}/activity`,
        controller.signal,
      )
      .then((page) => {
        if (!controller.signal.aborted) {
          setData(page);
          setError("");
        }
      })
      .catch((failure) => {
        if (!controller.signal.aborted)
          setError(failure instanceof Error ? failure.message : "运行状态读取失败");
      });
    return () => controller.abort();
  }, [api, projectID, tick]);
  const active = data?.active || [];
  const counts = data?.counts || { running: 0, paused: 0, queued: 0, tasks: 0 };
  return (
    <Panel
      className="activity-panel"
      title="运行中"
      eyebrow="项目实时状态"
      action={
        <span className="subtle-label">
          {counts.tasks} 个任务 · 运行 {counts.running} · 暂停 {counts.paused} · 待执行{" "}
          {counts.queued}
        </span>
      }
    >
      {error && <Failure message={error} />}
      {!error && active.length === 0 ? (
        <EmptyState title="当前没有运行中的任务">
          {counts.queued
            ? `还有 ${counts.queued} 条路径等待调度；任务开始运行后，阶段和日志会出现在这里。`
            : "任务开始运行后，阶段和 Agent 日志会出现在这里。"}
        </EmptyState>
      ) : (
        <div className="table-scroll">
          <table className="standard-table activity-table">
            <thead>
              <tr>
                <th>任务</th>
                <th>阶段</th>
                <th>运行时</th>
                <th>已运行</th>
                <th>待执行</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {active.map((entry) => {
                const stage = stages[entry.stage] || {
                  label: entry.stage,
                  status: entry.status || "RUNNING",
                };
                return (
                  <tr key={`${entry.task_id}:${entry.run_id || entry.stage}`}>
                    <td>
                      <button
                        className="text-button"
                        onClick={() => onOpenTask(entry.task_id)}
                      >
                        {entry.task_name || shortId(entry.task_id)}
                      </button>
                      <span className="subtle-label">
                        {" "}
                        {shortId(entry.task_id)}
                      </span>
                    </td>
                    <td>
                      <Badge status={stage.status} label={stage.label} />
                    </td>
                    <td className="mono">{entry.runtime || "—"}</td>
                    <td>{elapsed(entry.elapsed_ms)}</td>
                    <td>{entry.queued}</td>
                    <td>
                      {entry.run_id && (
                        <button
                          className="text-button"
                          onClick={() => setLog(entry)}
                        >
                          查看日志
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <Modal
        open={!!log}
        onClose={() => setLog(undefined)}
        title={`Agent 日志 · ${log?.task_name || shortId(log?.task_id)}`}
        eyebrow={log?.run_id ? `运行 ${shortId(log.run_id)}` : undefined}
        wide
      >
        {log?.run_id && (
          <>
            <p className="panel-copy muted">
              每 3 秒增量读取，保留最近 500 条；展开事件可查看原始载荷。
            </p>
            <EventFeed api={api} endpoint={`/runs/${log.run_id}/events`} />
          </>
        )}
      </Modal>
    </Panel>
  );
}
