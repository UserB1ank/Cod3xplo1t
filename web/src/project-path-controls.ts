import type { ApiClient } from "./api.ts";

export interface PathStopResult {
  api_version: string;
  project_id: string;
  state: "STOPPED" | "STOPPING" | "PARTIAL";
  cancelled_paths: number;
  paused_tasks: number;
  remaining_paths: number;
  pending_agent_runs: number;
  pending_verification_runs: number;
  pending_workflows: number;
  errors: { kind: string; id: string; message: string }[];
}

export function stopProjectPaths(api: ApiClient, projectID: string) {
  return api.post<PathStopResult>(`/v1/projects/${encodeURIComponent(projectID)}/stop-paths`, {});
}
export function projectPathStopStatus(api: ApiClient, projectID: string, signal?: AbortSignal) {
  return api.get<PathStopResult>(`/v1/projects/${encodeURIComponent(projectID)}/stop-paths`, signal);
}
export function pathStopMessage(result: PathStopResult) {
  if (result.state === "STOPPED") return "当前路径均已结束，任务调度已关闭。已有结果已保留。";
  const pending = [
    result.remaining_paths && `${result.remaining_paths} 条路径`,
    result.pending_agent_runs && `${result.pending_agent_runs} 个 Agent 运行`,
    result.pending_verification_runs && `${result.pending_verification_runs} 个验证运行`,
    result.pending_workflows && `${result.pending_workflows} 个工作流`,
  ].filter(Boolean).join("、");
  return `${result.state === "PARTIAL" ? "部分停止操作失败，可重试。" : "停止请求已处理。"}${pending ? `尚有 ${pending} 未结束。` : ""}删除项目时仍会核对活动执行。`;
}
