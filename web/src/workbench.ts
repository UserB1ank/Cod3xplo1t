import type { Audit, Finding, Snapshot } from "./types.ts";

export type Grade = "high" | "medium" | "low";
export const gradeNames: Record<Grade, string> = {
  high: "高危",
  medium: "中危",
  low: "低危",
};
export interface Task extends Audit {
  source_id?: string;
  source_version?: number;
  name?: string;
  objective?: string;
  scope?: string[];
  paused: boolean;
  version: number;
  budget: { max_tool_calls: number; max_depth: number; max_branches: number };
  counts_by_path_status?: Record<string, number>;
  limitations: string[];
}
export interface Identity {
  name: string;
  role: string;
  can_write: boolean;
  features: Record<string, boolean>;
}
export interface ProjectFinding extends Finding {
  sources: { task_id: string; finding_id: string }[];
}
export interface FindingPage {
  findings: ProjectFinding[];
  total: number;
  counts: Record<string, number>;
  truncated: boolean;
}
export interface Route {
  project?: string;
  task?: string;
  view: string;
}
export function readRoute(hash: string): Route {
  try {
    const [root, project, page, task, view] = hash
      .replace(/^#\/?/, "")
      .split("/")
      .map(decodeURIComponent);
    if (root === "settings") return { view: "settings" };
    if (root !== "projects" || !project) return { view: "projects" };
    if (page === "tasks" && task)
      return { project, task, view: view || "overview" };
    return {
      project,
      view: [
        "overview",
        "sources",
        "knowledge",
        "findings",
        "settings",
      ].includes(page)
        ? page
        : "tasks",
    };
  } catch {
    return { view: "projects" };
  }
}
export function routeHash(route: Route): string {
  if (!route.project && route.view === "settings") return "#/settings";
  if (!route.project) return "#/projects";
  const project = encodeURIComponent(route.project);
  return route.task
    ? `#/projects/${project}/tasks/${encodeURIComponent(route.task)}/${route.view}`
    : `#/projects/${project}/${route.view}`;
}
export function taskState(task: Task) {
  const counts = task.counts_by_status || {};
  if (task.status === "FAILED") return "FAILED";
  if (["ANALYZING", "LOCAL_EXPLORING", "VERIFYING"].some((s) => counts[s] > 0))
    return "RUNNING";
  if (task.paused) return "PAUSED";
  if (!task.path_count) return "EMPTY";
  if (counts.QUEUED > 0) return "QUEUED";
  if (["BLOCKED", "FAILED", "INTERRUPTED"].some((s) => counts[s] > 0))
    return "BLOCKED";
  return "CONCLUDED";
}
export function latestSnapshot(snapshots: Snapshot[]) {
  return [...snapshots].sort(
    (a, b) =>
      b.created_at.localeCompare(a.created_at) ||
      b.snapshot_id.localeCompare(a.snapshot_id),
  )[0];
}
export function taskGradeCounts(findings: ProjectFinding[], taskID: string) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    if (
      finding.status === "confirmed" &&
      finding.sources.some((s) => s.task_id === taskID) &&
      finding.severity in counts
    )
      counts[finding.severity as Grade]++;
  }
  return counts;
}
