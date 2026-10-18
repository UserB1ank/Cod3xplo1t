import type { Audit, Finding, Snapshot } from "./types.ts";

export type Grade = "high" | "medium" | "low";
export const gradeNames: Record<Grade, string> = {
  high: "高危",
  medium: "中危",
  low: "低危",
};
export interface Task extends Audit {
  workflow_run_id?: string;
  workflow_plan_id?: string;
  workflow_status?: string;
  source_id?: string;
  source_version?: number;
  name?: string;
  objective?: string;
  scope?: string[];
  paused: boolean;
  pinned?: boolean;
  archived?: boolean;
  category?: string;
  etag?: string;
  can_archive?: boolean;
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
export interface FindingSource {
  task_id: string;
  finding_id: string;
  observation_id?: string;
  producer?: {
    plugin_id: string;
    plugin_version: string;
    invocation_id: string;
    task_id?: string;
    config_digest: string;
  };
  rule_id?: string;
  rule_version?: string;
  rule_family?: string;
  title?: string;
  severity_hint?: Grade;
  status?: Finding["status"];
  file?: string;
  line?: number;
  end_line?: number;
  evidence_refs?: string[];
  limitations?: string[];
  created_at?: string;
}
export interface SeverityAudit {
  audit_id: string;
  finding_id: string;
  version: number;
  previous_severity?: Grade;
  severity: Grade;
  reason: string;
  actor: string;
  created_at: string;
}
export interface ProjectFinding extends Finding {
  fingerprint: string;
  fingerprint_version: string;
  sources: FindingSource[];
  severity_audit: SeverityAudit[];
}
export interface FindingPage {
  findings: ProjectFinding[];
  total: number;
  counts: Record<string, number>;
  confirmed_counts?: Record<string, number>;
  candidate_counts?: Record<string, number>;
  truncated: boolean;
}
export interface Route {
  project?: string;
  task?: string;
  snapshot?: string;
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
    if (page === "artifacts")
      return {
        project,
        view: "artifacts",
        ...(task ? { snapshot: task } : {}),
      };
    if (page === "tasks" && task)
      return { project, task, view: view || "overview" };
    return {
      project,
      view: [
        "overview",
        "sources",
        "knowledge",
        "findings",
        "reports",
        "artifacts",
        "plugins",
        "workflows",
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
    : `#/projects/${project}/${route.view}${route.view === "artifacts" && route.snapshot ? `/${encodeURIComponent(route.snapshot)}` : ""}`;
}
export function taskState(task: Task) {
  if (task.archived) return "ARCHIVED";
  if (task.workflow_status)
    return ["CREATED", "RUNNING"].includes(task.workflow_status)
      ? "RUNNING"
      : task.workflow_status === "SUCCEEDED"
        ? "CONCLUDED"
        : task.workflow_status === "PARTIAL"
          ? "BLOCKED"
          : "FAILED";
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
      finding.severity &&
      finding.severity in counts
    )
      counts[finding.severity as Grade]++;
  }
  return counts;
}
