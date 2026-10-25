import type { Route } from "./workbench.ts";

export const primaryNavigation = [
  { id: "overview", label: "项目总览" },
  { id: "knowledge", label: "代码图谱" },
  { id: "paths", label: "审查路径" },
  { id: "assistant", label: "Agent 工作台" },
  { id: "findings", label: "发现与证据" },
  { id: "reports", label: "审计报告" },
];
export const advancedNavigation = [
  { id: "tasks", label: "任务管理" },
  { id: "sources", label: "源码输入" },
  { id: "artifacts", label: "产物目录" },
  { id: "plugins", label: "插件中心" },
  { id: "workflows", label: "工作流" },
  { id: "settings", label: "项目设置" },
];
export function projectDestination(project: string, route?: Route): Route {
  return { project, view: route?.selecting ? route.view : "overview" };
}
