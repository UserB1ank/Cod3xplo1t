import type { ProjectInput } from "./types.ts";

// The server uses the same five-minute window; repeating it here keeps an
// already-open page from showing "importing" forever after an interrupted
// dialog. The server remains authoritative for mutations.
export const projectInputStaleMs = 5 * 60 * 1000;

export function effectiveProjectInput(
  input: ProjectInput | undefined,
  now = Date.now(),
): ProjectInput | undefined {
  if (!input) return undefined;
  if (input.state !== "importing") return input;
  const updated = Date.parse(input.updated_at);
  if (!Number.isFinite(updated) || now - updated <= projectInputStaleMs) return input;
  return {
    ...input,
    state: "failed",
    failure_code: "import_interrupted",
    failure_message: "源码导入已中断，未保存任何输入；可重试或删除项目。",
  };
}

export function projectInputState(input?: ProjectInput) {
  return effectiveProjectInput(input)?.state ?? "legacy";
}

export function projectInputLabel(input?: ProjectInput) {
  switch (projectInputState(input)) {
    case "ready":
      return "源码已就绪";
    case "importing":
      return "正在保存源码";
    case "failed":
      return "源码导入失败";
    default:
      return "旧多来源项目";
  }
}

export function canStartAnalysis(input?: ProjectInput) {
  return projectInputState(input) === "ready";
}

export function projectInputSourceLabel(input?: ProjectInput) {
  if (!input || input.state === "legacy") return "旧项目保留原代码源与快照";
  if (input.state === "failed") return input.failure_message || "导入失败，可重试或删除项目";
  if (input.state === "importing") return input.source_name || "正在保存审计输入";
  return `${input.source_name || "源码"} · ${input.files} 个文件`;
}

export function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}
