import type { ApiClient } from "./api.ts";
import type { ArtifactRef } from "./Artifacts.tsx";

export interface ReportSettings {
  format: "md" | "json" | "sarif";
  task_id?: string;
  view_id: string;
  knowledge_revision: string;
  include_candidates: boolean;
  captured_at: string;
  counts: Record<string, number>;
}
export interface ReportRecord {
  invocation_id: string;
  status: string;
  version: number;
  error_code?: string;
  created_at: string;
  config_digest: string;
  request: {
    plugin_id: string;
    plugin_version: string;
    package_digest: string;
    scope: ArtifactRef["scope"];
    inputs: ArtifactRef[];
    config: ReportSettings;
  };
  outputs: ArtifactRef[];
  limitations: string[];
}
export const reportActive = (report?: ReportRecord) =>
  !!report && ["CREATED", "RUNNING"].includes(report.status);

// Verify the complete bounded stream before allowing a preview or local save.
export async function readVerifiedReport(
  api: ApiClient,
  ref: ArtifactRef,
  signal?: AbortSignal,
): Promise<Uint8Array<ArrayBuffer>> {
  const maxBytes = 64 * 1048576;
  if (
    ref.kind !== "report.document" ||
    !Number.isSafeInteger(ref.bytes) ||
    ref.bytes < 1 ||
    ref.bytes > maxBytes
  )
    throw new Error("报告超出下载预算或产物类型无效。");
  const url = `/v1/projects/${encodeURIComponent(ref.scope.project_id)}/snapshots/${encodeURIComponent(ref.scope.snapshot_id)}/artifacts/${encodeURIComponent(ref.id)}/content?max_bytes=${maxBytes}`;
  const response = await api.response(url, { signal });
  const reader = response.body?.getReader();
  if (!reader) throw new Error("浏览器无法读取报告内容。");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > ref.bytes || size > maxBytes)
        throw new Error("报告长度超出声明，已拒绝保存。");
      chunks.push(chunk.value);
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  if (size !== ref.bytes) throw new Error("报告下载未完成，内容长度不匹配。");
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const digest = [
    ...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
  ]
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("");
  if (digest !== ref.sha256) throw new Error("报告摘要不匹配，已拒绝保存。");
  return bytes;
}
