import { ApiClient } from "./api.ts";

export function archiveFormat(name: string) {
  const lower = name.toLowerCase();
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) return "tar.gz";
  if (lower.endsWith(".tar")) return "tar";
  if (lower.endsWith(".zip")) return "zip";
  throw new Error("请选择 ZIP、TAR 或 TAR.GZ/TGZ 源码压缩包。");
}

export function validateArchive(file: File) {
  archiveFormat(file.name);
  if (!file.size || file.size > 8 * 1024 * 1024 * 1024)
    throw new Error("源码压缩包不能为空，且不能超过 8 GiB。");
}

export async function importArchive(
  api: ApiClient, project: string, source: string, name: string,
  file: File, buildKnowledge: boolean, signal?: AbortSignal,
): Promise<{ snapshot: { snapshot_id: string; files: number; skipped_total: number } }> {
  validateArchive(file);
  const query = new URLSearchParams({ name, format: archiveFormat(file.name),
    build_graph: String(buildKnowledge), build_asg: String(buildKnowledge) });
  return (await api.response(`/v1/projects/${encodeURIComponent(project)}/imports/${encodeURIComponent(source)}?${query}`, {
    method: "POST", body: file, signal, headers: { "Content-Type": "application/octet-stream" },
  })).json();
}
