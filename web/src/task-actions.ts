import type { ApiClient } from "./api.ts";
import type { Task } from "./workbench.ts";

export async function organizeTask(
  api: ApiClient,
  projectID: string,
  task: Task,
  patch: { pinned?: boolean; category?: string; archived?: boolean },
) {
  let etag = task.etag;
  if (!etag) throw new Error("任务缺少版本标识，请刷新重试。");
  if (patch.archived && !task.paused) {
    const paused = await api.response(`/tasks/${encodeURIComponent(task.audit_id)}/pause`, {
      method: "POST", body: "{}", headers: { "If-Match": etag },
    });
    etag = paused.headers.get("ETag") || undefined;
    await paused.arrayBuffer();
    if (!etag) throw new Error("任务暂停后缺少版本标识，请刷新重试。");
  }
  return api.response(`/projects/${encodeURIComponent(projectID)}/tasks/${encodeURIComponent(task.audit_id)}`, {
    method: "PATCH", body: JSON.stringify(patch), headers: { "If-Match": etag },
  });
}
