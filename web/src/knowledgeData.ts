import type { ApiClient } from "./api.ts";

export interface RevisionSummary {
  revision: string;
  revision_no: number;
  batch_id: string;
  producer: {
    plugin_id: string;
    plugin_version: string;
    invocation_id: string;
    task_id?: string;
  };
  created_at: string;
  view: {
    view_id: string;
    revision: string;
    scope: { project_id: string; snapshot_id: string };
  };
}
interface RevisionDirectory {
  head_revision: string;
  revisions: RevisionSummary[];
  next_cursor: string;
}
export interface PublicationRequest {
  api_version: "codexploit/v1";
  snapshot_id: string;
  invocation_id: string;
  batch_id: string;
  base_revision: string;
}

export async function preparePublication(
  api: ApiClient,
  project: string,
  snapshot: string,
  invocation: string,
  batch: string,
): Promise<PublicationRequest> {
  const directory = await api.get<RevisionDirectory>(
    `/v1/projects/${encodeURIComponent(project)}/knowledge/revisions?snapshot_id=${encodeURIComponent(snapshot)}&limit=1&cursor=`,
  );
  if (!/^rev-[0-9]+$/.test(directory.head_revision || ""))
    throw new Error("知识目录未返回有效 head，已拒绝发布。");
  return {
    api_version: "codexploit/v1",
    snapshot_id: snapshot,
    invocation_id: invocation,
    batch_id: batch,
    base_revision: directory.head_revision,
  };
}

export async function readRevisionDirectory(
  api: ApiClient,
  project: string,
  snapshot: string,
  signal?: AbortSignal,
): Promise<RevisionDirectory> {
  const revisions: RevisionSummary[] = [];
  const seen = new Set<string>();
  let cursor = "";
  let head = "";
  do {
    if (seen.has(cursor))
      throw new Error("知识版本目录重复分页，无法确认完整结果。");
    seen.add(cursor);
    const page = await api.get<RevisionDirectory>(
      `/v1/projects/${encodeURIComponent(project)}/knowledge/revisions?snapshot_id=${encodeURIComponent(snapshot)}&limit=200&cursor=${encodeURIComponent(cursor)}`,
      signal,
    );
    revisions.push(...page.revisions);
    head = page.head_revision;
    cursor = page.next_cursor;
    if (revisions.length > 10000)
      throw new Error("知识版本目录超出 10000 项读取预算。");
  } while (cursor);
  return { head_revision: head, revisions, next_cursor: "" };
}
