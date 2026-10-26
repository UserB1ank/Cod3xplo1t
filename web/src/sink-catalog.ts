export type SinkPartition = "high_risk" | "unclassified" | "all";

export interface AttackNodeWithDetail {
  node_id: string;
  kind: string;
  label: string;
  subject: string;
  file?: string;
  line?: number;
  confidence?: string;
  generator?: string;
  module_id?: string;
  detail?: Record<string, string>;
  scg_refs?: string[];
  evidence_status?: string;
}

export interface SinkEvidence {
  rule: string;
  version: string;
  digest: string;
  arguments: string;
  hasFlow?: boolean;
  priority?: number;
  note: string;
}

export function sinkCatalogQuery(
  projectID: string,
  viewID: string,
  partition: Exclude<SinkPartition, "all">,
  category: string,
  cursor: string,
  limit = 50,
) {
  const query = new URLSearchParams({
    partition,
    limit: String(limit),
  });
  if (category) query.set("category", category);
  if (cursor) query.set("cursor", cursor);
  return `/v1/projects/${encodeURIComponent(projectID)}/knowledge/views/${encodeURIComponent(viewID)}/sinks?${query}`;
}

export function sinkEvidence(node: AttackNodeWithDetail): SinkEvidence {
  const detail = node.detail || {};
  const priority = Number(detail.priority);
  return {
    rule: detail.catalog_id || "未分类兜底规则",
    version: detail.catalog_version || "未固定",
    digest: detail.catalog_digest || "",
    arguments: detail.dangerous_arguments || "—",
    hasFlow:
      detail.has_flow === "true"
        ? true
        : detail.has_flow === "false"
          ? false
          : undefined,
    priority: Number.isFinite(priority) && priority > 0 ? priority : undefined,
    note: detail.catalog_id
      ? "目录规则命中不等于可利用；可控性、控制有效性和运行时仍待审查。"
      : "兜底规则命中只表示发现敏感调用形状，不表示漏洞成立。",
  };
}
