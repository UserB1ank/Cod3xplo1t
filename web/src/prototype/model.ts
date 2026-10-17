export const API_VERSION = "codexploit/v1" as const;
export type Page =
  | "dashboard"
  | "projects"
  | "tasks"
  | "sources"
  | "knowledge"
  | "findings"
  | "workflows"
  | "plugins"
  | "executions"
  | "artifacts"
  | "models"
  | "storage"
  | "interfaces";
export type ArtifactKind =
  | "source.snapshot"
  | "code.ast"
  | "code.facts"
  | "security.facts"
  | "scanner.alerts"
  | "discovery.paths"
  | "discovery.findings"
  | "knowledge.view"
  | "report.document";
export interface PluginManifest {
  api_version: typeof API_VERSION;
  id: string;
  version: string;
  name: string;
  description: string;
  kind: "parser" | "analyzer" | "normalizer" | "graph" | "agent" | "reporter";
  languages: string[];
  runtime: {
    kind: "builtin" | "process" | "container" | "remote";
    entrypoint?: string;
  };
  consumes: ArtifactKind[];
  produces: ArtifactKind[];
  permissions: { network: "none" | "restricted"; source_write: false };
  config_schema: Record<string, unknown>;
}
export interface WorkflowNode {
  id: string;
  plugin_id: string;
  plugin_version: string;
  needs: string[];
  config: Record<string, unknown>;
  timeout_seconds: number;
}
export interface WorkflowSpec {
  api_version: typeof API_VERSION;
  id: string;
  version: string;
  name: string;
  description: string;
  inputs: ArtifactKind[];
  nodes: WorkflowNode[];
}
export type SourceKind = "local_folder" | "git_repository";
export interface Source {
  id: string;
  project_id: string;
  name: string;
  kind: SourceKind;
  location: string;
  ref: string;
  snapshot: string;
  files: number;
  revision: number;
}
export interface Project {
  id: string;
  name: string;
  description: string;
  language: string;
  updated: string;
}
export type TaskStatus = "RUNNING" | "PAUSED" | "SUCCEEDED" | "QUEUED";
export interface Task {
  id: string;
  project_id: string;
  source_id: string;
  snapshot_id: string;
  name: string;
  objective: string;
  category: string;
  status: TaskStatus;
  completed: number;
  pinned: boolean;
  archived: boolean;
  created: string;
  workflow: WorkflowSpec;
}
export interface Finding {
  id: string;
  project_id: string;
  task_id: string;
  title: string;
  severity?: "high" | "medium" | "low";
  status: "candidate" | "confirmed" | "inconclusive" | "refuted";
  cwe: string;
  file: string;
  line: number;
  plugin: string;
  source: string;
  sink: string;
  evidence: string;
  snapshot_id: string;
}
export interface Execution {
  id: string;
  task_id: string;
  project_id: string;
  node_id: string;
  plugin: string;
  plugin_version: string;
  status: "SUCCEEDED";
  inputs: ArtifactKind[];
  outputs: ArtifactKind[];
  timestamp: string;
}
export interface StorageProfile {
  api_version: typeof API_VERSION;
  metadata: {
    driver: "postgresql" | "sqlite" | "custom";
    host: string;
    port: number;
    database: string;
    credential_ref: string;
  };
  artifacts: { driver: "volume" | "s3"; endpoint: string; bucket: string };
  graph: { driver: "relational" };
  deployment: { database_service: string; artifact_service: string };
}
export const kinds: ArtifactKind[] = [
  "source.snapshot",
  "code.ast",
  "code.facts",
  "security.facts",
  "scanner.alerts",
  "discovery.paths",
  "discovery.findings",
  "knowledge.view",
  "report.document",
];
export const statusNames: Record<TaskStatus, string> = {
  RUNNING: "运行中",
  PAUSED: "已暂停",
  SUCCEEDED: "已完成",
  QUEUED: "待运行",
};
export const gradeNames = { high: "高危", medium: "中危", low: "低危" };
export const kindNames: Record<PluginManifest["kind"], string> = {
  parser: "语法解析",
  analyzer: "静态分析",
  normalizer: "结果归一化",
  graph: "图谱构建",
  agent: "Agent 分析",
  reporter: "报告生成",
};
const manifest = (
  id: string,
  name: string,
  kind: PluginManifest["kind"],
  consumes: ArtifactKind[],
  produces: ArtifactKind[],
  description: string,
): PluginManifest => ({
  api_version: API_VERSION,
  id,
  version: "1.0.0",
  name,
  kind,
  consumes,
  produces,
  description,
  languages: ["go"],
  runtime: { kind: "builtin" },
  permissions: { network: "none", source_write: false },
  config_schema: {
    type: "object",
    properties: {},
    additionalProperties: false,
  },
});
export const initialPlugins: PluginManifest[] = [
  manifest(
    "core.parser.go",
    "Go 语法与符号索引",
    "parser",
    ["source.snapshot"],
    ["code.ast", "code.facts"],
    "保留原生 AST，提取文件、符号、调用和引用事实。",
  ),
  manifest(
    "core.security.rules",
    "安全语义提取",
    "analyzer",
    ["code.facts"],
    ["security.facts"],
    "标记输入源、敏感操作、权限检查和信任边界。",
  ),
  manifest(
    "example.scanner.rules",
    "规则扫描适配器",
    "analyzer",
    ["source.snapshot"],
    ["scanner.alerts"],
    "演示外部静态扫描工具的标准输入与原始告警输出。",
  ),
  manifest(
    "core.normalize.results",
    "扫描结果归一化",
    "normalizer",
    ["scanner.alerts", "code.facts"],
    ["discovery.paths", "discovery.findings"],
    "保留工具来源和不确定性，关联代码位置与传播路径。",
  ),
  manifest(
    "core.graph.merge",
    "项目知识汇聚",
    "graph",
    ["discovery.paths", "security.facts"],
    ["knowledge.view"],
    "校验并发布当前快照的知识视图，保留任务和插件来源。",
  ),
  manifest(
    "core.agent.review",
    "证据驱动的 Agent",
    "agent",
    ["knowledge.view"],
    ["discovery.findings"],
    "读取共享图谱，输出带证据的候选发现；确认状态由证据裁定。",
  ),
  manifest(
    "core.report.export",
    "发现与证据报告",
    "reporter",
    ["discovery.findings"],
    ["report.document"],
    "按高、中、低分级汇总发现，保留确认状态与代码版本。",
  ),
];
export const initialWorkflow: WorkflowSpec = {
  api_version: API_VERSION,
  id: "workflow-discovery",
  version: "1.0.0",
  name: "标准漏洞挖掘",
  description: "语法解析、规则扫描、知识汇聚和证据分析。",
  inputs: ["source.snapshot"],
  nodes: [
    {
      id: "parse",
      plugin_id: "core.parser.go",
      plugin_version: "1.0.0",
      needs: [],
      config: {},
      timeout_seconds: 120,
    },
    {
      id: "semantics",
      plugin_id: "core.security.rules",
      plugin_version: "1.0.0",
      needs: ["parse"],
      config: {},
      timeout_seconds: 120,
    },
    {
      id: "scan",
      plugin_id: "example.scanner.rules",
      plugin_version: "1.0.0",
      needs: [],
      config: {},
      timeout_seconds: 120,
    },
    {
      id: "normalize",
      plugin_id: "core.normalize.results",
      plugin_version: "1.0.0",
      needs: ["parse", "scan"],
      config: {},
      timeout_seconds: 120,
    },
    {
      id: "publish",
      plugin_id: "core.graph.merge",
      plugin_version: "1.0.0",
      needs: ["normalize", "semantics"],
      config: {},
      timeout_seconds: 120,
    },
    {
      id: "review",
      plugin_id: "core.agent.review",
      plugin_version: "1.0.0",
      needs: ["publish"],
      config: {},
      timeout_seconds: 120,
    },
    {
      id: "report",
      plugin_id: "core.report.export",
      plugin_version: "1.0.0",
      needs: ["review"],
      config: {},
      timeout_seconds: 120,
    },
  ],
};

export const initialProjects: Project[] = [
  {
    id: "proj-spruce",
    name: "云杉支付服务",
    description: "支付接口、账单读取与商户权限边界",
    language: "Go",
    updated: "10-17 13:42",
  },
  {
    id: "proj-bridge",
    name: "星桥身份中心",
    description: "登录会话与组织间资源隔离",
    language: "Go",
    updated: "10-17 11:18",
  },
  {
    id: "proj-edge",
    name: "Edge Gateway",
    description: "网关请求处理与配置读取",
    language: "Go",
    updated: "10-16 17:36",
  },
];
export const initialSources: Source[] = [
  {
    id: "src-spruce",
    project_id: "proj-spruce",
    name: "支付服务仓库",
    kind: "git_repository",
    location: "https://forge.example.invalid/research/payment.git",
    ref: "main",
    snapshot: "snap-spruce-01",
    files: 186,
    revision: 1,
  },
  {
    id: "src-bridge",
    project_id: "proj-bridge",
    name: "身份服务本地目录",
    kind: "local_folder",
    location: "/repos/identity",
    ref: "",
    snapshot: "snap-bridge-01",
    files: 94,
    revision: 1,
  },
  {
    id: "src-edge",
    project_id: "proj-edge",
    name: "网关代码目录",
    kind: "local_folder",
    location: "/repos/gateway",
    ref: "",
    snapshot: "snap-edge-01",
    files: 63,
    revision: 1,
  },
];
export const initialTasks: Task[] = [
  {
    id: "task-pay-api",
    project_id: "proj-spruce",
    source_id: "src-spruce",
    snapshot_id: "snap-spruce-01",
    name: "支付 API 权限边界",
    objective: "检查商户间账单访问权限与输入传播",
    category: "权限边界",
    status: "RUNNING",
    completed: 4,
    pinned: true,
    archived: false,
    created: "10-17 13:42",
    workflow: structuredClone(initialWorkflow),
  },
  {
    id: "task-identity",
    project_id: "proj-bridge",
    source_id: "src-bridge",
    snapshot_id: "snap-bridge-01",
    name: "组织与会话隔离",
    objective: "追踪组织标识到资源读取的权限检查",
    category: "权限边界",
    status: "PAUSED",
    completed: 2,
    pinned: false,
    archived: false,
    created: "10-17 11:18",
    workflow: structuredClone(initialWorkflow),
  },
  {
    id: "task-pay-files",
    project_id: "proj-spruce",
    source_id: "src-spruce",
    snapshot_id: "snap-spruce-01",
    name: "账单文件读取路径",
    objective: "审查请求参数到文件操作的路径",
    category: "输入处理",
    status: "QUEUED",
    completed: 0,
    pinned: false,
    archived: false,
    created: "10-17 10:36",
    workflow: structuredClone(initialWorkflow),
  },
  {
    id: "task-edge",
    project_id: "proj-edge",
    source_id: "src-edge",
    snapshot_id: "snap-edge-01",
    name: "网关配置读取",
    objective: "定位配置读取中的路径边界",
    category: "输入处理",
    status: "SUCCEEDED",
    completed: 7,
    pinned: false,
    archived: false,
    created: "10-16 17:36",
    workflow: structuredClone(initialWorkflow),
  },
];
export const initialFindings: Finding[] = [
  {
    id: "finding-001",
    project_id: "proj-spruce",
    task_id: "task-pay-api",
    title: "商户账单查询缺少归属校验",
    severity: "high",
    status: "candidate",
    cwe: "CWE-639",
    file: "internal/handler/invoice.go",
    line: 42,
    plugin: "core.agent.review",
    source: "GET /invoices/:id",
    sink: "InvoiceStore.FindByID",
    evidence:
      "查询使用请求中的账单标识；当前代码切片未显示商户归属检查。仍需检查上游中间件。",
    snapshot_id: "snap-spruce-01",
  },
  {
    id: "finding-002",
    project_id: "proj-spruce",
    task_id: "task-pay-api",
    title: "账单导出文件名进入路径拼接",
    severity: "medium",
    status: "inconclusive",
    cwe: "CWE-22",
    file: "internal/export/report.go",
    line: 67,
    plugin: "example.scanner.rules",
    source: "query.filename",
    sink: "os.ReadFile",
    evidence:
      "扫描器报告文件名参与路径拼接；尚未确定上游规范化和目录边界校验是否有效。",
    snapshot_id: "snap-spruce-01",
  },
  {
    id: "finding-003",
    project_id: "proj-bridge",
    task_id: "task-identity",
    title: "组织标识校验覆盖范围待确认",
    severity: "low",
    status: "candidate",
    cwe: "CWE-863",
    file: "internal/session/organization.go",
    line: 31,
    plugin: "core.security.rules",
    source: "request.organization",
    sink: "OrganizationStore.Load",
    evidence: "权限控制节点已识别，但对当前调用链的覆盖范围未解析。",
    snapshot_id: "snap-bridge-01",
  },
  {
    id: "finding-004",
    project_id: "proj-edge",
    task_id: "task-edge",
    title: "配置文件访问可超出允许目录",
    severity: "high",
    status: "confirmed",
    cwe: "CWE-22",
    file: "internal/config/handler.go",
    line: 56,
    plugin: "core.agent.review",
    source: "GET /config",
    sink: "os.ReadFile",
    evidence: "本条为演示用的已确认记录，用于展示严重性与确认状态的独立关系。",
    snapshot_id: "snap-edge-01",
  },
];
export const initialStorage: StorageProfile = {
  api_version: API_VERSION,
  metadata: {
    driver: "postgresql",
    host: "postgres",
    port: 5432,
    database: "codexploit",
    credential_ref: "secret-database-main",
  },
  artifacts: {
    driver: "volume",
    endpoint: "artifact-service",
    bucket: "codexploit-artifacts",
  },
  graph: { driver: "relational" },
  deployment: { database_service: "postgres", artifact_service: "artifacts" },
};

export function validateSource(
  kind: SourceKind,
  location: string,
  ref: string,
): string[] {
  const errors: string[] = [];
  if (kind === "local_folder") {
    if (
      !location.startsWith("/repos/") ||
      location.includes("\\") ||
      location
        .split("/")
        .slice(1)
        .some((p) => [".", "..", ""].includes(p)) ||
      location.includes("\0")
    )
      errors.push("本地目录应位于已挂载的 /repos/ 下，且不能包含跳转路径。");
    if (ref) errors.push("本地文件夹按内容生成快照，无需 Git 分支。");
  } else {
    try {
      const url = new URL(location);
      if (
        !["https:", "ssh:"].includes(url.protocol) ||
        !url.hostname ||
        url.username ||
        url.password ||
        url.search ||
        url.hash
      )
        errors.push("仓库地址应使用无内嵌凭据的 HTTPS 或 SSH URL。");
    } catch {
      errors.push("请填写有效的仓库 URL。");
    }
    if (!ref.trim()) errors.push("请选择分支、标签或提交版本。");
  }
  return errors;
}

export function validateManifest(value: unknown): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return ["插件清单必须是 JSON 对象。"];
  const p = value as Record<string, unknown>,
    errors: string[] = [];
  if (p.api_version !== API_VERSION) errors.push("不支持的 api_version。");
  if (
    typeof p.id !== "string" ||
    !/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$/.test(p.id)
  )
    errors.push("插件 ID 应使用点分命名空间，例如 team.scanner.custom。");
  if (typeof p.version !== "string" || !/^\d+\.\d+\.\d+$/.test(p.version))
    errors.push("插件版本应为 major.minor.patch。");
  if (typeof p.name !== "string" || !p.name.trim() || p.name.length > 100)
    errors.push("插件名称需为 1–100 个字符。");
  if (typeof p.description !== "string") errors.push("请声明插件用途。");
  if (!Object.keys(kindNames).includes(String(p.kind)))
    errors.push("插件类型无效。");
  if (
    !Array.isArray(p.languages) ||
    !p.languages.length ||
    !p.languages.every((v) => typeof v === "string" && v.length > 0)
  )
    errors.push("请声明支持语言。");
  const runtime = p.runtime as Record<string, unknown> | undefined;
  if (
    !runtime ||
    !["builtin", "process", "container", "remote"].includes(
      String(runtime.kind),
    )
  )
    errors.push("运行方式无效。");
  if (
    runtime?.kind !== "builtin" &&
    (typeof runtime?.entrypoint !== "string" || !runtime.entrypoint.trim())
  )
    errors.push("外部插件需声明执行入口。");
  for (const field of ["consumes", "produces"] as const) {
    const items = p[field];
    if (
      !Array.isArray(items) ||
      !items.length ||
      !items.every((v) => kinds.includes(v as ArtifactKind)) ||
      new Set(items).size !== items.length
    )
      errors.push(`${field} 需声明不重复的标准产物类型。`);
  }
  const permissions = p.permissions as Record<string, unknown> | undefined;
  if (
    !permissions ||
    permissions.source_write !== false ||
    !["none", "restricted"].includes(String(permissions.network))
  )
    errors.push("需声明只读源码与网络权限。");
  if (
    !p.config_schema ||
    typeof p.config_schema !== "object" ||
    Array.isArray(p.config_schema)
  )
    errors.push("请提供参数 Schema。");
  const allowed = [
    "api_version",
    "id",
    "version",
    "name",
    "description",
    "kind",
    "languages",
    "runtime",
    "consumes",
    "produces",
    "permissions",
    "config_schema",
  ];
  if (Object.keys(p).some((key) => !allowed.includes(key)))
    errors.push("插件清单包含未知字段。");
  return errors;
}

export function validateWorkflow(
  value: unknown,
  plugins: PluginManifest[],
): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return ["工作流必须是 JSON 对象。"];
  const flow = value as WorkflowSpec,
    errors: string[] = [];
  if (
    flow.api_version !== API_VERSION ||
    typeof flow.id !== "string" ||
    !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/.test(flow.id) ||
    typeof flow.version !== "string" ||
    !/^\d+\.\d+\.\d+$/.test(flow.version) ||
    typeof flow.name !== "string" ||
    !flow.name.trim() ||
    typeof flow.description !== "string"
  )
    errors.push("工作流身份或版本无效。");
  if (
    !Array.isArray(flow.inputs) ||
    !flow.inputs.every((k) => kinds.includes(k))
  )
    errors.push("工作流输入类型无效。");
  if (
    !Array.isArray(flow.nodes) ||
    !flow.nodes.length ||
    flow.nodes.length > 32
  )
    return [...errors, "工作流需包含 1–32 个节点。"];
  if (
    flow.nodes.some(
      (n) =>
        !n ||
        typeof n.id !== "string" ||
        !/^[a-zA-Z][a-zA-Z0-9_-]{0,49}$/.test(n.id) ||
        !Array.isArray(n.needs) ||
        !n.needs.every((v) => typeof v === "string") ||
        new Set(n.needs).size !== n.needs.length ||
        !n.config ||
        typeof n.config !== "object" ||
        Array.isArray(n.config) ||
        !Number.isInteger(n.timeout_seconds) ||
        n.timeout_seconds < 5 ||
        n.timeout_seconds > 600,
    )
  )
    return [...errors, "节点名称、依赖、参数或超时格式无效。"];
  const byID = new Map(flow.nodes.map((node) => [node.id, node]));
  if (byID.size !== flow.nodes.length) errors.push("工作流存在重复节点 ID。");
  const visiting = new Set<string>(),
    visited = new Set<string>();
  const visit = (id: string): boolean => {
    if (visiting.has(id)) return false;
    if (visited.has(id)) return true;
    const node = byID.get(id);
    if (!node) return false;
    visiting.add(id);
    for (const dependency of node.needs) if (!visit(dependency)) return false;
    visiting.delete(id);
    visited.add(id);
    return true;
  };
  if (!flow.nodes.every((n) => visit(n.id)))
    errors.push("工作流存在循环或引用了不存在的依赖节点。");
  for (const node of flow.nodes) {
    const plugin = plugins.find(
      (p) => p.id === node.plugin_id && p.version === node.plugin_version,
    );
    if (!plugin) {
      errors.push(`节点 ${node.id} 引用了未注册的插件版本。`);
      continue;
    }
    const available = new Set(Array.isArray(flow.inputs) ? flow.inputs : []);
    for (const id of node.needs) {
      const dependency = byID.get(id);
      const producer =
        dependency &&
        plugins.find(
          (p) =>
            p.id === dependency.plugin_id &&
            p.version === dependency.plugin_version,
        );
      producer?.produces.forEach((kind) => available.add(kind));
    }
    const missing = plugin.consumes.filter((kind) => !available.has(kind));
    if (missing.length)
      errors.push(`${node.id} 缺少输入：${missing.join("、")}。`);
  }
  return errors;
}

export function workflowOrder(flow: WorkflowSpec): WorkflowNode[] {
  const result: WorkflowNode[] = [],
    done = new Set<string>();
  while (result.length < flow.nodes.length) {
    const next = flow.nodes.find(
      (n) => !done.has(n.id) && n.needs.every((id) => done.has(id)),
    );
    if (!next) return [];
    result.push(next);
    done.add(next.id);
  }
  return result;
}
export function validateStorage(profile: StorageProfile): string[] {
  const errors: string[] = [];
  if (profile.metadata.driver === "custom")
    errors.push(
      "自定义数据库需要实现并注册 StorageAdapter，当前原型仅展示扩展入口。",
    );
  if (
    profile.metadata.driver === "postgresql" &&
    (!/^[a-zA-Z0-9.-]+$/.test(profile.metadata.host) ||
      !Number.isInteger(profile.metadata.port) ||
      profile.metadata.port < 1 ||
      profile.metadata.port > 65535 ||
      !profile.metadata.database.trim() ||
      !profile.metadata.credential_ref.trim())
  )
    errors.push("请填写有效的 PostgreSQL 服务名、端口、数据库和凭据引用。");
  if (profile.artifacts.driver === "s3") {
    try {
      const u = new URL(profile.artifacts.endpoint);
      if (
        !["https:", "http:"].includes(u.protocol) ||
        u.username ||
        u.password ||
        u.search ||
        u.hash ||
        !profile.artifacts.bucket.trim()
      )
        throw new Error();
    } catch {
      errors.push("请填写不含凭据的对象存储地址和桶名称。");
    }
  }
  return errors;
}
export function canStart(task: Task, tasks: Task[], limit: number): boolean {
  return (
    !task.archived &&
    task.status !== "SUCCEEDED" &&
    (task.status === "RUNNING" ||
      tasks.filter((t) => t.status === "RUNNING" && !t.archived).length < limit)
  );
}
export function gradeCounts(findings: Finding[], taskID?: string) {
  return findings
    .filter(
      (f) => f.status === "confirmed" && (!taskID || f.task_id === taskID),
    )
    .reduce(
      (counts, f) => {
        if (f.severity) counts[f.severity]++;
        return counts;
      },
      { high: 0, medium: 0, low: 0 },
    );
}
export function downloadJSON(name: string, value: unknown) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2) + "\n"], {
      type: "application/json",
    }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
