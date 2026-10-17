import common from "../../../contracts/v1/common.schema.json";
import source from "../../../contracts/v1/source.schema.json";
import snapshot from "../../../contracts/v1/snapshot.schema.json";
import analysis from "../../../contracts/v1/analysis.schema.json";
import knowledge from "../../../contracts/v1/knowledge.schema.json";
import plugin from "../../../contracts/v1/plugin.schema.json";
import workflow from "../../../contracts/v1/workflow.schema.json";
import finding from "../../../contracts/v1/finding.schema.json";
import storage from "../../../contracts/v1/storage.schema.json";
import application from "../../../contracts/v1/application.schema.json";

export const schemaCatalog = {
  common,
  source,
  snapshot,
  analysis,
  knowledge,
  plugin,
  workflow,
  finding,
  storage,
  application,
};
export const interfaceCatalog: {
  id: string;
  name: string;
  port: string;
  description: string;
  schema: keyof typeof schemaCatalog;
  methods: [string, string, string][];
  rules: string[];
}[] = [
  {
    id: "L0",
    name: "公共契约",
    port: "ContractRegistry",
    description: "定义跨层作用域、产物引用、来源、错误与版本兼容。",
    schema: "common",
    methods: [
      ["Negotiate", "支持的协议版本", "选定版本 / 不兼容错误"],
      ["Validate", "Schema ID + 文档", "结构错误列表"],
      ["ResolveSchema", "Schema ID", "固定摘要的 Schema"],
    ],
    rules: [
      "project_id、source_id、snapshot_id 组成数据范围。",
      "标准对象严格拒绝未知字段，扩展须声明自己的 Schema。",
      "错误码稳定，错误详情不包含凭据。",
    ],
  },
  {
    id: "L1",
    name: "代码源层",
    port: "SourceProvider",
    description: "显式区分文件夹与 Git，将外部来源解析为可固定的读取对象。",
    schema: "source",
    methods: [
      ["Probe", "SourceDefinition", "能力、可用性、限制"],
      ["Resolve", "代码源 + 版本选择", "ResolvedSource"],
      ["ListSources", "项目 ID + 分页", "项目代码源列表"],
    ],
    rules: [
      "文件夹模式按内容读取，Git 模式按固定提交读取。",
      "本地目录来自受控挂载，不接受任意宿主机路径。",
      "仓库凭据只以 credential_ref 传递。",
    ],
  },
  {
    id: "L2",
    name: "快照与产物层",
    port: "SnapshotService / ArtifactStore",
    description: "物化只读源码，保存不可变、可校验的分析产物。",
    schema: "snapshot",
    methods: [
      ["Capture", "ResolvedSource + 限额", "SnapshotDescriptor"],
      ["Put", "产物流 + 摘要 + Scope", "ArtifactRef"],
      ["Open", "ArtifactRef + 读取预算", "有界字节流"],
      ["Retire", "快照 ID + 版本", "可恢复的删除操作"],
    ],
    rules: [
      "先校验内容摘要，再发布快照。",
      "相同内容幂等，冲突内容不能覆盖既有证据。",
      "大文件内容与数据库索引通过产物引用关联。",
    ],
  },
  {
    id: "L3",
    name: "分析与归一化层",
    port: "Parser / Analyzer / Normalizer",
    description: "将原生 AST、工具告警和传播路径转换为通用事实。",
    schema: "analysis",
    methods: [
      ["Parse", "源码快照 + 语言配置", "原生 AST + 代码事实"],
      ["Analyze", "固定输入产物", "原始报告 / 告警"],
      ["Normalize", "原始结果 + 代码索引", "AnalysisResult + 标准产物"],
    ],
    rules: [
      "原始 AST 和报告保留，通用事实进入知识层。",
      "调用路径与污点路径保留不同语义。",
      "缺失的传播步骤标为未知，覆盖范围和跳过原因必须返回。",
    ],
  },
  {
    id: "L4",
    name: "知识图谱层",
    port: "KnowledgeReader / KnowledgePublisher",
    description: "按项目与快照读取事实，原子发布带来源的图谱增量。",
    schema: "knowledge",
    methods: [
      ["OpenView", "Scope + 层版本", "不可变 KnowledgeView"],
      ["Query", "视图 + 有界结构化查询", "节点 / 关系 / 路径 + 截断信息"],
      ["Publish", "GraphBatch + 基准版本", "新视图 + ID 映射"],
      ["GetProvenance", "事实 ID + 视图", "插件、任务与证据来源"],
    ],
    rules: [
      "任务共享项目知识，快照间关系须显式声明。",
      "插件不能直接连接底层数据库。",
      "发布校验作用域、引用、来源和并发版本。",
    ],
  },
  {
    id: "L5",
    name: "插件层",
    port: "PluginCatalog / PluginHost",
    description: "通过版本化清单注册能力，再由统一执行器运行工具。",
    schema: "plugin",
    methods: [
      ["Register", "PluginManifest + 包摘要", "插件版本记录"],
      ["Execute", "固定插件 + Scope + 输入引用", "InvocationHandle"],
      ["GetStatus", "调用 ID", "状态 / 产物 / 诊断"],
      ["Cancel", "调用 ID + 原因", "取消受理结果"],
    ],
    rules: [
      "注册清单与实际执行状态分别记录。",
      "声明权限需经宿主策略收紧后生效。",
      "进程、容器和远程执行器遵循相同产物协议。",
    ],
  },
  {
    id: "L6",
    name: "工作流层",
    port: "WorkflowCompiler / WorkflowRunner",
    description: "将插件组合成有类型、可取消和可重现的 DAG。",
    schema: "workflow",
    methods: [
      ["Validate", "工作流 + 插件目录", "环路 / 类型 / 版本错误"],
      ["Compile", "流程 + 快照 + 预算", "固定的 ExecutionPlan"],
      ["Start", "计划 + 幂等键", "WorkflowRun"],
      ["Pause / Resume / Cancel", "运行 ID + 版本", "状态变更"],
      ["ReadEvents", "运行 ID + 游标", "有序执行事件"],
    ],
    rules: [
      "节点版本和输入摘要在任务创建时固定。",
      "仅依赖显式成功输出，失败产物不会自动进入下游。",
      "恢复和重试使用租约、栅栏令牌及幂等提交。",
    ],
  },
  {
    id: "L7",
    name: "发现与证据层",
    port: "FindingService / EvidenceStore",
    description: "关联告警、路径和证据，独立管理严重性与确认状态。",
    schema: "finding",
    methods: [
      ["RecordCandidate", "候选结论 + 证据引用", "Finding"],
      ["AssessSeverity", "发现 ID + 高中低 + 版本", "更新后的分级"],
      ["RecordVerdict", "发现 ID + 证据裁定", "独立确认状态"],
      ["ExportReport", "项目 / 任务 / 固定视图", "报告产物引用"],
    ],
    rules: [
      "严重性仅 high、medium、low，未评估时字段缺省。",
      "模型与扫描器不能自行确认发现。",
      "结果去重保留所有来源和相互矛盾的证据。",
    ],
  },
  {
    id: "L8",
    name: "应用服务层",
    port: "ProjectService / TaskService",
    description: "面向 WebUI、REST 和 CLI 暴露项目与任务操作。",
    schema: "application",
    methods: [
      ["CreateProject", "项目配置", "Project"],
      ["CreateTask", "代码快照 + 工作流版本 + 目标", "Task"],
      ["ListTasks", "项目 / 状态 / 分类 / 游标", "有界任务页"],
      ["Archive / Restore", "任务 ID + 版本", "任务记录"],
      ["GetCapabilities", "当前身份", "可用能力与未接线状态"],
    ],
    rules: [
      "产品层级保持项目 → 任务。",
      "管理、写入和读取权限在入口统一检查。",
      "系统密钥配置只返回是否已设置。",
    ],
  },
  {
    id: "L9",
    name: "持久化层",
    port: "StorageAdapter / UnitOfWork",
    description: "支持独立 PostgreSQL 容器，向上保持数据库无关的事务语义。",
    schema: "storage",
    methods: [
      ["Capabilities / Health", "适配器配置引用", "事务、CAS、租约能力与健康"],
      ["WithinTransaction", "领域写入操作", "原子提交 / 回滚"],
      ["Claim / Renew / Complete", "工作 ID + 租约 / 栅栏令牌", "有界执行权"],
      ["AppendEvents", "运行 ID + 预期序号", "事件序号"],
      ["Migrate", "目标版本 + 独占迁移锁", "迁移结果"],
    ],
    rules: [
      "PostgreSQL 保存元数据与图谱索引，文件或对象存储保存大产物。",
      "数据服务使用独立持久卷，应用容器不保存唯一数据。",
      "新数据库适配器必须通过相同并发与故障恢复契约。",
    ],
  },
];
