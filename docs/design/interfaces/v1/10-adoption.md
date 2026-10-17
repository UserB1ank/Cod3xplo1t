# 现有映射、实施顺序与验收

本文件区分已经实现的业务基础、这次可运行的交互原型，以及需要后续接线的基础设施。

## 现有映射

| 目标接口 | 现有入口 | 需要补充 |
|---|---|---|
| SourceProvider | repository.Source / Manager.Resolve | 显式 source kind、项目多个代码源、挂载登记与凭据引用 |
| SnapshotService / ArtifactStore | repository.Snapshot、lifecycle.Snapshots | 统一引用、外部产物存储与跨服务发布恢复 |
| Parser / Analyzer | scg.Frontend、analysis.Detector | 包装为类型化产物与通用插件能力 |
| Normalizer | ASG、路径和验证各自领域逻辑 | 原始工具格式适配、公共结果与局部 ID 映射 |
| KnowledgeReader / Publisher | graph.Service、ASGService、GraphStore | 多层固定视图、观察账本、增量批次 CAS |
| PluginHost | agent.Runtime / verify.Executor | 通用清单、握手、插件安装状态与统一执行器 |
| WorkflowRunner | schedule.Scheduler、path.Service | DAG 编译、节点状态、产物绑定、栅栏与恢复 |
| FindingService | verify.Store / Verifier、项目发现 API | 适配公共 DTO，保留所有来源与现有裁定 |
| ProjectService / TaskService | 当前 /api、WebUI、path.Audit | 归档分类等持久化、工作流引用、/api/v1 适配 |
| StorageAdapter | storage.SQL / Memory、SQLite wiring | PG 驱动/迁移/契约测试、外部产物、账号会话与加密设置数据库化 |

## 本次方案与原型验收范围

- `/prototype/` 提供 ARTEX 参考下的功能导航与任务表格。
- 本地目录 / Git 表单分别校验；模拟快照不改变已有任务版本。
- 任务筛选、分页、暂停/继续、置顶、归档、并发限制与节点推进可交互。
- 图谱可切换项目、快照和层；节点展示来源、证据和代码位置。
- 严重性仅高、中、低，确认状态独立。
- 插件清单导入/导出、工作流节点与依赖编辑、环路和类型校验、固定版本可操作。
- 存储页面说明独立 PostgreSQL 和产物服务，支持配置结构校验与方案导出。
- JSON Schema、完整样例和分层端口文档可供扩展开发。

原型不读取/写入正式业务数据，不执行扫描，不调用模型，不迁移数据库。演示操作有明确标识，刷新重置。

## 实施顺序

1. **契约基线**：冻结 DTO/错误/作用域与版本；跑 Schema 和负面用例；为每个新适配器使用同一套契约测试。
2. **代码源垂直切片**：显式 source kind → 真实快照 → 页面展示与任务绑定；保留旧项目默认代码源。
3. **独立存储**：接 PostgreSQL 驱动、迁移和事务验收，再接 ArtifactStore；最后迁移账号、会话和加密设置。通过恢复测试后才切换真实数据。
4. **内置插件闭环**：将已有 Go AST、ASG、Path 包装成 builtin 插件，记录产物和调用；验证读写范围。
5. **工作流闭环**：DAG 编译 → 固定执行计划 → 内置插件 → 原子发布 → 任务报告；验证暂停、取消与重试。
6. **第三方插件**：交付一套 process adapter + normalizer + 测试报告，再开放容器/远程 worker；未具备隔离能力时返回 unsupported。
7. **正式界面接线**：把原型交互逐页接到应用服务，删除该页演示状态前必须完成相应后端验收。

## 必须保留的兼容行为

旧 /api 与现有 CLI / MCP 行为保持兼容。旧项目 ID、snapshot_id、symbol_id 和证据引用不重算。已有任务继续绑定旧快照；旧 GraphStore 写入语义通过 adapter 保留，不能改为无条件图增量。

新增 DTO 和协议版本与存储迁移版本分别管理。接口 Schema 不等于 SQL schema。改变路径语义、置信类别、ID 算法和确认门槛需要独立设计评审与迁移计划。

## 完成扩展的交付清单

每个扩展交付 Manifest、固定版本/包摘要、输入输出样例、Normalizer 或解析器、能力/覆盖局限、失败和取消行为、最小工作流，以及跨平台契约测试。对数据库还需真实服务并发和恢复测试；对执行器还需部署隔离验证。
