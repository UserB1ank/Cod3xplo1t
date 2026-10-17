# 现有映射、实施顺序与验收

本文件区分已经实现的业务基础、这次可运行的交互原型，以及需要后续接线的基础设施。

## 现有映射

| 目标接口 | 现有入口 | 需要补充 |
|---|---|---|
| SourceProvider | repository.Source / Manager.Resolve、SourceRepository；本地文件夹、Git 固定提交、多代码源、受控根目录、凭据引用及快照绑定已接线 | 独立 Probe / Resolve / Release 协议与 TTL |
| SnapshotService / ArtifactStore | repository.Snapshot、lifecycle.Snapshots、artifact.Store 本地适配器、规范引用与 SQLite 索引 | 外部产物存储、跨服务恢复与分析产物接线 |
| Parser / Analyzer | 内置 Go 解析、ASG 语义和路径插件，固定上游产物、实际版本与覆盖范围 | 第三方工具执行器 |
| Normalizer | plugin.Normalizer；公共 AnalysisResult、标准语义 / 路径候选、原始报告与 canonical ID 绑定 | 第三方工具格式适配和跨工具观察账本 |
| KnowledgeReader / Publisher | graph.Service、ASGService、GraphStore、knowledge.Reader 固定视图 | 观察账本、增量批次 CAS 与外部图数据库 |
| PluginHost | plugin.Catalog / Host、内置 Go 执行、持久化调用与原子产物发布 | container / remote worker 执行器与多实例租约；process 握手、包安装和扫描器已由 #12 接入 |
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

## 已完成的正式界面切片

Issue #1 已在正式 `/` 工作区接通：创建独立项目 → 添加本地文件夹代码源 → 真实快照及 SCG/ASG → 从固定快照创建任务。项目可登记多个代码源；任务可按来源选择快照。文件夹内容变化后重新采集，旧任务仍使用原快照。Memory / SQLite 存储、SQLite 重启读取、项目隔离、采集期间变化、挂载越界和删除后重新采集均有公开 API 或 Manager 入口测试。

Issue #2 已补充 Git 代码源 → 固定提交快照及图谱 → 独立任务；界面显示请求版本与实际提交，并区分网络、凭据、提交和获取错误。凭据由部署侧文件引用解析并检查项目 / origin 归属。合成 HTTPS 远端测试覆盖分支移动、首次标签、提交重用、默认 HEAD 更新、真实授权和持久化；SSH 策略要求固定身份和 known_hosts，并已在独立 Docker OpenSSH 远端完成真实获取的页面验收。

这些切片不代表全部目标接口已实现：定义编辑、外部产物容器、通用插件和工作流执行、PostgreSQL 均留在后续 issue。旧项目默认源通过独立兼容区域保留，不重算既有 ID。

Issue #3 的正式任务表已接通项目分类目录、置顶、归档/恢复和已有暂停/继续操作。搜索、状态、分类及归档过滤在服务端完成后稳定分页；状态和进度读取实时路径记录。任务与分类目录均使用 ETag / 版本 CAS，拒绝陈旧写入和跨项目任务更新；归档需先暂停并等待活动路径和未结束运行完成，保留原任务与所有引用。Memory / SQLite 公开 HTTP 用例覆盖重启恢复、并发编辑、分页边界和实时状态。

## 实施顺序

Issue #6 的正式插件中心已接入 Schema 校验的不可变目录与内置 Go 解析器。调用固定输入、版本、包和参数摘要，保存覆盖、局限及 AST / facts 产物，支持 CAS 取消、预算与单宿主重启中断状态。外部清单仅登记，不显示为已安装执行器。实际接口、版本指纹和部署限制见 [插件接口](../../../plugins.md)。

Issue #12 已把部署目录中的 `codexploit.static-patterns@1.0.0` 接入正式插件目录、工作流与知识发布：包摘要和 entrypoint 校验后才显示 installed/executable；扫描器通过 NDJSON JSON-RPC 读取冻结 tar，只输出告警位置和 `security.facts` 候选；`$publish` 以 `scanner.alert` 事实进入不可变版本，任务页展示原始报告、标准告警、来源和发布版本。CodeQL 等重依赖工具因许可/构建约束未内置，后续可用同一适配器接入。详见 [进程扫描器](../../../process-scanner.md)。

Issue #11 已把运行控制接到正式任务：`POST .../workflow-runs/{id}/pause|resume|cancel|retry`（writer）实现 PAUSING/PAUSED/CANCELLING 状态机与幂等控制，暂停只阻断新节点、活动节点到边界完成；只有可重试错误按退避与次数上限重试，取消不重试；节点写入租约与独立 attempt，迟到结果被拒；进程重启后 `Recover` 恢复非终态运行，已成功节点复用原产物不重复发布。运行并发与重试上限固定写入运行记录，事件游标保持 `after_seq` 语义。正式任务页新增暂停/继续/取消/重试与尝试次数、并发策略展示。

Issue #8 已把插件标准结果接到不可变共享版本：新增 `POST .../knowledge/publications`（writer）与 `GET .../knowledge/revisions/{view}/facts`（reader），版本 CAS、幂等批次、scope / 孤立边校验、冲突观察保留和 outbox 同事务提交；同一事实的多工具来源保留为独立观察。正式图谱页的“共享知识版本”面板可选择任意已发布版本并展开来源。旧 `/api` 与 #5 的固定视图保持兼容；PostgreSQL 规范化索引仍属后续存储切片。

Issue #5 已把正式“共享知识图谱”页面接到固定视图：`POST /api/v1/projects/{id}/knowledge/views` 记录快照的 SCG / ASG 版本与构建时间，`symbols`、`neighborhood`、`nodes`、`paths`、`code_slice`、`provenance` 都从该 pin 读取并带覆盖与截断说明。同快照的多个任务共享一组事实与路径，重建后旧视图显式返回 `view_superseded`。旧 `/api` 图谱接口保持兼容；增量发布仍属 #8。

Issue #4 已接通正式产物目录、完整引用、预算校验、清单预览与认证下载。新代码源快照自动登记逐文件清单和冻结源码 tar，既有快照可显式登记。ArtifactStore 与认证 HTTP API 的测试覆盖不可变发布、冲突、读取取消、预算、损坏/丢失、项目与来源隔离、分页、退役拒绝和 SQLite 重启；外部容器存储另由 #19 接入。

1. **契约基线**：冻结 DTO/错误/作用域与版本；跑 Schema 和负面用例；为每个新适配器使用同一套契约测试。
2. **代码源垂直切片**：显式 source kind → 真实快照 → 页面展示与任务绑定；保留旧项目默认代码源。
3. **独立存储**：接 PostgreSQL 驱动、迁移和事务验收，再接 ArtifactStore；最后迁移账号、会话和加密设置。通过恢复测试后才切换真实数据。
4. **内置插件闭环**：将已有 Go AST、ASG、Path 包装成 builtin 插件，记录产物和调用；验证读写范围。
5. **工作流闭环**：DAG 编译 → 固定执行计划 → 内置插件 → 原子发布 → 任务报告；验证暂停、取消与重试。
6. **第三方插件**：process adapter + 第一个固定版本扫描器 + normalizer + 测试报告已由 #12 接入（[进程扫描器](../../../process-scanner.md)）；容器/远程 worker 和更多第三方工具仍待后续，未具备隔离能力时返回 unsupported。
7. **正式界面接线**：把原型交互逐页接到应用服务，删除该页演示状态前必须完成相应后端验收。

## 必须保留的兼容行为

旧 /api 与现有 CLI / MCP 行为保持兼容。旧项目 ID、snapshot_id、symbol_id 和证据引用不重算。已有任务继续绑定旧快照；旧 GraphStore 写入语义通过 adapter 保留，不能改为无条件图增量。

新增 DTO 和协议版本与存储迁移版本分别管理。接口 Schema 不等于 SQL schema。改变路径语义、置信类别、ID 算法和确认门槛需要独立设计评审与迁移计划。

## 完成扩展的交付清单

每个扩展交付 Manifest、固定版本/包摘要、输入输出样例、Normalizer 或解析器、能力/覆盖局限、失败和取消行为、最小工作流，以及跨平台契约测试。对数据库还需真实服务并发和恢复测试；对执行器还需部署隔离验证。
