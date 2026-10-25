# 固定视图与知识查询

Issue #5 在现有 `graph.Service`、`graph.ASGService` 与 `path.Service` 之上增加 `internal/knowledge`：把一次读取固定到某个快照的确切图层版本，并在正式“共享知识图谱”页面按图层浏览真实符号、攻击面与审计路径。

## 视图

`POST /api/v1/projects/{projectID}/knowledge/views`

```json
{"api_version": "codexploit/v1", "snapshot_id": "snap-…", "layers": ["scg", "asg", "paths"]}
```

返回 `{api_version, view}`，`view` 包含 `view_id`、`revision`、`scope`、`layers`、`engine`、`coverage` 与 `limitations`，并通过 `contracts/v1/view.schema.json` 校验。

- `layers` 省略表示三层全要；`scg` 总是包含，其它层都从它派生。
- `view_id` 是自描述的 pin（scope + 图层版本 + built_at 的 base64url），不依赖服务端会话，重启后仍可验证；`revision` 是同一 pin 的短摘要。
- 每层状态显式为 `available`、`not_built` 或 `unavailable`，缺失能力不会被静默省略。
- 快照没有代码图谱时打开视图返回 409 `knowledge_unavailable`；查询未请求的图层返回 409 `layer_unavailable`。

**固定语义。** pin 记录 SCG 的 `version` 与 `built_at`、ASG 的 `version` 与 `built_at`。`GraphVersion` 只由快照、引擎和前端决定，不随内容变化，所以重建检测依赖 `built_at`：任一图层重建后，旧视图的查询返回 409 `view_superseded`，必须重新打开视图。真正不可变的多版本发布由 #8 提供；这里先保证“不隐式切换 latest”。

## 查询

统一前缀 `/api/v1/projects/{projectID}/knowledge/views/{viewID}`。

| 方法与后缀 | 参数 | 行为 |
|---|---|---|
| `GET /symbols` | `q`、`kind`、`cursor`、`limit` | SCG 符号分页，按名称子串匹配 |
| `GET /neighborhood` | `symbol_id`、`direction=callers\|callees`、`depth`、`max_nodes` | SCG 调用邻居与未解析调用点 |
| `GET /asg-neighborhood` | `node_id`、`depth=1\|2`、`max_nodes` | 有界 ASG 局部图；只展开出边，`DERIVED_FROM` 作为来源而非调用边；返回 `unresolved_edges`、截断与局限 |
| `GET /nodes` | `kind`、`subject`、`q`、`cursor`、`limit` | ASG 节点分页；`q` 对 subject / label 做大小写不敏感子串匹配，正式入口目录使用 `kind=EntryPoint` |
| `GET /paths` | `audit_id`、`entry_node_id`、`target_node_id`、`cursor`、`limit` | 固定快照的 AuditPath 分页 |
| `GET /code-slice` | `symbol_id` 或 `file`、`start_line`、`end_line`、`include`、`max_lines`、`max_sections`、`context_lines` | 固定快照中的有界源码切片或文件行窗口 |
| `GET /provenance` | `fact_id` | 事实来源 |

每个响应都带 `meta`：`view_id`、`revision`、`layer`、`versions`、`total`、`truncated`、`truncation_reason`、`omitted`、`coverage`、`limitations`。

- `cursor` 是不透明游标；`limit` 默认 50、上限 200，越界直接 400。
- `truncated` 只表示预算截断，`truncation_reason` 说明来源；`omitted` 给出因版本不符而跳过的路径条数（原因为 `stale_layer_version`）。
- 路径查询始终按视图的快照过滤，并丢弃 SCG / ASG 版本与 pin 不一致的路径，因此不同快照与旧构建不会混入一页。
- `code-slice` 的 `symbol_id` 与 `file` 互斥；只给文件时按 `start_line` / `end_line` 读取，行号越界会截到文件末尾并保留 `total_lines`，不会用最新工作区补旧快照。图谱只记录声明行、没有结束行时，服务端从声明行向前取 `context_lines` 并读取一个有界行窗口，在 `note` 中明确说明“函数结束未记录”，不伪造函数边界。
- `provenance` 返回 producer（插件、版本、调用 ID、配置摘要）、代码位置、共享该快照版本的任务，以及已发布的源码产物引用；`fact_id` 可以是符号或 ASG 节点，未知事实返回 404 而不是空结果。

## 入口与路径选择

正式页面先列出固定视图的 ASG `EntryPoint`，搜索与分页都由服务端完成；选中入口后读取 `asg-neighborhood` 的 1–2 跳节点和出边。节点抽屉读取固定视图的源码切片、节点文件位置、SCG 引用、边证据/置信和 `provenance`，不展示示例图。无入口、未构建攻击面、旧视图失效或节点不存在分别返回真实空态 / 409 / 404。

候选路径页读取固定视图的 `path.Path`：入口、目标、调用/数据证据等级、源文件位置、优先级、评分与筛选原因、任务/插件/Agent 来源和覆盖局限。勾选若干路径（1–5 条）后调用：

`POST /api/v1/projects/{projectID}/path-selections`（writer）

```json
{"api_version":"codexploit/v1","path_ids":["path-…","path-…"]}
```

返回稳定的 `selection_id`（由 project + 规范 path_id 派生）、`audit_id`、`path_id`、`run_id`、状态与来源；只读投影还带 `entry_subject`、`target_subject`、`target_kind`，供子任务目录显示审查对象，不按标题合并任务。选择通过现有 Agent 应用服务为每条路径创建独立运行；重复选择返回已记录的 run，不按标题合并，也不创建第二个调度器。`GET .../path-selections?path_id=…` 是同一映射的只读投影。路径不存在、跨项目/跨快照和权限不足分别返回 404/403；优先级不是漏洞严重度，调用可达不是污点流，过滤不是安全证明。

## 错误

401 表示未认证；reader 可读，writer / admin 同样可读。404 `knowledge_not_found` 表示视图、项目或快照不属于该作用域；409 `knowledge_unavailable` 表示快照尚无代码图谱；409 `layer_unavailable` 表示该层未固定或未构建；409 `view_superseded` 表示图层已重建；400 `invalid_request` 表示非法游标、预算或方向；501 表示该部署未接线知识查询；503 表示查询故障。

## 发布与版本

语义分析等工具产出的标准结果不会直接改写共享图谱，而是由宿主作为 GraphBatch 原子发布：

`POST /api/v1/projects/{projectID}/knowledge/publications`（writer）

```json
{"api_version": "codexploit/v1", "snapshot_id": "snap-…", "invocation_id": "inv-…",
 "task_id": "audit-…", "batch_id": "batch-…", "base_revision": "rev-0"}
```

- 只接受已完成（`SUCCEEDED` / `PARTIAL`）的调用；事实来源取该调用的生产者、版本、配置摘要，`task_id` 必须属于同一快照。
- 跨层边（例如指向 SCG 调用点）不属于本批事实，适配层会省略并在 `limitations` 中计数，不伪造端点。
- 版本 CAS：`base_revision` 必须等于当前 `head`（首个版本为 `rev-0`），否则 409 `version_conflict`。
- 幂等：相同 `batch_id` 且摘要相同返回原版本；摘要不同返回 409 `batch_conflict`。
- 孤立边、非法事实返回 400 `invalid_batch`；失败批次、版本和 outbox 都不落库。
- 冲突观察保留：同一 `fact_id` 的第二个生产者会新增 observation（携带其原始属性），不覆盖既有 canonical 字段。

`GET /api/v1/projects/{projectID}/knowledge/revisions?snapshot_id=…`（reader）列出不可变版本；`GET /api/v1/projects/{projectID}/knowledge/revisions/{viewID}/facts?snapshot_id=…` 按版本读取事实与全部观察。`view_id` 自描述版本号，读取永远不会落到 “latest”。正式页面的“共享知识版本”面板用它选择版本并展开同一事实的多来源。

发布记录持久化在 `knowledge_revisions` / `knowledge_outbox`（migration `0017`）：版本行、批次索引与 outbox 事件在同一事务提交，失败整体回滚。查询侧暂以版本文档形式保存事实与观察；PostgreSQL 规范化索引属于后续存储切片。

## 兼容与边界

旧 `/api/snapshots/{id}/…` 图谱接口形状不变，正式页面、CLI 与 MCP 继续使用它们不受影响。知识共享是逻辑共享：同一快照的多个任务复用同一组事实与路径；不同快照通过不同 `view_id` 读取，不会在一次查询中混合。增量批次发布、跨快照显式映射、统一观察账本与外部图数据库属于 #8 及后续切片。
