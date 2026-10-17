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
| `GET /neighborhood` | `symbol_id`、`direction=callers\|callees`、`depth`、`max_nodes` | 调用邻居与未解析调用点 |
| `GET /nodes` | `kind`、`subject`、`cursor`、`limit` | ASG 节点分页 |
| `GET /paths` | `audit_id`、`entry_node_id`、`target_node_id`、`cursor`、`limit` | 固定快照的 AuditPath 分页 |
| `GET /code-slice` | `symbol_id`、`max_lines`、`max_sections`、`context_lines` | 有界源码切片 |
| `GET /provenance` | `fact_id` | 事实来源 |

每个响应都带 `meta`：`view_id`、`revision`、`layer`、`versions`、`total`、`truncated`、`truncation_reason`、`omitted`、`coverage`、`limitations`。

- `cursor` 是不透明游标；`limit` 默认 50、上限 200，越界直接 400。
- `truncated` 只表示预算截断，`truncation_reason` 说明来源；`omitted` 给出因版本不符而跳过的路径条数（原因为 `stale_layer_version`）。
- 路径查询始终按视图的快照过滤，并丢弃 SCG / ASG 版本与 pin 不一致的路径，因此不同快照与旧构建不会混入一页。
- `provenance` 返回 producer（插件、版本、调用 ID、配置摘要）、代码位置、共享该快照版本的任务，以及已发布的源码产物引用；`fact_id` 可以是符号或 ASG 节点，未知事实返回 404 而不是空结果。

## 错误

401 表示未认证；reader 可读，writer / admin 同样可读。404 `knowledge_not_found` 表示视图、项目或快照不属于该作用域；409 `knowledge_unavailable` 表示快照尚无代码图谱；409 `layer_unavailable` 表示该层未固定或未构建；409 `view_superseded` 表示图层已重建；400 `invalid_request` 表示非法游标、预算或方向；501 表示该部署未接线知识查询；503 表示查询故障。

## 兼容与边界

旧 `/api/snapshots/{id}/…` 图谱接口形状不变，正式页面、CLI 与 MCP 继续使用它们不受影响。知识共享是逻辑共享：同一快照的多个任务复用同一组事实与路径；不同快照通过不同 `view_id` 读取，不会在一次查询中混合。增量批次发布、跨快照显式映射、统一观察账本与外部图数据库属于 #8 及后续切片。
