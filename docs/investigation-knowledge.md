# 调查知识：猜想、问题与证据

2026-10-26 首个实现切片。代码图谱页保存和读取调查知识，项目主 Agent 通过私有 MCP 提交同一类记录。生产持久化使用 PostgreSQL 迁移 `0023_knowledge_claims`，Memory 用于开发与回归；没有新增 SQLite 功能或迁移。

## 已实现的闭环

项目助手先查询已有猜想，再提出绑定真实源码位置的判断，追加缺失前提的问题，引用支持、反驳或上下文证据，并读回保存结果。没有图谱时也能积累源码调查知识。断言账本独立于 SCG/ASG、引擎轨迹和验证裁定。

| 记录 | 固定内容 | 状态 |
| --- | --- | --- |
| claim | 类别、陈述、适用条件、相对源码路径及行范围 | conjecture |
| observation | 对同一精确命题的独立重复观察与来源 | conjecture |
| question | 关联猜想及具体待解问题 | open |
| evidence | 关联猜想、理由、supports / contradicts / context、核验后的引用 | recorded |

类别为 `vulnerability`、`control` 或 `business_rule`。业务规则同样是猜想，不自动成为用户前提或代码事实。当前没有把记录提升为事实的写接口；支持证据和模型同意不改变猜想状态。正式漏洞确认继续由既有验证服务负责。

遵循 [ADR 0002](adr/0002-read-only-project-source.md)：`snapshot_id` 是内部源码关联键，不增加新项目源码版本管理或完整性校验。这里的 `revision` 是调查账本版本，与 Joern 和知识发布 `rev-N` 分开。

## 正式 HTTP 接口

以下均在 `/api/v1/projects/{projectID}/knowledge/claims` 下。GET 要求 reader，POST 要求 writer。

| 方法与后缀 | 用途 |
| --- | --- |
| POST 根路径 | 提出猜想 |
| GET 根路径 | 分页查询独立猜想，不重复计算 observation |
| GET `/{claimID}` | 分页读取该猜想的观察、问题和证据 |
| POST `/{claimID}/questions` | 追加待解问题 |
| POST `/{claimID}/evidence` | 追加证据引用和关联理由 |

提出猜想的请求示例（身份均为示意值）：

```json
{
  "snapshot_id": "source-scope-example",
  "request_key": "investigation-entry-1",
  "category": "vulnerability",
  "statement": "下载入口的文件名可能缺少目录约束",
  "conditions": "生产入口接受外部文件名时",
  "target": {"file": "src/download.go", "start_line": 20, "end_line": 35}
}
```

追加问题只接收 `snapshot_id`、`request_key`、`statement`。追加证据还接收 `relation` 和 `reference`：

```json
{
  "snapshot_id": "source-scope-example",
  "request_key": "investigation-entry-evidence-1",
  "statement": "检查路径约束是否覆盖此调用点",
  "relation": "context",
  "reference": {
    "kind": "source",
    "target": {"file": "src/download.go", "start_line": 20, "end_line": 35}
  }
}
```

`reference.kind` 也可以是 `evidence` 或 `artifact`，通过 `id` 引用同一源码 Scope 的已有对象。源码由宿主读取并保存当时片段，采用现有证据脱敏规则；单文件不超过 4 MiB，每段不超过 200 行和 16,000 字节。越界路径、链接文件、敏感文件类型、缺失行与不可用源码均拒绝。产物引用由 ArtifactStore 核对大小与摘要，超过 16 MiB 明确失败；源码目录绑定不充当内容证据。已有证据引用保存原 ID 和摘要，正文仍由证据接口读取。

首次追加返回 201、`api_version`、`record`、`created=true`；同键同内容重放返回 200 和原记录；同键异内容返回 409。请求键在同一源码账本内共享。未知字段（包括 `status`、`actor`、`run_id`、角色、自报证据正文）拒绝。

GET 要求 `snapshot_id`，可选 `revision`、`cursor`、`limit`（默认 25，上限 100）。响应为 `records`、`revision`、`head_revision`、`next_cursor`、`has_more`。省略 revision 或传 0 打开当前账本；续页固定返回的 revision 和 next_cursor。未来版本返回 409；对应版本下不存在的猜想返回 404。响应经[公开 Schema](../contracts/v1/investigation-knowledge.schema.json) 校验。

参数错误 400、权限不足 403、跨项目/不存在引用 404、幂等或运行冲突 409、产物超预算 413、存储或源码不可用 503。失败不保存聊天替代记录。

## Agent、并发与页面

私有项目 MCP 新增 `propose_claim`、`open_question`、`attach_evidence`、`query_investigation_knowledge`。省略源码身份时使用会话输入，显式选择仍须属于当前项目。写工具与通用 `project_api` 复用正式 HTTP 处理器。公开 stdio MCP 保持既有只读范围。

主 Agent 使用 `supervisor/v5`，要求先读已有知识、保存判断和问题，并核对写入结果。session/run ID 由宿主绑定，可追溯运行的模型、配置和工具版本；人工提交不虚构运行。写入事务重新检查主会话运行仍为 RUNNING；PostgreSQL 对会话行持共享锁直到提交，使取消和写入有明确先后。取消完成后旧 MCP 连接也不能追加知识。

命题身份使用精确类别、陈述、条件与目标，不按标题或语义相似度合并。独立重复提交追加 observation，重放同一请求不增加数量。来源、时间和反对证据不覆盖。

PostgreSQL 使用与源码 Scope 删除相同的事务锁，检查归属与删除标记，然后同事务追加记录、推进账本并写 outbox。证据或问题必须引用真实猜想；外键随 Scope 删除清理记录和 outbox，迟到写入不能重建数据。outbox 目前只记变更，还没有自动消费为探索任务。

图谱页“调查知识”面板支持未构图状态、固定账本分页、条件/来源/问题/证据详情、writer 手动提交和 reader 只读；存储错误与空列表分别显示。源码片段保存后可直接阅读。当前没有事实节点自动投影或全图布局。

## 验收与后续

覆盖认证 HTTP/MCP 提交读回、问题、真实源码/证据/产物引用、非法引用/越权/伪造裁定拒绝、同键幂等、固定分页、重复观察和取消后迟到写入。真实 PostgreSQL覆盖应用重建文档一致、双实例并发重放与取消栅栏；前端检查续页固定 Scope/版本及失败传播。隔离应用完成页面提出猜想、追加问题、保存源码证据和重启读回。

本轮验证：真实 PostgreSQL 全套集成、前端 57 项测试/构建、契约检查、可编译包的完整乱序竞态与三轮稳定性，以及受影响包 vet/staticcheck 通过；新增证据兼容修正另经三轮定向竞态验证。原样运行 `make test` 和 `make lint` 被已有未跟踪的 `internal/app/example_test.go` 引用未实现方法阻塞，该文件未修改或删除；其余包通过不代表根门禁通过。页面验收使用独立服务，原有部署未更新。

首个切片不含探索/审查/复核工作槽、自动派工和问题解决、语义模型执行、依赖重审、finding 的事实投影及固定报告接入。这些沿[组织方案](design/graph-audit-organization-20261025.md)后续切片实施。
