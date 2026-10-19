# 固定工作流执行

正式任务创建页可以选择当前快照的固定计划，执行真实的解析、语义和路径插件，发布项目共享知识，并按需调用程序中配置的模型分析候选。工作流定义与编译见[工作流 API](workflows.md)。执行记录保存在 Memory / SQLite / PostgreSQL；暂停、取消、重试与重启恢复见下节。PostgreSQL 使用服务端时钟、数据库 coordinator 租约和单调 epoch 协调 worker，详见 [PostgreSQL 执行模式](postgres-catalog.md#worker-租约与恢复)。

## 操作流程

1. 在项目内采集本地文件夹或 Git 固定提交快照，登记真实源码产物。
2. 在“工作流”页保存版本，选择同一快照的输入，编译并保存固定计划。
3. 新建任务，选择快照及固定计划。模型分析可选；先在程序的模型设置中配置 LLM，密钥不会写入计划或执行记录。
4. 默认拒绝部分覆盖。确需继续时显式接受指定节点的 PARTIAL；页面复选框接受所有选定节点及应用阶段，API 可以逐节点指定。
5. 在任务详情查看真实节点状态、输入输出、插件调用、共享知识版本、Agent 运行与有序事件。“产物与证据”页可校验、预览和下载对应内容。

内置链路为 `parse → semantic → paths → $publish → $analyze`。最后两个是应用阶段，不能在 WorkflowSpec 中冒充插件：`$publish` 发布完成调用的标准结果并建立任务候选，`$analyze` 通过既有 Agent runtime 分析候选。未启用模型或没有候选时分析阶段明确 SKIPPED。

部署目录提供进程包后，工作流也可以选择 `codexploit.static-patterns@1.0.0` 作为独立扫描节点（最小定义只需根输入 `source.snapshot`）。扫描器输出 `scanner.alerts` 原始报告与 `security.facts` 候选；`$publish` 把候选按独立观察写入不可变版本，事实 `kind=scanner.alert`。该节点不执行目标仓库代码，也不把告警位置升级为污点流或已确认漏洞。协议、限额与页面字段见 [进程扫描器](process-scanner.md)。

## 流程控制与恢复

| 方法与地址 | 角色 | 行为 |
|---|---|---|
| POST `/api/v1/projects/{projectID}/workflow-runs/{runID}/pause` | writer | RUNNING → PAUSING；活动节点到边界完成后 PAUSED；重复请求幂等 |
| POST `.../resume` | writer | PAUSED（或仍在 PAUSING）→ RUNNING，从持久化状态继续 |
| POST `.../cancel` | writer | → CANCELLING；执行器被取消、迟到结果丢弃，终态 CANCELLED；重复请求幂等 |
| POST `.../retry` | writer | 仅 FAILED 可重试：创建新运行，已成功节点复用原调用与产物，不再重复发布 |

状态机：`CREATED → RUNNING ⇄ PAUSING → PAUSED`，任一活动态可进入 `CANCELLING → CANCELLED`；终态为 `SUCCEEDED / PARTIAL / FAILED / CANCELLED`。每次转换追加一个有序事件（`run_pause_requested`、`run_paused`、`run_resumed`、`run_cancel_requested`、`run_finished`、`run_recovered` 等），事件流沿用 `after_seq` 游标恢复。

**重试策略**：只有被标记为可重试的执行器错误与超时会重试；取消、非法输入和输出完整性失败不重试。单节点上限取任务 limits 的 `max_attempts`（默认 3，1–10），退避为 100ms 起指数增长、上限 3s；耗尽后节点以 `retry_exhausted` 失败。并发上限为 `max_active_leases`（默认 4，1–16），固定写入运行记录。

**租约与恢复**：节点开跑前写入 `attempt`、`lease_owner`、`lease_expires_at`。迟到 worker 的结果（状态已取消、或租约不属于本进程）只记录 `node_result_rejected`，不覆盖现有节点。进程重启时 `Recover` 扫描非终态运行，把 RUNNING 节点回收为 PENDING 后重新调度，已 SUCCEEDED 的节点保留原调用与产物，因此不会重复发布。暂停中的运行不占用执行器；恢复时按当前应用设置重新绑定模型，运行记录仍保留原模型 pin。

## 认证 HTTP API

| 方法与地址 | 角色 | 结果 |
|---|---|---|
| GET `/api/v1/projects/{projectID}/workflow-plans?snapshot_id=...&cursor=...&limit=50` | reader | 固定计划目录、next_cursor；limit 1–100，按 plan_id 排序 |
| POST `/api/projects/{projectID}/tasks` | writer | 原任务请求增加 workflow_plan_id、analyze_candidates、accept_partial_nodes，返回 task、project_id、workflow_run |
| GET `/api/v1/projects/{projectID}/workflow-runs/{runID}` | reader | `{api_version,run}` |
| GET `/api/v1/projects/{projectID}/workflow-runs/{runID}/events?after_seq=0&limit=100` | reader | `{api_version,events,next_seq}`；limit 1–200，序号严格递增 |

固定计划必须属于任务所在项目与快照。创建请求继续支持原有 name、objective、source_id、snapshot_id、scope、budget 和 limits。未选择计划时沿用原任务入口。写请求沿用应用的认证、Origin 和幂等机制。

```json
{
  "name": "入口到敏感操作分析",
  "objective": "收集并分析可追溯的漏洞候选",
  "snapshot_id": "snap-example",
  "workflow_plan_id": "plan-example",
  "analyze_candidates": false,
  "accept_partial_nodes": ["paths"],
  "scope": [],
  "budget": {"max_tool_calls": 30, "max_depth": 2},
  "limits": {"max_paths": 200, "max_active_leases": 2}
}
```

读取执行和事件的响应在服务端通过[workflow-run Schema](../contracts/v1/workflow-run.schema.json)离线验证；计划目录通过 workflow-runtime Schema 验证。标准 ArtifactRef 沿用产物层协议。无权限返回 403；跨项目或快照资源返回 404 `workflow_not_found`；无效运行输入返回 400 `invalid_workflow`；模型未配置返回 503 `candidate_runtime_unavailable`，不会先创建空任务再宣称成功。活动工作流的旧路径暂停 / 继续入口返回 409 `workflow_managed`；其归档和快照删除受活动运行栅栏保护。

## 运行与追踪协议

`internal/workflow.Runner` 公开 `Start(ctx, StartRequest)`、`Get(ctx, projectID, runID)`、`Events(ctx, projectID, runID, afterSeq, limit)` 和 `Close()`。Start 原子创建独立任务和运行记录，再交给应用拥有的上下文执行；浏览器断开不会取消后台任务。Close 请求取消并等待活动执行器退出。

运行保存 runner_version、独立 workflow_run_id / task_id、Scope、plan_id / plan_digest、规范化任务预算、显式部分接受策略、模型配置版本、节点和事件。每个插件节点具有独立 node_run_id 与 invocation_id；Agent 分析通过 agent_run_ids 单独关联。节点运行与插件调用在开始前关联，完成后记录输入输出的真实 ArtifactRef。插件产物中的 producer 绑定 invocation_id；所属任务通过执行记录关联，知识发布的 producer 额外写入 task_id。

`ModelRuntime.Freeze` 在任务开始时原子捕获模型配置和公开版本。后续修改应用设置不会替换在途运行使用的模型、端点或凭据；运行记录仅保留模型名称、runtime 与配置版本。候选分析使用该次插件报告冻结的代码 / 安全事实，避免 latest 图谱重建改变分析依据。

| 对象 | 状态 |
|---|---|
| 运行 | CREATED → RUNNING → SUCCEEDED / PARTIAL / FAILED |
| 节点 | PENDING → RUNNING → SUCCEEDED / PARTIAL / FAILED / CANCELLED / TIMED_OUT；未调度依赖为 SKIPPED |

每次状态写入使用 version CAS，与新增事件一同保存；固定任务、计划、Scope、模型配置、终态节点和事件前缀不可改写。事件包含 seq、type、node_id、status、created_at，可按 after_seq 分页。完成运行在重启后可直接读取；本版不承诺硬崩溃后的活动 DAG 自动恢复。

## 调度、覆盖与预算

- 插件调度最多并行两个已满足依赖的节点。输入仅来自计划根产物和该节点的直接依赖，通过 kind、Schema 和 producer 绑定；不会偷取其他同类型分支的结果。
- 执行前核对固定包 / 清单摘要，执行后核对真实产物 Scope、摘要、producer、参数摘要及声明输出。节点超时取固定计划值；单节点输出校验总上限 64 MiB。
- 默认 fail-fast：首个失败或未接受的 PARTIAL 停止新调度，取消并等待活动兄弟调用，未开始节点记 SKIPPED。已提交产物保留；取消无法确认时明确记录 cancellation_unconfirmed，不虚报已停止。
- accept_partial_nodes 只允许计划中的 node_id 及 `$publish` / `$analyze`。接受后继续执行，最终运行仍标记 PARTIAL。未接受时保留节点 PARTIAL 与真实产物，运行 FAILED。
- 路径分支按相同图层版本合并、去重，再按任务 scope 和 max_paths 筛选。预算截断使 `$publish` PARTIAL，需要显式接受。旧路径调度器不会领取工作流任务，避免绕过选择或重复模型调用。
- 当前模型阶段顺序分析至多 10 条候选；其余候选保留并使 `$analyze` PARTIAL。每路径调用、深度、分支预算受任务限制。页面的路径并发预算保留在任务中，当前模型阶段仍顺序执行，插件并行度独立固定为 2。

## 共享知识与标准应用产物

`internal/workflow.NodeExecutor` 负责固定节点的实际执行，`PluginExecutor` 接 PluginHost。`Effects.Bind` 为每次运行捕获独立模型上下文；`Effects.Execute` 接知识发布和候选分析。新增执行器仍须登记插件目录、Schema 与编译器适配器输入协议，不能绕过产物核验。

`$publish` 从完成调用读取真实 AnalysisResult，按插件调用逐批发布不可变知识版本，使用 head CAS 重试，保留已提交的版本。跨层边端点不在本批事实中时省略并计数。整个阶段涉及多个批次，不宣称跨批次事务；后续失败仍保留先前发布证据。代码 / 安全图不存在时从真实报告建立；既有代码图版本冲突时失败，兼容代码图旁缺少安全图时补齐。

应用阶段产物 producer 为 `builtin.workflow@1.0.0`，绑定 node_run_id、task_id 和效果策略摘要：

| kind / schema_id | 内容 |
|---|---|
| `knowledge.view` / `codexploit/knowledge-revisions/v1` | api_version、scope、plan_digest、revisions（revision / digest）、path_origins（插件路径到任务路径的来源映射） |
| `report.document` / `codexploit/workflow-analysis/v1` | 固定计划、任务、模型配置版本、知识版本、Agent 运行列表及分析数量 |

工具提供候选与证据，沿用高中低建议分级；本流程不会自动写入 confirmed 裁定或覆盖人工结论。实际输出与局限可从对应插件调用和原始产物继续追溯。

测试仅位于预先确认的认证 HTTP API 和 WorkflowRunner 公开接口，覆盖并行、直接绑定、fail-fast、部分拒绝、真实链路、模型固定、事件、重启和项目隔离；正式 UI 另做 Docker 浏览器验收。
