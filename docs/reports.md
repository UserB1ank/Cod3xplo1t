# 固定版本报告

正式任务的“报告”标签和项目的“固定版本报告”共用 `internal/reporting`。
任务报告固定该任务及其快照；项目报告覆盖所选快照，不混合不同代码基线。
报告是 ArtifactStore 中不可变的 `report.document`，预览和下载读取同一引用。
旧 `GET /api/audits/{id}/report` 保留即时渲染兼容行为。

## 固定内容

生成请求必须指定快照、SCG / ASG 固定视图、格式和候选策略，可选任务与共享知识发布版本。
视图通过既有 `/knowledge/views` 创建；生成时及采集结束时再次校验，重建后的旧视图返回
`view_superseded`，不会自动换成当前视图。

图谱版本和发现账本是不同的时间维度：选择 `rev-1` 不会恢复当时的发现裁定。
服务保存生成时的完整发现分组、成员版本、观察、分级审计、证据、任务、路径及覆盖信息，
并记录采集时间、输入产物摘要与所选知识版本。每条插件观察明确标记
`included`、`outside_revision` 或 `not_selected`；只表示该 producer 是否出现在所选共享版本。
旧版本之外的观察仍属于生成时的真实发现账本，不冒充所选图谱中的事实。

发现使用 #13 的版本化指纹分组，跨任务的同组来源不会重复计数或丢失。
候选默认排除，包含时单独计数；严重性 high / medium / low 和确认状态分别表达，
未评估严重性显示待分级。`blocked`、`inconclusive` 不表示已排除。
路径保留原始 `path_kind`、SCG / ASG 版本、覆盖局限和未解决问题；调用可达不声明为污点流。

证据支持两类真实来源：verification Evidence 逐项校验内容摘要及快照；插件原始产物
通过 ArtifactStore 重新校验，报告保存其完整引用信封，不把引用元数据伪装成源码引文。
支持、反对、未决列表分别保留。缺失、损坏、跨快照的引用，以及没有所需证据的
confirmed / refuted 结论，会拒绝生成。

## Reporter 与原子性

`builtin.reporter@1.0.0` 是已安装的内置 reporter，消费 `discovery.findings`
（Schema `codexploit/report-input/v1`），只渲染保存的输入，不读取最新数据库、不扫描目标、
不改变裁定。输出为 `report.document`（`codexploit/report-document/v1`）。

Markdown、JSON 和 SARIF 2.1.0 共用既有 `verify.RenderReport`，关闭旧渲染器的
500 条默认截断。三个格式均保留固定输入与来源；Markdown 另有人可读的覆盖及开放问题，
SARIF 在 result properties 中分别记录 severity、status 和相关路径种类。
报告包含 reporter 版本、包摘要、配置摘要和调用 ID。

采集会完整聚合分页数据，并比较两次完整的版本化输入；期间发生变更返回冲突，要求重试。
这是有界乐观采集，不宣称跨服务事务或历史时点数据库快照。
输入文档成功保存后再登记调用；登记前失败不会创建成功报告。
宿主将成功状态与输出引用在同一事务中发布。准备但未发布的对象不进入产物目录。
预算失败、超时、取消及重启中断均不发布报告输出。

取消沿用插件调用的 If-Match / CAS；即使执行器忽略取消并迟到返回，也不能覆盖终态。
单宿主重启将未完成调用记为 FAILED / `host_restarted`，已完成报告及其内容保持不变。
活动调用阻止快照删除；快照被正式删除后，其报告引用也随现有快照生命周期清理。

宿主包发生变化，因此解析器版本升至 1.2.0、语义 / 路径插件升至 1.1.0；正式工作流模板同步更新。
原有清单、计划与调用记录保留，旧包不会被同版本新摘要覆盖。旧计划需要其固定包，
未安装旧执行器时明确不可执行；新执行需选择已安装版本重新编译。

## 认证 API

公共响应经 `contracts/v1/report-runtime.schema.json` 校验。

| 接口 | 权限与行为 |
| --- | --- |
| `POST /api/v1/projects/{projectID}/reports` | writer；返回 202 和 `report` 调用，支持持久化 Idempotency-Key |
| `GET /api/v1/projects/{projectID}/reports?snapshot_id=...` | reader；`cursor`、`limit`（默认 50，最大 100）、可选 `task_id` |
| `GET /api/v1/projects/{projectID}/reports/{reportID}?snapshot_id=...` | reader；保存的状态、固定选择、输入 / 输出及 ETag |
| `POST .../snapshots/{snapshotID}/plugin-invocations/{reportID}/cancel` | writer；既有 If-Match 取消接口 |
| `GET .../snapshots/{snapshotID}/artifacts/{artifactID}/content` | reader；既有认证内容下载，读取前校验完整性 |

创建示例（标识符需替换为同项目的真实对象）：

```json
{
  "api_version": "codexploit/v1",
  "snapshot_id": "snapshot-example",
  "task_id": "task-example",
  "view_id": "view-example",
  "knowledge_revision": "rev-1",
  "format": "json",
  "include_candidates": false,
  "max_findings": 2000,
  "max_paths": 10000,
  "budget": { "max_output_bytes": 16777216 }
}
```

`format` 只接受 md / json / sarif；项目报告省略 task_id。
省略 knowledge_revision 使用 rev-0，表示不引用共享发布版本，界面明确标注。
目录游标遍历宿主调用目录后筛选 reporter / task，因此一页可能为空但仍有 next_cursor；
客户端必须继续使用该游标，不能把空页当作目录结束。

默认输入 64 MiB、输出 16 MiB、超时 60 秒、发现 2,000 组、路径 10,000 条。
上限为输入 256 MiB、输出 64 MiB、超时 120 秒、发现 10,000 组、路径 20,000 条；
项目聚合最多 1,000 个任务。发现服务触及其 10,000 条收集上限时声明截断，报告拒绝成功。
超限返回 413，采集变更和缺失证据返回 409，采集中断返回 408；不静默省略尾页。
未认证 401、reader 写入 403、项目 / 快照 / 任务不匹配 404、能力不可用 501。

## 页面验收

页面显示五种确认状态的独立计数，以及独立的高 / 中 / 低 / 待分级统计。
生成失败保留原因；不会使用原型数据补空。reader 可查看与下载，writer 才可生成或取消。
Markdown 以文本预览，不执行 HTML；预览最多显示 100,000 字符，并明确标注截断。
浏览器完整读取最多 64 MiB，在核对字节数及 SHA-256 后才开启预览或保存下载。

验收覆盖真实 HTTP API、Memory / SQLite、超过一页的发现、三种格式、候选策略、分组来源、
旧知识版本、授权下载、预算失败、取消迟到输出、快照删除栅栏及数据库重启。
隔离容器使用合成 Go 服务和真实 process scanner；不执行目标 build / test / hook。
