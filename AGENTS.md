## Security & Privacy

禁止在项目中出现以下敏感信息和敏感文件：

- 本机 hostname、本地用户名称
- 真实密钥、API keys、tokens、passwords
- 邮箱地址、手机号等个人信息
- .env 文件、私钥文件（PEM、SSH key 等）
- 禁止出现 `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` 相关字样
- 只有在人工同意后才能push和commit。在多次commit后，人工要求push再进行push，绝对不要主动push。

## Issue delivery workflow

用户已明确授权以下办事流程：每完成并验收一个 Issue，更新本文件的完成记录，执行 commit，关闭对应 GitHub Issue，然后推进下一个未阻塞的 Issue。此授权覆盖按该流程交付的 Issue 的 commit 和关闭操作，无需逐次重复确认；push 仍必须等待用户明确要求。

- 使用 TDD，在已确认的公开边界逐个完成 red → green；新测试边界先按技能要求确认。
- 交付包含真实后端、认证 API、正式 UI、持久化、文档与适当验收；失败不得退回演示成功。
- 提交前检查差异与隐私，运行相关测试、完整竞态回归、前端测试/构建及 `make lint`；涉及文件系统或生命周期时运行 `make test-stress`。
- 每个 Issue 独立提交，使用可说明最终行为的提交信息。提交成功后用 `gh issue close --reason completed` 关闭，再按依赖继续。

### Completed issues

- 2026-10-17 — #1 本地文件夹代码源生成真实快照并创建任务：支持项目多代码源、受控目录采集、当前文件内容、不可变快照与任务绑定、SQLite 重启恢复和旧 API 兼容。已通过 TDD red/green、三轮乱序竞态回归、`make lint`、前端测试/构建、Docker 构建及浏览器验收；提交 `5816c0c`，Issue 已关闭。PostgreSQL 和 Git v1 provider 属于后续 Issue。
- 2026-10-17 — #2 Git 仓库固定提交并创建可复现任务：正式代码源页面支持 HTTPS / SSH、分支 / 标签 / 提交、固定快照与任务绑定；凭据引用校验项目与 origin，SSH 固定身份与 known_hosts；分支及默认 HEAD 移动不影响旧快照。已通过 TDD red/green、三轮完整乱序竞态回归、`make lint`、前端测试/构建、Docker 构建，以及合成 HTTPS / 真实 SSH 远端的页面验收；提交 `8256701`，Issue 已关闭；未 push。
- 2026-10-17 — #3 任务分类、置顶、归档与恢复持久化：正式任务表支持项目共享分类、搜索、状态/分类筛选和稳定排序分页；任务与分类目录分别使用 ETag/CAS 拒绝陈旧及并发写入。归档要求暂停且无活动路径或运行，保留任务、证据及图谱引用；恢复后保持暂停。Memory / SQLite 的认证 HTTP API 已覆盖项目隔离、并发冲突、实时路径状态、归档恢复及数据库重启；完整乱序竞态回归、三轮稳定性测试、`make lint`、前端测试/构建和 Docker 构建通过，浏览器已验收真实操作及容器重启恢复。按交付流程提交并关闭；未 push。
- 2026-10-17 — #4 正式页面查看、校验并下载快照产物：`internal/artifact` 本地内容寻址存储按暂存 → 核对大小与 SHA-256 → 原子建对象 → 事务发布推进，读取前重新核对并拒绝缺失、损坏与链接逃逸；Memory 与 SQLite 保存同一不可变引用、Scope 归属和快照删除栅栏。`/api/v1/projects/{id}/snapshots/{id}/artifacts` 提供 reader 目录、writer 登记、校验元数据与流式下载（摘要 ETag、Content-Length、attachment、nosniff），预算、冲突与损坏先于成功响应返回 413/409。正式“产物与证据”页接通项目、快照详情与任务固定输入，展示 kind、摘要、大小、Scope 与 producer，支持校验、有界 JSON 预览和下载后浏览器复核摘要，失败呈现真实错误而不退回演示成功。共享采集输入早于任务产生，Producer `task_id` 改为可选。已通过 TDD red/green、完整乱序竞态回归、三轮稳定性测试、`make lint`、前端测试/构建，并在独立 Docker 容器完成目录、校验、下载、重启恢复、源目录变化后的冻结内容、同尺寸损坏与恢复的接口及页面验收。按交付流程提交并关闭；未 push。
- 2026-10-17 — #5 正式图谱页面探索固定快照的真实代码事实：`internal/knowledge` 在现有 SCG / ASG / 路径查询之上提供自描述、重启可验证的固定视图（scope + 图层版本 + built_at），`symbols`、`neighborhood`、`nodes`、`paths`、`code_slice`、`provenance` 全部按 pin 读取，重建后旧视图返回 `view_superseded` 而不是隐式换版；路径按快照与版本过滤并报告 `stale_layer_version` 省略数。`/api/v1/projects/{id}/knowledge/views` 提供 reader 可用的认证接口，响应经 `contracts/v1/view.schema.json` 校验，旧 `/api` 图谱接口保持兼容。正式“共享知识图谱”页接通三个图层、键盘行选择、覆盖与截断说明、空图 / 未构建 / 不可用 / 失效状态，以及源码切片、调用方和来源（插件、版本、配置摘要、共享任务、原始产物）。已通过 TDD red/green（两个已确认边界）、完整乱序竞态回归、三轮稳定性测试、`make lint`、前端测试 / 构建，并在独立 Docker 容器完成三层目录、节点抽屉、项目隔离与重启恢复的接口及浏览器验收。按交付流程提交并关闭；未 push。

- 2026-10-17 — #6 版本化插件与内置 Go 解析：实现插件目录、不可变版本 / 包摘要、真实 Go AST / facts、原子输出发布、预算、CAS 取消、单宿主重启中断状态与正式插件中心；接口文档见 `docs/plugins.md`。外部清单登记后明确标记执行器未安装，内置解析保留输入、配置、覆盖范围和输出来源，兼容既有符号 ID。已通过完整乱序竞态回归、修正切片共享竞态后的十轮相关竞态用例、完整三轮 `make test-stress`、`make lint`、前端测试 / 构建及 Docker 构建；独立容器已完成认证 API、原子预算失败、项目隔离和重启恢复验收。内置浏览器已验收清单导入、真实解析、无效参数拒绝、覆盖范围、AST JSON 预览、下载后摘要核对，以及容器重启后的清单 / 调用恢复。按交付流程提交并关闭；未 push。
- 2026-10-17 — #7 内置语义与路径插件输出标准候选：将真实 ASG / 路径引擎接为固定版本工具，显式绑定解析与语义上游调用，产出原始报告、security.facts、discovery.paths 和标准 AnalysisResult；Normalizer 校验来源、Scope、图层版本及 canonical 引用，区分调用可达 / 假设和完整度，仅输出候选与高中低分级建议，不写入既有裁定。规范化失败仅保留原始证据；预算失败和取消不发布半成品。修正路径读取器只取 ASG 第一页的问题，1100 入口样例验证枚举与跳过数量、默认 / 显式路径预算和截断说明。解析器因宿主包变更升至 1.1.0，旧清单与调用保留。已通过两个已确认边界的 TDD red/green、完整乱序竞态回归、三轮 `make test-stress`、`make lint`、前端测试 / 构建和 Docker 构建；独立容器与正式页面已验收解析 → 语义 → 路径、候选证据与局限、无效能力拒绝、预算截断、产物预览 / 下载摘要、canonical 符号兼容及重建恢复。接口文档见 `docs/builtin-analysis.md`；共享图层原子发布仍由 #8 接入。按交付流程提交并关闭；未 push。
- 2026-10-17 — #8 原子发布共享图谱版本并查看多工具来源：新增 `internal/publication` 发布器，把已完成插件调用的标准结果作为 GraphBatch 原子发布为不可变版本（`rev-N`）：版本 CAS（`base_revision` 必须等于 head）、同批次同摘要幂等 / 不同摘要冲突、scope 与孤立边校验、冲突属性保留为独立 observation，版本行、批次索引与 outbox 事件在同一事务提交，失败批次不可见。`POST /api/v1/projects/{id}/knowledge/publications`（writer）由宿主从 invocation 解析标准结果并绑定任务；`GET .../knowledge/revisions` 与 `GET .../knowledge/revisions/{view}/facts`（reader）按自描述版本读取事实与全部来源，不会被 latest 替换。正式图谱页新增“共享知识版本”面板，可选择版本并展开同一事实的多工具观察（插件、任务、属性）。跨层边不属于本批事实时省略并计数，不伪造端点。已通过两个已确认边界的 TDD red/green、完整乱序竞态回归、三轮 `make test-stress`、`make lint`、前端测试 / 构建与 Docker 构建；独立容器完成两任务发布、旧版本不变、重启后版本与事实可读，并完成版本选择与多来源展开的浏览器验收。按交付流程提交并关闭；未 push。

- 2026-10-17 — #9 工作流版本与真实编译计划：正式“工作流”页以同一 WorkflowSpec 支持图形 / JSON 编辑、文件导入导出、项目内不可变版本、head CAS 和固定计划读取。WorkflowCatalog / WorkflowCompiler 校验字段 Schema、插件执行器、参数、超时、环路、直接依赖、输入类型 / Schema / producer 与歧义；独立 source 字段区分根输入和名为 root 的节点。计划固定完整定义、插件包 / 清单 / 配置摘要、真实输入、知识版本和预算，编译不创建插件调用或模拟运行状态。Memory / SQLite 保存版本、head 与计划；快照删除栅栏阻止迟到写入。新增公共 workflow-runtime Schema 和 `docs/workflows.md`。已通过两个已确认边界的 TDD red/green、并发 CAS / 取消 / 项目隔离 / 旧计划不变测试、完整乱序竞态回归、最终三轮 `make test-stress`、`make lint`、前端测试 / 构建与 Docker 构建；独立容器和正式页面已验收图形 / JSON 同步、参数错误、不兼容输入拒绝、文件导入、新旧版本、真实三节点编译与重启恢复。已部署本地 Docker 服务并保留原数据卷和应用内 LLM 设置；按交付流程提交并关闭；未 push。工作流执行由 #10 接入。
- 2026-10-17 — #10 从任务选择工作流并执行真实内置分析 DAG：任务创建接受固定 `workflow_plan_id`，按计划执行真实 `parse → semantic → paths → $publish → $analyze`，独立节点并行调度，失败取消兄弟节点并跳过下游，PARTIAL 必须显式接受（节点或应用阶段），否则运行失败且不写入半成品。每个节点运行与插件调用使用独立 ID（`node_run_id` / `invocation_id`），运行记录保留计划摘要、知识版本、产物、Agent run ID 与固定模型 / 配置版本；候选分析只产出候选与分析结果，不写入已确认裁定。Memory / SQLite 持久化运行、节点与有序事件，活动运行阻止快照删除并拒绝把旧调度暂停当作流程暂停。新增 `workflow-run` 公共 Schema、`docs/workflow-execution.md`，正式任务页接入计划选择、节点状态、输入输出与事件。已通过两个已确认边界的 TDD red/green、完整乱序竞态回归、三轮 `make test-stress`、`make lint`、前端测试 / 构建与 Docker 构建；独立容器与正式页面已验收真实五节点执行、4 条候选关联 4 个独立 Agent 运行、候选预算截断且未接受部分覆盖时明确失败、17 个产物摘要核对，以及容器重启后运行文档逐字节一致。按交付流程提交并关闭；未 push。

- 2026-10-17 — #11 工作流暂停、取消、重试与重启恢复：`workflow.Runner` 新增 `Pause / Resume / Cancel / Retry / Recover` 与 PAUSING / PAUSED / CANCELLING 状态机；暂停只阻断新节点、活动节点到边界完成，取消等待执行器并把迟到结果记为 `node_result_rejected`。只有标记为可重试的错误与超时按指数退避重试，单节点上限取任务 `max_attempts`（默认 3，1–10），耗尽以 `retry_exhausted` 失败，取消与非法输入不重试；并发上限取 `max_active_leases`（默认 4，1–16）并固定写入运行记录。节点写入 `attempt` / 租约，重启时 `Recover` 回收 RUNNING 节点继续执行，已成功节点复用原调用与产物；`retry` 仅对 FAILED 生效，创建带 `retry_of` 的新运行并复用已完成节点，不重复发布产物。暂停 / 活动 / 取消中的运行继续阻止快照删除。新增 `POST .../workflow-runs/{id}/pause|resume|cancel|retry`（writer、幂等、项目隔离），正式任务页提供控制按钮、尝试次数与并发策略展示，运行 Schema 扩展新状态与字段，`docs/workflow-execution.md` 补充控制与恢复语义。已通过两个已确认边界的 TDD red/green（暂停边界与重复请求、取消迟到结果、可重试 / 不可重试 / 耗尽、重启复用、重试血缘）、完整乱序竞态回归、三轮 `make test-stress`、`make lint`、前端测试 / 构建与 Docker 构建；容器内验证“暂停 → 页面继续 → 完成”全链路（12 个有序事件、并发 4 / 重试上限 3），暂停时 parse 已完成、应用阶段未调度。按交付流程提交并关闭；未 push。

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues via `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Project docs live under `docs/` (`docs/mcp-tools.md`, `docs/api.md`, `docs/architecture.md`, `docs/design/`).

### Releases

Use the release PR process in `docs/releasing.md` before tagging. Give the PR
a `release/vX.Y.Z` head branch or `release: vX.Y.Z` title, run
`make prepare-release RELEASE_VERSION=vX.Y.Z`, and review the generated
changelog and `server.json` changes. CI checks both files before merge.

### Tests run in CI on three OSes

Whenever you write or modify a test, remember it must pass in
`.github/workflows/test.yml` — ubuntu, macos and windows, via
`go test ./... -count=1 -shuffle=on -race -timeout 240s` (identical to
`make test`). For races the detector cannot see — filesystem and lifecycle
races — run `make test-stress` locally before pushing. Assume concurrency, a
fresh runner, and dirty state from other tests or processes. Never hardcode a
shared absolute path; `t.TempDir()` is the default. See
`docs/agents/testing.md`.

Static analysis is a gate too: the `lint` job runs `make lint` (gofmt over the
files `git ls-files` returns, `go vet`, and Staticcheck at the version pinned in
the Makefile) on ubuntu. Run `make lint` before pushing — a new Staticcheck
finding, including unused code, fails CI.
