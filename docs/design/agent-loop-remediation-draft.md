# Agent 循环整改方案（草案）

状态：已拆分并发布为 GitHub Issue #37–#51，索引见 [agent-loop-issues.md](agent-loop-issues.md)。本文保留为设计与验收依据；未立项项（T03、M01–M03）的取舍理由见索引。
范围：只改 Agent 循环、编排与审计完成性；不动 SCG / ASG 事实层语义、插件体系与验证环境。
目标：把"是否完成"从模型自评改成账本计算，把预算从终止信号改成可续资源，把循环成本降到可测量。

---

## 0. 诊断结论（带代码位置）

| # | 事实 | 位置 |
|---|---|---|
| 1 | 工具参数类型错误直接终止 run：once `json.Unmarshal` into `map[string]string` fails, the run returns an error and all prior tokens are lost | `internal/agent/llm.go` `runModel` |
| 2 | 答案结构/证据校验失败同样终止 run，没有修复回合 | `internal/agent/llm.go`、`agent.DecodeAnswer` |
| 3 | 结果截断是字节切片 `result[:20000]`，能把 JSON 切成非法文档；`toolJSON` 本身没有上限（只有 `toolText` 有 8000） | `internal/agent/protocol.go` `TruncateToolResult`、`internal/graph/agenttools.go` `toolJSON` |
| 4 | `TokenBudget` 默认 0 = 不强制；`ToolResult` 不回传余额 | `internal/agent/model.go` `DefaultExplorationPolicy` |
| 5 | `RunPaused`、`path.StatusBlocked`、`path.StatusPaused` 已定义但 Agent 运行侧从未使用 | `internal/agent/model.go`、`internal/path/model.go` |
| 6 | 任务没有可判定的完成条件，答案没有义务闭合检查；收敛只能靠 `MaxRepeatedOutputs` | `internal/agent/model.go` `Task` / `Answer` |
| 7 | 工具名与签名在 system prompt 里出现两次，`refs[]` 与 payload 内 id 重复 | `internal/agent/llm.go` `modelInstructions`、`internal/graph/agenttools.go` |
| 8 | 没有代码文本搜索、没有 `list_unresolved_calls`、没有 ASG 查询工具 | `internal/graph/agenttools.go` `agentToolNames` |

---

## 1. 整改原则

1. **可判定优先于舒适**：任何让模型"更快给结论"的优化，必须在黄金集上证明召回不降。
2. **可续优先于终止**：资源耗尽产生检查点，不产生半结论。
3. **abstain 是一等公民**：`unknown + blocker` 是合法终态，且必须比猜测更划算。
4. **先测量再改**：B01 不完不进入后续任何一项。
5. **复用既有词表**：不新增状态机名词，只接线 `RunPaused` / `StatusBlocked` / `StatusPaused`。

---

## 2. 工作项

规模：S ≤ 半天，M ≤ 2 天，L ≤ 4 天（含测试与文档）。
"首个测试"是 TDD 的 red 边界；按 `AGENTS.md`，新测试边界先确认再写。

### Phase 0 — 基线（阻塞项）

| ID | 目标 | 改动点 | 首个测试 | 验收 | 依赖 | 规模 |
|---|---|---|---|---|---|---|
| B01 | 停止质量的埋点与黄金集 | `internal/agent/runner.go` 记录 rounds / tool_calls / tokens / novelty(%) / invalid_calls / truncations；`internal/agent/testdata/golden/` 20 条 scripted 场景（seeded 漏洞 5、已知安全 5、真不可判定 5、边界 5）；`make bench-agent` 打印汇总 | `agent_test`：同一脚本两次运行，结论与计数逐字节一致 | 20 条全部有确定 `stop_reason`；`novelty` 可作为后续判据 | 无 | M |

golden 场景先用 `ScriptedRuntime`（`internal/agent/scripted.go`），不依赖真模型；真模型只用于质量评测。

### Phase 1 — 缺陷修复（不依赖设计决策）

| ID | 目标 | 改动点 | 首个测试 | 验收 | 依赖 | 规模 |
|---|---|---|---|---|---|---|
| D01 | 参数类型错误可修复 | `llm.go` 解析失败不再返回 error，改为产出纠错工具消息；新增 `MaxRepairs=2`（独立计数，不占 tool 预算） | `runModel` 收到数字型 `max_depth` 后继续，且事件记录 `output_rejected` | 2 次修复后仍失败才算 `invalid_output`；参数类型错误导致的 run 失败 = 0 | 无 | M |
| D02 | 答案校验失败可修复 | 把 `DecodeAnswer` 的第一条错误回灌给模型，走同一修复预算 | 校验器拒绝 `confirmed` 时 run 继续并最终产出合法答案 | 黄金集上 answer 合法率 ≥ 99% | D01 | S |
| D03 | 结构化截断 | 删除字节切片；每个工具在序列化前按结构裁剪（nodes ≤ 20、paths ≤ 3、refs ≤ 40、symbols ≤ 50、text ≤ 8k rune、JSON ≤ 8k）；runner 兜底改为返回 `{"error":"result_too_large","hint":"narrow the query"}` | 取上限参数跑全套工具，断言每个结果可 `json.Unmarshal` | 截断产生的非法 JSON = 0 | 无 | M |
| D04 | 去重与预算 footer | `refs` 只放 payload 之外的 id；system prompt 删除重复工具清单；每个工具结果追加 `_budget{calls_left,tokens_left,repairs_left}` | `ToolResult` 序列化测试：同一事实的 id 不出现两遍 | 单次工具结果 token 降 15%+ | 无 | S |

### Phase 2 — 可判定性

| ID | 目标 | 改动点 | 首个测试 | 验收 | 依赖 | 规模 |
|---|---|---|---|---|---|---|
| C01 | 义务清单 | `agent.Task` 增 `Obligations []Obligation`；`graph.AgentFacts.BuildTask` 从 path 形状机械生成 4 条（source / flow / control / sink）；`schema_version=2`，v1 任务仍可读 | 生成器：给定 path，产出 4 条义务且 id 确定 | 同一 path 两次生成逐字节一致 | 无 | M |
| C02 | 义务闭合校验 | `DecodeAnswer` 要求逐条 verdict（`met/not_met/unknown+blocker`）；`runner.applyAnswer` 在存在 open 义务且非 abstain 时拒绝 | 4 条义务留 1 条 open 的答案被拒绝，且 run 继续 | 开放义务被接受的 run = 0 | C01 | M |
| C03 | falsifier | `Answer` 增 `falsifier{claim,checked,how}`；`runner` 校验 `how` 引用的 call_id / 证据确实出现在本 run 事件里 | 声明 checked 但无对应工具事件的答案被拒绝 | 未经核验的 conclusive 答案 = 0 | C02 | S |
| C04 | task 渲染 + 别名 | `Task.Render()` 取代 `json.Marshal`；`AliasTable`（S/A/C/E/P）按首次出现编号，工具参数与证据引用都接受别名；存储与事件保留真 id | 渲染输出快照测试 + 别名往返测试（别名 → 真 id → 别名） | 单 run task 输入 token 降 ≥ 35% | C01 | M |
| C05 | 并行工具调用 | `llm.go` 接受 1..N 个 call，按剩余预算执行；事件按请求顺序成对记录 | 一轮两个 call 的脚本：两个 `tool_result` 都出现，run 继续 | 黄金集 p50 轮数降 30%+ | D01 | M |

### Phase 3 — 收敛与续跑

| ID | 目标 | 改动点 | 首个测试 | 验收 | 依赖 | 规模 |
|---|---|---|---|---|---|---|
| S01 | novelty 收敛 | 按证据 id / 代码位置 / 边计新颖度（不按调用计）；连续 K=3 轮为 0 触发 `StopNoNewEvidence` | 重复同一查询的脚本在 K 轮后停止 | 黄金集上 novelty=0 后 ≤ K 轮内停 | C02 | M |
| S02 | stop_reason 扩展 | 增 `obligation_open`、`blocker`、`no_new_evidence`、`budget_paused` | `stop_reason` 合法性表测试 | 每个 run 必有 `stop_reason` | S01 | S |
| S03 | paused 终态与检查点 | 接线 `RunPaused`；`harness` 保存已闭合义务、证据引用、`frontier[]`；预算 hard cap 触发 checkpoint | 预算耗尽的脚本产出 `PAUSED` + 非空 `frontier`，且不产出结论 | 预算耗尽无 checkpoint = 0 | S02, C02 | M |
| S04 | 续跑 | `resume` 创建 `resume_of` 新 run，只处理 open 义务与 frontier；已闭合义务不重算 | resume 后不重复调用已闭合义务对应的工具 | 续跑 token ≤ 首跑 60% | S03 | L |
| S05 | 预算分层 | soft / hard / audit 三层；audit 层超限需 writer 批准 `resume +N`；默认 hard = 60k/run | 超 audit 预算的 resume 被拒绝并记录审计 | 无未批准的预算超限 | S03 | M |

### Phase 4 — 审计完成性

| ID | 目标 | 改动点 | 首个测试 | 验收 | 依赖 | 规模 |
|---|---|---|---|---|---|---|
| A01 | 覆盖合同 | 审计创建时固定 `coverage_contract`（`min_entry_coverage`、`required_sink_kinds`、`max_unresolved_ratio`），不可变 | 合同创建后修改被拒绝 | 报告中的合同与创建时逐字节一致 | 无 | M |
| A02 | `AuditComplete(ledger)` | 纯函数：入口点三分类、高风险 sink 覆盖、路径终态、frontier 分类、无未批准 pause | 表驱动测试覆盖 6 种账本状态 | 同一账本两次计算一致 | A01, S03 | M |
| A03 | 报告"审计边界"节 | `internal/reporting` 从账本生成该节，含覆盖、未决 frontier、无法判定原因 | 报告快照测试（同一账本 → 同一节） | 该节字段全部可追溯到账本 | A02 | M |

新迁移：SQLite `0026`、PostgreSQL `0008`（合同、frontier、义务聚合视图；若复用 path JSON 则只需合同表）。`0025` / `0007` 已由 #37 的 run 指标占用。

### Phase 5 — 成本（正交优化）

| ID | 目标 | 改动点 | 首个测试 | 验收 | 依赖 | 规模 |
|---|---|---|---|---|---|---|
| T01 | 原生 tool schema | `ToolExecutor` 增 `Schema()`；`ModelRuntime` 从 registry 构造 tools，删除 prose 签名；参数走原生类型 | 每个工具 schema 快照测试 + 一次真实调用往返 | 参数类型错误率降 90% | C04 | M |
| T02 | 预算/进度 footer | 见 D04，扩展到义务进度：`closed/total` | footer 快照测试 | 模型每轮可见剩余义务数 | D04, C02 | S |
| T03 | 入口点批量（暂缓） | `task.mode=entry_batch`，一个 run 覆盖 ≤5 条同源路径，共享切片 | 批量 run 的切片只出现一次 | 同源 5 条路径 token 降 40% | S04, A02 | L |

T03 在 A 阶段出数之后再决定是否做。

### Phase 6 — 能力（由 blocker 频率驱动）

| ID | 工具 | 说明 | 依赖 |
|---|---|---|---|
| K01 | `search_code` | 字面/正则、glob 过滤、matches ≤20、行文本 ≤200 字符；只读冻结树 | A02 的 blocker 统计 |
| K02 | `list_unresolved_calls` | 对齐 MCP 面，增 `reason` 过滤（dynamic/ambiguous/external/unsupported） | 无（可提前） |
| K03 | ASG 查询 | `list_entry_points`、`list_sinks`、`get_asg_node` | 无 |
| K04 | `repo_map` | 顶层模块、入口点分布、sink 分布、未解析率 Top5，≤500 token | 无 |

排序规则：按 `blocker` 出现频率建，不按直觉建。K02/K03 可先做（成本低、风险低）。

### Phase 7 — 记忆与增量（暂缓）

| ID | 目标 | 依赖 |
|---|---|---|
| M01 | symbol 级 annotation（note/negative/decision，带证据、TTL、`subject_hash` 失效） | A02 |
| M02 | 跨快照增量：`changed_symbols` + finding 指纹去 snapshot 维度 | M01 |
| M03 | 失败重试注入上次 hypothesis + blocker | S04 |

---

## 3. 排期

| Sprint | 内容 | 产出 |
|---|---|---|
| 1（约 1 周） | B01、D01–D04 | 基线数字 + 无"一次错误就报废"的 run |
| 2（约 1.5 周） | C01–C05 | 义务闭合、falsifier、task v2、并行调用 |
| 3（约 1 周） | S01–S05 | 收敛信号、paused、续跑、预算分层 |
| 4（约 1 周） | A01–A03、T01–T02 | 审计完成性可计算、成本下降 |
| 5（按数据） | K01–K04、T03 | 能力补齐、粒度优化 |
| 暂缓 | M01–M03 | — |

---

## 4. 验收总闸

| 指标 | 基线 | 目标 |
|---|---|---|
| 参数/格式错误导致 run 失败 | 存在 | 0 |
| 截断产生的非法 JSON | 可达 | 0 |
| 开放义务被接受的 run | 不适用 | 0 |
| 预算耗尽且无 checkpoint 的 run | 全部 | 0 |
| 未经核验的 conclusive 答案 | 不适用 | 0 |
| p50 token/run | B01 实测 | −35% |
| 每确认发现 token | B01 实测 | −50% |
| 播种漏洞召回 | B01 实测 | 不降 |
| 同快照重跑结论一致率 | — | ≥95% |

任一项不达标，不得推进到下一 Sprint。

---

## 5. 兼容与迁移

- `task.schema_version`：1 与 2 共存；调度器按项目配置选择，v1 路径在 v2 稳定后保留一个版本周期。
- `Answer`：v2 增加 `obligations`、`falsifier`；对 v1 任务的答案仍按 v1 校验。
- 状态机：只接线既有 `RunPaused` / `StatusBlocked` / `StatusPaused`，不新增名词。
- 迁移：SQLite `0025`、PostgreSQL `0007`；Memory 实现同步补齐。
- 旧 run 记录不回填，新增字段可空，报告对缺失字段显式标注"未记录"。

---

## 6. 风险与缓解

| 风险 | 缓解 |
|---|---|
| 义务过严，全部落 `unknown` | 在黄金集上调；`unknown` 占比 >60% 的 path 自动标 `needs_human`；blocker 分类统计后回头改生成规则 |
| `paused` 无限续跑，审计永不完成 | audit 预算上限；每次 resume 需 writer 批准；超过 3 次自动转 `BLOCKED(needs_human)` |
| 修复回合被滥用 | `MaxRepairs=2`，独立计数，超限按 `invalid_output` |
| 并行调用打乱事件语义 | 同 `call_id` 成对；请求按发出顺序、结果按返回顺序追加 |
| novelty 被"换个 limit 再查"伪造 | 按证据 id / 位置 / 边计，不按调用计 |
| v2 迁移拖长 | 双版本共存 + 项目级开关，v1 路径在 Sprint 3 前保持默认 |

---

## 7. 明确不做

- 不把 SCG / ASG 改成面向模型的新格式；图仍在服务端计算。
- 不做独立 verifier 模型；先用 falsifier + 账本。
- 不做 entry_batch，直到 A 阶段有数据。
- 不做跨快照增量，直到 frontier 与 annotation 存在。
- 不改插件、验证环境与报告既有契约；A03 只新增一节。

---

## 8. 第一天

1. 建 `internal/agent/testdata/golden/` 的 20 条 scripted 场景（先写 4 条：正常作答、开放义务、参数类型错误、预算耗尽）。
2. 写 B01 的第一个测试：同一脚本两次运行结论与计数逐字节一致（red）。
3. 同时写 D01 的 red：数字型 `max_depth` 不应终止 run。

这两条红一旦出现，整个整改就有了可回归的锚点。
