# Agent 循环整改 Issues 索引

> 当前#37–#46/#49已关闭，#47/#48/#50/#51仍开放并已按主Agent/覆盖账本修订。下文Sprint/依赖是首次发布历史，不要求重做；参见 [当前实施索引](interaction-issues.md)。

> 2026-10-19 Pi 集成协调：首次协调时 #41–#51 的行为、依赖、指标口径与迁移约束以更新后的 GitHub 正文及 [Pi 执行索引](pi-runtime-issues.md) 为准。下文保留首次规划记录；#37–#40 交付历史不变。脚本基线不作为真实模型 token / 召回基线。

状态：已按草案拆分并发布（2026-10-19）。共 15 项，全部 AFK，标签 `needs-triage`；每项含用户故事、端到端行为、验收条件、真实依赖编号与共同交付约束。

来源：[agent-loop-remediation-draft.md](agent-loop-remediation-draft.md)。该草案的 28 个工作项合并为 15 个可独立交付的 Issue；未合并的能力项单独列出原因。

| 草案 | Issue | 对应工作项 | 阻塞项 |
|---|---|---|---|
| G01 | [#37 记录 Agent 停止质量基线并固定脚本黄金集](https://github.com/UserB1ank/Cod3xplo1t/issues/37) | B01 | 无 |
| G02 | [#38 工具参数与答案校验失败改为可回灌修复](https://github.com/UserB1ank/Cod3xplo1t/issues/38) | D01、D02 | #37 |
| G03 | [#39 结构化截断工具结果并去除重复引用](https://github.com/UserB1ank/Cod3xplo1t/issues/39) | D03、D04 | #37 |
| G04 | [#40 把审计任务改为可判定的义务清单](https://github.com/UserB1ank/Cod3xplo1t/issues/40) | C01、C02 | #37 |
| G05 | [#41 要求每条结论给出可机器核验的反证](https://github.com/UserB1ank/Cod3xplo1t/issues/41) | C03 | #40 |
| G06 | [#42 以渲染文本与会话别名下发任务](https://github.com/UserB1ank/Cod3xplo1t/issues/42) | C04 | #40 |
| G07 | [#43 支持一轮多个工具调用并按预算执行](https://github.com/UserB1ank/Cod3xplo1t/issues/43) | C05 | #38 |
| G08 | [#44 用证据新颖度判定收敛并扩展停止原因](https://github.com/UserB1ank/Cod3xplo1t/issues/44) | S01、S02 | #40、#43 |
| G09 | [#45 预算耗尽时暂停并可从检查点续跑](https://github.com/UserB1ank/Cod3xplo1t/issues/45) | S03、S04 | #44 |
| G10 | [#46 分层运行预算与人工批准的续跑额度](https://github.com/UserB1ank/Cod3xplo1t/issues/46) | S05 | #45 |
| G11 | [#47 用覆盖合同与账本计算审计完成性](https://github.com/UserB1ank/Cod3xplo1t/issues/47) | A01、A02 | #45、#46 |
| G12 | [#48 固定报告生成审计边界与未决前沿](https://github.com/UserB1ank/Cod3xplo1t/issues/48) | A03 | #47 |
| G13 | [#49 原生工具 Schema 与每轮预算回执](https://github.com/UserB1ank/Cod3xplo1t/issues/49) | T01、T02 | #39、#42 |
| G14 | [#50 补齐文本搜索与未解析调用查询工具](https://github.com/UserB1ank/Cod3xplo1t/issues/50) | K01、K02 | #47、#49 |
| G15 | [#51 补齐攻击面查询与仓库地图工具](https://github.com/UserB1ank/Cod3xplo1t/issues/51) | K03、K04 | #40、#49 |

## 未拆分的草案项

- **T03 入口点批量**（`task.mode=entry_batch`）：按草案要求，等 G11 给出 blocker 分布与成本数据后再决定是否立项。
- **M01–M03 记忆与增量**（annotation、跨快照增量、重试注入）：依赖 G11 的账本与 G09 的 frontier 先存在，暂不立项。

两项都不阻塞 G01–G15。

## 排期

| Sprint | Issue | 产出 |
|---|---|---|
| 1 | G01–G03 | 基线数字；不再"一次格式错误就报废整轮" |
| 2 | G04–G07 | 义务闭合、反证核验、任务渲染与别名、并行调用 |
| 3 | G08–G10 | 收敛信号、暂停与检查点、续跑、预算分层 |
| 4 | G11–G13 | 审计完成性可计算、报告边界、原生工具 Schema |
| 5 | G14–G15 | 按 blocker 数据补齐查询能力 |

任一 Sprint 的验收总闸不达标，不推进下一 Sprint。

## 与现有开放 Issue 的关系

- **#19、#20、#21、#27、#28–#36** 与本次改动没有实现重叠：G 系列只改 Agent 循环、编排与审计完成性，不改变插件、验证环境、产物存储与报告既有契约。因此未修改这些 Issue。
- **#22 正式仪表盘**：会消费 G 系列新落库的 run 状态字段（`stop_reason`、义务闭合数、暂停 / 续跑状态）。已在该 Issue 追加一条验收，使仪表盘展示这些真实状态，而不是只展示运行中 / 成功。
- 验证环境系列（#28–#36）与本组无共享代码路径；G 系列的 `frontier`、义务与预算字段对验证计划不可见。

## 交付原则

- 只改 Agent 循环、编排与审计完成性；不改 SCG / ASG 事实语义、插件体系与验证环境。
- 保留既有项目、快照、符号、证据 ID；旧 task / run 记录可读，`schema_version` 1 与 2 共存直到 v2 稳定。
- 每单交付真实后端、持久化、认证 API（如涉及）、测试与文档；失败不得退回演示成功。
- 新测试边界先确认再写；Go 测试兼容 Ubuntu / macOS / Windows；相关测试、完整竞态回归与 `make lint` 通过；文件系统或生命周期变更运行 `make test-stress`。
- 不记录隐藏推理；答案只含显式结论。
- AFK 表示无需额外产品决策即可实现；commit / push 仍需人工授权。
- 不提交凭据、个人信息、运行数据。

## 验收总闸（来自草案 §4）

| 指标 | 目标 |
|---|---|
| 参数 / 格式错误导致 run 失败 | 0 |
| 截断产生的非法 JSON | 0 |
| 开放义务被接受的 run | 0 |
| 预算耗尽且无 checkpoint 的 run | 0 |
| 未经核验的 conclusive 答案 | 0 |
| p50 token/run | 相对 G01 基线 −35% |
| 每确认发现 token | 相对 G01 基线 −50% |
| 播种漏洞召回 | 不降 |
| 同快照重跑结论一致率 | ≥95% |

基线由 G01 产出；未产出基线前，本表只作为方向，不作为通过判据。
