# Pi 运行时 Issues 执行索引

> #56–#62已关闭；首次Pi集成排期已完成。新主Agent不等于重写运行时，接下来按 [当前实施索引](interaction-issues.md)与 [DeepSeek接手指南](deepseek-handoff.md)开发。

日期：2026-10-19。状态：#56–#62已关闭，以下为首次发布与依赖历史。

总览：[#56 Pi 内核集成总计划](https://github.com/UserB1ank/Cod3xplo1t/issues/56)。完整方案：[pi-runtime-plan.md](pi-runtime-plan.md)。GitHub 各 Issue 正文自包含，可直接交给 DeepSeek；本地文档尚未 commit / push。

| 顺序 | Issue | 类型 | 阻塞项 |
|---|---|---|---|
| P1 | [#57 统一 Agent 宿主轮次许可、答案纠错与真实轮次指标](https://github.com/UserB1ank/Cod3xplo1t/issues/57) | AFK | #38, #39, #40|
| P2 | [#58 通过固定版本 Pi worker 完成真实路径分析并回灌图谱工具](https://github.com/UserB1ank/Cod3xplo1t/issues/58) | AFK | #57, #42, #49|
| P3 | [#59 从正式任务选择 Pi 并固定工作流运行时与模型配置](https://github.com/UserB1ank/Cod3xplo1t/issues/59) | AFK | #58|
| P4 | [#60 让 Pi 分析复用宿主批次预算、反证核验和收敛规则](https://github.com/UserB1ank/Cod3xplo1t/issues/60) | AFK | #58, #41, #43, #44|
| P5 | [#61 从宿主检查点续跑 Pi 并在重启和租约失效时拒绝旧结果](https://github.com/UserB1ank/Cod3xplo1t/issues/61) | AFK | #59, #60, #45, #46|
| P6 | [#62 建立 llm 与 Pi 真实模型对照评测并验收两种部署](https://github.com/UserB1ank/Cod3xplo1t/issues/62) | HITL | #59, #60, #61|

## 旧 Issue 调整

已更新开放 #20、#22、#41–#51，共 13 项。没有关闭、重开或修改已完成 Issue。

- #41：沿既有 inconclusive 词表、宿主反证 / 输出纠错；不能把调用存在当语义证明。
- #42 / #49：Go 唯一渲染 / 别名与原生工具描述符，两个 runtime 共用。
- #43 / #44：宿主批次预算；真实模型轮次统计；按整轮证据并集计算 novelty。
- #45 / #46：领域检查点与全局预算由 Go 实现，#61 仅接 Pi；配置缺版本明确阻断。
- #47 / #48：账本决定完成性，报告保留真实 runtime pin；迁移号实施时分配。
- #20 / #22：备份 / 仪表盘正确消费新增状态与来源。
- #50 / #51：继续在 Go 实现领域工具，通过 #49 自动供 llm / pi 使用。

## 给 DeepSeek 的顺序

先 #57；其后 #42 → #49；#41 / #43 可在 #57 后推进，#44 跟随 #43。完成 #49 后做 #58，再做 #59 和 #60。领域续跑 #45 → #46 不依赖 Pi，可先推进；#61 等 #59 / #60 / #45 / #46。最后 #62 真实对照与部署验收，默认值另待人工决定。

已关闭 #37–#40 不重做；脚本黄金集不能证明真实模型成本 / 召回。每单按 AGENTS.md 的测试边界确认与验收流程；遇 WIP / 全量编译失败先确认根因，不删除他人工作，不排除失败包后声称全量通过。

本轮只交方案 / 文档与 GitHub Issue，无实现代码、commit 或 push。
