# 插件互操作与虚拟化漏洞验证 Issues 索引

> 2026-10-21已同步#28–#36及#21，保留已有评论中的动态执行授权。#29现在服务默认四阶段增强；主Agent不扩大验证权限，参见 [当前实施索引](interaction-issues.md)。

状态：已由用户确认，并于 2026-10-19 发布 GitHub。共 9 项：7 项 AFK、2 项 HITL；包含 50 条专项验收条件。

来源：[已批准的拆分草案](plugin-verification-issues-draft.md)。每项包含用户故事、端到端行为、验收条件、真实依赖编号及共同交付约束，标签均为 `needs-triage`。

| 草案 | Issue | 类型 | 阻塞项 |
|---|---|---|---|
| V01 | [#28 在插件中心和工作流编译时核验版本化能力与输入输出契约](https://github.com/UserB1ank/Cod3xplo1t/issues/28) | AFK | 无新增阻塞 |
| V02 | [#29 确定性路径增强插件接入一键分析并解释筛选依据](https://github.com/UserB1ank/Cod3xplo1t/issues/29) | AFK | [#28](https://github.com/UserB1ank/Cod3xplo1t/issues/28) |
| V03 | [#30 在候选详情生成并审批绑定环境要求的固定验证计划](https://github.com/UserB1ank/Cod3xplo1t/issues/30) | AFK | [#28](https://github.com/UserB1ank/Cod3xplo1t/issues/28) |
| V04 | [#31 通过环境供应插件创建并销毁真实容器验证环境](https://github.com/UserB1ank/Cod3xplo1t/issues/31) | AFK | [#28](https://github.com/UserB1ank/Cod3xplo1t/issues/28)、[#30](https://github.com/UserB1ank/Cod3xplo1t/issues/30)、[#21](https://github.com/UserB1ank/Cod3xplo1t/issues/21) |
| V05 | [#32 在授权容器环境验证单服务候选并基于真实证据派生裁定](https://github.com/UserB1ank/Cod3xplo1t/issues/32) | HITL | [#30](https://github.com/UserB1ank/Cod3xplo1t/issues/30)、[#31](https://github.com/UserB1ank/Cod3xplo1t/issues/31) |
| V06 | [#33 验证带数据库依赖的多服务目标并恢复已知基线](https://github.com/UserB1ank/Cod3xplo1t/issues/33) | AFK | [#32](https://github.com/UserB1ank/Cod3xplo1t/issues/32) |
| V07 | [#34 重启或 worker 失联后回收验证环境并拒绝旧执行结果](https://github.com/UserB1ank/Cod3xplo1t/issues/34) | AFK | [#32](https://github.com/UserB1ank/Cod3xplo1t/issues/32) |
| V08 | [#35 用第二种虚拟机供应器复用同一验证工具完成真实验证](https://github.com/UserB1ank/Cod3xplo1t/issues/35) | HITL | [#32](https://github.com/UserB1ank/Cod3xplo1t/issues/32)、[#34](https://github.com/UserB1ank/Cod3xplo1t/issues/34) |
| V09 | [#36 固定报告展示验证环境、结构化断言与完整证据链](https://github.com/UserB1ank/Cod3xplo1t/issues/36) | AFK | [#32](https://github.com/UserB1ank/Cod3xplo1t/issues/32)、[#34](https://github.com/UserB1ank/Cod3xplo1t/issues/34) |

## 与已有任务的关系

- #31 复用已有 #21 的受控容器 Worker；#21 自身依赖 #19。扫描工具容器与运行被审计程序的验证环境分别授权，不重复建设。
- #32 的人工节点是动态执行授权与部署信任验收；#35 的人工节点是选择一个实际可用 VM 后端并验收。其余项目无需额外产品决策。
- #33 的多服务和 #35 的 VM 扩展遵循共同环境及证据契约；#36 不被这两项阻塞，可先交付真实容器验证报告。
- 所有 Issues 均保持开放，未修改或关闭已有任务；本次发布不表示需求已实现。

## 交付原则

- 复用已完成的插件、工作流、发现及固定报告；各单包含必要 Schema、认证 API、正式 UI、持久化、真实执行验收和文档。
- 环境供应器和验证工具解耦，插件自身 runtime 与目标 environment backend 分开建模；能力必须由真实执行后端兑现。
- 动态执行使用精确授权，观察与裁定分离，环境失败或未复现不能冒充已排除；审批、秘密和基础设施权限不得由 Agent 或插件自授。
- 环境创建、验证、证据、销毁、租约和失联回收形成闭环，报告固定实际环境和证据；历史输入不得隐式换用 latest。
- 遵守 AGENTS.md 的 TDD、测试、隐私及提交流程；AFK/HITL 不改变 commit / push 的授权范围。
