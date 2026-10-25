# 分层接口与扩展方案 v1

状态：**设计基线与交互原型**。本目录定义后续实现需要遵守的接口；不代表所有接口已在正式 API 接线。协议标识为 `codexploit/v1`，文档修订为 `2026-10-21`（文档设计版本，不改变已发布机器契约）。

产品保持 **项目 → 子任务**：新项目对应一份源码的一次审计，创建时隐含保存输入；一键四阶段准备后，主Agent开放对话并通过MCP协调路径探索和审查。旧多来源/快照项目兼容保留，内部snapshot/版本不暴露成必经操作。严重性为高、中、低。当前架构与开发步骤见 [目标架构](../../project-agent-architecture.md)和 [接手指南](../../deepseek-handoff.md)。

## 阅读顺序

| 层 | 文档 | 边界 |
|---|---|---|
| L0 | [公共约定](00-common.md) | 作用域、版本、错误、幂等、覆盖范围 |
| L1 | [代码源](01-sources.md) | 本地文件夹 / Git 仓库，固定输入 |
| L2 | [快照与产物](02-snapshots-artifacts.md) | 不可变源码与内容寻址产物 |
| L3 | [分析与归一化](03-analysis.md) | AST、工具报告、标准事实 |
| L4 | [知识图谱](04-knowledge.md) | SCG / ASG / 路径 / 证据的统一读写 |
| L5 | [插件](05-plugins.md) | 清单、能力、执行协议、权限 |
| L6 | [工作流](06-workflows.md) | DAG 编译、版本固定、取消与恢复 |
| L7 | [发现与证据](07-findings.md) | 分级、确认、去重、证据与报告 |
| L8 | [应用服务与用户功能](08-application.md) | ARTEX 参考下的导航与用户操作 |
| L9 | [持久化与 Docker](09-persistence.md) | PostgreSQL 独立容器及其他存储适配器 |
| L10 | [项目准备、主Agent会话与MCP](11-project-supervisor.md) | 新项目/阶段/开放消息/工具/主子控制目标接口 |
| 接线 | [兼容性与实施步骤](10-adoption.md) | 现有代码映射、差距、验收条件 |

机器可读的契约位于 [contracts/v1](../../../../contracts/v1/README.md)，包含分层定义、已接线的运行时 Schema 与完整示例；样例映射以 `contracts/v1/examples.json` 为准。现有机器契约仍单独版本化；新主Agent DTO需实现时补Schema与样例，不能据文档宣称已接线。

## 数据流

```mermaid
flowchart TD
  Source[创建项目并导入一份源码] --> Input[内部固定输入]
  Input --> Prepare[默认四阶段传统分析]
  Prepare --> Knowledge[图谱与初始路径]
  Knowledge --> UI[入口局部图与路径页]
  Human[人 / 开放对话] --> Master[主Agent模型]
  Master --> MCP[宿主管控MCP能力]
  MCP --> Knowledge
  MCP --> Discovery[候选路径提案]
  Discovery --> Knowledge
  MCP --> Child[审查子任务 / 消息 / 控制]
  Child --> Evidence[发现 / 证据 / 覆盖账本]
  Evidence --> Report[固定报告]
  Knowledge --> PG[PostgreSQL]
  Child --> PG
  Master --> PG
  Input --> Artifact[ArtifactStore]
  Report --> Artifact
```

代码结构、安全语义、分析路径和发现保留独立类型。原生 AST 和原始扫描报告作为产物保存，通用事实进入图谱索引。每个事实能追溯到源码版本、插件、参数摘要、任务和证据。

## 可操作原型

构建后访问 `/prototype/`。当前入口已按“一个项目对应一份源码的一次审计”重做，完整说明见 [审计流程交互原型](../../audit-interaction-prototype.md)。

可验证：创建 / 编辑 / 删除模拟项目、一键四阶段图谱化分析、入口局部调用图、路径筛选、独立 Agent 工作台、启动 / 暂停 / 继续 / 停止、人工方向回执、候选证据和报告预览 / 下载。

原型不请求正式业务 API，示例数据在页面内存中保存，刷新重置。文件仅记录名称，工具与 Agent 均为模拟执行。原有通用原型与接口目录保留在源码中，正式系统不受此入口切换影响。

## 扩展原则

1. 添加语言通过 Parser，添加扫描器通过 Analyzer，添加报告格式通过 Reporter。
2. 工具返回原始产物，Normalizer 转换公共语义；插件不直接写数据库。
3. 工作流只依赖类型化产物与明确的图谱视图。
4. 新数据库实现同样的事务、CAS、事件、租约与恢复契约。
5. 新版本通过契约样例、负面用例和真实适配器验收后才宣告可用。
