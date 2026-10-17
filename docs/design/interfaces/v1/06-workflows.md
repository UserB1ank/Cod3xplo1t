# L6 工作流层

已实现：`WorkflowCatalog`、`WorkflowCompiler`（版本、校验、不可变编译计划与正式页面，见 [工作流 API](../../../workflows.md)）及 `WorkflowRunner`（固定计划、真实 DAG、知识发布、可选模型分析、节点事件与正式任务详情，见[执行协议](../../../workflow-execution.md)）。Memory / SQLite 已接入；下文暂停、租约、重试和崩溃恢复仍为后续设计约束。

接口：`WorkflowCompiler`、`WorkflowRunner`。Schema：[workflow.schema.json](../../../../contracts/v1/workflow.schema.json)。示例：[workflow.json](../../../../contracts/v1/examples/workflow.json)。

## 定义与输入绑定

WorkflowSpec 包含 id、version、name、description、inputs 和 nodes。节点含 id、plugin_id、plugin_version、needs、config、timeout_seconds。v1 最多 32 个节点。

每个节点从根 inputs 和**直接依赖节点**的输出集合满足插件 consumes。相同类型存在多个产物时传入稳定排序的产物引用列表，顺序为来源 node_id / artifact_id；消费者必须声明如何处理集合。需要单一输入却存在多个候选时，编译报 ambiguous_input，不能任意挑选。后续版本可增加命名端口与显式选择器。

同列节点不必然存在依赖，执行器可以并行运行所有上游已成功的节点。原型用分阶段视图显示 DAG，右侧勾选上游依赖；可通过 JSON 编辑完整定义。

## 标准方法

| 方法 | 输入 | 输出 |
|---|---|---|
| `Validate` | WorkflowSpec、固定插件目录 | 有字段路径的错误列表 |
| `Compile` | WorkflowSpec、Scope、初始产物、固定视图、预算 | 不可变 ExecutionPlan 与摘要 |
| `Start` | project / snapshot / plan ID、TaskDefinition、部分接受策略、模型开关 | 原子创建任务与 WorkflowRun |
| `Get / Events` | project_id、run_id、after_seq、limit | 执行记录 / 有序事件页 |
| `Pause / Resume / Cancel`（后续） | run_id、expected_version、原因 | 新状态版本 |

Compile 固定工作流字节、插件版本/包摘要、输入摘要、图谱视图、规则版本和参数摘要。后续编辑模板不修改正在运行的计划。

## 编译校验

- 拒绝未知字段、重复节点、缺失依赖和循环。
- 检查插件已注册且所选执行器具有所需能力。
- 检查语言、输入类型、参数 Schema、预算、超时与网络策略。
- 缺少路径能力时允许只产出告警，但不能把其接成依赖真实 taint_flow 的节点。
- 当前正式编译器固定根产物实际摘要、适配器输入 Schema / producer、插件版本与包摘要、参数、知识版本和输入预算，按单值协议拒绝歧义。输出内容与运行时产物归属由后续执行器再次验证；原型仍单独隔离。

## 状态、失败与恢复

运行状态：CREATED → RUNNING → SUCCEEDED / PARTIAL / FAILED / CANCELLED；RUNNING 可进入 PAUSING → PAUSED，再 Resume。TIMED_OUT 作为节点终态与运行失败原因保存。

默认失败策略是 fail-fast：停止调度新节点、取消活动节点，保留已经提交的产物。partial 输出必须由消费者显式接受，不能自动按成功处理。重试只针对 retryable 错误，具有最大次数、退避和总预算；任务取消不触发自动重试。

Pause 停止领取新节点，活动节点在边界完成后进入 PAUSED；Cancel 请求中断活动调用。收到中断请求不立即宣称程序已停止，必须等执行器终态或租约回收。

调度使用数据库租约与单调栅栏令牌。worker 崩溃后重新领取会得到新令牌，旧 worker 的产物提交被拒绝。exactly-once 外部运行不保证；宿主以至少一次运行 + 幂等产物/图谱提交获得一致结果。

## 默认漏洞挖掘流程

```text
快照 → 语法索引 → 安全语义 ──────────────┐
   └→ 扫描器 → 结果归一化 ← 代码事实 ───┤
                                      ↓
                             项目知识发布 → Agent 分析 → 报告
```

现有 P7 调度器面向 AuditPath；统一 DAG 独立调度插件，分别保存流程运行、节点运行、插件调用与 Agent 运行。旧调度器排除工作流任务，避免重复领取或绕过模型开关。Issue #11 补齐运行控制：`pause / resume / cancel / retry`、PAUSING / PAUSED / CANCELLING 状态机、节点租约与迟到结果拒绝、可重试错误的退避与次数上限、重启后的 `Recover`，以及重试复用已提交节点的语义；详见 [固定工作流执行](../../../workflow-execution.md#流程控制与恢复)。

验收：环路、错误类型、缺失版本被拒；中断、重试、双 worker 抢占和崩溃恢复不重复提交；图谱发布节点与后续视图绑定一致。
