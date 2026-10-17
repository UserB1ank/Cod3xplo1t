# L4 项目知识图谱层

接口：`KnowledgeReader`、`KnowledgePublisher`。Schema：[knowledge.schema.json](../../../../contracts/v1/knowledge.schema.json)。示例：[graph-batch.json](../../../../contracts/v1/examples/graph-batch.json)。

## 统一图层

| layer | 主要实体 | 主要关系 |
|---|---|---|
| `scg` | code.file、code.module、code.symbol、关键语法节点 | CONTAINS、DEFINES、CALLS、REFERENCES |
| `asg` | security.source、sink、control、boundary、asset | INPUT_TO、TOUCHES、SCOPED_BY |
| `paths` | path.entry、step、target、question | NEXT_STEP、REACHES、SUPPORTED_BY |
| `evidence` | finding、evidence、observation | SUPPORTS、CONTRADICTS、PRODUCED_BY |

命名空间注册表保留核心类型。扩展使用 `team.tool.node_type` 与注册的属性 Schema；扩展不得修改核心字段含义。

## 标准方法

| 方法 | 输入 | 输出 |
|---|---|---|
| `OpenView` | Scope、所需层、精确版本或首次解析 latest | view_id、revision、层版本、Coverage |
| `Query` | 固定 view_id、查询种类、过滤与预算 | 类型化结果、所用版本、截断信息、cursor |
| `GetProvenance` | view_id、事实 ID | 生成插件、任务、参数摘要、证据与原始产物 |
| `Publish` | GraphBatch、幂等键、预期版本 | 新视图引用、canonical ID 映射、统计 |

v1 查询种类为 symbols、callers、callees、neighborhood、paths、code_slice、findings。查询是结构化 DTO，不将任意 SQL 或特定图数据库查询语言作为跨数据库公共契约。

`KnowledgeView` 是某个 Scope 下各层版本的一份不可变清单。执行计划固定 view_id；任务显式执行发布节点后，后续节点可以使用新视图。不能在执行中隐式切换 latest。

## 发布约束

1. GraphBatch 由归一化器产生，包含 Scope、batch_id、base_revision、producer、layer、nodes、edges、Coverage。
2. 外部工具的局部 ID 先在归一化阶段映射到 canonical ID；现有 SCG ID 继续使用原算法。ID 映射产物也保存用于追溯。
3. 边两端必须存在于本批次或相同 Scope 的基准视图；证据引用必须可解析且作用域匹配。
4. 相同 canonical fact 可拥有多条不同工具观察；属性冲突保留为独立 observation，不能静默覆盖。
5. 版本检查、所有记录写入、视图发布、幂等记录和 outbox 事件必须原子提交。失败整批不可见。
6. 相同 batch_id + 相同内容返回原视图；内容不同返回 conflict。基准版本过期返回 version_conflict，由宿主重读并重新计算或显式合并。

项目共享是逻辑共享，同一快照的事实可由多个任务复用；不同快照的符号通过显式映射建立关系。跨项目引用在 v1 禁止。

## 存储与验收

PostgreSQL 可通过规范化节点、边、观察及版本索引提供上述接口。后续图数据库作为适配器或投影接入；公共查询和 Scope 语义保持一致，见 [持久化层](09-persistence.md)。

现有 `graph.Service`、`ASGService` 与 `GraphStore.ReplaceGraph` 提供单快照查询和整图事务写入。Issue #5 已在其上接线 `internal/knowledge.Reader`：`OpenView` 固定快照的 SCG / ASG 版本与 `built_at`，`symbols`、`neighborhood`、`nodes`、`paths`、`code_slice`、`provenance` 按 pin 读取，重建后旧视图返回 `view_superseded` 而不是隐式换版；Schema 见 `contracts/v1/view.schema.json`，端口与限额见 [固定视图与知识查询](../../../knowledge.md)。增量批次、统一观察账本和真正的不可变多版本视图仍待 #8 接线。

验收：并发批次 CAS、原子可见性、重复提交、孤立边、跨 Scope 引用、冲突观察保留、固定视图分页和截断声明。
