# 实施 Issues 索引

状态：已由用户确认，并发布到 GitHub。共 22 项：20 项 AFK，2 项 HITL。

仓库：[UserB1ank/Cod3xplo1t](https://github.com/UserB1ank/Cod3xplo1t)。实现基线：`f2867db`。

每项均含用户故事、端到端交付说明、验收条件和真实阻塞编号，并已添加 `needs-triage` 标签。

AFK / HITL 描述实施中的人工决策需求，不改变 AGENTS.md 对 commit / push 的授权要求。

来源：[已批准的拆分草案](implementation-issues-draft.md)、[分层接口方案](interfaces/v1/README.md)。

| 草案 | Issue | 类型 | 阻塞项 |
|---|---|---|---|
| D01 | [#1 本地文件夹代码源生成真实快照并创建任务](https://github.com/UserB1ank/Cod3xplo1t/issues/1) | AFK | 无 |
| D02 | [#2 Git 仓库固定提交并创建可复现任务](https://github.com/UserB1ank/Cod3xplo1t/issues/2) | AFK | [#1](https://github.com/UserB1ank/Cod3xplo1t/issues/1) |
| D03 | [#3 任务分类、置顶、归档与恢复持久化](https://github.com/UserB1ank/Cod3xplo1t/issues/3) | AFK | [#1](https://github.com/UserB1ank/Cod3xplo1t/issues/1) |
| D04 | [#4 正式页面查看、校验并下载快照产物](https://github.com/UserB1ank/Cod3xplo1t/issues/4) | AFK | [#1](https://github.com/UserB1ank/Cod3xplo1t/issues/1) |
| D05 | [#5 在正式图谱页面探索固定快照的真实代码事实](https://github.com/UserB1ank/Cod3xplo1t/issues/5) | AFK | [#1](https://github.com/UserB1ank/Cod3xplo1t/issues/1) |
| D06 | [#6 注册版本化插件并实际执行内置 Go 解析器](https://github.com/UserB1ank/Cod3xplo1t/issues/6) | AFK | [#4](https://github.com/UserB1ank/Cod3xplo1t/issues/4)、[#5](https://github.com/UserB1ank/Cod3xplo1t/issues/5) |
| D07 | [#7 内置语义与路径插件输出标准候选结果](https://github.com/UserB1ank/Cod3xplo1t/issues/7) | AFK | [#6](https://github.com/UserB1ank/Cod3xplo1t/issues/6) |
| D08 | [#8 原子发布共享图谱版本并查看多工具来源](https://github.com/UserB1ank/Cod3xplo1t/issues/8) | AFK | [#7](https://github.com/UserB1ank/Cod3xplo1t/issues/7) |
| D09 | [#9 保存工作流版本并在页面编译校验](https://github.com/UserB1ank/Cod3xplo1t/issues/9) | AFK | [#6](https://github.com/UserB1ank/Cod3xplo1t/issues/6) |
| D10 | [#10 从任务选择工作流并执行真实内置分析 DAG](https://github.com/UserB1ank/Cod3xplo1t/issues/10) | AFK | [#8](https://github.com/UserB1ank/Cod3xplo1t/issues/8)、[#9](https://github.com/UserB1ank/Cod3xplo1t/issues/9) |
| D11 | [#11 工作流暂停、取消、重试和重启恢复](https://github.com/UserB1ank/Cod3xplo1t/issues/11) | AFK | [#10](https://github.com/UserB1ank/Cod3xplo1t/issues/10) |
| D12 | [#12 接入首个进程扫描器并在自定义工作流使用](https://github.com/UserB1ank/Cod3xplo1t/issues/12) | AFK | [#11](https://github.com/UserB1ank/Cod3xplo1t/issues/11) |
| D13 | [#13 多插件发现分组、分级审计与来源查看](https://github.com/UserB1ank/Cod3xplo1t/issues/13) | AFK | [#12](https://github.com/UserB1ank/Cod3xplo1t/issues/12) |
| D14 | [#14 导出固定版本的真实任务与项目报告](https://github.com/UserB1ank/Cod3xplo1t/issues/14) | AFK | [#13](https://github.com/UserB1ank/Cod3xplo1t/issues/13) |
| D15 | [#15 独立 PostgreSQL 部署保存项目、代码源和快照目录](https://github.com/UserB1ank/Cod3xplo1t/issues/15) | AFK | [#4](https://github.com/UserB1ank/Cod3xplo1t/issues/4) |
| D16 | [#16 PostgreSQL 部署构建、共享和查询真实图谱](https://github.com/UserB1ank/Cod3xplo1t/issues/16) | AFK | [#8](https://github.com/UserB1ank/Cod3xplo1t/issues/8)、[#15](https://github.com/UserB1ank/Cod3xplo1t/issues/15) |
| D17 | [#17 PostgreSQL 部署执行持久化任务与工作流](https://github.com/UserB1ank/Cod3xplo1t/issues/17) | AFK | [#3](https://github.com/UserB1ank/Cod3xplo1t/issues/3)、[#13](https://github.com/UserB1ank/Cod3xplo1t/issues/13)、[#16](https://github.com/UserB1ank/Cod3xplo1t/issues/16) |
| D18 | [#18 PostgreSQL 部署共享登录会话与加密模型设置](https://github.com/UserB1ank/Cod3xplo1t/issues/18) | AFK | [#17](https://github.com/UserB1ank/Cod3xplo1t/issues/17) |
| D19 | [#19 独立产物容器保存与恢复源码和分析结果](https://github.com/UserB1ank/Cod3xplo1t/issues/19) | AFK | [#15](https://github.com/UserB1ank/Cod3xplo1t/issues/15) |
| D20 | [#20 SQLite 数据迁移、备份与恢复演练](https://github.com/UserB1ank/Cod3xplo1t/issues/20) | HITL | [#2](https://github.com/UserB1ank/Cod3xplo1t/issues/2)、[#14](https://github.com/UserB1ank/Cod3xplo1t/issues/14)、[#18](https://github.com/UserB1ank/Cod3xplo1t/issues/18)、[#19](https://github.com/UserB1ank/Cod3xplo1t/issues/19) |
| D21 | [#21 通过受控容器 Worker 执行扫描插件](https://github.com/UserB1ank/Cod3xplo1t/issues/21) | HITL | [#12](https://github.com/UserB1ank/Cod3xplo1t/issues/12)、[#19](https://github.com/UserB1ank/Cod3xplo1t/issues/19) |
| D22 | [#22 正式仪表盘与全局搜索使用真实聚合数据](https://github.com/UserB1ank/Cod3xplo1t/issues/22) | AFK | [#3](https://github.com/UserB1ank/Cod3xplo1t/issues/3)、[#13](https://github.com/UserB1ank/Cod3xplo1t/issues/13) |

PostgreSQL 与外部产物线可以按依赖并行推进；存量切换和容器 Worker 授权保留人工验收。
