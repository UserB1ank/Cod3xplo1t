# L8 应用服务与用户功能

参考用户提供的 ARTEX 任务界面：分组侧栏、浅色数据表、筛选、分类、并发设置、置顶和归档。保留代码漏洞挖掘的项目上下文，不引入与当前目标无关的流量代理和资产攻击功能。

Schema：[application.schema.json](../../../../contracts/v1/application.schema.json)。示例：[task.json](../../../../contracts/v1/examples/task.json)。

## 用户功能分区

| 导航 | 用户操作 | 所属数据 / 接口 |
|---|---|---|
| 仪表盘 | 汇总项目、运行任务、候选发现与插件能力 | Project / Task / Finding 只读聚合 |
| 项目 | 新建、项目范围切换、查看共享图谱 | ProjectService |
| 任务 | 新建、搜索、状态/分类过滤、分页、暂停/继续、置顶、归档/恢复、并发限制 | TaskService / WorkflowRunner |
| 发现 | 按高中低和确认状态筛选、查看证据、分级、导出 | FindingService |
| 代码源 | 选择本地文件夹或 Git、所属项目、固定版本、生成快照 | SourceProvider / SnapshotService |
| 知识图谱 | 项目/快照切换，代码结构/安全语义/路径分层，节点来源与代码查看 | KnowledgeReader |
| 产物与证据 | 输入输出引用、原生报告、内容摘要、来源与导出 | ArtifactStore / EvidenceStore |
| 工作流 | 选择插件、依赖配置、节点参数、版本与类型校验、导入导出 | WorkflowCompiler |
| 插件中心 | 能力分类、版本、清单校验、运行方式、可用性 | PluginCatalog |
| 工具执行 | 任务/节点/插件输入输出、诊断、事件与取消状态 | PluginHost / WorkflowRunner |
| LLM 配置 | 协议、服务地址、模型、Key、真实连接测试 | 管理员设置；现有正式工作区已有 |
| 数据存储 | 独立数据库与产物后端、能力、引用凭据、方案导出 | StorageAdapter |
| 接口规范 | 分层方法、Schema、扩展规则与样例导出 | ContractRegistry |

## 领域服务方法

| 方法 | 请求字段 | 响应 | 权限 |
|---|---|---|---|
| `ProjectService.CreateProject` | name、description、幂等键 | Project | writer |
| `TaskService.CreateTask` | application Schema；固定 source/snapshot/workflow | Task + 固定计划引用 | writer |
| `TaskService.ListTasks` | project_id、status、category、archived、cursor、limit | 有界任务页 | reader |
| `TaskService.Archive / Restore` | task_id、expected_version | 更新后记录 | writer |
| `TaskService.SetPinned / SetCategory` | task_id、新值、expected_version | 更新后记录 | writer |
| `TaskService.SetConcurrency` | 项目或全局范围、limit、expected_version | 并发策略 | 全局 admin / 项目 writer |
| `GetCapabilities` | 当前认证身份 | 各能力的 ready / unavailable / unsupported 及原因 | reader |

任务详情分为执行过程、探索与图谱、发现、报告。后台区分 `task_id`、workflow_run_id、invocation_id、Agent run_id；它们不是同一个运行对象。

## HTTP 目标映射

统一扩展 API 预留 `/api/v1`；现有 `/api` 不迁移、不改错误结构。以下是**待接线设计路由**，不是当前可用端点：

| 路由 | 用途 |
|---|---|
| `GET/POST /api/v1/projects/{id}/sources` | 代码源 |
| `POST /api/v1/sources/{id}/snapshots` | 请求快照操作 |
| `GET/POST /api/v1/plugins` | 插件目录与注册 |
| `GET/POST /api/v1/workflows` | 工作流版本 |
| `POST /api/v1/projects/{id}/tasks` | 固定快照和工作流后创建任务 |
| `GET /api/v1/tasks/{id}/events` | 有界事件页 |
| `POST /api/v1/tasks/{id}/pause`、`resume`、`cancel` | 流程控制 |
| `POST /api/v1/knowledge/query`、`publish` | 有界查询 / 宿主发布 |
| `GET /api/v1/artifacts/{id}` | 授权的元数据或流式内容 |
| `GET /api/v1/settings/storage` | 管理员存储配置的脱敏视图 |

读取与写入由同一应用服务供 WebUI、CLI 和后续 MCP 适配；页面不直接执行工具和数据库查询。

## 账号与安全边界

正式工作区已有账号密码登录、HttpOnly 会话、限流、退出和管理员模型设置。后续权限分 reader / writer / admin，项目归属在每次请求校验。系统配置只返回凭据是否已设置。

公开原型页面仅使用内存示例，不读取登录会话数据或正式业务 API。表单保存、执行记录和数据库状态均标示为原型；账户凭据不在原型中录入。

验收：项目切换不混入其他项目记录；任务固定版本；所有操作有空状态、错误状态与权限反馈；正式数据和演示数据互不写入。
