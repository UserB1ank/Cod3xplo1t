# L10 项目准备、主 Agent 会话与 MCP 目标接口

状态：**部分实现**。2026-10-21 已交付 #63 的项目输入、管理信息与可恢复删除；#64–#69 仍待开发。本页其余部分是目标设计，不是已接线 API 清单。新增 DTO 已登记 `project-input.schema.json`；迁移号按实施时的下一可用值落地。

## 应用服务边界

| 服务 | 操作 | 关键不变量 |
|---|---|---|
| ProjectAuditService | 创建/读取输入绑定、编辑管理信息、请求删除 | 单份输入；ready之前不能假成功；旧多输入兼容；活动删除栅栏 |
| AnalysisRunService | Start/Get/List/Events、阶段控制 | 固定默认计划与四阶段映射；真实输出/覆盖；CAS/租约与恢复 |
| SupervisorSessionService | Create/Get/List、AppendMessage、Events、StartTurn | 独立session/run，消息幂等/有序；无intent/action_type用户分类字段 |
| SupervisorToolService | 描述目录、执行受控工具 | 共用Registry/Schema/应用服务；宿主注入身份与scope |
| PathProposalService | Validate/Publish/ListProvenance | canonical证据与view校验、稳定身份、去重与来源、账本修订 |
| ChildCoordinationService | Create/Dispatch/List/Get、AppendMessage/GetReceipt | audit/path/task/run显式映射；单次投递幂等；generation与回执 |
| ProjectControlService | Pause/Resume/Stop/GetOperation | 控制范围/批次、执行确认、paused原因、迟到结果栅栏 |

消息内容为开放文本与可选对象引用；引用只是上下文，不强制动作。模型公开答复、模型工具请求、宿主执行结果和子Agent回执分别建模，不把所有事件塞进消息role=user。只有明确注册的工具可执行，用户文字本身不是工具。

## 已实现的项目管理切片（#63）

| 已实现路由 | 行为 |
|---|---|
| `GET /api/v1/projects` | 真实目录：`{project, audit_input?}`；旧项目不伪造输入 |
| `GET /api/v1/projects/{id}/audit-input` | `importing / ready / failed / legacy`，含绑定 source/snapshot 与真实失败原因 |
| `POST /api/v1/projects` | 同时创建项目与 `importing` 输入，`description` 可选 |
| `PATCH /api/projects/{id}` | `If-Match` 下编辑名称/说明；源码绑定不可编辑 |
| `DELETE /api/v1/projects/{id}` | writer；活动引用冲突，tombstone + snapshot 栅栏可重试恢复 |
| `POST /api/v1/projects/{id}/imports/{sourceID}` | 归档/目录导入在快照和产物发布后置 ready；失败置 failed |
| `POST /api/v1/projects/{id}/sources`、`POST /api/v1/sources/{id}/snapshots` | Git/本地目录输入绑定与 capture；完成后拒绝换源 |

输入只在不可变快照存在后 ready；第二份源码 `409 input_fixed`，活跃导入 `409 import_in_progress`。中断超过五分钟的导入按 `failed/import_interrupted` 展示，可重试或删除。旧多来源项目没有输入行，继续兼容。删除时校验排队/运行中的路径、分析、Agent/workflow/plugin/验证、待审批计划与环境租约；tombstone 完成后迟到项目/来源/快照写入被拒绝。四项实现细节见 `docs/api.md` 的“Project input lifecycle and deletion”。

## HTTP 设计候选（尚未接线的其余能力）

命名在实现时对齐现有router，不重复建设已发布接口。下列仅明确需要的能力与scope。

| 候选路由 | 用途 |
|---|---|
| `GET /api/v1/projects/{projectID}/audit-input` | 新项目固定输入/导入状态；创建复用现有导入链 |
| `DELETE /api/v1/projects/{projectID}` | writer请求删除及可恢复清理，不绕过活动引用 |
| `GET/POST /api/v1/projects/{projectID}/analysis-runs` | 创建/列出四阶段运行 |
| `GET /api/v1/projects/{projectID}/analysis-runs/{runID}` | 阶段、输入/输出、覆盖/失败和固定计划 |
| `GET/POST /api/v1/projects/{projectID}/agent-sessions` | 主Agent会话目录/创建 |
| `GET/POST /api/v1/projects/{projectID}/agent-sessions/{sessionID}/messages` | 有界历史/幂等发送 |
| `GET /api/v1/projects/{projectID}/agent-sessions/{sessionID}/events` | after_seq有序页；如提供SSE保持相同事件身份/恢复语义 |
| `POST /api/v1/projects/{projectID}/child-tasks/{childID}/messages` | 对子Agent直接发消息 |
| `GET /api/v1/projects/{projectID}/instructions/{instructionID}` | 投递/应用回执 |
| `POST /api/v1/projects/{projectID}/control` | 明确范围和pause/resume/stop动作（机器控制枚举，不是自然语言意图分类） |

写请求包含请求幂等键与适用的expected_version；对象lookup必须校验project归属。异步动作返回operation_id/当前状态，只有实际完成才终态。读取按reader权限，发送/控制/路径登记按writer，部署与全局模型设置按admin。

## MCP 设计原则

使用真实MCP SDK目录/调用，运行时原生tools可代理同一工具handler，不能把两套实现各自维护。现有stdIO只读面保留默认权限。新会话按身份/角色暴露已安装能力；transport选型不能留下未认证管理端口。

会话scope从服务器认证绑定：project_id、input/snapshot、知识pin、session/run/generation、有效权限与预算。模型参数只携带工具所需的领域对象引用；引用也要复核归属，不能自选project提升权限。

概念能力：项目/阶段/覆盖查询、图谱/源码/攻击面查询、路径提交、任务创建/调度、消息、暂停/停止、发现/报告查询。实际名称以SDK支持的注册名为准；点分原型名不是冻结协议。严格Schema包含有界数组/复合参数时先扩展验证能力，旧Descriptor不变义。

普通已授权工具自动执行；不对每轮会话强制“先生成计划再点执行”。模型若需要澄清或工具返回需要额外授权，可提出具体请求。动态验证和追加预算沿独立审批对象，不由模型消息自授。

## 事件、错误与恢复

消息/工具/任务事件包含稳定ID、服务器顺序、因果引用和实际状态。工具call/result必须配对，重放不重复写入。工具错误返回可修复的结构化原因，预算/权限/未知引用/版本失效明确，不回退演示。

主Agent可在模型/工具边界收到新消息；子Agent消息区分pending/received/applied/rejected/not_applied及原因。暂停可排队；终态/旧generation不应用。继续只恢复该全局控制批次暂停的任务。历史证据、答案和已生成报告不被纠正消息覆盖。

完整领域状态详见 [目标架构](../../project-agent-architecture.md)。
