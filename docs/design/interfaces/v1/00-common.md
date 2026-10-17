# L0 公共约定

状态：目标接口。Schema：[common.schema.json](../../../../contracts/v1/common.schema.json)。本文中的 MUST / MUST NOT 表示实现要求。

## 基础接口

| 方法 | 输入 | 输出 | 错误 |
|---|---|---|---|
| `ContractRegistry.Negotiate` | 客户端版本集合、支持的 Schema 摘要 | 选定协议与 Schema 摘要 | `version_unsupported` |
| `ContractRegistry.ResolveSchema` | Schema ID | 本地注册且不可变的 Schema | `not_found` |
| `ContractRegistry.Validate` | Schema ID、JSON 数据 | 按字段路径排序的校验问题 | `schema_invalid` |

采用 [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core) 描述数据；Schema ID 中的 `codexploit.invalid` 是离线命名空间，不是需要访问的服务。解析器 MUST 只加载本地注册 Schema，MUST NOT 根据上传文档中的 `$ref` 联网。

## 请求上下文

所有领域方法接收 `context.Context` 和 `CallContext`。HTTP、CLI 和插件宿主负责构造上下文。

| 字段 | 类型 | 约定 |
|---|---|---|
| `request_id` | opaque ID | 每次调用唯一；用于错误与日志关联 |
| `trace_id` | opaque ID | 同一任务执行链关联 |
| `actor_ref` | opaque ID | 从认证层获得，插件不能自报身份 |
| `project_id` | opaque ID，项目方法必填 | 全局注册方法可省略 |
| `task_id` | opaque ID，可选 | 任务执行中的调用必须绑定 |
| `deadline_at` | UTC RFC3339 时间 | 与宿主预算取更短期限 |
| `idempotency_key` | opaque ID，可选 | 创建、提交等可重放写入必填 |

公开 DTO 中不暴露 SQL 连接、宿主机绝对路径、裸密钥、数据库事务对象。凭据只传递 `credential_ref`，解析权限归宿主管理。

`Scope = {project_id, source_id, snapshot_id}` 是事实与产物的数据边界。读取前验证三者所属关系。v1 任务绑定单个快照；一个项目可管理多个代码源。跨快照、跨源匹配使用显式关系；跨仓库联合分析待后续版本定义。

## 数据与版本

- `api_version` 固定为 `codexploit/v1`。插件版本和工作流版本采用 `major.minor.patch`，遵循 [Semantic Versioning](https://semver.org/spec/v2.0.0.html)。
- 标准 DTO 拒绝未知字段。扩展类型使用自己的命名空间和注册 Schema；新增标准字段需要新的协商版本，不能假设旧消费者会忽略它。
- 发布后的插件包、Schema、工作流定义和分析产物不可修改；修改创建新版本或新内容摘要。
- ID 对调用方不透明。保留当前 `proj-`、`snap-`、`sym-` 等 ID，不在客户端重新拼接；现有确定性算法见 [contracts.md](../../../contracts.md)。
- 配置摘要对去密钥、已规范化的参数计算。内容摘要为 SHA-256 小写十六进制；工作流和清单摘要基于入库后保存的确切 UTF-8 字节，不能依赖任意 JSON 对象的键顺序。
- 文件路径是快照相对 POSIX 路径，禁止绝对路径、反斜杠、NUL、`.` / `..` 段和空段。代码源配置中的 `/repos/...` 是受控挂载路径，属于不同字段。
- 位置起点使用 1-based 行和 UTF-8 字节列。终点存在时为排他终点；无精确终点时省略，不制造范围。

## 覆盖范围与有界读取

每个分析结果必须返回 `files_seen`、`files_analyzed`、`files_skipped` 和 `limitations`。一次分析中 `files_seen = files_analyzed + files_skipped`；原始产物的独立清单记录跳过原因。部分解析的文件计为 analyzed，并在 limitations 中描述。

列表使用稳定排序和 opaque `cursor`，`limit` 默认 50、上限 200。图查询还必须声明 `max_depth`、`max_nodes` 和超时；响应返回 `truncated`、`truncation_reason`、所用视图版本。跨页使用同一个固定视图，不能混入后续版本。

## 错误、重试与幂等

| code | HTTP 目标映射 | 可重试条件 |
|---|---|---|
| `invalid_argument` / `schema_invalid` | 400 | 修正输入 |
| `unauthenticated` / `forbidden` | 401 / 403 | 重新登录或改变授权 |
| `not_found` | 404 | 引用需要重新解析 |
| `conflict` | 409 | 同一幂等键对应不同内容时不可原样重试 |
| `version_conflict` | 412 | 重读版本并重新计算结果 |
| `precondition_required` | 428 | 提供 ETag / expected_version |
| `resource_exhausted` | 429 | 依据 Retry-After 与预算重试 |
| `unsupported` | 422 | 安装满足能力的适配器 |
| `unavailable` | 503 | 退避，保持同一逻辑幂等键 |
| `deadline_exceeded` | 504 | 调整合法预算或恢复检查点 |
| `cancelled` | 409 | 已取消操作不自动重新启动 |

新版本错误体采用 common 的 `Error`：`code`、`message`、`retryable`、`request_id`，可选 `details`。详情只含安全的字段路径与诊断，不回显提供商响应中的凭据。现有 `/api` 的 `error/code` 结构保持原状。

幂等作用域为 actor + project + operation + key。相同规范化请求返回相同资源引用；不同请求使用同一 key 返回 conflict。CAS 用 expected_version / If-Match；资源版本检查与写入必须在同一事务完成。

取消不等于成功，超时不等于无漏洞。租约丢失后的迟到结果不能提交。审计事件记录简短事实和工具交换，不记录隐藏推理内容。

## 验收

协议版本不兼容、未知字段、非法路径、跨项目引用、过大产物和重复幂等键的冲突均有确定错误；任何错误路径都不回显密钥。
