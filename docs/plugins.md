# 版本化插件与内置 Go 解析器

Issue #6 将插件目录、内置执行器和正式插件中心接到真实存储。插件目录在工作区共享，调用与产物严格限定 project / source / snapshot。当前安装 `builtin.go-parser@1.1.0`、两个内置分析插件，以及部署目录提供的固定版本进程扫描器 `codexploit.static-patterns@1.0.0`。进程扫描器通过有界 NDJSON JSON-RPC 读取冻结源码 tar，只报告告警位置，不运行目标项目的 build、test、hook 或依赖安装；包格式、协议、归一化和局限见 [进程扫描器](process-scanner.md)。

## 标准接口

Go 端口在 `internal/plugin`：

| 端口 | 方法 | 行为 |
|---|---|---|
| PluginCatalog | `Register(ctx, manifest, packageDigest, source)` | 规范 Schema 校验、参数 Schema 离线解析、不可变登记；同版本不同清单/包摘要 conflict |
| PluginCatalog | `Get / List` | 返回固定定义、清单摘要、包摘要、来源与实际可执行性；ID@version 游标，最多 100 条 |
| PluginHost | `Execute(ctx, request)` | 验证固定版本、包摘要、Scope、权威输入、参数与预算；持久化调用后异步开始；同 invocation_id 和完整请求重试返回原记录 |
| PluginHost | `GetStatus / List / Wait` | 有界状态、输入输出、覆盖与局限；Wait 是可取消的终态等待 |
| PluginHost | `Cancel(ctx, scope, id, expectedVersion)` | CAS 取消，终态不再覆盖；取消成功后迟到输出不能发布 |
| PluginHost | `Close` | 拒绝新调用、取消并等待本宿主调用结束，然后才能关闭存储 |

清单使用 `contracts/v1/plugin.schema.json`，运行时目录与调用响应使用 `plugin-runtime.schema.json`。认证接口返回前执行离线 Schema 校验。`examples/plugin-runtime.json` 提供外部清单仅登记的完整样例。

清单登记不下载或安装程序，也不会因为 runtime.kind 写成 builtin 就获得执行权限。内置可用性要求 ID、版本、规范清单摘要和编译包摘要全部匹配宿主。部署目录中的 process 包在启动时校验摘要和安全相对 entrypoint 后登记并安装；容器 / 远程 worker 以及 HTTP 安装仍由后续 Issue 提供。参数 Schema 的外部引用被拒绝，不能触发网络下载。

内置包摘要绑定宿主适配器源码、Go frontend 源码和 Go 工具链版本。它是可复现的编译输入指纹，不是整个服务器可执行文件的摘要。进程包摘要绑定规范化清单和包内每个普通文件。修改包内容或工具链后需要提升插件版本，不能在已有数据库中静默替换相同 ID/version；升级前应保留旧版本记录和已有调用。

`Record` 同时返回 `installed` 与 `executable`：前者表示部署目录中存在通过摘要/入口校验的包，后者表示宿主实际注册了执行适配器。手工导入但没有本地包的 process 清单只显示“已登记 · 未安装 · 不可执行”，不会退化为可执行。

## 执行请求和结果

请求固定 `api_version=codexploit/v1`、`invocation_id`、`plugin_id`、`plugin_version`、`package_digest`、完整 `scope`、有序输入 ArtifactRef 列表、`config` 和 `budget`。解析输入必须是当前 Scope 的 `source.snapshot` tar，引用全部字段与权威索引一致；不接受路径或可执行命令。省略 invocation_id 由宿主生成；自定义 ID 限 120 个字母、数字、短横线或下划线，首字符为字母或数字。

内置参数为 `{ "include_comments": false }`，字段可省略；多余字段和非布尔值拒绝。配置会规范化并保存 SHA-256。记录保留规范化请求、请求摘要、实际版本/包、输入和输出引用、独立覆盖计数、有限错误码、局限、UTC 时间和单调版本。

| 预算 | 默认 | 允许上限 |
|---|---|---|
| `max_input_bytes` | 64 MiB | 256 MiB |
| `max_output_bytes` | 两项输出合计 16 MiB | 64 MiB |
| `max_files` | 2000 | 20000 |
| `max_file_bytes` | Go / go.mod 单文件 1 MiB | 4 MiB |
| `max_ast_nodes` | 100000 | 500000 |
| `timeout_seconds` | 60 秒 | 120 秒 |

零值采用默认值；负数和超过上限拒绝。宿主最多同时执行两项新调用，达到容量时返回预算错误，已有调用的同请求重试仍幂等。取消和超时在输入读取与文件/节点阶段检查，Go frontend 单次解析会先完成当前有界文件，不宣称进程或内核级强制隔离。

调用状态为 CREATED → RUNNING → SUCCEEDED / PARTIAL / FAILED / CANCELLED / TIMED_OUT / UNSUPPORTED。Go 语法错误计入 partial / unparsed；其他语言与非 Go 输入计入 unhandled，go.mod 单列 descriptor。没有 Go 文件时 UNSUPPORTED，扫描数为零，不发布空的成功产物。预算失败或取消不发布半成品。

当前为单宿主部署。宿主启动时将遗留 CREATED / RUNNING 记录标记 FAILED / `host_restarted` 并提升版本，旧调用不能迟到提交；不会自动重跑旧请求。多实例租约与分布式调度由后续 PostgreSQL / 工作流 Issue 接入，当前不可让两个宿主并行拥有同一数据库。

## 原子发布和输入生命周期

解析输入通过 ArtifactStore 校验读取，不从活动源目录取文件，也不将 tar 解包执行。拒绝无效 tar、重复路径、穿越/链接/特殊文件和超预算内容。Go frontend 继续提供语法事实；AST 由 Go 原生 parser 生成节点索引。

`artifact.Local.Prepare` 只准备并验证内容对象，不登记引用。全部输出准备完成后，Repository 在同一锁/事务中检查调用版本、状态和快照删除栅栏，原子发布两个引用及终态。取消或重启提升版本后，旧完成结果被拒绝；未引用对象保持不可见，后续产物回收由 #19 负责。活动插件调用阻止快照退役，完成删除时同时清理调用与引用元数据。

输出格式：

- `codexploit/go-ast/v1`：Scope、coverage、文件与 parse_status；节点记录原生 Go AST 类型、父节点下标、起止位置及标识符/字面量值，`format=go/ast-node-index/v1`。可选包含注释。
- `codexploit/go-facts/v1`：Scope、coverage、文件、符号、调用位置及局限；复用现有 `scg.FileID`、`SymbolID`、`CallSiteID`。调用仅是语法引用，解析关系、污点流与漏洞确认属于后续分析。

输出 Producer 保存插件 ID、版本、invocation_id 和配置摘要。手动项目解析早于任务运行，因此不伪造 task_id。此切片不替换共享图谱发布版本，也不写入已确认漏洞。

Issue #7 已接通内置语义和路径分析、Normalizer、AnalysisResult 与只读候选详情。后两类插件使用两个显式上游输入。格式、失败保留和接口见 [内置分析](builtin-analysis.md)。

## 认证 HTTP API

| 路径 | 权限 / 行为 |
|---|---|
| `GET /api/v1/plugins` | reader；`cursor`、`limit`，默认 50、最大 100 |
| `POST /api/v1/plugins` | admin；`{api_version, manifest, package_digest, source}`，返回固定插件记录 |

调用统一前缀为 `/api/v1/projects/{projectID}/snapshots/{snapshotID}/plugin-invocations`：

| 方法 / 后缀 | 权限 / 行为 |
|---|---|
| `POST` | writer；上述 Request，返回 202 与调用记录；支持持久化 Idempotency-Key |
| `GET` | reader；按排他调用 ID 游标分页，最多 100 条 |
| `GET /{invocationID}` | reader；返回调用及 ETag |
| `GET /{invocationID}/result` | reader；已成功规范化的标准结果，默认 2 MiB / 最大 64 MiB |
| `POST /{invocationID}/cancel` | writer；If-Match 必需，取消后返回新记录及 ETag |

请求非法为 400，未认证 401，权限不足 403，错误 Scope/记录 404，相同版本/ID 冲突 409，未安装版本 409 `plugin_unsupported`，取消的陈旧版本 412，预算/容量 413，缺少 If-Match 428，能力未配置 501，存储故障 503。损坏或缺失输入沿用 ArtifactStore 的公开错误。失败状态和有限 error_code 如实保存，不返回隐藏推理或真实密钥。

正式插件中心可导入清单、查看注册/安装/可执行状态、能力/Schema、选择快照和版本、编辑参数与预算、发起/取消并查看记录。进程扫描器调用额外显示标准候选与原始告警报告；任务页显示原始报告、标准告警、来源和知识发布版本。产物入口进入已有“产物与证据”，支持 Go AST / 代码事实预览和认证下载。LLM 设置、登录、CLI / MCP 和旧 `/api` 图谱行为保持兼容。

## 验收

按已确认的 PluginCatalog / PluginHost 和认证 HTTP API 边界使用真实解析器、Memory / SQLite 与本地产物服务，覆盖清单校验、固定包冲突、参数、作用域、真实输出、包含边界的节点预算、取消的迟到输出、启动幂等、未知语言、重启记录和活动快照删除保护。进程执行器另覆盖包摘要/入口安全、握手、双向宿主读取、事件序号、消息/报告限额、环境隔离、取消迟到结果和真实扫描器发布；页面另在独立 Docker 合成项目验收。
