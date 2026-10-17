# 工作流版本与编译计划

正式工作区的“工作流”页支持图形和 JSON 编辑同一份 WorkflowSpec，保存项目内不可变版本，导入 / 导出定义，校验并编译固定计划。编译不会调用插件、启动扫描或生成模拟运行状态。流程执行、暂停和恢复由后续 WorkflowRunner 接入。

## 用户操作

1. 进入项目 → 工作流，新建草稿或选择历史版本。内置草稿使用 Go 解析 → 安全语义 → 候选路径三个已安装插件。
2. 在流程视图配置节点、插件版本、直接依赖、JSON 参数和超时；也可切换 JSON 编辑完整定义。未完成的参数 JSON 明确显示为未应用。
3. 校验草稿，按字段路径处理错误。保存只要求 WorkflowSpec Schema 有效，因此允许持久化尚待修正的依赖 / 插件配置；编译要求全部语义校验通过。
4. 首次保存使用空 expected_head；修改模板必须提升版本号并提供当前 head 摘要。旧版本不能覆盖，相同版本相同内容可幂等重试。
5. 选择快照，登记真实输入产物，按根类型选择产物。Go 解析器需要 `codexploit/source-tar/v1`，文件清单虽同为 source.snapshot，不能作为解析输入。
6. 声明语言、知识版本及根输入字节预算，编译已保存版本。latest 在这一次编译中解析为确定版本。页面显示定义、插件包 / 清单 / 参数摘要、根产物和拓扑输入绑定。
7. 导出计划或按 plan_id 重新读取。页面会记住本次浏览器会话的最近计划 ID；服务端计划存储不依赖浏览器。模板升级、重启及知识 head 前移不会修改既有计划。

## 公共接口

定义：[workflow.schema.json](../contracts/v1/workflow.schema.json)。版本、目录、字段诊断和计划响应：[workflow-runtime.schema.json](../contracts/v1/workflow-runtime.schema.json)。响应在服务端通过离线 Schema 校验，不能加载远程 Schema。

所有路径前缀为 `/api/v1/projects/{projectID}`。操作需要已登录会话或具有相应能力的凭据；会话写请求还校验同源。

| 方法 / 路径 | 权限 | 请求 / 响应 |
|---|---|---|
| GET `/workflows?limit=30&cursor=...` | reader | workflows、next_cursor；每条包含 head_digest |
| POST `/workflows` | writer | `{api_version,spec,expected_head}` → workflow |
| GET `/workflows/{id}/versions/{version}` | reader | workflow；ETag 为定义摘要 |
| GET `/workflows/{id}/versions/{version}/export` | reader | 原始 WorkflowSpec；attachment、nosniff、ETag |
| POST `/workflows/validate` | reader | `{api_version,spec}` → `{api_version,valid,diagnostics,nodes}` |
| POST `/workflows/{id}/versions/{version}/compile` | writer | 编译请求 → plan |
| GET `/workflow-plans/{planID}` | reader | 不可变 plan；ETag 为计划摘要 |

目录 limit 为 1–100（默认 50），cursor 为上一页最后一条 `id@version`，按该键稳定升序，不能将字典序当作版本新旧。head_digest 指向同一工作流的当前版本。版本按三段非负十进制数比较，不受整数溢出影响；新版本必须严格递增。

编译请求示意（ID 由真实接口返回）：

```json
{
  "api_version": "codexploit/v1",
  "snapshot_id": "snapshot-id",
  "inputs": ["source-artifact-id"],
  "language": "Go",
  "knowledge_revision": "latest",
  "max_input_bytes": 67108864
}
```

inputs 是根产物 ID 列表，每个已声明类型恰好一项。服务端从项目与快照解析 authoritative Scope，再读取并校验产物实际大小、摘要、Schema 与适配器要求，调用方不能提交伪造 ArtifactRef。max_input_bytes 默认 64 MiB，上限 256 MiB；它是根输入总预算，各节点还有 WorkflowSpec 固定的超时。当前宿主上限 120 秒，Schema 通用上限 600 秒不代表当前宿主支持该上限。

language 是操作者声明的分析语言，必须被所有插件支持。编译不解析源码，不能把该声明当作实际覆盖证明；后续调用报告才说明分析范围。knowledge_revision 省略或 latest 时解析当前共享版本；rev-0 是无发布事实的初始版本，其稳定摘要为 SHA-256(`rev-0`)。

## 类型绑定与版本固定

`WorkflowCompiler.Validate` 校验未知字段、重复节点、缺失依赖、环路、插件存在与执行器可用性、离线参数 Schema、节点超时和类型歧义。诊断使用 JSON Pointer 字段路径，例如 `/nodes/0/config/include_comments`，不回显配置值。

节点的 consumes 只能由根类型或 **needs 中直接列出的节点输出** 满足。不能从传递依赖、其他任务或任意已有产物中隐式取值。当前适配器均为单值输入，零来源报 missing_input，多来源报 ambiguous_input；没有集合输入合并或命名端口选择器。已安装输入协议还固定 schema_id 与必要的 producer_plugin。

计划保存完整 WorkflowSpec / 定义摘要、编译器版本、插件版本 / 包摘要 / 清单摘要、参数字节 / 摘要、Scope、完整根 ArtifactRef、声明语言、知识 revision / digest、输入总预算、节点超时、拓扑序、直接依赖和类型 / Schema 输入绑定。绑定的 source 区分 root / node，避免节点名 root 与根输入碰撞；内部输入通过 from=node_id 指向上游输出；真实中间产物将在运行时生成，编译器不伪造它们的 ID 或摘要。

计划摘要是 PlanBody（不含 plan_id、digest、created_at）的 JSON 编码 SHA-256；plan_id 使用摘要前 32 个十六进制字符。相同固定输入重编译返回首次保存的计划时间。内置插件源代码摘要规则保持兼容。

## 错误与持久化

| HTTP | code | 含义 |
|---|---|---|
| 400 | invalid_workflow | Schema / 请求格式错误 |
| 401 / 403 | 认证或权限错误 | 未登录 / 无相应能力 |
| 404 | workflow_not_found | 项目、版本、计划或快照不在当前 Scope |
| 409 | workflow_conflict | 同版本不同定义、陈旧 head 或非递增版本 |
| 422 | workflow_invalid | 编译失败；diagnostics 包含字段路径、code 和说明 |
| 500 / 503 | contract_violation / workflows_unavailable | 合约或服务失败，不返回模拟成功 |

Validate 正常返回 200，通过 valid 表示结果；失败时 nodes 为空。常见诊断包括 schema、duplicate_node、cycle、missing_dependency、plugin_missing、plugin_unavailable、config_schema、timeout_policy、missing_input、ambiguous_input、input_schema、input_producer、language、budget、revision_missing。

`internal/workflow` 提供 Catalog（Save / Get / List）和 Compiler（Validate / Compile / Get）公开边界。Repository 负责不可变版本、head CAS 和计划原子保存；插件目录、产物存储、Scope 和 Knowledge 是窄接口。新增执行适配器时，在应用组合层向 Compiler.AdapterInputs 登记与 PluginHost 一致的 Schema / producer 协议；只导入清单不会安装执行器。

Memory 使用同一锁保护版本和 head；SQLite 使用项目行写锁与事务将版本、head 一起提交。计划按快照写入栅栏保存，快照删除时清理计划，迟到写入不能复活已删除快照。版本、head、计划分别由 migration 0018 的三张表持久化。SQL 使用通用语法；本次已验收 Memory / SQLite，未宣称经过真实 PostgreSQL 容器验收。

本次测试仅位于已约定的认证 HTTP API 和 WorkflowCatalog / WorkflowCompiler 公开边界，覆盖重启、权限、项目隔离、CAS 并发、旧版本 / 计划不可变、Schema、参数、类型、依赖、预算、取消及快照删除。正式页面另做浏览器验收。
