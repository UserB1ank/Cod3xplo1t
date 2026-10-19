# 内置语义、路径与规范化接口

Issue #7 接通真实的解析 → 语义 → 路径调用。三个工具都从固定产物读取，保留版本、包摘要、配置、原始报告和 canonical ID；不会执行目标代码、构建、依赖安装或 hook。共享图层的发布在 #8 实现，本切片不替换既有图谱、任务路径或发现裁定。

## 固定工具与输入

| 插件 | 版本 | 有序输入 | 输出 |
|---|---|---|---|
| builtin.go-parser | 1.1.0 | source.snapshot tar | code.ast、code.facts |
| builtin.security-semantics | 1.0.0 | 同一快照的 tar、成功解析调用的 code.facts | 原始 report.document、security.facts |
| builtin.discovery-paths | 1.0.0 | 同一个语义调用的 security.facts、原始 report.document | 原始 report.document、discovery.paths |

解析器因宿主协议与包内容变更升级为 1.1.0。已有 1.0.0 清单、调用和证据保留，旧版本在当前宿主不再显示可执行。包摘要包含宿主、Normalizer、适配器、Go frontend、SCG / ASG / 路径 / 查询引擎源码指纹与工具链；变更编译输入需要提升版本，不能覆盖已有 id/version。

语义参数为 `{}`；路径参数支持 `max_paths`（1–500，默认 200）、`max_depth`（1–8，默认 2）。其余字段拒绝，包括请求 taint_flow 或 confirmed。路径引擎的默认枚举预算还包括最多 200 个入口、每入口 20 个 sink、2000 次链查询；达到预算时保留截断说明，不能据此断言没有漏洞。

宿主校验每个 ArtifactRef 的完整值、摘要、Scope、成功上游调用及对应输出；语义输入还须匹配解析调用所读的 tar，路径的两个输入必须来自同一次语义调用。只有登记的伪造 producer 不能充当上游执行结果。输入总大小和输出合计遵循 [插件预算](plugins.md)。语义阶段的 max_ast_nodes 另外约束生成的符号、调用与边总数；超过限制失败且不发布输出。

## Go 端口

`plugin.Executor` 是组合根提供的编译适配器，包含 Manifest、PackageDigest、有序 InputSchemas / InputPlugins 和 `Run(ctx, invocation, inputBytes)`。HTTP 导入清单无法新增执行代码。当前适配器在 `internal/builtinanalysis`，在私有临时目录重建经过路径、类型、重复项及预算校验的冻结文件，然后仅调用静态 SCG / ASG builder；目录在调用结束时清理。目标源目录始终只读。

`Normalizer.Normalize(invocation, nativeRef, rawBytes)` 返回 DiscoveryDocument，检查原始摘要、宿主 producer、Scope、图层版本、节点/边/步骤的归属和引用。只接受已知原生格式；观察或推断不能变成 verified。原生 ASG 关系沿用既有的混合引用，映射到同一快照的真实 SCG / ASG ID，不重算符号或证据 ID。

`PluginHost.Result(ctx, scope, invocationID, maxBytes)` 读取持久化的不可变标准产物，重新核对摘要并校验 Schema；失败、取消、未结束或不支持的调用不能被下游消费。`GET /api/v1/projects/{projectID}/snapshots/{snapshotID}/plugin-invocations/{invocationID}/result` 为 reader 接口，默认 2 MiB，可用 max_bytes 提高至 64 MiB；超限返回 413。结果只读，无确认或分级修改方法。

## 标准结果与证据

调用的 `analysis` 字段遵循 `analysis.schema.json`：scope、producer、status、outputs、coverage、diagnostics。标准产物遵循 `discovery.schema.json`：

- `native_artifact` 与 `inputs` 固定原始报告和全部输入，保留其 SHA-256 和调用来源。
- `canonical_ids` 列出源图及语义图的原始 ID；nodes / edges 保留规则、来源和 observed / inferred。
- `paths` 保留路径引擎生成的 ID、有序 steps、SCG / ASG 引用、原始证据与 completeness。完整的调用链标为 call_reachability；缺失调用证据或未解析部分标为 hypothesis / partial。complete 仅描述提供的调用步骤，不证明污点传播或可利用性。
- `candidates` 仅允许 status=candidate，含 severity_hint（high / medium / low）、位置、path_refs、evidence_refs、局限。候选 ID 按调用及原生路径 ID 派生；不跨工具去重，不冒充已确认 finding。规则匹配可能过度近似，severity_hint 是待裁定的建议。

工具没有裁定存储的写端口，不创建 confirmed，不覆盖已有的 severity / verdict / evidence。多工具发现分组及审计在 #13 接入。

原生格式分别为 codexploit/semantic-native/v1、codexploit/paths-native/v1，包含当前 SCG / ASG 原生文档，后者增加路径引擎原生生成结果。节点和关系规则、解析不完整或其他语言会保留在 coverage / limitations；未发现候选不能排除漏洞。

## 失败、持久化与页面

正常结果与两项输出在同一事务中发布。规范化失败返回 FAILED / normalization_failed；未知原生格式返回 UNSUPPORTED / unsupported_report_version；两者仅保留原始报告，标准产物不可见。预算失败、取消和超时均不发布半成品。快照删除栅栏、CAS 和单宿主重启规则沿用 #6。

正式插件中心选择固定快照和工具，再选择当前执行记录页内成功的上游调用。详情展示所有输入和输出；候选展开后可查看有序步骤、路径依据、canonical 引用、原始报告摘要和覆盖局限。产物页支持原始 / 标准 JSON 预览、校验和认证下载。解析器、登录和 LLM 配置仍使用已有程序界面。

Issue #17 的宿主路径与图谱依赖升级后，语义与路径插件包版本为 `1.2.0`。旧 `1.1.0` 清单、调用、知识版本和产物继续可读；新执行须在正式工作流页选择当前可执行版本并重新编译计划，旧固定计划不能自动换用新包。
