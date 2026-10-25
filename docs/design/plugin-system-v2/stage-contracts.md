# 各阶段输入输出规范

本文是 [插件方案](README.md) 的 payload 规范，与 [stages.json](templates/stages.json) 配套。字段是对外数据要求，不规定工具内部的类、数据库或分析步骤。已有领域 Schema 继续约束 Agent/环境/验证；正式跨语言 JSON Schema 位于 contracts/v2；运行边界见 [开发手册](../../plugins-v2.md)。

## 共同调用与数据包装

调用使用 plugin_id + plugin_version + release_digest + operation_id 固定执行身份；宿主权威保存输入 ArtifactRef、config_digest、knowledge pin、租约及任务关联。适配器无法自行改变这些字段。file-job 是它的本地传输视图，不要求把宿主租约或凭据发送给工具。

端口 `cardinality=one` 恰好一个引用，`many` 至少一个引用；`required=false` 表示允许整个端口缺席。空集合内容与缺失产物不同：空 alerts 数组是有覆盖情况下的零命中，缺少 alerts 输出则是契约错误。

标准 JSON 产物包装：

| 字段 | 类型 / 要求 |
|---|---|
| api_version / kind / schema_id | 固定的协议版本、类型、Schema 版本，不能以自由字符串协商隐式降级 |
| scope | project_id、source_id、snapshot_id 必须与宿主一致；source 创建阶段由宿主预分配身份 |
| producer | plugin_id、plugin_version、operation_id、package_digest、invocation_id、config_digest、normalizer_digest；无 normalizer 时其值为 null |
| inputs | 固定 ArtifactRef 列表，每个都有 kind、schema_id、Scope、bytes、sha256 |
| coverage | 同单位 seen/analyzed/skipped/failed、truncated、reasons；未知计数为 null |
| limitations | 字符串数组，不省略解析失败、动态派发、外部依赖或预算截断 |
| data | 下列各阶段的数据对象 |

现有 v1 原生 Schema 没有这些统一字段时，桥接器负责生成 v2 包装；不能要求旧产物原地变化。Markdown/SARIF/CPG 等原生文件使用 sidecar 描述符，宿主验证媒体类型与内容格式，不往二进制内强塞 JSON 包装。

位置 `Location={file,start_line,start_column,end_line,end_column}`：快照相对路径，1-based、结束开区间，未知列或结束位置为 null；没有源码位置时 Location=null 并提供原因。旧产物若使用其他坐标约定，由桥接器显式转换并记录版本。

## source：源码接入

输入 `source.request.data`：

- source_definition_ref：宿主登记的目录/Git/上传定义 ID，禁止直接传任意命令；
- expected_revision：可选的固定 Git commit 或导入 ID；
- exclusion_policy_ref、capture_budget：固定排除规则版本和采集预算；
- credential_ref：可选、受 Scope 限制的宿主引用；秘密由驱动注入，禁止输出。

输出 source.snapshot：不可变 tar/file-set 字节，sidecar 包含 files（path/bytes/sha256/parseable language hint）、content_digest、source_revision、exclusions（path/reason）、capture coverage。语言 hint 不等于解析成功。

不允许执行目标构建或 hook。相同快照引用必须读到相同内容；采集失败或超过硬预算不得发布“空快照成功”。创建/最终发布快照的权力由宿主保存。

## parse：代码事实

输入为固定 source.snapshot，可带用户明确指定的语言/前端配置。标准输出 code.facts.data：

| 字段 | 必要子字段 |
|---|---|
| files[] | file_id、path、language、parse_status（parsed/partial/unparsed/unhandled）、reason |
| symbols[] | id、file_id、kind、name、qualified_name、signature、location |
| calls[] | id、caller_ref、callee_ref（可为 null）、callee_text、location、resolution、evidence_refs |
| native_id_mappings[] | native_artifact_ref、native_id、canonical_ref、mapping_rule、mapping_status |

解析器可提供 AST/CPG/CFG 等附加原生产物，但标准 code.facts 是替换默认 parse 节点的条件。普通名称相同不能成为跨文件调用解析证据；没有 callee 时保持 unresolved，不生成假边。

canonical ID 由宿主规范化器以固定身份规则生成；适配器可提供候选 ID 与键，宿主核对映射。映射失败、冲突、语言不支持分别计数，旧 Go ID 不变。

## semantic：安全语义

输入 source.snapshot 和 code.facts；两者必须来自同快照，代码事实已验证。security.facts.data：

- entries[]：id、entry_kind、symbol_ref、location、observed_or_inferred、evidence_refs；
- sinks[]：id、operation_kind、symbol_ref、location、sensitivity、evidence_refs；
- controls[]：id、control_kind、location、status（observed/unassessed）、evidence_refs；
- relations[]：id、from、to、kind、observed_or_inferred、evidence_refs；
- ruleset：id、version、digest。

关系端点必须存在于固定输入或本批节点内。识别到 sanitizer 名称不证明某条路径已消毒；实际控制是否生效留给带证据的路径/Agent/验证分析。输出候选必须显式 status=candidate。

## scan：规则扫描

输入固定 source.snapshot。scanner.alerts 使用现有 scanner-alerts/v1 数据语义：tool/ruleset 元数据与 alerts。每条 alert 必须给出 id、rule_id、rule_version、title、location、message、severity_hint、evidence_refs、limitations。

工具原始报告单独留存，转换器绑定 raw artifact。告警的工具本地 ID 不能直接成为跨工具 finding 指纹；只有显式规则等价表可归并。无法解析的文件计 failed，不包含在“扫描无告警”统计。

## path.generate：候选路径

输入 code.facts + security.facts，并固定各自图版本；Joern 原生图可作为显式第三端口，不可暗查另一个快照。

discovery.paths.data：paths[]、graph_pins（code/security 是输入 ArtifactRef.ID）、omitted（count/reasons）。每条 path：

- id、entry_ref、sink_ref、ordered_steps（from_ref/to_ref/relation_ref/location）；
- basis（call_reachability/data_flow/hypothesis）、completeness（complete/partial）；
- scg_refs、asg_refs、evidence_refs、unresolved_segments、limitations。

complete 只表示该 basis 的已提供步骤完整，不表示可利用。data_flow 需要对应数据流边/变量传播证据，不能把 AST、CFG 或调用边重命名为 taint。探索路径缺少 sink 时必须 hypothesis/partial。

## path.enhance：路径筛选与评分

输入 discovery.paths，必要配置包括 scoring_version、weights_digest 及数量/优先级/入口预算。输出保留路径与 path.enhancement：

- selected[]：path_id、rank、score、features、reason_codes；
- filtered[]：path_id、filter_code、reason；
- scoring_version、weights_digest、source_path_artifact；集合输出使用 codexploit/path-enhancement/v2。

selected 与 filtered 不相交，其并集等于输入 path ID 集；不产生新 ID/端点/步骤/证据，禁止改变 basis、完整度或严重度。排序平分使用稳定 path ID 打破平局。因预算过滤标 truncated；明确阈值过滤保留原因但不自动当分析故障。

路径扩展/补边应成为另一个 path.generate operation；不能混入纯筛选阶段。

## agent：义务审查

输入 agent.task 沿用宿主实际 Schema 版本，固定 obligations、path、知识 pin、工具权限、预算和已有证据。输出 agent.answer 按 obligation 的 kind 提交 met/not_met/unknown；unknown 必须有合法 blocker，附 evidence_refs、falsifiers、recommendation。

旧 schema 1 与 schema 2 必须分别验收；不能把当前 v1 Schema 名当作所有 run 都有义务字段的证明。模型、prompt、工具集和配置版本由领域 runtime 固定。

普通分析插件不能通过返回 agent.answer 自授模型工具或变成已确认裁定；领域答案校验通过才入库，结构错误按现有修复策略处理。

## environment：环境供应

输入 environment.request 包含 approved_plan_ref、authorization_ref、frozen source/target digest、components（镜像/二进制摘要与依赖）、network_policy、resource_budget、lease_ttl。

输出 environment.receipt：environment_id、provider id/version、applied_spec_digest、actual components、actual network policy、lease id/epoch/expires_at、health checks、cleanup_handle、limitations。

环境供应失败必须记录资源清理结果；创建成功不等于目标健康。未知网络隔离能力返回 unsupported，不能以清单 network=none 代替真实隔离。租约与销毁由 provider/宿主协调。

## verification：真实证据

输入 verification.plan 和 environment.receipt；plan 绑定授权、目标快照、环境要求、固定步骤、断言和预算。宿主在执行前再次检查批准版本和租约。

输出 verification.evidence：plan_digest、environment receipt ref、started_at/finished_at、execution_status、assertions[]（id/expected/observed/result/evidence_refs）、command/test evidence refs、cleanup、limitations。

assertion result 为 passed/failed/inconclusive；基础设施异常独立标 execution_status=infra_error。未复现、计划错误、环境失败不推出已排除；最终裁定由宿主明确规则从结构化证据派生。

## report：固定报告

输入 report.input 固定 Scope、任务选择、knowledge revisions、发现账本版本、候选策略、finding/observation/severity audit/evidence/path、开放问题和覆盖；不能在生成时隐式读取 latest。

输出 report.document 可为 Markdown、JSON 或 SARIF；描述符固定格式、bytes、sha256、input refs、producer、generated_at、limitations。SARIF 的 tool/rule/location 信息从固定来源生成，不能漏掉“仅候选”语义。

报告只复述捕获的事实与裁定；缺失证据或超限明确失败/PARTIAL，是否接受由计划控制。报告不能为了格式完整虚构验证环境或日志。

## 标准 profile 与 native profile

standard profile 必须交付对应阶段的全部 required 输出。native profile 可以返回 tool.native，但仅供明确接受该 Schema 的端口消费；不可进入要求标准输出的默认阶段。

每个 native Schema 由 registry 登记供应商 namespace、格式版本、对应工具发行版本范围和媒体类型，例如 joern/cpg/v1 是本方案的逻辑包装版本，并非声称 Joern 上游官方格式版本叫 v1。CPG 真实格式元数据另外记录，缺失则不允许跨版本复用。
