# 分阶段插件运行与开发

本实现借鉴 ScopeSentry 的模块职责、类型化衔接和独立安装检查机制。完整设计和上游源码依据见 [设计方案](design/plugin-system-v2/README.md)。宿主只验收阶段输入输出、执行身份和生命周期，第三方工具可以保持闭源二进制形式。

## 身份和登记

清单使用 `codexploit/plugin/v2`。一个 operation 显式声明 stage、capability、profile、具名输入输出端口和参数 Schema。十个阶段对应九类能力：source、parse、semantic、scan、path.generate、path.enhance、agent、environment、verification、report。正式目录为 `contracts/v2/stages.json`，数据结构为 `stage-payload.schema.json`；[十份清单模板](design/plugin-system-v2/templates/manifests/) 覆盖全部阶段。

逻辑定义由 plugin_id + version + manifest_digest 固定；平台 release 另登记 OS/arch、package_digest。相同版本不能替换清单，同一平台发行包不能静默换内容。宿主内编译的旧插件另存 build_id，以兼容既有宿主构建指纹；此例外不适用于外部 process 包。

每个工作区生成持久化、随机 worker_id，独立记录 installed、enabled、integrity、probe、checked_at 和 CAS version。不采集 hostname 或系统用户名。登记不安装，安装不代表功能实测。真实调用完成才更新 probe；完整性检查不执行工具，不把握手通过写成 probe passed。禁用阻止新调用；卸载只撤销执行登记，保留历史及部署文件，有活动调用时拒绝卸载。

PostgreSQL 的 `0021_plugin_releases.sql` 保存发行与安装状态；Memory 支持相同边界。SQLite 保留 v1 兼容路径，不新增 v2 安装表。旧清单、固定计划和 ArtifactRef 不原地升级。

## 开发一个二进制插件

```sh
make build-plugin-tools
mkdir -p /tmp/example-plugin/bin
# 将固定版本工具与依赖放入包内，并提供 bin/adapter。
# 复制阶段模板为 manifest.json，选 file-job/v1 并填写准确端口。
bin/pluginpack --directory /tmp/example-plugin --seal
bin/pluginpack --directory /tmp/example-plugin
```

最后两个命令仅封存/核验文件，输出可登记的 Release JSON，不启动插件。`--seal` 生成 `files.lock.json`，拒绝覆盖不同的已有锁。打包后任何文件、可执行位或清单改变均需要重新发布版本。清单和锁使用 RFC 8785 JCS；重复 JSON 键被拒绝。锁覆盖工具、adapter、JAR、脚本、查询、模型及依赖文件。拒绝链接、特殊文件、绝对路径、穿越、路径大小写冲突、缺失/额外文件和摘要不符。包上限 2 GiB、64,000 文件；v1 包上限保持不变。

开发者可导入仅依赖标准库的公开 `pkg/pluginsdk`，或用其他语言实现同一文件/JSON 协议，不需导入宿主 internal 包。`JobRequest`、`JobResult`、具名端口和 DTO 位于该包；`ReadJob`、`ReadInput`、`WriteResult` 提供有界读取、绑定输入核验及原子结果写入。[接口模板](design/plugin-system-v2/templates/adapter.go.tmpl) 说明生命周期；它本身不含分析算法。

对于现成 CLI，可把 `bin/plugin-adapter` 作为清单 entrypoint，在包根放 `recipe.json`。recipe 固定 executable 与 argv，禁止 shell；支持 `{input:port}`、`{input:source_tree}`、`{config:key}`、`{output:name}`，以及包内 `runtime_paths`。源码 tar 在独占目录安全展开，工具读取该冻结副本。adapter 收集实际产物大小与摘要。通用 CLI 未提供覆盖计数时返回 PARTIAL 和未知 analyzed，不伪造全面分析成功。

可采用如下包结构：

```text
manifest.json
files.lock.json
recipe.json
bin/adapter
vendor/tool
vendor/runtime/...
queries/...
```

启动配置 `--plugin-packages=/deployment/plugin-packages` 指向发行包父目录。管理 API 只能安装该目录中已完整核验的发行包；没有下载 URL、任意本机目录或在线安装脚本入口。包不必使用特定编程语言。

## 两种进程协议

`codexploit/file-job/v1`：宿主创建独占 job 目录，写入 job.json 与输入副本，固定 argv `--request <job.json> --response <result.json>` 启动 adapter。它写出 result.json 和 outputs 中的普通文件。响应包含 invocation、status、具名端口、kind/schema、bytes/sha256、coverage 和 limitations。宿主核验全部输出后一次提交调用终态和全部产物索引。

`codexploit/process-plugin/v2`：有界 NDJSON JSON-RPC 2.0，提供 initialize、execute、status；双向 `host.artifacts.read` 只能读取绑定端口/产物，输出通过 begin/write/finish/abort 暂存。握手必须匹配包、清单、operation 和端口；消息 ≤ 1 MiB，块 ≤ 256 KiB，连续序号及实际摘要必须一致。finish 不等于发布。最多 200 个有序进度事件随成功终态持久化；进程中断前尚未终态保存的事件不是持久审计日志。

每次执行前核验原始发行包，复制全包至私有目录再次核验，执行后重新核对；不直接运行可能正在被管理员修改的部署目录。环境变量仅注入固定路径和临时 HOME/TMP，避免继承宿主密钥环境。Unix 使用独立进程组取消，Windows 尝试终止进程树。超时、取消、摘要失败和迟到结果不发布部分输出。

这些是普通本地进程驱动，不是 OS 沙箱。`network=none` 是契约声明，不能当作内核网络隔离证明。需要强隔离或不可信二进制时，应由独立受限 worker/容器部署提供；restricted 网络策略及目标代码执行在普通驱动返回 unsupported。source、agent、environment、verification 使用现有领域服务/适配器；普通 process 清单不能授予这些领域权限。

输入预算上限 256 MiB；输出合计默认 256 MiB、上限 512 MiB，标准 JSON/文本报告单项最多 64 MiB，原生文件按预算流式核验。超时默认 300 秒、上限 3600 秒。旧适配器保留原来的 64 MiB/120 秒限制。

## 数据与工作流

宿主验证实际 ArtifactRef、Scope、具名端口、基数、参数和预算。required=false 允许缺席；many 可绑定多个同契约产物。工作流依赖根据 kind + schema + output port 解析，不再要求新节点由某个内置 plugin_id 生产。

标准代码事实、安全语义、路径和路径增强由宿主添加 scope、producer、inputs、coverage 与 normalizer 摘要。代码文件/符号/调用 ID 按既有 SCG 身份规则规范化，重写本批引用及 native 映射；未知位置保留 null。同一快照下相同身份跨工具稳定，原生 CPG ID 不能直接进入标准图谱。未解析调用不生成已解析调用边。

语义引用必须存在于固定代码输入或本批节点；路径固定 `graph_pins.code/security` 为输入产物 ID，校验端点、步骤连续性和对应关系。调用边不能充当 data_flow。path.enhance 使用 `codexploit/path-enhancement/v2`，selected/filtered 必须覆盖且分割原路径集合，保留路径内容逐项一致，分数平局按 ID 稳定排序。

标准 code/security/path 结果可由 `$publish` 或知识发布 API 转成不可变共享事实；候选路径不会自动变为确认漏洞。扫描阶段的 scanner.alerts 保持 v1 原始告警格式，若要直接发布共享安全事实，应显式声明并生成 security.facts 输出；既有 v1 scanner 继续走已安装的独立 Normalizer。原生 tool.native 只供显式接受其 Schema 的端口消费，不满足默认 parse 节点的 code.facts 要求。

当前内置候选 Agent 仍消费既有 native path/SCG/ASG。v2 候选路径可发布和继续交给显式 operation；尚未配置领域转换桥时，请求旧 `$analyze` 会明确失败 `stage_domain_bridge_unavailable`，不会显示“没有候选”或虚构 Agent 成功。

报告验证实际 MIME、UTF-8 和完整 JSON；SARIF 要求 2.1.0 与 runs 数组。报告来源和输入引用由宿主产物描述符固定。Joern CPG、Markdown 等保留原生字节，不强塞 JSON 包装。

## 认证管理 API

| 方法和路径 | 行为 / 权限 |
|---|---|
| GET `/api/v2/plugin-stages` | 十阶段契约及当前 OS/arch；reader |
| GET/POST `/api/v2/plugins` | 查询 / 登记 v2 定义；reader / admin |
| GET `/api/v2/plugins/{id}/versions` | 固定版本目录；reader |
| GET/POST `/api/v2/plugins/{id}/versions/{version}/releases` | 平台发行目录 / 不可变登记；reader / admin |
| GET/POST `/api/v2/plugin-installations` | 节点安装目录 / 从部署包安装；reader / admin |
| POST `/api/v2/plugin-installations/{id}/check` | 全包完整性复核；admin，If-Match |
| PATCH `/api/v2/plugin-installations/{id}` | enabled 策略；admin，If-Match |
| DELETE `/api/v2/plugin-installations/{id}` | 撤销安装登记；admin，If-Match |

调用和历史继续通过 `/api/v1/projects/{project}/snapshots/{snapshot}/plugin-invocations`，增加 operation_id 与和 inputs 一一对应的 input_ports，返回 stage_coverage/stage_events。请求固定实际 package_digest；不允许以 latest 替换。v1 目录保留旧清单兼容读取，v2 目录包含两代定义。认证响应按生产 Schema 离线验证。

正式“插件中心”的“分阶段插件管理”支持阶段筛选、版本/摘要/工具/节点状态、清单登记、安装/检查/启停/卸载，以及固定输入执行；工作流图形与 JSON 编辑支持 operation 选择和具名绑定。

## Joern 集成范围

`codexploit.joern@1.0.1` 已接入 Go 标准解析：固定二进制与 JDK，产出原生 CPG 和 `code.facts/v2`，支持插件中心调用及类型化工作流。构建、安装、平台范围、覆盖局限和验收命令见 [Joern 手册](joern.md)。

宿主允许标准代码事实通过 `output:<port>` 引用本调用唯一的 native 输出，在发布前绑定真实 ArtifactRef；只有已绑定 native 输入或本次输出可以出现在 native 映射中。


`codexploit/file-job/v2` 保持 v1 执行方式，额外要求每个输入携带宿主固定的 `artifact_id`；请求与响应必须同版本。新 Joern 适配器使用 v2，将 CPG、标准代码事实、污点报告和路径 pin 绑定到实际产物身份。v1 独立二进制继续收到原有字段。完整接入见 [Joern](joern.md)。
