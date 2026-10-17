# 进程扫描器与 NDJSON JSON-RPC 适配器

Issue #12 接入首个固定版本的进程扫描器 `codexploit.static-patterns@1.0.0`。
它作为独立进程运行，通过有界的 NDJSON JSON-RPC 2.0 与宿主通信，读取冻结的
源码 tar，只解析 Go 语法并报告告警位置。它不构建、测试或执行目标仓库的代码，
也不宣称污点流、可利用性或已确认漏洞。

CodeQL 等第三方工具没有随本切片内置：官方 CLI 体积大、许可限制再分发，Go
数据库创建通常需要运行构建/自动构建器，与 v1 的“不执行目标 build/test/hook”
约束冲突。后续可以用同一协议单独接入，不需要改宿主执行路径。

## 包格式与安装

进程包的安装来源是部署目录中的已登记包，而不是 HTTP 上传或任意命令行：

```
plugin-packages/
  codexploit.static-patterns@1.0.0/
    manifest.json
    scanner            # Windows 包为 scanner.exe
```

服务器通过 `--plugin-packages=<dir>` 指向该目录。启动时：

1. `plugin.DiscoverPackages` 读取每个含 `manifest.json` 的目录；
2. `plugin.LoadPackage` 按公共 `plugin.schema.json` 校验清单，并要求
   `runtime.kind=process`；
3. `runtime.entrypoint` 必须是包内相对路径，不能是绝对路径、`..`、反斜杠、
   盘符或冒号；入口必须是普通文件（Unix 还要求可执行位）；
4. 包摘要绑定规范化清单和除 `manifest.json` 外的每个普通文件（路径、大小、
   SHA-256）；符号链接、特殊文件、大小写重复路径和越界路径拒绝；
5. `plugin.NewHost` 把包清单登记为不可变插件版本，并记录
   `source=local package <id>@<version>`；同版本不同清单/包摘要返回
   conflict，不会静默替换。

`GET /api/v1/plugins` 的 `Record` 现在同时给出 `installed` 与 `executable`：

| 状态 | 含义 |
|---|---|
| 已登记 | 清单在目录中，可能是手工导入的外部清单 |
| 已安装 | 部署目录中的包内容通过校验，包摘要与登记版本一致 |
| 可执行 | 宿主实际注册了对应执行适配器、入口存在且可启动 |

手工登记的外部 process 清单在没有本地包时显示为“仅登记”。容器/远程 worker、
多实例租约和 HTTP 安装接口仍是后续 Issue；当前只用部署目录安装。

构建与部署：

```bash
# 生成 bin/plugin-packages/codexploit.static-patterns@1.0.0/
make build-scanner

# 或随完整构建
make build
bin/server --plugin-packages=bin/plugin-packages ...
```

Docker 镜像在构建阶段编译扫描器并把同一版本的包复制到
`/app/plugin-packages`；`compose.yaml` 通过 `--plugin-packages` 启用它。

## 扫描器能力

`codexploit.static-patterns@1.0.0`：

- 语言：Go；
- 消费：`source.snapshot`；生产：`scanner.alerts` 原始报告与 `security.facts`
  规范化候选；
- 规则集摘要：`scanner.RulesetDigest()`，随规则表变化；
- 配置 Schema：`{"max_alerts": 1..500}`，默认 200；为零采用默认；
- 权限：`network=none`、`source_write=false`。

规则是明确的语法选择器启发式，不是完整数据流分析：

| 规则 | 观察 | 分级建议 |
|---|---|---|
| `CP001` | `os/exec.Command` / `CommandContext` 收到非字符串字面量参数 | high |
| `CP002` | 文件导入 `database/sql` 时，`Query` / `QueryContext` / `Exec` / `ExecContext` 收到非字面量查询表达式 | medium |

每条告警保留规则 ID/版本、文件与行号、消息、证据摘要和局限。文件解析失败计入
`unparsed_files`，非 Go 文件计入 `unhandled_files`，描述文件（`go.mod` 等）
单独计数；达到告警预算时设置 `truncated`，不会把剩余文件静默当成“干净”。
没有 Go 文件时返回 unsupported，不发布空成功结果。

扫描器只从冻结 tar 读取内容，不落盘解包，不运行 `go build`、测试、hook 或依赖
安装脚本；隐藏推理和宿主环境变量不会写入报告。

## 协议 v1

传输为 UTF-8 NDJSON、JSON-RPC 2.0；stdout 只放协议消息，stderr 是宿主捕获的
限额日志（最多 8 KiB，不进入结果）。单条控制消息上限 1 MiB，请求 ID 为非空
字符串。宿主按 ID 路由响应，并允许插件在 `plugin.execute` 期间反向请求宿主。

| 方法 | 方向 | 内容 |
|---|---|---|
| `plugin.initialize` | host → plugin | 协议版本、清单/包摘要、宿主能力、消息与报告限额 |
| `plugin.execute` | host → plugin | 固定 invocation、Scope、输入 ArtifactRef、配置与预算 |
| `plugin.status` | host → plugin | 有界状态、错误码、覆盖、局限与报告摘要/大小 |
| `plugin.cancel` | host → plugin | 请求取消指定调用 |
| `plugin.event` | plugin → host | `invocation_id`、从 1 开始、连续无重复的 `seq`、短事件 |
| `plugin.output` | plugin → host | 报告分块：连续 `index`、base64 数据、`final` |
| `host.artifacts.read` | plugin → host | 当前 invocation 绑定输入的有界分块读取 |

握手验证：

- `protocol` 必须完全等于 `codexploit/process-plugin/v1`；
- 插件回报的 ID、版本和清单摘要必须与安装包一致；
- 必须声明 `alerts=true`、`network=none`，且不能声明本宿主无法强制的
  `data_flow` 或 `call_reachability`；
- 清单权限为 `restricted` 网络时返回 unsupported，不尝试启动进程假装隔离；
- 报告上限不能超过 16 MiB。

限额与取消：

- 单条读取/输出分块解码后最多 256 KiB，报告总数受调用输出预算与 16 MiB 双重限制；
- 事件序号或输出块序号重复/跳跃、消息 JSON 非法、超长行或越界读取都会终止该次
  调用并记录有限的协议错误码；不回传 stderr 或环境值；
- 取消先发送 `plugin.cancel`，300 ms 后仍未退出则终止进程；迟到的报告块和终态由
  宿主 invocation 版本栅栏拒绝，不能覆盖已取消记录；
- 宿主只把 `PATH`、`HOME`、`TMPDIR`/`TEMP`/`TMP`、`SystemRoot`/`WINDIR` 等
  运行必需变量传给子进程；`CODEXPLOIT_*` 和服务器凭据不会继承；
- 扫描器结束时关闭 stdin，宿主在 2 秒宽限后仍存活则杀死进程。

失败映射：握手/能力不支持 → `UNSUPPORTED`；协议违规 →
`protocol_violation`；预算/超限 → `budget_exceeded`；取消 → `cancelled`；
超时 → `deadline`；工具返回的有限错误码写入 invocation；任何失败都不发布半成品。

## 归一化

`processplugin.Normalize` 把原生 `codexploit/scanner-alerts/v1` 文档绑定到本次
调用并生成标准 `DiscoveryDocument`：

- 检查格式版本、Scope、原始产物 SHA-256/大小/Producer、插件 ID/版本、工具
  ID/版本、规则集与能力声明；
- 每条告警成为 `status=candidate` 的 `Candidate`，标题带规则 ID，证据引用指向
  原始 `scanner.alerts` 产物；`path_refs` 和 `paths` 保持为空，不伪造调用步骤；
- 拒绝绝对/穿越/反斜杠文件路径、非法行号、未知分级、重复告警 ID、超预算数量；
- 全局和逐条局限保留在候选与文档上，明确“仅告警位置，不建立污点流、控制有效性
  或可利用性”；
- 未知报告版本或声明 `data_flow`/`call_reachability` 时返回 unsupported，原始
  报告仍可作为证据保留。

## 工作流、发布与页面

插件在正式插件目录出现后，可在工作流节点中选用；工作流编辑器在扫描器已安装且
可执行时提供“加入进程扫描器”快捷入口。扫描节点的原始报告和标准结果都经过
ArtifactStore 核对，`$publish` 把候选事实（`kind=scanner.alert`）与其他插件
观察一起发布为不可变知识版本；候选保留插件、版本、调用、任务、配置摘要和原始
证据引用。重试不会重复计数不同版本的候选。

发布完成后，宿主把带显式 `rule_id` 的候选观察写入 finding 观察账本：同 Scope、同规则族、同规则版本、同文件与行号的观察按版本化指纹归组，重复发布/重试按 observation id + digest 幂等，新的调用只增加来源而不增加组或统计数。没有 `rule_id` 的内置路径候选不进入该账本，避免按标题跨工具合并。候选保持 `candidate`，不能改变验证裁定。正式“项目漏洞库”页显示组、来源任务/插件/规则/证据和分级审计；分级必须填写原因，并与发现版本一起原子写入。

任务页的“进程扫描告警”区域显示：

- 插件与版本、调用 ID、状态、输入覆盖和包摘要；
- 标准候选、分级建议、文件行号、证据引用和局限；
- 原始报告内容、原始产物 ID/SHA-256 和是否已进入知识发布。

API 路径沿用已认证的插件调用与知识发布端点，不新增绕过 Scope 的入口。正式页面
失败时显示真实错误，不退回演示数据。

## 验收测试

- `internal/plugin/rpc`：真实双向管道上的调用、通知、超长行、非法响应；
- `internal/plugin`：包摘要、清单规范化、入口逃逸/链接/缺失、发现顺序、重复包、
  registered/installed/executable 状态；
- `internal/processplugin`：握手、事件序号、宿主读取、输出分块、环境隔离、
  消息/报告限额、取消迟到结果、真实 `cmd/scanner` 二进制经 Host 执行与归一化；
- `internal/scanner`：合成漏洞样例、语法错误、告警预算、越界 tar、无目标代码执行；
- `internal/api`：认证目录、真实扫描调用、原始报告读取、候选结果、知识发布与
  revisions facts；
- 工作流集成：扫描节点执行后 `$publish` 产生含 `scanner.alert` 的不可变版本。
