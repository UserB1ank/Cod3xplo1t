# L5 统一插件层

接口：`PluginCatalog`、`PluginHost`。Schema：[plugin.schema.json](../../../../contracts/v1/plugin.schema.json)。示例：[plugin.json](../../../../contracts/v1/examples/plugin.json)。

## 清单字段

id 使用命名空间；version 固定 major.minor.patch；kind 为 parser / analyzer / normalizer / graph / agent / reporter。清单声明 languages、runtime、consumes、produces、permissions、config_schema。

`runtime.kind` 可以为 builtin、process、container、remote。后三者声明 entrypoint，具体解释由执行适配器确定：受信任包内相对程序、固定摘要镜像、已登记服务地址。不得解释为任意 shell 命令。注册 Manifest 与下载/安装/授权/运行是不同状态。

config_schema 只使用本地注册 Schema。节点 config 必须通过该 Schema；敏感参数使用凭据引用，不保存明文值。v1 示例 Schema 采用关闭额外字段的空配置。

## 宿主接口

| 方法 | 请求 | 响应 | 约定 |
|---|---|---|---|
| `Register` | 清单、包内容摘要、来源信息 | 插件版本记录 | 同版本不可替换包 |
| `Get / List` | id + version / 能力过滤分页 | 清单、可用性与不可用原因 | 可区分注册、已安装、可执行 |
| `Execute` | 固定插件与包摘要、CallContext、Scope、输入引用、输出预算、config、租约栅栏令牌 | invocation_id、状态查询与事件游标 | 幂等启动，及时返回 |
| `GetStatus` | invocation_id | 状态、已发布产物、有限诊断 | 不回传隐藏推理或原始密钥 |
| `Cancel` | invocation_id、原因、expected_version | 受理状态 | 重复取消成功；取消后的迟到输出无权提交 |

调用状态：CREATED → STARTING → RUNNING → SUCCEEDED / PARTIAL / FAILED / CANCELLED / TIMED_OUT / UNSUPPORTED。失败状态不会隐式创建已确认漏洞。

## 进程传输协议

目标 transport 为双向 [JSON-RPC 2.0](https://www.jsonrpc.org/specification)，UTF-8 NDJSON，每行一个完整消息，stdout 仅放协议消息，stderr 是限额日志。请求 id 为字符串；宿主按 id 路由响应，支持执行中反向请求，不能持有全局执行锁等待工具回调。

| RPC 方法 | 方向 | 内容 |
|---|---|---|
| `plugin.initialize` | host → plugin | 协议版本、清单摘要、宿主能力；返回选定版本和插件能力 |
| `plugin.execute` | host → plugin | 上述 Execute 请求；返回 invocation_id |
| `plugin.status` | host → plugin | 有界状态与产物引用 |
| `plugin.cancel` | host → plugin | 请求取消指定调用 |
| `plugin.event` | plugin → host，通知 | invocation_id、seq、type、简短内容 |
| `host.graph.query` | plugin → host | 当前固定视图的有界只读查询 |
| `host.artifacts.read` | plugin → host | 当前 Scope 产物的有界分块读取 |
| `host.artifacts.stage` | plugin → host | 声明输出类型、大小和期望摘要，申请暂存引用 |

单条控制消息上限 1 MiB；大型 AST/报告走产物通道。收到无效 JSON、重复/跳跃事件序号、越界读取或协议超限后终止本次调用并记录诊断。事件恢复从持久化 seq 读取，通知投递允许重复，消费者按调用 ID + seq 去重。

## 执行与权限

有效权限 = 清单声明 ∩ 安装授权 ∩ 任务策略 ∩ 执行器可强制能力。process 执行器本身不能证明网络或系统调用隔离；要求强隔离的插件只能选择满足能力的容器/远程 worker，否则返回 unsupported。

源码只读、工作目录独立、资源限额、超时与取消由宿主控制。v1 不允许运行目标项目的 build/test/hook。运行分析工具程序与执行被审计仓库代码是两个不同权限。

容器执行由受控 worker 管理，应用和分析插件不挂载宿主 Docker socket。应用一体编译；外部工具通过按需工具镜像或 worker 安装，不要求打包所有工具到主镜像。

## 兼容与验收

现有 `agent.Runtime`、`ToolExecutor`、`verify.Executor` 是各自领域接口，并未实现本协议。可用 adapter 保留现有语义；不得把新的 plugin.initialize 发给现有 Agent CLI。

验收：握手拒绝不兼容版本、相同版本包冲突、参数 Schema、工具结果反馈、预算取消、失联恢复、越界与迟到提交，以及没有真实安装时的可用性说明。
