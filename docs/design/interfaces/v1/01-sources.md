# L1 代码源层

接口：`SourceProvider`。Schema：[source.schema.json](../../../../contracts/v1/source.schema.json)。示例：[本地文件夹](../../../../contracts/v1/examples/source-local.json)、[Git 仓库](../../../../contracts/v1/examples/source-git.json)。

## 职责与类型

项目拥有代码源定义；代码源提供读取与版本解析能力，源码只有物化为快照后才能分析。

| kind | location | ref | 读取语义 |
|---|---|---|---|
| `local_folder` | 挂载登记范围内的 `/repos/...` 路径 | 空字符串 | 按文件内容读取，不因存在 `.git` 自动切换模式 |
| `git_repository` | 无内嵌凭据的 HTTPS / SSH 仓库 URL | 分支、标签或提交 | 解析并固定到提交，后续分析使用固定对象 |

v1 先支持挂载文件夹与远程 Git。浏览器上传、同步目录及本地 Git 对象库可以作为新的 provider 能力接入，不能把浏览器电脑路径当作容器路径。

## 标准方法

| 方法 | 请求 DTO | 响应 DTO | 副作用 / 幂等 |
|---|---|---|---|
| `ListSources` | project_id、cursor、limit | SourceDefinition 页 | 只读 |
| `Probe` | SourceDefinition、网络策略引用 | 可用性、能力、限制、诊断 | 可做有界连接探测；不运行仓库代码 |
| `Resolve` | source_id、source_version、ref、CallContext | resolution_id、固定 source_revision、能力、限制、到期时间 | 可更新克隆缓存；相同固定输入可复用 |
| `Release` | resolution_id | 释放受控读取句柄 | 重复释放为成功 |

`ResolvedSource` 保存来源类型、固定版本、内容摘要所需的读取句柄引用。不得把 provider 的临时绝对路径当作可移植公开接口。读取句柄具有 TTL，快照服务在到期前完成物化。

## 校验与失败

- 定义修改递增版本；新快照必须记录所用定义版本。
- 项目归属、挂载登记和凭据访问在 Resolve 前校验。
- 目录复制前后重算内容清单，变化时返回 `source_changed`（409），不发布半成品快照。
- Git 的分支变动不会改变已经解析的提交。获取失败返回 `unavailable`，不存在的提交返回 `not_found`。
- 网络策略不允许时，远程 Probe / Resolve 返回 `forbidden`。
- 省略、过大、不可读、链接、子模块和不支持的内容都计入覆盖范围。源码中的脚本、hook、安装器不能执行。

## 扩展步骤与现有映射

新 provider 声明 location Schema、可固定的版本类型、网络需求、忽略规则和读取能力，然后实现 Probe / Resolve / Release。通用快照服务仍负责限额、内容摘要和冻结。

现有 `internal/repository.Manager.Resolve` 支持目录、本地 Git 和远程 Git的自动识别；显式用户类型及 `local_folder` 强制读取语义尚未在正式 API 接线。原型展示目标分型。

验收：同一固定提交可复现；文件夹变化被检测；跨项目和越界挂载被拒绝；添加代码源不改变已有任务的固定快照。
