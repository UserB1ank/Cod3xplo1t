# PostgreSQL 执行模式（Issue #15 / #16 / #17）

这是使用独立 PostgreSQL 容器的实验部署。业务执行可通过数据库租约协调多个 worker；现有账号、会话和模型设置尚未共享，正式 Compose 仍部署一个应用实例。默认 `compose.yaml` 仍使用完整 SQLite 模式，已有数据卷不变。本模式不会回退或双写 SQLite，也不迁移已有 SQLite 数据。

## 已接通的操作

- 认证 API 和正式页面创建、列出、重命名项目；项目版本使用 ETag / CAS。
- 登记本地文件夹与 HTTPS / SSH Git 代码源；凭据仍使用现有项目与 origin 绑定的引用。
- 采集真实固定快照、保存源码清单和基础识别结果；快照 ID 和来源绑定不可变。
- 保存产物索引，按项目 / 代码源 / 快照隔离；读取前核对大小与 SHA-256，下载与 SQLite 模式相同。
- 构建和查询真实 SCG / ASG；插件中心直接执行内置 Go 解析、语义和路径插件，保存不可变清单、调用状态、输入输出与覆盖说明。
- 从已完成调用发布共享知识版本；原生 SCG / ASG / 候选路径索引、直接分析元数据、版本、批次索引和 outbox 同事务提交。相同批次重放返回原版本，不同内容冲突；并发发布使用 head CAS。
- 正式图谱页按固定视图分页查看符号、节点、候选路径、源码和来源；共享知识版本保留同一事实的多个插件观察。直接分析以 invocation 标识，不能冒充执行任务。
- 创建并持久化任务组织、路径队列、Agent / 验证运行、连续事件、发现与证据、工作流版本 / 计划 / 运行 / 节点。正式任务页支持暂停、继续、取消和重试，漏洞库支持带原因的分级审计，报告保存固定版本内容并提供授权下载。
- 应用和数据库容器重建后保留任务、事件、证据、版本与 ID。快照、产物内容、账号和模型设置仍保存在应用工作区卷；PostgreSQL 保存结构化业务状态。

基础源码识别和内置分析不执行目标的 build、test、hook 或安装脚本。外部插件仅登记不代表执行器已安装，以插件目录的 executable 能力为准。模型未配置、验证执行器不可用或产物缺失时返回真实错误，不能由存储 readiness 推断执行器可用。

账号、会话、加密模型设置和产物文件仍沿用现有工作区实现；共享认证与设置由 #18 接入。双 worker 集成测试覆盖共享业务数据库下的执行竞争，不代表多个公开应用实例已具备完整的共享登录和文件部署能力。

## worker 租约与恢复

- 路径领取、退避到期、续租、过期回收与完成校验使用 PostgreSQL `clock_timestamp()`；请求传 TTL，不相信 worker 的绝对时钟。每次新分配递增 `lease_epoch`；续租、释放及结果写入核对 owner、epoch 与数据库有效期。旧 worker 即使复用同名 owner 也无法提交。认证路径 heartbeat / release 在 PostgreSQL 上必须携带领取响应的 `lease_epoch`，缺失返回 400，陈旧返回 409；SQLite 保留原接口兼容性。
- 工作流每次由一个数据库授权的 coordinator 调度，节点仍按固定并发预算并行执行。coordinator 和插件宿主租约为 10 秒，每 2 秒续租，续租请求最多等待 3 秒；连接失败或栅栏失效停止调度，未提交的领用不产生状态或事件。另一个 worker 只能在旧租约失效后接管。API 控制请求通过数据库 CAS 写入，能够从另一个 worker 暂停、继续或取消。
- 工作流状态和连续事件、Agent 创建 / 更新及事件、路径状态和审计事件分别在同一事务提交。插件输出、应用阶段产物、候选 Agent、验证运行 / 证据 / 裁定都检查相应租约；活动工作流、路径、Agent 和验证阻止快照删除。
- 新 coordinator 复用已完成插件调用与产物，从固定产物恢复应用阶段输入；完成的候选 Agent 不重复执行。被接管的旧 Agent 标为失败，其遗留路径分配被回收并增加尝试计数。已暂停运行等待显式继续，中断的直接插件或验证执行记录标为失败，不伪造成功。另一个仍存活宿主的直接调用保持运行。
- 数据库明确回滚的 `40001`（序列化失败）和 `40P01`（死锁）事务最多重试 8 次，使用有界退避。连接中断或提交结果未知不会自动重放；调用方应读取持久化状态并使用原幂等键 / 批次身份重试。

## 启动独立部署

准备仓库外的凭据文件，目录仅部署管理员可访问。两个文件分别包含：

- 数据库密码，供官方 PostgreSQL 镜像的 `POSTGRES_PASSWORD_FILE` 读取。
- PostgreSQL URL，供应用的 `--postgres-dsn-file` 读取。地址为 Compose 服务名 `postgres:5432`、数据库 `codexploit`、用户 `catalog`；密码与第一个文件一致。内部容器网络可使用 `sslmode=disable`；外部部署须按自己的 TLS 策略配置。

通过环境变量传入**文件路径**与只读代码根目录，不将凭据写入命令行、Compose 或 `.env`。文件必须允许容器用户读取（Compose 的文件 secret 使用只读 bind mount），父目录保持私有。

```sh
export CODEXPLOIT_POSTGRES_PASSWORD_FILE=/runtime-secrets/postgres-password
export CODEXPLOIT_POSTGRES_DSN_FILE=/runtime-secrets/postgres-dsn
export CODEXPLOIT_SOURCE_ROOT=/srv/source-inputs
docker compose -p codexploit-catalog -f compose.postgres.yaml up -d --build
```

应用默认仅监听本机 `18095`，可用 `CODEXPLOIT_PG_PORT` 修改。数据库没有宿主机端口，只加入 `internal: true` 的目录网络；应用另外加入 Web 网络用于其明确授权的出站访问。Git 网络访问默认关闭，可用 `CODEXPLOIT_ALLOW_NETWORK=true` 启用。只读输入根中的 `service` 对应页面的 `/repos/service`。

首次在页面设置管理员账号后，可创建项目和代码源、固定快照、查看和下载产物；在工作流页编译真实计划后，可从任务页执行并查看运行及控制。在“插件中心”依次运行 Go 解析、语义与路径插件，选择明确的上游调用，完成后点击“发布到共享图谱”；部分覆盖结果会明确标注。进入“共享知识图谱”查看固定图层和共享知识版本。管理员侧栏“数据存储”实时展示驱动、执行模式、迁移版本、readiness、实际能力及数据保存位置。模型设置继续在程序内管理。Compose 开启任务调度器并加载镜像内固定扫描器包；验证执行器默认 `unsupported`，没有可用环境时明确返回阻塞结果。

停止服务使用相同项目名与文件执行 `docker compose ... down`；保留数据时不要加 `--volumes`。重建仅应用容器使用 `docker compose ... up -d --force-recreate codexploit`，业务状态保留在 PostgreSQL 卷中。

## 状态与失败语义

`GET /api/v1/storage/status` 需要 admin 权限，响应受 `contracts/v1/storage-status.schema.json` 校验，且 `Cache-Control: no-store`。已接线业务的数据库连接和必要列探测成功时返回 200；断连、取消或结构缺失时返回带 `readiness: unavailable` 的 503。readiness 只代表声明的存储模式，不代表未接线功能、每个产物内容或外部执行器可用。

响应只含固定枚举、能力布尔值和迁移版本；不返回 DSN、数据库地址、用户名、凭据文件路径、工作区路径或驱动原始错误。读者可通过 `/api/me` 的 `features` 获得功能开关，不能查看管理员状态接口。PostgreSQL 连接或迁移失败会终止启动，不创建备用 SQLite 文件。

迁移使用独立目录 `migrations/postgres/`。应用先在同一事务与连接中取得 PostgreSQL advisory transaction lock，再创建迁移表、读取版本、执行 DDL 与写入版本；失败整体回滚，连接断开或事务结束自动释放锁。多个应用同时启动不会重复应用迁移。参考 [PostgreSQL 16 锁文档](https://www.postgresql.org/docs/16/explicit-locking.html#ADVISORY-LOCKS)。

快照写入、登记、产物发布和删除使用相同事务级快照栅栏；先锁快照，再锁代码源行。删除 tombstone 阻止迟到写入，完成后仅能用已重新物化且匹配的树恢复登记。项目 CAS 和代码源唯一键由真实数据库约束执行。

活动工作流、插件调用、路径、Agent 和验证阻止快照删除；删除同时清理执行记录、发现、证据、 SCG / ASG、直接分析、候选路径、调用及知识版本索引。发布在已有图层版本相同时保留原索引与 built_at；不同版本返回冲突，不能悄悄改写打开的固定视图。候选路径保持原 ID 和 DISCOVERED 状态，覆盖被预算截断时查询仍显示 `analysis_coverage`，不会表示已完整分析或已确认漏洞。

共享知识版本目录提供 `head_revision` 与 `next_cursor`（每页最多 200，目录预算 10000）；客户端使用真实 head 发布，不能从第一页猜测 head。事实与候选路径同样分页读取。路径查询的直接分析元数据最多显示 1000 条，达到预算会明确标记；完整运行模式合并任务与直接路径时按 10000 条预算截断。图谱查询、Scope、canonical ID 和产物摘要与 SQLite 使用同一实现和契约。

## 验收

```sh
make test-postgres
```

此命令在仓库外生成随机临时凭据，建立独立 Compose 项目与全新数据库，执行真实 PostgreSQL 的乱序竞态集成测试，最后删除该项目、测试卷及临时凭据。数据库不暴露宿主端口。需要 Docker Compose、Python 3 和镜像下载权限。

已有独立测试数据库时，可将 `CODEXPLOIT_TEST_POSTGRES_DSN_FILE` 指向 PostgreSQL URL 文件后运行：

```sh
go test ./internal/storage ./internal/api -run '^TestPostgres' -race -shuffle=on -count=1 -timeout 240s
```

测试覆盖双 worker 服务端时钟与 epoch 栅栏、真实会话断连回滚、Serializable 并发重试、远端控制、发布后中断恢复、证据和报告授权。每个用例创建独立临时 schema，结束后删除；测试身份需有建 schema 权限。常规三平台 `make test` 不需要外部服务，继续覆盖完整 SQLite / Memory 模式，显式跳过 PostgreSQL 用例。
