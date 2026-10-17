# 本地产物接口与接入约定

Issue #4 实现 `internal/artifact.Store` 本地适配器，并在正式项目、快照详情和任务页面接入“产物与证据”。当前输入包括逐文件清单 JSON 与确定性源码 tar，两者 kind 均为 `source.snapshot`，通过 `schema_id` 区分。分析器输出和漏洞证据的统一登记由后续插件/发现切片接入。

## 标准引用

`artifact.Ref` 与 `contracts/v1/common.schema.json#/$defs/ArtifactRef` 一致，每次发布均经过 Schema 校验：

- `id`：不可变逻辑 ID，同 ID 的完整引用必须相同。
- `kind`、`sha256`、`bytes`、`media_type`、`schema_id`：内容身份与解读方式。
- `scope`：`project_id`、`source_id`、`snapshot_id` 与已登记、未删除的快照绑定一致。
- `producer`：`plugin_id`、`plugin_version`、`invocation_id`、`config_digest`，任务输出可带 `task_id`。采集在任务创建之前发生，共享输入省略 `task_id`，不伪造任务 ID。

旧项目默认代码源以 `legacy-<project_id>` 表示逻辑来源，不改变旧 ID。引用和公开错误不包含磁盘路径或部署凭据。

## Go 端口

| 方法 | 输入 | 输出 / 行为 |
|---|---|---|
| `Put(ctx, ref, reader, maxBytes)` | 完整期望引用、字节流、预算 | 暂存、核对长度和摘要后发布；同引用重试幂等，修改已有引用返回 conflict |
| `List(ctx, scope, cursor, limit)` | 固定 Scope、排他 ID 游标、1–100 条 | 按 ID 排序的已发布引用；目录不表示内容已校验 |
| `Stat(ctx, scope, id, maxBytes)` | 权威引用的 Scope/ID、预算 | 完整核对对象后返回引用；缺失、损坏、超限返回错误 |
| `Open(ctx, scope, id, maxBytes)` | 同上 | 验证后返回只读流和权威引用，调用方负责 Close |

读取通过 Scope/ID 查找权威索引，不接受调用方伪造的摘要、大小或磁盘路径。取消在流读操作之间检查；自定义 Reader 应配合取消并及时返回，接口不会强行终止阻塞在 Reader 内部的调用。

`artifact.Index` 元数据端口包含 `PublishArtifact`、`LookupArtifact`、`ListArtifacts`、`ArtifactScope`。Memory / SQLite 实现相同的归属校验、不可变比较与快照删除栅栏。SQL migration `0015_artifacts.sql` 保存引用与 Scope 索引，外部产物适配器可复用该端口。

## HTTP 接口

统一前缀为 `/api/v1/projects/{projectID}/snapshots/{snapshotID}/artifacts`。

| 方法和后缀 | 权限 | 行为 |
|---|---|---|
| `GET` | reader | `artifacts` 与 `next_cursor`；`limit` 默认 50、最大 100；`cursor` 为排他 ID 游标 |
| `POST` | writer | 从保留的冻结源码登记/核对清单与归档，返回目录；可重试 |
| `GET /{artifactID}` | reader | 校验后返回 `{api_version, artifact, availability:"verified"}` 与摘要 ETag |
| `GET /{artifactID}/content` | reader | 校验后流式下载，Content-Length、摘要 ETag、attachment 与 nosniff |

单产物 GET 接受 `max_bytes`，默认 64 MiB，上限 512 MiB；超预算先返回 413，不开始成功响应。401 表示未认证；reader 发布为 403；错误项目/来源、未知/未发布/已删除引用或缺失对象为 404 `artifact_not_found`；冲突为 409 `artifact_conflict`；摘要或大小不符为 409 `artifact_integrity`；非法预算为 400。适配器未配置为 501，存储故障为 503。传输中出错会中断连接，不补写模拟成功结果。

新代码源采集自动登记。旧 API / CLI 既有快照可显式 POST 登记：从保留的冻结副本建立内容校验基线，不能据此证明没有历史逐文件摘要的旧副本从未被磁盘修改。已有引用不重算覆盖，重登记会核对旧身份。任务页始终使用任务固定快照，项目页可选择版本，快照详情可直接跳转。

## 发布、恢复与限额

本地布局在应用数据卷内：`artifacts/staging/` 暂存，`artifacts/objects/<sha256>` 内容寻址。大内容用固定缓冲区写入、校验和读取。源码归档在快照目录暂存，单文件流式加入，仅含相对路径普通文件；链接、特殊文件、文件数量/大小变化和超限拒绝发布。单产物上限 512 MiB，清单最多 100000 个文件，tar 开销也占预算。

顺序为完整暂存 → 核对大小与 SHA-256 → 原子创建内容对象 → 元数据事务发布。正常失败/取消会关闭并删除本次暂存，未发布对象不能通过 API 读取。进程崩溃可能留下不可见孤立暂存/对象，此切片不自动回收，避免误删并发写入或被引用内容；恢复后可重复发布。清单和归档各自原子，第二项失败时目录可能只有已完整发布的第一项，响应仍报错，重试补齐。

已发布对象发生损坏时不静默覆盖：读取返回 `artifact_integrity`，重登记同样拒绝，因为幂等比较的是权威引用而不是磁盘现状。运维删除损坏对象后再重登记即可恢复，下载摘要应与原引用一致。

读取使用受限文件根目录，拒绝逃逸链接。返回流前核对内容，浏览器下载后再次核对大小与 SHA-256，JSON 预览上限 128 KiB。服务端流式读取，浏览器在选定预算内缓冲以校验和保存；校验表示该次读取通过，不代表永久健康。

备份需同时保留 SQLite、产物目录和快照输入。当前使用现有应用数据卷；独立 PostgreSQL、外部产物容器与迁移切换分别在后续 Issue 实现，不宣称已完成外部部署或垃圾回收。

## 验收边界

已确认使用认证 HTTP API 和 ArtifactStore 端口，搭配真实 Memory / SQLite 与临时文件。覆盖固定源码、目录/下载、重启、作用域隔离、重复发布、分页、预算、摘要冲突、损坏/缺失、读取取消、失败不可见及退役拒绝；正式 UI 在独立 Docker 合成数据环境验收。
