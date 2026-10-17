# L2 快照与产物层

接口：`SnapshotService`、`ArtifactStore`。Schema：[snapshot.schema.json](../../../../contracts/v1/snapshot.schema.json)、common 的 ArtifactRef。示例：[snapshot.json](../../../../contracts/v1/examples/snapshot.json)。

## 数据契约

发布快照包含 Scope、来源固定版本、内容摘要、UTC 创建时间、`state=ready`、源码树 ArtifactRef 和覆盖范围。文件清单另外作为不可变产物保存，逐文件记录相对路径、尺寸和摘要。

ArtifactRef 包含 id、kind、Scope、sha256、bytes、media_type、schema_id 与 producer。物理文件名、对象存储访问密钥和数据库连接不进入引用。大型字节内容通过 ArtifactStore 流式读取。

| kind | 内容 |
|---|---|
| `source.snapshot` | 冻结源码与文件清单 |
| `code.ast` / `code.facts` | 语言原生 AST / 跨语言通用事实 |
| `security.facts` | 输入、敏感操作、控制与边界 |
| `scanner.alerts` | 原始工具报告及告警 |
| `discovery.paths` / `discovery.findings` | 标准路径 / 标准发现 |
| `knowledge.view` | 固定的图谱层版本引用 |
| `report.document` | 可导出的报告 |

## 标准方法

| 方法 | 输入 | 输出 | 原子性 |
|---|---|---|---|
| `Capture` | resolution_id、项目、限额、忽略规则、幂等键 | SnapshotDescriptor 或异步 operation_id | 完整树与清单校验后发布 |
| `Get / List` | 项目与快照引用 / 分页 | 快照描述 | 已删除或未发布版本不可作为分析输入 |
| `Put` | Scope、kind、期望摘要与大小、有界字节流 | ArtifactRef | 暂存、摘要核对、发布 |
| `Open` | ArtifactRef、读取预算 | 只读字节流及实际摘要 | 验证调用方 Scope 权限 |
| `Stat` | ArtifactRef | 长度、摘要、可用状态 | 只读 |
| `Retire` | snapshot_id、expected_version | 可恢复的删除操作 | 活跃任务阻止删除；墓碑阻止迟到写入 |

## 内容寻址与恢复

同一 id 与相同摘要重试返回原引用。相同 id、不同摘要返回 conflict。不能修改既有源码或证据。

文件/对象存储与 PostgreSQL 不共享事务，发布顺序为：写暂存对象 → 核对摘要 → 数据库事务登记引用与发布状态 → 返回引用。崩溃留下的孤立暂存对象按宽限期回收；已被固定任务或图谱引用的对象不能直接删除。

从对象存储加载源码时，执行器将快照解包到临时只读工作目录。解包拒绝绝对路径、目录穿越、链接逃逸、超限展开和特殊文件。执行器工作目录是缓存，可从产物服务恢复。

## 适配与验收

ArtifactStore 可实现为独立文件服务或 S3 兼容后端。更换后端不改变 ArtifactRef 的逻辑身份，迁移服务负责核对摘要后切换物理索引。

Issue #4 已实现规范 ArtifactRef、本地 `artifact.Store`、Memory / SQLite 索引和认证目录/校验/下载接口，并在项目、快照详情及任务固定输入页面接线。共享采集输入早于任务产生，Producer 的 `task_id` 为可选；保留调用 ID 和配置摘要。实际端口、限额、错误及恢复语义见 [本地产物接口](../../../artifacts.md)。远程产物容器、对象存储、自动回收和分析/证据产物的统一登记留给后续 Issue。

验收：大文件流式限额、摘要不匹配、重复写入、发布中断、任务引用中的快照删除、跨平台只读目录清理均有明确行为。
