# v2 实现与验收记录

更新日期：2026-10-23。运行、安装与开发范围见 [开发手册](../../plugins-v2.md)。

## 已验证的生产边界

- 清单、十阶段目录、全文件锁、平台 release 和节点安装登记；重复 JSON 键、同版本替包、输入歧义、越界路径、链接、摘要/可执行位变化被拒绝。
- Memory / PostgreSQL 不可变发行、安装 CAS、活动卸载栅栏、worker 归属和重启恢复；SQLite 不新增维护面。
- 两种真实进程驱动：独立进程 file-job 与 NDJSON v2 的绑定读取、分块暂存、摘要核验和完整输出提交。协议独立二进制测试覆盖正确产物与损坏摘要。
- 标准代码事实的宿主 ID 规范化、安全语义引用、固定路径图 pin、关系依据，以及路径增强原内容与 selected/filtered 集合守恒。报告拒绝不完整 JSON 与不兼容 SARIF；原生字节不冒充标准结果。
- 工作流按 operation 与具名端口编译、执行；同契约可换工具，无新内置 producer ID 要求。修正执行槽位暂满被误判失败及产物预算超硬上限的问题。
- 标准代码事实进入固定共享版本；原生工具输出保留证据，缺少领域桥时不伪造 Agent 执行。

## 检查结果

- 已完成登记、驱动、类型化编译、输出契约、路径增强、引用依据和公开 API 响应边界的 red → green；独立进程输出、工作流到产物发布及取消/禁用/恢复有集成回归。
- `contracts/v1` 与 `contracts/v2` 离线解析及生产 Schema 验证通过，十个阶段清单与开发模板一致；模板脚本验证 18 份 JSON、固定样例摘要和本地文档链接。
- 全量乱序竞态回归及三轮 `make test-stress` 通过；随后增加的 API 协议名和报告/引用回归已重新运行相关竞态与全量套件。
- 全量测试使用临时 Go overlay：仅把工作区原有、无法编译的 `internal/app/example_test.go` 映射为空测试包，并映射格式化的 `internal/api/verification_execute_test.go`；没有修改这两个用户文件。普通 `make lint` 仍被后者的原有 gofmt 问题阻断；vet 通过，staticcheck 对其余包及 app 生产代码通过（未完成的 app 测试不纳入 staticcheck）。
- 两次 `make test-postgres` 在独立真实数据库通过；额外的运行态验收使用独立 PostgreSQL 和应用，不修改 18085 服务。
- 前端 43 项测试、TypeScript 和 Vite 生产构建通过；Docker 镜像构建通过。

## 正式页面与独立二进制

在独立数据库中从正式页面创建真实固定源码项目，展示十阶段目录，执行了新编译的独立 C CLI（通过通用 recipe adapter）。工具未提供分析覆盖计数，因此调用真实返回 PARTIAL，保存一个原生产物；宿主没有写入虚构代码事实或确认漏洞。

页面验收包括：按阶段/名称/状态筛选、版本聚合与历史版本切换、详情抽屉、具名输入输出、随包工具、完整性复核、启用/禁用、固定输入执行、终态记录及接口模板下载。功能实测、完整性与启用状态分开展示。窄屏使用横向阶段导航，表格在自身容器中滚动。

运行态额外核对：修改第三方工具同尺寸字节后，新调用以 integrity_mismatch 失败且无输出；还原后复核并重新执行成功。重启独立 PostgreSQL 与应用后，原调用文档逐字节相同、原生产物逐字节相同，禁用策略和随机 worker ID 保留。另登记真实封存但未安装的 1.0.1 发行定义，验证其不能被显示成已安装或可执行。

## 尚未宣称支持

Joern 多语言、污点语义与路径操作已接入，详见 [Joern 手册](../../joern.md) 和后续验收记录。普通进程驱动不等于内核沙箱；强隔离、多宿主自动分发和普通进程对 source/agent/environment/verification 的自授权不在本次实现范围。未创建/关闭 Issue，未 commit 或 push。

## Joern 实际验收（2026-10-23）

- `codexploit.joern@1.0.1` 固定 Joern 4.0.664、Temurin 21.0.9+10 与 goastgen 0.1.2。macOS ARM64 原生进程及 Linux ARM64 容器均真实生成 CPG 与标准 code.facts；Linux 验收使用非 root、只读容器与 `--network none`，解析带 go.mod 的冻结源码。
- 三个公开边界先 red 后 green：缺少工具真实返回 unsupported；实际 Go 源码输出内部 / 外部调用和双产物；无效 Go 源码不能用空 CPG 宣称部分成功。宿主 native 映射绑定和知识目录现代 producer 契约分别有 red/green 回归。
- 插件中心真实执行、双产物大小 / SHA-256、认证 API、标准知识发布与 Joern 工作流已验收。预算失败、取消、查询脚本篡改均无输出；恢复原包后可重新执行。
- 独立应用与 PostgreSQL 同时重启后，原调用和工作流响应逐字节一致，两份产物内容逐字节一致，worker、完整性和实测状态保留。首次登记的 1.0.0 未被覆盖；JVM 私有临时目录 / home 修复以 1.0.1 独立登记。
- 最终三轮完整乱序竞态回归、真实 PostgreSQL 套件、43 个前端测试 / 构建、契约与模板检查、vet、相关包 staticcheck、应用 Docker 构建及 Linux 插件包构建通过。实际 Joern 的独立测试另行启用真实离线包运行，不用模拟工具替代。
- 工作区既有 `internal/app/example_test.go` 引用尚未提供的接口，`internal/api/verification_execute_test.go` 尚未 gofmt；原始 `make lint` 仍被后者阻止。完整回归使用仓库外 overlay 隔离前者并格式化后者的临时副本，原文件保留。当前修改没有 commit 或 push。

## Joern 多语言与污点验收（2026-10-23）

最终适配器为 `codexploit.joern@2.0.1`，固定 Joern 4.0.664。2.0.0 的开发验收记录保留，2.0.1 补齐工作流 `Mixed` 声明。旧 1.0.x 清单和调用未覆盖。

| 前端 | macOS ARM64 | Linux ARM64 |
| --- | --- | --- |
| C / C++、C#、Go、Java 源码、Java 字节码 | 真实 CPG + 标准事实 | 真实 CPG + 标准事实 |
| JavaScript / TypeScript、Kotlin、PHP、Python、Ruby | 真实 CPG + 标准事实 | 真实 CPG + 标准事实 |
| Rust、Swift、ABAP、Ghidra 二进制 | 真实 CPG + 标准事实 | 真实 CPG + 标准事实 |

共 14 个前端逐个验收，不以启动成功代替真实文件覆盖。样例覆盖 TypeScript / C++；Java 字节码和 Ghidra 标准位置为 null，保留原生表示。ABAP 报告样例产生文件 CPG，未伪造函数或调用。其他操作系统 / 架构只有锁定的构建配方，尚不宣称已实测。

- 两个平台均真实运行 C / JavaScript / Python 混合解析，生成三个 CPG。各语言另运行参数 → 局部变量 → sink 的 `reachableByFlows` 查询；同时存在的常量 sink 调用没有被算作污点。路径回归验证准确 code / security pin，并拒绝另一份 code 产物的原始报告。
- 独立 PostgreSQL 预览服务在正式认证 API 执行 parse / taint / paths，获得三个 CPG、三条真实数据流和三条标准候选路径；匹配三个 source、六个 sink，常量未被污染。全部七个产物核对大小与 SHA-256。标准代码 / 安全 / 路径分别发布为知识版本，完整 `Mixed` 工作流完成并成功执行 `$publish`，部分覆盖保留为 PARTIAL。
- 预算失败、取消、封存查询脚本被修改时均没有输出发布；还原脚本并检查完整性后可重新执行。应用与独立 PostgreSQL 同时重启后，三个调用、完整工作流文档逐字节相同，七份产物内容逐字节相同，worker 身份与实测 / 完整性状态保留。
- Linux 在非 root、只读容器、`--network none` 环境验收。Rust 原生前端需要 glibc 2.39+，Joern 覆盖文件使用 Trixie。上游 Ghidra JAR 缺少 Linux ARM64 decompiler，打包器从 JAR 指定的固定提交构建补充资源，单独锁定源码和许可，补充后的 JAR 重新纳入文件摘要；实测 Ghidra 解析通过。
- 插件中心已核对 14 个前端、三层操作、依赖版本、安装 / 校验 / 实测状态，以及选择 Python 后参数 JSON 同步变化。浏览器页面指向隔离的 18092 服务，既有默认部署未替换。

常规完整竞态回归、三轮 `make test-stress`、`make test-postgres`、公共契约、前端 43 项测试 / 构建与应用 / 插件 Docker 构建通过。额外修复进程协议的错误分类竞态：超限关闭后，后续 RPC 仍返回原始预算错误；确定性 red / green 和五轮传输竞态回归通过。

完整 Go 回归使用已有临时 overlay，隔离未跟踪的 `internal/app/example_test.go` 并使用既有 `internal/api/verification_execute_test.go` 的格式化副本；原文件未修改。原样 `make lint` 仍被后者的 gofmt 阻挡；完整 Staticcheck 还受既有 app 测试导入问题、`internal/repository/source.go` 的 `planDir` / `copyPlan` 未使用问题影响。本次 Joern、SDK、plugin / RPC、processplugin、workflow、publication 和 scripts 的 Staticcheck，以及 overlay 下 go vet 通过。未创建 / 关闭 Issue，未 commit 或 push。

以上仅证明固定样例的前端和查询行为，不宣称所有框架、sanitizer、动态调用或跨语言桥接都已覆盖。规则可配置，原生轨迹保留，污点路径仍为待审查候选。

## Joern 主引擎链路（2026-10-23）

`codexploit.default-analysis@2.0.0` 固定 `codexploit.joern@2.1.0` 的 parse → taint → paths → enhance。项目入口预检、全链路 pin、原样候选保留与排序、审查投影、当前图层原子替换、运行引擎 pin 的持久化和不可变性均有回归。历史 Go 计划作为显式兼容夹具继续验收。

真实 macOS / Linux 混合项目均生成三个 CPG、三条数据流候选和十份校验产物，常量对照未进入污点轨迹。正式页面按钮已实际触发整条链路，显示 Joern 版本、四阶段状态、发布版本、真实调用位置与筛选依据；静态局限保留为 PARTIAL。PostgreSQL 的真实 Joern → 路径 → Agent 任务边界使用明确的测试运行时验证源码、证据和义务清单，不将其当作模型准确率证明。

正式 Linux 镜像采用非 root、只读文件系统和有界临时空间。应用与独立 PostgreSQL 同时重启后，运行文档和十份产物摘要不变。镜像内的封存文件锁归运行用户所有；同一契约的重建发行物以包摘要作为 Build ID，旧空 Build ID 发布记录保留。两份不同摘要的构建可并存，伪造 Build ID 或改写同一发布仍被拒绝。

完整竞态回归和三轮稳定性测试使用前述仓库外 overlay，原始进行中文件保持不变；真实 PostgreSQL、43 项前端测试 / 构建、契约、vet、修改范围 Staticcheck 均已运行。原样 `make lint` 仍由既有测试文件格式问题阻断。未 commit 或 push。

最终部署已连续通过 `make run`，18085 应用和 PostgreSQL 均为 healthy，重启计数为 0；升级前后的项目、快照、插件调用与分析运行数量一致，账号、会话及加密模型设置逐行摘要一致。修复停止接口在工作流终态已落库、AnalysisRun 投影尚未同步时提前报告 STOPPED 的竞态；确定性 red → green、20 次真实 PostgreSQL 取消回归、三轮相关控制测试及最终完整 `make test-postgres` 均通过。

## termcp 原项目全流程与工作台诊断（2026-10-24）

真实故障为 taint 查询超过默认 `max_flows=100`，固定 CPG 上直接重放得到 `flow_budget_exceeded`。原快照和冻结源码存在，parse 已生成三个 CPG；图谱因后续失败尚未发布。旧源码切片也依赖图谱，不能据其 not_found 断言快照元数据丢失。

`codexploit.joern@2.1.1` / 默认流程 `2.0.1` 对路径枚举上限返回有证据的 PARTIAL；原始流报告与 coverage 标记截断，审查路径和 Agent 继续继承上游局限。其他执行/输出/轨迹预算失败仍不发布输出；已知 file-job 错误码保留。已完成真实 CPG 的超限 red → green、独立进程错误分类、上游截断到领域审查路径、独立源码读取与项目隔离的回归。

## Java sink 目录与高风险分区（2026-10-26）

`codexploit.joern@2.3.4` 随包发布 `java-sink-catalog@1.0.0`。目录以严格 JSON 解码、固定分类和危险参数索引校验，并按解码后的规范字节计算 SHA-256；摘要不随格式空白变化。首批 30 个条目覆盖 Runtime / ProcessBuilder、Java / XML / XStream / SnakeYAML 反序列化、SpEL / ScriptEngine / OGNL、JNDI、JDBC Statement / MyBatis / Hibernate、XXE、HttpClient / RestTemplate、文件、LDAP 与模板入口。

语义阶段先在固定 Java CPG 上保存全部精确类型 / 方法命中的 sink，再对目录安全和兜底规则执行数据流。未产生流的 XMLDecoder 调用仍出现在 inventory；高风险类别最多使用 80% `max_flows`，剩余预算交给配置规则，类别按最高 priority 排序并滚动复用未用份额。路径记录 `priority_hint`，`joern.static-support/v2` 只改变审查顺序，不改变严重度或裁定。

真实容器验收使用已封存的 Joern 4.0.664 / JDK 21 包，而不是模拟 CPG：Java fixture 覆盖 Runtime、ObjectInputStream、XMLDecoder、SpEL、InitialContext、Context、DocumentBuilder、JDBC Statement、MyBatis、Hibernate、Freemarker 与 Thymeleaf；PreparedStatement 反例没有进入 SQL 目录。零流 inventory、每个高风险分区、`max_flows=4` 下 3/1 的目录 / 回退配额与 `pending` / `truncated` 账本、catalogue digest、PATH priority hint、enhancement 首项顺序均通过。

每个 CPG / 目录类别 / 回退规则的分区行进入不可变 `flows` 产物，PostgreSQL invocation 重建后可再次读取；正式页面默认打开高风险目录并保留未分类探索。当前限制是 MyBatis mapper XML `${}` 等框架包装仍需专门语义模型，Java 真实语料质量评测留待下一阶段。

- 使用正式服务保存的同一份 termcp 冻结源码（564 文件）在独立 PostgreSQL 运行完整四阶段，获得 100 条候选和三个知识版本，十份输出大小与 SHA-256 全部通过；原生污点报告 `truncated=true`。
- 正式 18085 的原 termcp 项目通过相同后端领域入口重新运行：`analysis-7IZER32QJ62OGAGHMPGHQT7PQW`，固定原快照，四阶段 PARTIAL、`$publish` SUCCEEDED，100 条路径、十份输出校验通过，聚合 coverage.truncated=true。使用仓库外临时操作脚本在容器内调用既有 handler，没有新增网络入口、修改登录或模型设置，也没有用手工 SQL 伪造运行。
- 早期临时脚本漏接 Audit 读取服务，曾产生一条 `analysis_task_unavailable` 聚合误报，其底层工作流已完成；该记录未删除或覆写。补齐脚本后以上新运行独立验收通过。原先 2.1.0 的失败记录逐行摘要不变，账号与加密模型设置摘要不变。
- 原项目的真实 MCP `inspect_project(source/analysis)`、`read_source_file(README.md)`、`graph_summary` 全部成功，源码元数据、物理源码树和图谱均就绪。主会话新增的诊断工具只读并由宿主固定归属；原 stdio 工具面保持兼容。
- 浏览器验证 Ctrl+Enter 插入换行而不发送、普通 Enter 发送完整多行消息，输入法/长按回车由客户端回归覆盖。占位符显示“回车发送，Ctrl+回车换行”。独立 PostgreSQL 主会话通过真实 MCP 返回源码、分析和 README；其中模型使用明确标注的测试适配器，不宣称真实模型诊断准确率。

最终三轮 `make test-stress`（既有仓库外 overlay）、真实 `make test-postgres`、45 项前端测试、TypeScript/Vite、契约、vet 和修改范围 Staticcheck 通过。两处固定旧清单版本的测试夹具已随插件升级同步，最初全量运行因此失败，修正后的三轮全量通过。原样 `make lint` 仍被既有 `internal/api/verification_execute_test.go` 的 gofmt 问题阻挡，原文件保留。正式 `make run` 健康，未 commit 或 push。

最终诊断收尾另验收当前 worker 的插件禁用即时生效、目录未绑定时不冒充安装状态，以及无效/缺失源码路径的独立错误分类。MCP / supervisor 三轮乱序竞态与相关 API 回归通过；意外存储错误不向模型转发底层驱动文本或宿主物理路径。

## 2026-10-25：termcp 正式页面最小闭环

通过 18085 的已认证正式页面，从项目总览重新开始 Joern 分析，随后从审查路径勾选一条候选、启动真实 Pi / DeepSeek 运行、进入工作台核对事件，再从任务报告页面生成、校验并下载 Markdown；没有使用脚本答案或手工插入成功状态。

- 项目 `proj-QUPPR2NTUDUMS6XJWWP4UXMNDJ`，冻结输入 `snap-f15e4fb98c288a2f90715ce2b496ef8a`。
- 新分析 `analysis-ZTVK5DKY7XKXS5SJOS2JW7LHEJ`，任务 `task-P76VBNSXZK7GGSRXUAL2KH75AI`；四个 Joern 阶段完成并保留 PARTIAL 覆盖声明，发布 `rev-7` / `rev-8` / `rev-9`，生成 100 条当前版本候选。
- 旧版本 200 条路径在分页前排除；当前页面可连续读取两页，每页 50 条。历史路径、失败和暂停记录保留。
- 路径 `path-8546f1ce8b8bd20257a837bcd1f43131` 对应运行 `run-fb1031adc2bdc7c8`，状态 SUCCEEDED / completed；2 次成功工具调用，输入 / 输出 12,962 / 1,101 tokens，任务账本实际使用 14,063、预留归零。
- 接受的模型答案为 inconclusive、finding_candidate=false，四项义务均保留 unknown 与阻断原因，4 条支持引用和 2 条反对引用保留。所选候选关联测试辅助函数，未建立可信的敏感操作路径；没有因此创建或确认漏洞。
- `builtin.reporter@1.1.0` 保存普通审查及其证据引用，无漏洞发现也不会漏掉审查结论。最终报告 `report-QMB3V75CZRPJB7YIKLJDLHYN4B` 固定到 rev-9，大小 885,704 bytes，SHA-256 `61d29ae9f57b415bd500caedd96e26bc480a555449ff42b8a5658a9e941c1452`。浏览器下载和独立本地复核一致；服务重建后再次预览，摘要和审查结论保持不变。

修复的实际断点：固定图谱版本在分页后过滤会产生空页；子任务从全库最早 100 次运行筛选导致当前项目不可见；Pi 用量帧与批准请求 ID 不一致导致预留累积，并遗漏缓存输入；未形成发现的审查未进入报告；报告表单默认选择最早知识版本。图谱 PARTIAL 在工作台单独显示为“已完成 · 部分覆盖”。首次验收报告因旧默认选择固定到了 rev-1，作为明确标注版本的历史报告保留；最终验收使用 rev-9。

已完成各断点 red / green、两项认证报告 HTTP 回归、真实 worker 协议测试、三轮完整乱序竞态回归、真实 PostgreSQL 回归、46 项前端测试 / 构建、契约检查、相关 vet / staticcheck 及 make run 健康验证。Go 全量竞态沿用此前仓库外 overlay，隔离不能编译的既有 `internal/app/example_test.go` 并仅格式化 overlay 中的 `internal/api/verification_execute_test.go`；原文件未改。make lint 仍被后一个既有文件的 gofmt 问题阻塞。

本次证明单条候选的执行、审查记录和固定报告可以形成闭环。其余 99 条尚未审查；100 条污点上限和前端覆盖缺口仍有真实记录。当前默认规则产生了测试辅助函数相关候选，规则查准率与跨函数建模需要单独评估，本次没有把流程完成视作审计完成。
