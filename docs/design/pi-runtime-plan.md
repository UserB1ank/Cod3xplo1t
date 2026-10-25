# Pi 运行时集成编程方案

> #56–#62已关闭，Pi/llm与宿主集成已交付；本文P1–P6作为历史规格，不再按未实施计划重做。项目主Agent新会话与MCP写能力见 [当前实施索引](interaction-issues.md)。

日期：2026-10-19。状态：已授权规划与发布，尚未实现。GitHub 正文为 DeepSeek 的执行依据，本文件为本地完整副本。

## 决策

采用 Go PiRuntime + 每个 run 独立的可信 Node / TypeScript worker，嵌入 Pi Agent Core 与 pi-ai。Go 继续是领域与持久化真相；不重写主服务，不 fork Pi，不把 Pi 当作扫描插件或验证执行器。保留 llm 为可切换对照，默认值须另有人工授权才变更。

## 控制协议

固定协议 v1 的双向 JSONL，hello 后发 start；普通帧包含 run_id / generation / seq / request_id，回执带 reply_to。业务请求包括 request_permit、tool_request、answer_proposed，事件包括 usage / settled / error。Go 拒绝重复不同摘要、乱序、旧 generation 与超限帧；同 ID 同摘要可幂等返回但不重做工具 / 计费。敏感初始化单独走不记录的私有帧，不与公开事件混序列或回放。

Pi 自定义 streamFn 在每个 provider 请求前等待宿主许可。Pi 工具 execute 仅转发宿主请求，不直接访问文件 / shell。Go 绑定 scope，校验原生 Schema、别名与额度，执行固定快照工具并投射精简结果。工具预算 / 最终答案 / 反证 / 义务与 novelty 只有一个宿主实现。

许可处理 token 预留与响应后对账；严格模式必须有可验证的输入上界和 provider 输出限制，否则拒绝声称可强制。usage 缺失不是零。取消可阻止新请求并尽快中断在途，但不能保证撤销供应商已经发生的计费。

多调用先按一整轮提交宿主，分配稳定 call_id，源顺序预算预留、完成顺序结果事件、源顺序 provider tool results。参数非法走独立 repair 预算；工具错误不当作完整一轮重复重试。答案必须经 Go 回执才可成功，Pi settled / 进程成功退出也必须完成；不存 reasoning / thinking 流或原始 provider 历史。

## 运行身份与恢复

公共 Freeze 接口替代 workflowexec 对 ModelRuntime 的类型断言。任务 / workflow run 固定 runtime、worker / Pi / 协议版本、工具和 prompt 摘要、模型与配置版本。密钥只沿既有密文设置仓储保留，不随公开 pin 记录。

数据库检查点而非 Pi 会话是恢复来源。暂停结束当前 attempt 并释放租约，resume 建立新 run / generation / lease，保留 resume_of 与累计预算。只从有效证据、义务和 frontier 重建上下文；缺旧配置、版本或知识视图时明确 blocked，不使用当前 latest 冒充原固定输入。首版不做 LLM compaction、原始上下文持久化或跨 runtime 自动续跑。

## 依赖与冲突

#56 是总览。顺序：#57；#42 → #49；#58；#59 和 #60；#45 → #46 与 #61；#62。
#41、#43 依赖 #57；#44 依赖 #43；#60 消费 #41 / #43 / #44。领域续跑不依赖 Pi，因此无依赖环。

已关闭 #37–#40 保留历史。开放 #41–#49 修正为共享边界，#22 / #20 / #50 / #51 补数据消费约束。旧整改草案与索引涉及本方案重叠部分，以本方案及更新后的 GitHub 正文为准。

## 实施原则

每单先核对最新工作区与 issue，按 AGENTS.md 确认新的公开 TDD 边界，逐个 red / green，不处理或删除其他人的 WIP。测试 / 构建失败要记录根因，不能略过包后声称全量通过。工程验收包含实际 API / 正式 UI、三种仓储、跨平台 Go 测试、真实 PG、生命周期 stress、契约、前端与 Docker；真实质量另需 opt-in 模型评测。

脚本 20 例仅验证编排，不是模型质量 / token 基线。真实对照按相同模型 / 固定输入 / 工具 / 预算测召回、误报、义务闭合、证据有效、token 和时延；样本不足标证据不足。是否默认使用 Pi 由人工阅报告另决。

## 逐项实现正文

### P1 统一 Agent 宿主轮次许可、答案纠错与真实轮次指标

<!-- codexploit-pi-plan:2026-10-19:P1 -->

## Parent

#56

## What to build

**类型：AFK**


**用户故事：** 使用现有 llm 分析路径时，每次模型请求和答案提交都受同一宿主控制，页面能区分真实模型轮次、修复与工具交换；之后接 Pi 不再复制规则。

先在已有 llm → Runner → Store → 认证 API → 正式运行详情完成纵向闭环。保持 Runtime.Start/Handle 基本边界，用可选能力和版本化控制消息扩展交互；scripted / 旧 cli 不被强迫模拟其不支持的能力。

建议触点：internal/agent/runtime.go、runner.go、llm.go、protocol.go、model.go、internal/storage/*agent*、internal/api/agent.go、web/src/inspector.tsx。新增共享 TurnController / OutputValidator / RepairPolicy（名称可调整），Runner 是策略与账本唯一裁决者，适配器只投递请求并等待回执。

每个 provider 请求前申请 request_permit：request_id、round_id、运行 generation、模型固定版本、输入用量依据与输出上限；宿主回 continue / repair / stop / pause（pause 在 #45 落地前不得声称已支持）。许可绑定一次请求，过期、重放或迟到不能重新执行。答案通过 answer_proposed → Go 校验 → accepted / repair / rejected 回复；复用 #38 的最多 2 次、≤300 字符纠错，token 计费但不占工具预算。输出仍是 candidate / refuted / inconclusive，不新增 abstain 枚举，不允许 confirmed。

## Acceptance criteria

- [ ] 首个建议 red：llm 首次给出缺义务答案，宿主反馈后给出合法答案；run 仅接受后者，错误原因与 1 次修复可经真实 API / 页面核对。重复校验不重复消耗修复额度。
- [ ] 每次实际 provider 请求前得到宿主许可；收到 stop、失去租约、取消、超时或存储失败后不发下一请求，等待回执的双方可被 context 取消，不阻塞心跳 / 取消处理。
- [ ] 有界 token 模式在请求前预留输入保守上界 + 输出上限；在已验证 provider 可执行该上限且输入估计有上界时才声明可强制。无法可靠核算 / 无 usage 时明确失败或拒绝能力，不能写成零。响应后用 usage 对账，重复 usage 不能重复计费。说明 provider 在途取消不能保证追回已计费 token，不承诺不可实现的绝对账单硬限。
- [ ] repairs、model_requests / 实际 rounds、exchanges、tool_calls 分开计数，修复轮也计入请求数；legacy #37 的 exchanges+1 仅作为明确标注的旧估算，不对历史记录伪造真轮次。API / UI 标出 metrics 来源与缺失值。
- [ ] 校验拒绝、修复、预算决定与 run 变化按既有存储事务 / CAS / fencing 约束提交；无 event-only 成功，无候选在验收前发布。
- [ ] 验证参数修复 / 未注册工具 / 越权 / 预算耗尽 / 输出修复耗尽 / 没有答案等公开行为与 #38–#40 一致；Capabilities 按实际行为声明，旧 cli 与 scripted 协议兼容。
- [ ] 单工具和修复的 fake-provider 合同测试、三个仓储往返、真实认证 API 和正式详情验收通过；不能只给接口定义。


## Blocked by

- #38
- #39
- #40

## 交付与边界

- 按 AGENTS.md，在公开边界逐项 TDD red → green；本文首个测试是待确认的边界建议，不等于已经得到测试边界确认。DeepSeek 先核对当前代码与 Issue 最新正文，再按项目约定确认新边界。
- 每单交付实际链路、Memory / SQLite / PostgreSQL 持久化（如涉及）、认证 API、正式 UI（如涉及）、公共 Schema、测试与文档；失败不得切换脚本、模拟成功或偷偷改用其他 runtime。
- 沿用现有项目 / 快照 / 符号 / 证据 ID、登录、加密模型设置、CLI / MCP。旧 task / run / workflow / 报告可读，历史缺失字段是 unknown，不能填成零或成功。
- Go 兼容 Ubuntu / macOS / Windows；执行相关测试、完整乱序竞态回归、前端测试 / 构建、make lint、make check-contracts；涉及生命周期 / 文件系统跑 make test-stress，数据库变更跑真实 make test-postgres。不得排除失败包后宣布全量通过。
- 迁移编号在实现时取仓库中下一可用编号，不预占；内置插件包摘要随宿主变动时遵守既有升级与旧版本保留约束。
- 不存储隐藏推理、原始 provider 消息、API Key、真实个人信息或运行数据；不写 .env / 私钥。模型设置沿用程序内配置与密文仓储。
- Issue 验收后按已有授权更新完成记录、独立 commit 并关闭；push 必须等用户明确要求。本组方案本身不授权真实存量切换、默认 runtime 切换或新账号 / 凭据创建。


### P2 通过固定版本 Pi worker 完成真实路径分析并回灌图谱工具

<!-- codexploit-pi-plan:2026-10-19:P2 -->

## Parent

#56

## What to build

**类型：AFK**


**用户故事：** 以部署选项 --agent-runtime=pi 启动后，正式路径分析通过 Pi 的真实模型循环查询固定快照并产生有证据的候选，能查看真实运行与错误。

在 runtime/pi-worker/ 建独立 Node / TypeScript 包（不放进 web/），固定同一兼容发行版的 pi-agent-core + pi-ai 和 Node 运行版本，提交精确依赖及 lockfile、许可证 / 包摘要清单。实施时核对官方包名与 API；当前上游使用 @earendil-works 命名空间，旧教程 @mariozechner 不得混装。不 fork、不引入 coding-agent CLI、内置 bash/read/edit/write、扩展加载或 Pi 会话目录。

新增 internal/agent PiRuntime：每个 run 一个 worker / 内存 Agent，Go 直接执行固定 argv，JSONL 双向 stdin/stdout。旧 CLIRuntime 写完 task 会关闭 stdin，不能直接换命令复用；可提取进程生命周期帮助函数但不改变旧协议。建议 Schema contracts/v1/agent-worker.schema.json 定义协议 v1：hello / start / request_permit / tool_request / answer_proposed / usage / settled / error；所有公开 frame 含 run_id、generation、单向递增 seq、request_id / reply_to，工具含 round_id、call_id。重放相同 request_id + digest 返回同一回执，不同摘要冲突；新 worker generation 拒绝旧 frame。

Pi 使用自定义 streamFn 在每次 provider 请求前等待 #57 许可；所有自定义工具只是 #49 描述符的代理，Go Runner 独立执行授权 / scope / 类型 / 预算 / 截断 / refs 账本。scope 强制填入在 Go，禁止只沿用 llm.go 内的适配器补参。Pi 本地预校验也需映射宿主错误与修复计数，不能让类型错误落入未计数的无限自动回合。

## Acceptance criteria

- [ ] 首个建议 red：固定 provider fixture 要求 get_code_slice，只有收到 Go 对冻结快照执行的真实工具回执才输出合法 v2 答案；正式认证 API 创建 / 查询 run 与 UI 可验收，无脚本替代 Pi。
- [ ] 配置复用应用内 llm.Config（chat-completions / responses、base_url、model、timeout、max_output_tokens）；覆盖已支持的两种协议与自定义兼容端点契约。通过 Pi provider 显式注册配置，不读用户 Pi 登录 / 环境 / 模型目录；不支持的组合明确 unavailable，不能改 endpoint / model。
- [ ] 运行内凭据仅经不记日志的私有初始化帧传递，worker 只保留内存且退出释放；不放 argv、环境、普通事件、临时文件或浏览器。stdout 仅允许协议，stderr 有界脱敏；原始 request / provider 消息和 reasoning / thinking delta 不进事件。串流只投射允许字段。
- [ ] hello 5 秒、单 frame 1 MiB、累计公开输出 16 MiB、stderr 64 KiB、取消宽限 2 秒、总时限取 run deadline（常量可配置但必须有上限）；超限 / 无效 JSON / 乱序 / 缺回执 / worker 崩溃 / 非零退出 / settled 前断流均明确失败。合法答案先到而进程随后失败，不能提前 SUCCEEDED。
- [ ] tool / answer 只通过 #57 控制与 #49 Schema；任何 project / snapshot / audit / path 伪造或查询其他 run 的引用由宿主拒绝。保留完整 refs 为宿主元数据，模型侧仍用 #39 精简结果。
- [ ] 取消、超时、租约丢失停止模型与工具并回收整个进程树，拒绝迟到答案 / usage；握手、管道读写、取消同时发生无死锁 / 泄漏。平台专用实现包含 Windows 测试策略，不能仅验证 Unix kill。
- [ ] 在隔离临时 cwd 与空私有 HOME 启动，环境白名单无用户设置继承，不把仓库路径、应用工作区、数据库 DSN 或安装密钥传给 worker。不声称子进程就是安全沙箱；worker 为固定可信运行代码，仅可访问显式模型配置，强隔离扫描插件仍属于 #21。
- [ ] 固定依赖构建、typecheck、worker 测试与 Go 桥测试加入 Make / CI；运行镜像包含锁定 Node 和 worker，三个 Compose 保持现有端口 / 数据卷 / 密文设置。无 Pi 时 llm / cli / scripted 可用，选 pi 且缺依赖显示 unavailable。Docker 非 root 路径真实分析验收通过。


## Blocked by

- #57
- #42
- #49

## 交付与边界

- 按 AGENTS.md，在公开边界逐项 TDD red → green；本文首个测试是待确认的边界建议，不等于已经得到测试边界确认。DeepSeek 先核对当前代码与 Issue 最新正文，再按项目约定确认新边界。
- 每单交付实际链路、Memory / SQLite / PostgreSQL 持久化（如涉及）、认证 API、正式 UI（如涉及）、公共 Schema、测试与文档；失败不得切换脚本、模拟成功或偷偷改用其他 runtime。
- 沿用现有项目 / 快照 / 符号 / 证据 ID、登录、加密模型设置、CLI / MCP。旧 task / run / workflow / 报告可读，历史缺失字段是 unknown，不能填成零或成功。
- Go 兼容 Ubuntu / macOS / Windows；执行相关测试、完整乱序竞态回归、前端测试 / 构建、make lint、make check-contracts；涉及生命周期 / 文件系统跑 make test-stress，数据库变更跑真实 make test-postgres。不得排除失败包后宣布全量通过。
- 迁移编号在实现时取仓库中下一可用编号，不预占；内置插件包摘要随宿主变动时遵守既有升级与旧版本保留约束。
- 不存储隐藏推理、原始 provider 消息、API Key、真实个人信息或运行数据；不写 .env / 私钥。模型设置沿用程序内配置与密文仓储。
- Issue 验收后按已有授权更新完成记录、独立 commit 并关闭；push 必须等用户明确要求。本组方案本身不授权真实存量切换、默认 runtime 切换或新账号 / 凭据创建。


### P3 从正式任务选择 Pi 并固定工作流运行时与模型配置

<!-- codexploit-pi-plan:2026-10-19:P3 -->

## Parent

#56

## What to build

**类型：AFK**


**用户故事：** 创建任务时可以明确选择 llm 或 pi，并在任务 / Agent 运行详情看到固定的 runtime、版本、模型及配置版本；修改设置不影响已有运行。

沿既有配置页 / 创建任务表单 / 工作流 $analyze 接线 runtime 可用目录和选择，不把 runtime 伪装成 scanner 插件。编译计划的插件身份保持不变；候选分析 runtime 在任务 / workflow run 创建时固定。部署允许的 runtime 集合由服务器控制，客户端不能提供 executable、环境、脚本或任意模块路径。

目前 internal/workflowexec/effects.go Bind 对 *agent.ModelRuntime 做类型断言后 Freeze。抽象 Ready / Freeze 为共享可选接口（冻结输出是不可变 runtime + 脱敏 ModelPin，不是把秘密放 DTO），让 llm / pi 均可绑定；补齐从 run 恢复时的固定配置行为。

## Acceptance criteria

- [ ] 首个建议 red：同一工作流创建两个任务选 llm / pi，均真实执行 $analyze，保存独立 Agent run ID；创建后更改当前配置，正在运行的 provider 请求仍用各自固定版本。
- [ ] 认证 API 提供运行时可用性 / 能力与脱敏版本；创建参数、默认值、配置 CAS、权限及公共 Schema 明确；旧请求缺 runtime 时继续沿用原部署默认，绝不自动切成 pi。
- [ ] Memory / SQLite / PostgreSQL 保存选择及 runtime/worker/协议/Pi 包版本、工具契约摘要、prompt 版本、模型和 config_version；计划 / 知识 / 源码快照仍按既有 pin。真实 PG 双实例更新设置与创建任务不混用版本。
- [ ] 重启恢复只使用原 pin；当前设置版本已改变且没有原密文版本时返回 config_version_unavailable 并阻止恢复，不能把旧 pin 配新密钥 / 模型。首版不新增密钥历史仓储，版本变化时阻断；如后续立项历史密文，另定保留与密钥策略。
- [ ] 正式配置页显示 pi readiness 与不可用原因，创建任务提供可用选项，任务 / run 详情展示固定元数据和错误；reader 不能修改配置或发起 writer 操作，跨项目 ID 不能借选择绕权。
- [ ] Pi 未安装 / 不支持当前 provider 时明确拒绝选择，不回退 llm；现有 llm、CLI、MCP、旧任务 / workflow / 报告兼容，历史缺字段显示未记录。
- [ ] 两种部署重建保留 runtime 选择与脱敏记录；浏览器验收真实任务、错误状态与配置变更，控制台无错误。


## Blocked by

- #58

## 交付与边界

- 按 AGENTS.md，在公开边界逐项 TDD red → green；本文首个测试是待确认的边界建议，不等于已经得到测试边界确认。DeepSeek 先核对当前代码与 Issue 最新正文，再按项目约定确认新边界。
- 每单交付实际链路、Memory / SQLite / PostgreSQL 持久化（如涉及）、认证 API、正式 UI（如涉及）、公共 Schema、测试与文档；失败不得切换脚本、模拟成功或偷偷改用其他 runtime。
- 沿用现有项目 / 快照 / 符号 / 证据 ID、登录、加密模型设置、CLI / MCP。旧 task / run / workflow / 报告可读，历史缺失字段是 unknown，不能填成零或成功。
- Go 兼容 Ubuntu / macOS / Windows；执行相关测试、完整乱序竞态回归、前端测试 / 构建、make lint、make check-contracts；涉及生命周期 / 文件系统跑 make test-stress，数据库变更跑真实 make test-postgres。不得排除失败包后宣布全量通过。
- 迁移编号在实现时取仓库中下一可用编号，不预占；内置插件包摘要随宿主变动时遵守既有升级与旧版本保留约束。
- 不存储隐藏推理、原始 provider 消息、API Key、真实个人信息或运行数据；不写 .env / 私钥。模型设置沿用程序内配置与密文仓储。
- Issue 验收后按已有授权更新完成记录、独立 commit 并关闭；push 必须等用户明确要求。本组方案本身不授权真实存量切换、默认 runtime 切换或新账号 / 凭据创建。


### P4 让 Pi 分析复用宿主批次预算、反证核验和收敛规则

<!-- codexploit-pi-plan:2026-10-19:P4 -->

## Parent

#56

## What to build

**类型：AFK**


**用户故事：** 同一轮查询多个事实时，Pi 和 llm 使用同样的调用预算、反证核验与停止条件；不能因为更换内核而绕过审计规则。

消费 #41、#43、#44 的公共能力，不在 TypeScript 重写 validator / batch scheduler / novelty tracker。Pi 收到一轮多个 call 先完整提交宿主批次，宿主按源顺序预留预算并返回每个 call 的处理决定；首版宿主按顺序执行即可，真实并发由 #43 的宿主实现统一启用。Pi 自己的 parallel 默认值不能拥有执行调度权。

## Acceptance criteria

- [ ] 首个建议 red：一轮 3 调用但只剩 2 次预算，宿主只执行前 2 个；第 3 个收到配对拒绝，三个 provider call 均有合法配对消息，实际执行 / 拒绝 / 消耗与 llm 相同。
- [ ] 正式 run 详情显示同一 round 的批次、稳定 call_id、执行 / 拒绝与真实轮数；请求按源顺序，结果事件按完成顺序，provider 历史按源顺序，无重复调用 / 错配回执。
- [ ] 参数非法、局部工具错误、预算已尽、同批越权、取消期间批次、重复 frame 等覆盖；不能靠 toolExecution=sequential 冒充单轮一调用限制，也不能因某一 Pi 工具失败自动重试整个批次。
- [ ] #41 的 falsifier 在 Go 还原别名并校验本 run 可解析证据；checked=true 但只有调用存在、结果不支持 / 失败的情况不能通过结构检查冒充证明。Pi 仅收到有界纠错，无权直接写 finding 或 confirmed。
- [ ] novelty 按 #44 的整个模型轮次内证据集合计算；同一批次中先重复后新证据不提前停止；连续 K 个已完成探索轮次无新证据才停止。修复回合不冒充探索轮次。
- [ ] 一组相同 provider-fixture 脚本经 llm / pi，断言领域状态、预算、证据与停止原因一致；不要求各 provider 原始消息和不同 runtime 元数据逐字节相同。完成正式 API / 页面验收。


## Blocked by

- #58
- #41
- #43
- #44

## 交付与边界

- 按 AGENTS.md，在公开边界逐项 TDD red → green；本文首个测试是待确认的边界建议，不等于已经得到测试边界确认。DeepSeek 先核对当前代码与 Issue 最新正文，再按项目约定确认新边界。
- 每单交付实际链路、Memory / SQLite / PostgreSQL 持久化（如涉及）、认证 API、正式 UI（如涉及）、公共 Schema、测试与文档；失败不得切换脚本、模拟成功或偷偷改用其他 runtime。
- 沿用现有项目 / 快照 / 符号 / 证据 ID、登录、加密模型设置、CLI / MCP。旧 task / run / workflow / 报告可读，历史缺失字段是 unknown，不能填成零或成功。
- Go 兼容 Ubuntu / macOS / Windows；执行相关测试、完整乱序竞态回归、前端测试 / 构建、make lint、make check-contracts；涉及生命周期 / 文件系统跑 make test-stress，数据库变更跑真实 make test-postgres。不得排除失败包后宣布全量通过。
- 迁移编号在实现时取仓库中下一可用编号，不预占；内置插件包摘要随宿主变动时遵守既有升级与旧版本保留约束。
- 不存储隐藏推理、原始 provider 消息、API Key、真实个人信息或运行数据；不写 .env / 私钥。模型设置沿用程序内配置与密文仓储。
- Issue 验收后按已有授权更新完成记录、独立 commit 并关闭；push 必须等用户明确要求。本组方案本身不授权真实存量切换、默认 runtime 切换或新账号 / 凭据创建。


### P5 从宿主检查点续跑 Pi 并在重启和租约失效时拒绝旧结果

<!-- codexploit-pi-plan:2026-10-19:P5 -->

## Parent

#56

## What to build

**类型：AFK**


**用户故事：** Pi 分析预算用完或服务重启后，用户可以查看真实检查点、批准额度并继续尚未完成的义务；旧 worker 不会重复发布结果。

消费 #45 / #46 的领域检查点与 resume_of，不另建 Pi session 作为运行真相。检查点固定 scope / 知识版本、义务状态、引用、frontier、别名、模型与工具契约、预算累计和 CAS 版本，由 Go 保存；worker 重建成新内存 Agent，仅收到有界任务与规范化上下文。首版不引入 LLM compaction / Pi JSONL 会话 / 原始 thinking 历史存储。

## Acceptance criteria

- [ ] 首个建议 red：Pi 获得一个有效证据后预算暂停，销毁应用与 worker 并重建，从真实 PG 检查点获批续跑；旧证据仍可解析、已闭合义务不重查、resume_of 与额度审计完整。
- [ ] 预算不足在请求前暂停；在途响应造成超限时记录真实用量并在最早安全边界检查点，暂停不是成功或 inconclusive 答案，不写半结论。无可用快照 / 存储 / 证据时明确 checkpoint_unavailable 或 blocked，不伪造可续跑状态。
- [ ] 同一检查点并发 resume 只有一个获胜；未批准 / reader / 跨项目 / 超续跑次数 / 已失效知识版本均拒绝并可查询原因。新 run 使用新 generation，旧进程迟到 call / answer / usage 不改变任一新账本。
- [ ] 运行时 / 模型 / config / 工具契约按 #59 固定；找不到旧兼容版本时 blocked 并要求显式新任务，不静默升级 worker、替换 provider、改为 llm 或读取 latest 图谱。
- [ ] 真实 PG 双应用 worker 杀进程、租约失效和断连测试：失去数据库时停止领任务 / 发新请求；恢复后使用现有 fencing，完成证据不重复发布。readiness 不把其他应用存活工作误判为可接管。
- [ ] API 与正式详情显示暂停原因、frontier、累计用量、续跑 lineage、批准 / 拒绝；Memory / SQLite 同语义，SQLite 重启恢复通过，无子进程 / 临时目录泄漏。


## Blocked by

- #59
- #60
- #45
- #46

## 交付与边界

- 按 AGENTS.md，在公开边界逐项 TDD red → green；本文首个测试是待确认的边界建议，不等于已经得到测试边界确认。DeepSeek 先核对当前代码与 Issue 最新正文，再按项目约定确认新边界。
- 每单交付实际链路、Memory / SQLite / PostgreSQL 持久化（如涉及）、认证 API、正式 UI（如涉及）、公共 Schema、测试与文档；失败不得切换脚本、模拟成功或偷偷改用其他 runtime。
- 沿用现有项目 / 快照 / 符号 / 证据 ID、登录、加密模型设置、CLI / MCP。旧 task / run / workflow / 报告可读，历史缺失字段是 unknown，不能填成零或成功。
- Go 兼容 Ubuntu / macOS / Windows；执行相关测试、完整乱序竞态回归、前端测试 / 构建、make lint、make check-contracts；涉及生命周期 / 文件系统跑 make test-stress，数据库变更跑真实 make test-postgres。不得排除失败包后宣布全量通过。
- 迁移编号在实现时取仓库中下一可用编号，不预占；内置插件包摘要随宿主变动时遵守既有升级与旧版本保留约束。
- 不存储隐藏推理、原始 provider 消息、API Key、真实个人信息或运行数据；不写 .env / 私钥。模型设置沿用程序内配置与密文仓储。
- Issue 验收后按已有授权更新完成记录、独立 commit 并关闭；push 必须等用户明确要求。本组方案本身不授权真实存量切换、默认 runtime 切换或新账号 / 凭据创建。


### P6 建立 llm 与 Pi 真实模型对照评测并验收两种部署

<!-- codexploit-pi-plan:2026-10-19:P6 -->

## Parent

#56

## What to build

**类型：HITL**


**用户故事：** 维护者能依据真实质量、成本和恢复数据决定是否推广 Pi，而不是因为换了框架就宣称审计更准、更省。

保留 make bench-agent 的 ScriptedRuntime 回归；新增显式 opt-in 的真实模型 benchmark 与机器可读报告。固定同一源码 / 知识快照、任务集、工具 / prompt 版本、模型、配置和预算，仅比较 runtime。运行 fixture 合同测试与真实 provider 质量评测分别报告。

## Acceptance criteria

- [ ] 首个建议 red：评测汇总面对 scripted 的零 token、provider 未报 usage、某组失败或缺失结果时输出 unavailable / failed，绝不当作零成本胜出。
- [ ] 真实集合覆盖播种漏洞、已知安全、不可判定、协议与生命周期边界；每组至少 20 个有标注任务、每任务每 runtime 至少 3 次，固定种子（若支持）并记录不确定性 / 样本量。不得用 20 个脚本 replay 代替真实模型数据。
- [ ] 记录召回 / 误报 / 义务闭合与不可判定分布、证据有效率、真实请求数、调用数、repairs、novelty、停止原因、p50/p95 token 和耗时；区分 cached / reasoning 等用量避免重复相加。每确认发现 token 仅在真实 verifier 产出 confirmed 时计算，否则 N/A。
- [ ] 必须为零：接受开放义务的 conclusive 输出、伪造 / 跨 scope 引用通过、取消后发布、无授权预算追加、协议超限后成功、隐藏推理 / 凭据泄漏。标注集合上播种召回不降且误报不升；样本不足 / 噪声导致无法判断则结论是证据不足，不宣称胜出。
- [ ] 成本目标作为报告项，不预设 Pi 必须降低 35% / 50%；与相同真实 llm 基线比较，报告原始差值和限制。真实调用必须由运行者显式 opt-in 且已有配置可用；未运行报告待验收，CI fixture 通过不等于质量通过。
- [ ] 默认 PostgreSQL 和独立 SQLite 部署完成页面选 Pi → 真模型 / 真工具 → 候选 / 报告 → 取消 / 暂停 / 续跑 → 容器重建验收；已有卷、账号、会话、密文设置、旧插件与工作流保持可读，不能清库换成功。
- [ ] 文档给出固定依赖安装、readiness、原生模式缺 Node、故障诊断、同部署选择 llm 的回退与数据兼容方法；回退只影响新任务，不能悄悄换旧 run。验证 clean checkout 构建，不依赖实现者全局 Pi 或 Node 包。
- [ ] HITL：交付可审阅的对照报告与默认切换建议，人工根据报告决定是否另行授权默认 runtime 变更；本单不自动更改默认值。数据不达标则保留可选 Pi 并如实记录，不为关单伪造评测。


## Blocked by

- #59
- #60
- #61

## 交付与边界

- 按 AGENTS.md，在公开边界逐项 TDD red → green；本文首个测试是待确认的边界建议，不等于已经得到测试边界确认。DeepSeek 先核对当前代码与 Issue 最新正文，再按项目约定确认新边界。
- 每单交付实际链路、Memory / SQLite / PostgreSQL 持久化（如涉及）、认证 API、正式 UI（如涉及）、公共 Schema、测试与文档；失败不得切换脚本、模拟成功或偷偷改用其他 runtime。
- 沿用现有项目 / 快照 / 符号 / 证据 ID、登录、加密模型设置、CLI / MCP。旧 task / run / workflow / 报告可读，历史缺失字段是 unknown，不能填成零或成功。
- Go 兼容 Ubuntu / macOS / Windows；执行相关测试、完整乱序竞态回归、前端测试 / 构建、make lint、make check-contracts；涉及生命周期 / 文件系统跑 make test-stress，数据库变更跑真实 make test-postgres。不得排除失败包后宣布全量通过。
- 迁移编号在实现时取仓库中下一可用编号，不预占；内置插件包摘要随宿主变动时遵守既有升级与旧版本保留约束。
- 不存储隐藏推理、原始 provider 消息、API Key、真实个人信息或运行数据；不写 .env / 私钥。模型设置沿用程序内配置与密文仓储。
- Issue 验收后按已有授权更新完成记录、独立 commit 并关闭；push 必须等用户明确要求。本组方案本身不授权真实存量切换、默认 runtime 切换或新账号 / 凭据创建。
