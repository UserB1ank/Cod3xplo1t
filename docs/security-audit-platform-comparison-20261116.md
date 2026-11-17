# 自主安全审计项目分层对照

核查日期：2026-11-16。目标是“主 Agent 自主协调，包含动态复现与验证”。本文只核查外部项目的一手资料，不替代 Codexploit 当前源码与运行验收。

本次读取 Shannon `main` 的提交为 `cf7c21b32c8151246c87e129b988e8cd6174f8cc`，Strix `main` 为 `4719329d1c3eb0db796714397551945c514a2301`。官方文档会更新，结论以本次读取内容为准。没有运行这些产品的同一目标对照实验，因此不对发现率、误报率、成本或可靠性排名；未核实的能力也不按“不存在”处理。

## 比较对象与层次

Shannon 与 Strix 最接近自主审计产品；Semgrep Code、CodeQL 与 Joern 用来对照分析引擎；DefectDojo 用来对照结果管理。后四者可贡献模块和工程方法，不能直接替代主 Agent 的完整执行闭环。

| 对象 | 本次比较的定位 | 已核实能力 | 与自主审计目标的关系 |
|---|---|---|---|
| Shannon | 源码感知的 Web/API 自主渗透测试 | 源码与运行应用并用；候选汇合后交给 exploitation agents；持久 workspace 与续跑；证据报告 | 接近“调查→候选→实际验证→报告”。需要运行目标；不能把其工作容器等同任意目标环境自动供应 |
| Strix | 多 Agent 白盒/黑盒安全测试 | 源码、仓库与部署目标；动态 Agent 协作；Docker 工具环境；本地结果查看；明确的成本/轮次控制 | 适合参照主子协调与可观察性；白盒结论条件和源码可写策略与不可变审计输入并不相同 |
| Semgrep Code | 规则和数据流分析 | 规则定义匹配行为；本地/CI 扫描；正反例规则测试 | 用作候选或审查线索。此处只比较其 SAST 模块，不把整个 Semgrep 产品限制为规则扫描 |
| CodeQL | 代码数据库与查询分析 | 告警查询、source-to-sink 路径查询；查询库与 expected-result 回归 | 提供可定位的静态证据和查询测试方法；静态路径不是实际复现 |
| Joern | CPG 与程序分析查询 | 多语言前端、CPG、数据流查询、可缺少完整构建环境的导入 | 是审计工具层；不应要求主 Agent 或 UI 重新实现程序分析求解器 |
| DefectDojo | 结果汇聚与生命周期管理 | Import/Reimport；可配置去重；发现身份与历史状态管理 | 适合借鉴结果入库与去重语义，不能代替漏洞调查及动态验证 |

### Shannon：闭环比较清楚，阶段化执行与 Agent 自主性可以共存

官方当前架构把源码分析与运行时调查的候选汇合、去重，再交给 exploitation agents；通过实际利用验证的结果进入 pentest 报告和 CI 严重度门禁。每次扫描使用临时 Docker worker。它属于源码感知的白盒测试，适用于 Web 应用/API，不能当作任意语言、任意可运行环境的通用源码审计系统。[官方架构与范围](https://github.com/KeygraphHQ/shannon#architecture)

Workspace 保存执行状态并对各 Agent 做 checkpoint；中断后可跳过已完成工作，恢复时校验原目标 URL。源码构建文档还提供统一的状态、日志与停止入口，并指出 Temporal 的监控入口。这些资料能证明它把续跑当作执行能力；不能据此断言任意外部副作用均具备 exactly-once 语义。[Workspace/续跑](https://github.com/KeygraphHQ/shannon/blob/main/docs/workspaces.md)、[执行命令与日志](https://github.com/KeygraphHQ/shannon/blob/main/docs/development.md)

可借鉴的判断：确定的阶段负责组织可恢复工作，模型负责阶段内调查与证据判断，两者并不矛盾。也不宜照搬“无法证明就不进入 pentest findings”到整个审计账本：面向审计覆盖的产品仍需保留未验证候选、阻塞条件和未覆盖范围；不进入已验证结果不等于已排除。

### Strix：更接近主子 Agent 协调，但要审视“验证”究竟由谁保证

官方介绍包括本地源码、仓库和运行应用作为输入，专门 Agent 分享发现并协调测试，CLI 和本地 Web viewer 展示运行与 Agent 团队。CLI 文档还明确整个扫描的累计预算、子 Agent 收尾空间以及交互/非交互停止行为。[项目能力与入口](https://github.com/usestrix/strix)、[CLI 合同](https://docs.strix.ai/usage/cli)

必须区分两项实际语义。第一，CLI 文档说明本地目录会 live、可写挂入 sandbox；这不等于源码已经固定成不可变证据。第二，当前系统提示词中，白盒 `confirmed` 可由可工作的 PoC 或完整且可达的 source→control→sink→impact 论证满足；还要求把无法完成证明的候选保留为 `open_proof_gap`。因此不能把所有白盒 confirmed 都解释成独立宿主已重放动态复现。这里描述的是公开执行指导；其宿主如何独立验证每一条证明，本次未完成代码级审计。[公开 Agent 协调与验证指导](https://github.com/usestrix/strix/blob/main/strix/agents/prompts/system_prompt.jinja)

Strix 的公开 CI 包含 Python lint/type 检查、pytest、Go TUI 的竞态测试、viewer 构建和发布包内容检查。这说明它把执行内核、显示和发布产物分别验收；这些检查不能直接证明安全发现质量。[公开 CI](https://github.com/usestrix/strix/blob/main/.github/workflows/ci.yml)

可借鉴的判断：建立主子 Agent 的统一生命周期、可查询任务树和明确结束动作；把证明缺口单独记录。Docker 中有浏览器、终端和安全工具，并不能自动证明目标应用的创建、网络限制、回收和重启恢复已经交付；这些需单独验收。

### Semgrep Code：规则质量有可以重复执行的正反例

Semgrep Code 的规则承载匹配与数据流逻辑，支持本地和 CI 使用。规则测试可标注应命中、不应命中以及暂未支持的正反例，以 `--test` 核对结果。本文只对照这个分析模块；不评价其其他 AI/工作流产品能力。[Semgrep Code](https://docs.semgrep.dev/semgrep-code/overview)、[规则测试](https://docs.semgrep.dev/writing-rules/testing-rules)

可借鉴的判断：每种引擎能力都应有最小正例、对应安全反例和明确预期；解析成功率、扫描命中数、漏洞确认率分别度量。

### CodeQL：静态证据的表达和查询回归值得复用

CodeQL 把告警查询和 source-to-sink 路径查询明确分开。其查询测试通过示例代码建库，对照 `.expected` 结果；变化会产生测试差异。这些是程序分析和规则回归机制，不是对目标进行动态利用。[查询种类](https://codeql.github.com/docs/writing-codeql-queries/about-codeql-queries/)、[查询测试](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/test-custom-queries)

可借鉴的判断：接入引擎时保留查询版本、源位置、路径和局限；不要只把结果压成一条模型总结。查询包和目标语言的实际使用条件需要在选型时另行核实。

### Joern：应当作为现成程序分析能力使用

Joern 提供多语言 CPG 与查询；其文档分别说明数据流来源查询和数据流路径查询。可缺少完整构建环境的解析，不代表所有语言具有相同语义成熟度，也不代表所有调用和数据流都能解决。[总体能力与语言表](https://docs.joern.io/)、[数据流查询](https://docs.joern.io/cpgql/data-flow-steps/)

可借鉴的判断：模块负责输入固定、工具版本、执行诊断、查询与来源转换；优先修复这些接线的可观察性和契约。是否增加自研 Go type/SSA 能力，应由具体漏检案例决定，不能只根据早期 Go 前端的不足推导整个系统缺少数据流能力。

### DefectDojo：结果身份与历史比“把更多工具结果放进库”更难

DefectDojo 的 Import/Reimport 负责接入报告和更新持续测试。Reimport 的匹配与已有 Finding 的去重不是同一个过程；算法和作用域不当可丢弃输入或制造重复。它强调结果身份、导入范围和历史管理，这些不是发现引擎的替代品。[Reimport](https://docs.defectdojo.com/import_data/import_intro/reimport/)、[去重语义](https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/)

可借鉴的判断：确定“观察”“候选”“同一个漏洞”“验证 attempt”各自身份，分别追加来源、状态和证据；修订规则时应保留旧输入与旧报告，不能靠标题相似就合并。

## 对重构方向的推断

以下是根据上述项目机制作出的工程建议，不是外部产品对 Codexploit 的评价：

1. 将“自主审计一次任务”作为用户面对的主对象。主 Agent 可以拆出调查、静态查询、候选复核、动态验证和报告工作；持久调度层统一记录父子关系、attempt、停止原因、授权和产物。无需把所有工作塞进一个巨型 Agent 循环。
2. 统一工作语义，保留执行差异。静态插件、模型请求、目标启动和 PoC 都可以成为可跟踪工作；它们的取消、重试和副作用不同，应由各自执行适配器实现，再向上报告真实状态。
3. 以工具接口交付确定能力：输入引用、参数 Schema、资源/权限要求、成功/失败回执、详情读取方式、可恢复性。只让模型猜路由和请求体，会把协议错误转化为昂贵的探索。
4. 将“候选成立”和“动态复现成功”分开。模型解释、静态路径、可执行脚本、执行观察和已验证证据分别存储。主 Agent 可以安排验证；宿主应核对 scope、环境、断言和证据后决定平台状态。
5. 动态环境供应属于第一条完整流程的一部分。第一版可以只支持一种可信容器模板和单服务目标，但必须贯通授权、创建、运行、证据采集、销毁、崩溃回收和重试；仅有底层 Provider 或 API 不应作为用户流程完成。
6. 每次只交付一个可重放案例：一次用户目标，主 Agent 自主安排至少一项调查和验证，遇到受控失败可恢复，最后生成可核对的证据报告。先把这一条做到稳，再扩展多服务、更多引擎和更多供应器。
7. 建立与基础工程测试分开的发现效果评测。固定源码版本、已知漏洞与对应安全版本、可利用性断言、执行条件和模型配置；统计确认/误报/漏检/阻塞、成本与重复运行差异。单元测试、页面构建或厂商宣传的 benchmark 数字都不能代替这套对照。

本次没有验证任何项目对任意目标的自动建环境能力、完整跨实例故障恢复或真实发现率，也没有据文档未写就判定其不支持。正式选型仍需使用同一组已授权目标做可复现的实际比较。
