# Spring Framework 真实审计全流程验收记录

日期：2026-10-26（Asia/Shanghai）。结论：**全流程验收未通过**。实际登录、读取源码、启动两次工作流、主 Agent 源码调查与知识保存均已执行；两次工作流均被语义输出契约阻断，没有路径子 Agent、正式固定报告或动态验证结果。不能据此宣称 Spring Framework 安全。

本次是正式运行验收与问题登记，没有修改产品实现，没有执行目标项目的 build、test、hook 或安装脚本，没有提交或推送代码。工作区原有进行中改动未纳入本次交付。

## 环境与输入

- 使用内置浏览器中的正式登录会话，服务为现有 PostgreSQL 部署。
- 项目：`springframwork`，`proj-M3MSFNAFVYXVUOVVN34DR7SXOD`。
- 来源：已导入的 `https://github.com/spring-projects/spring-framework`，本轮复用现有只读目录，没有重新获取另一份源码。
- 内部输入关联：`snap-12d45ef78c358905c2c5cfddede8bb67`；来源：`src-5bed0bb4-1d74-4794-9e93-299e9f8d18b8`。
- 输入 11,342 文件、60,615,176 字节。导入时另有 141 项排除：1 项链接、45 项二进制、95 项忽略规则记录；这些统计不是解析失败统计。
- 主引擎 `codexploit.joern@2.3.1`，默认工作流 `codexploit.default-analysis@2.2.0`。固定包摘要：`8ddf4bb07e32cbe05575dd49c1fa501bfc4dff3d5f86dfbbf16761b66e3a733c`。
- 主 Agent 使用应用现有 `llm / deepseek-chat`、配置版本 4；受限任务固定 `pi`。未追加审计额度或修改模型设置。

历史 Joern 2.2.0 的三条 `normalization_failed` 记录保留，与本轮两次失败不是同一运行。

## 两次真实工作流

| 项目 | 默认流程 | 受限流程 |
| --- | --- | --- |
| 目的 | 验收当前默认链路 | 单独减少流预算，尝试隔离重复 sink，并验证后续链路 |
| taint.max_flows | 100 | 1 |
| parse / taint 堆 | 4096 MiB | 4096 MiB |
| 任务 | `task-T4SYHYI5FUXZMFM6ORKARJSAKT` | `task-GJYTIWA4AXFEOFBRPUKCDFV6TJ` |
| 运行 | `wrun-4HXFIUCAMBOX6MQIQZF5LAHYZS` | `wrun-Z3APUP3BBL4PFSOMJNJSFDI43M` |
| 计划 | `plan-f6a6108e9214dd78e48ac9b4046c6f73` | `plan-6b13df1994a4aa445b12fc0174d3938e` |
| parse | PARTIAL，4 份真实产物 | PARTIAL，4 份真实产物 |
| semantic | FAILED / output_contract_mismatch | FAILED / output_contract_mismatch |
| paths / enhance / publish | SKIPPED / upstream_failed | SKIPPED / upstream_failed |
| 路径 Agent | 默认未开启 | 已请求开启，但 $analyze 被上游失败跳过 |
| 最终状态 | FAILED | FAILED |

受限工作流 `codexploit.restricted-1path-acceptance@1.0.0`，名称“受限1轨迹验收”，由工作台主 Agent 使用正式 API 保存、编译并创建任务。它不是默认失败的替代成功；两个失败均保留。主 Agent 在获取准确请求契约和新计划 ID 后才完成创建，不能把这段操作认定为自主编排通过。

两次 parse 覆盖相同：seen=11,342、analyzed=5,512、failed=4,131、skipped=1,699；PARTIAL，存在真实覆盖缺口。每次保存 3 份 CPG 和约 136.6 MB code.facts。插件请求中的 `max_files=2000` 在 file-job 映射为输出文件预算，不能据此断言输入源码最多覆盖 2,000 文件。

受限流程权威节点时间（北京时间，来自数据库节点记录）：

- parse：19:07:33.830 → 19:09:22.113。
- semantic：19:09:22.115 → 19:10:04.332。

主 Agent 最后散文汇报误把 semantic 时间归给 parse；本文已按节点记录纠正，相关证据追加到 #74。

## 阻塞复现与隔离

正式宿主保留相同 `output_contract_mismatch`，但没有给出具体字段。为定位，在临时诊断目录使用镜像内同一封存适配器重放原始 code/CPG 输入。重放产物没有登记成正式成功输出，也没有绕过发布校验。

| 直接适配器重放 | max_flows=100 | max_flows=1 |
| --- | --- | --- |
| 适配器状态 | PARTIAL | PARTIAL |
| CPG | 3 个已见，2 个已分析，1 个失败 | 同左 |
| 流 | 32 | 1 |
| sink 元素 / 唯一 ID | 82 / 81 | 67 / 67 |
| 分区 | 10 truncated、3 complete | 10 pending、1 truncated、2 complete |
| Kotlin | taint / execution_failed | 同左 |
| 正式 SecurityFacts Schema | 拒绝目录元数据字段 | 同样拒绝 |

已确认两个独立阻塞：

1. `securityFacts` 的非目录关联 sink 分支加入顺序列表后没有标记 `seen[sinkID]`，不同流共享同一 sink 时输出重复 ID。实际重复对象为 `spring-webflux/.../FreeMarkerView.java:377`，宿主按唯一 ID 拒绝是正确保护，见 #80。
2. adapter 在 ruleset 中输出 `catalog_id`、`catalog_version`、`catalog_digest`、`catalog_entries`、`catalog_sink_matches`、`catalog_sink_nodes`，正式 SecurityFacts Schema 未声明这些字段且禁止额外属性。使用与宿主相同的 jsonschema-go 检查两份真实输出，都在 `/SecurityFacts/properties/ruleset` 拒绝这六项，见 #86。单轨迹输出无重复 ID，仍失败，排除了“只有重复 sink”这一解释。

Kotlin 失败与 parse 覆盖不足另行保留为真实限制；不据其笼统错误推断资源不足或目标代码缺陷。受控诊断仍不足以定出 Kotlin 的内部根因，详见 #85。

## 主 Agent 实际完成的审计

会话：`ss-IVXSLGUKE6QYHWXCX7OUY5VASA`。源码调查运行：`srun-5BD6YRIXOPESCPWLR7ICLWLJF4`。最终收尾运行：`srun-JLSYD4CTQ2P22YELSRWZJ3L2YY`。

实际读取了 Spring MVC 静态资源链及 SpEL 相关源码，包括 ResourceHttpRequestHandler、PathResourceResolver、ResourceHandlerUtils、SpelExpressionParser、StandardEvaluationContext、SimpleEvaluationContext。

持久化调查知识账本 revision 9，数据库数量与正式图谱页核对：

- 2 条猜想：默认资源解析链的路径约束；SpEL 求值上下文的危险能力与调用前提。
- 5 条已绑定真实源码窗口的证据。
- 2 个未解决问题。

这些记录是 conjecture / recorded / open，不是已确认漏洞，也不是完整路径 Agent 的结构化义务裁决。没有证明不可信输入可达 SpEL 危险求值；对默认资源链的有限静态阅读也不能证明整个框架不存在路径穿越。

遇到的工具问题包括：未构图时 repo_map/list_modules/get_code_slice 返回不可用，主 Agent 能改用独立源码窗口；open_question 第一次携带不允许字段被拒，修正后保存成功。不得把修复后的调用成功抹去之前失败记录。

## 操作契约与费用观测

以下是 provider 返回并保存的累计用量，不是价格估算，也不能据此推导缓存收费。

| 主会话运行 | 行为 | 模型轮数 | 输入 tokens | 输出 tokens | 结果 |
| --- | --- | ---: | ---: | ---: | --- |
| srun-APTJPCY4CWLOTSD23UKOGLI5JA | 状态/源码地图核对 | 6 | 154112 | 2072 | SUCCEEDED |
| srun-5BD6YRIXOPESCPWLR7ICLWLJF4 | 源码调查与知识保存 | 20 | 979440 | 6777 | SUCCEEDED |
| srun-JK2BG7HT3MM3KXAY5AKGHXUOL6 | 猜工作流请求封装 | 20 | 1027197 | 5831 | FAILED / round_limit |
| srun-MNQP7WSZSITVBPX3I7NKWLMQIL | 编译成功但无法取新 plan_id | 20 | 676529 | 4691 | FAILED / round_limit |
| srun-UGDUAM7WGB7EOICFMQMBBLSPLU | 提供准确 plan_id 后创建任务 | 2 | 52241 | 788 | SUCCEEDED |
| srun-JLSYD4CTQ2P22YELSRWZJ3L2YY | 最终终态核对 | 3 | 91353 | 1906 | SUCCEEDED |

工作流创建阶段实际暴露：操作目录只有路由与路径参数，缺请求 Schema；缺少外层 api_version 得到笼统 invalid_workflow；计划列表缺必填 snapshot_id 得到易误判的 workflow_not_found；大型 POST 成功回执的 plan_id 位于截断窗口之外，且 POST 不允许续窗读取。主 Agent 两次耗尽 20 轮仍未完成任务，人工查处理器/存储补参后才推进。分别登记 #81、#82、#83。

## 产物、页面与持久化核对

- 正式产物目录可见两次 parse 的 8 份不可变引用；独立核对对象字节数和 SHA-256。
- 浏览器完成一份 85,942 字节原生 CPG 的“校验→下载→下载后摘要核对”，摘要与引用相同。
- 下载文件被命名为 `.tar`，但实际文件头为 `FLT GRPH`，不是 TAR/ZIP；内容没损坏，命名错误登记 #88。
- code.facts 超过 JSON 预览上限时预览按钮禁用；读取预算可调整至 512 MiB，这是现有有界策略，不作为数据丢失报告。
- 图谱/路径页明确未构建，未显示模拟路径。正式报告页因没有固定视图禁用生成，没有保存成功报告。
- 报告页混淆正常空目录和读取失败，并显示底层英文未构图错误，登记 #87。
- 主 Agent 新建第五个项目任务后，侧栏数量仍为 4，手动全局刷新/重载才同步；追加 #22。
- 工作台 1104×895 视口中央列宽 446px，最终 article 宽约 704px、父容器 scrollWidth=752px；普通中文结论被迫整篇横向滚动，登记 #89。
- 调查知识、会话和失败任务从 PostgreSQL 及页面重载读回；本轮没有重启主部署，不声称完成重启/灾难恢复验收。

## 已提交的问题

| Issue | 问题 | 优先级 |
| --- | --- | --- |
| [#80](https://github.com/UserB1ank/Cod3xplo1t/issues/80) | 多流共享 sink 输出重复 ID | P1 |
| [#81](https://github.com/UserB1ank/Cod3xplo1t/issues/81) | 主 Agent 操作目录缺请求契约与字段单位 | P1 |
| [#82](https://github.com/UserB1ank/Cod3xplo1t/issues/82) | 大型 POST 回执裁剪丢失创建资源 ID | P1 |
| [#83](https://github.com/UserB1ank/Cod3xplo1t/issues/83) | 主 Agent 缺请求前 token 预算与有界上下文 | P1 |
| [#84](https://github.com/UserB1ank/Cod3xplo1t/issues/84) | Java vendor/target/build 包被误排除 | P1 |
| [#85](https://github.com/UserB1ank/Cod3xplo1t/issues/85) | 输出拒绝丢失诊断，Kotlin 失败缺可行动原因 | P2 |
| [#86](https://github.com/UserB1ank/Cod3xplo1t/issues/86) | catalogue ruleset 与正式 Schema 不兼容 | P1 |
| [#87](https://github.com/UserB1ank/Cod3xplo1t/issues/87) | 报告页空/失败状态混淆与中文错误不足 | P2 |
| [#88](https://github.com/UserB1ank/Cod3xplo1t/issues/88) | 原生 CPG 被命名为 TAR | P2 |
| [#89](https://github.com/UserB1ank/Cod3xplo1t/issues/89) | 工作台长总结撑宽中央列，普通中文结论被裁切 | P2 |

另外向已有 [#48](https://github.com/UserB1ank/Cod3xplo1t/issues/48) 补充“图谱失败但调查知识已产生，无法生成受阻审计报告”的验收证据；向 [#74](https://github.com/UserB1ank/Cod3xplo1t/issues/74) 补充 coverage/节点时间误读；向 [#22](https://github.com/UserB1ank/Cod3xplo1t/issues/22) 补充主 Agent 写入后的统计刷新问题。避免为已有交付范围创建重复工单。

## 验收裁定与恢复顺序

正式完整审计仍被阻塞。先修 #80/#86，再从真实新版本流程验证 semantic→paths→enhance→publish→路径子 Agent→固定中文报告；同时修 #81/#82，才能验收主 Agent 在没有人工逐字段喂参时自主完成调度。#83 是继续扩大审计前的成本控制问题。

本轮没有实现或关闭这些 Issues，未运行与产品变更对应的完整单元/竞态/构建门禁，也没有把局部 adapter 重放、会话完成、零发现或源码猜想冒充全流程通过。
