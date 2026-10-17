# L7 发现、证据与报告层

接口：`FindingService`、`EvidenceStore`、`ReportService`。Schema：[finding.schema.json](../../../../contracts/v1/finding.schema.json)。示例：[finding.json](../../../../contracts/v1/examples/finding.json)。

## 独立的维度

| 维度 | 值 | 含义 |
|---|---|---|
| 严重性 | high / medium / low | 高、中、低；未评估时省略 severity，界面显示待分级 |
| 确认状态 | candidate / confirmed / refuted / inconclusive / blocked | 候选、已确认、已排除、证据不足、无法完成确认 |
| 路径种类 | call_reachability / taint_flow / control_flow / hypothesis | 分开说明分析依据 |

扫描器或模型可以生成候选与 severity_hint，不能自行写 confirmed。确认由明确的证据裁定接口执行；低置信度和低严重性不是同一概念。

## 标准方法

| 方法 | 输入 | 输出 / 幂等规则 |
|---|---|---|
| `RecordCandidate` | Scope、producer、结论、位置、证据、可选路径 | Finding；按来源观察指纹幂等 |
| `Get / List` | 项目/任务/快照、分级、状态、分页 | 发现与来源列表 |
| `AssessSeverity` | finding_id、grade、原因、expected_version | 只更新分级与评估审计记录 |
| `RecordVerdict` | finding_id、verdict、证据引用、裁定原因、expected_version | 更新确认状态与审计记录 |
| `EvidenceStore.Put / Open` | 作用域与脱敏证据 / 引用与预算 | 不可变 ArtifactRef / 有界内容 |
| `ExportReport` | 固定视图、项目/任务过滤、格式、候选包含策略 | 不可变 report.document |

## 去重与来源

同项目、同快照、同规则语义、同代码位置/路径、同结论的观察可归到一个发现组。组保留所有 finding_id、task_id、producer 和证据引用。不同快照使用显式版本关联；相互矛盾结论分别保留。

具体指纹算法版本化，存量指纹不能因升级直接改变。没有可证明的规则等价时，不以相似标题跨工具自动合并。

证据分别记录支持、反对和无结论的引用。引用必须解析到同 Scope 的有效证据；源码片段引用同时携带文件摘要与代码位置。后续修正写新证据并 supersede 旧引用。

## 确认与报告

confirmed 需要达到项目明确声明的证据门槛并有支持证据，存在未解释的直接反证时不得确认。refuted 需要反对证据。执行失败、未发现或缺失环境分别属于不同状态，不能据此排除漏洞。

项目和任务统计明确标注“已确认”与“候选”。报告包含固定版本、分析范围、分级、独立确认状态、证据、路径语义、工具版本、覆盖局限和未解决问题。产品不包含修复工单、自动补丁或修复复测流程。

Issue #13 已把插件观察接入现有 finding/evidence 体系：`internal/findings` 使用版本化规则族指纹（显式等价表；未声明规则留在自身命名空间；标题不参与）把同 Scope、同规则版本、同位置、同结论的观察归入一个 finding group。观察账本保存 producer、task、rule、证据引用和局限；重复调用按 observation id + digest 幂等，新的 invocation 只增加来源，不增加组或统计数。`verify.Finding` 仍保存裁定和 severity CAS，插件观察只能是 candidate。

`/api/v1/projects/{id}/findings`、详情和 reason-required severity PATCH 使用公共 `finding-runtime.schema.json`；分级更新与 append-only audit 在同一事务提交，候选/已确认统计分开。旧 `/api` 端点保留。

验收：分级不会改变裁定；扫描器不能伪造确认；去重不丢来源；证据不可覆盖；报告计数与分页声明一致。
