# L3 分析与归一化层

接口：`Parser`、`Analyzer`、`Normalizer`。Schema：[analysis.schema.json](../../../../contracts/v1/analysis.schema.json)。示例：[analysis.json](../../../../contracts/v1/examples/analysis.json)。

## 标准方法

| 接口方法 | 输入 | 输出 | 特殊约束 |
|---|---|---|---|
| `Parser.Parse` | Scope、源码 ArtifactRef、语言、参数 | 原生 AST、代码事实、Coverage | 单文件语法错误返回 partial 诊断，保留文件记录 |
| `Analyzer.Analyze` | 固定输入产物列表、图谱视图、规则版本、预算 | 原始报告、告警或原生路径 | 工具本身运行，目标仓库中的代码不运行 |
| `Normalizer.Normalize` | 原始产物、代码位置索引、工具格式版本 | AnalysisResult 与标准产物 | 标记来源与无法可靠映射的部分 |

`AnalysisResult = {api_version, scope, producer, status, outputs, coverage, diagnostics}`。producer 中包含插件版本、调用 ID、任务和配置摘要；由宿主核实绑定，不能接受插件伪造的身份或 Scope。

## 原生格式与通用事实

原生 AST 作为 `code.ast` 保存。通用代码事实至少表达文件、模块、符号、定义、调用、引用、位置、未解析项和 evidence_refs。CFG、DFG 和跨函数污点传播是可选能力，必须明确声明。

| 输入结果 | 标准化行为 |
|---|---|
| 工具只返回告警位置 | 建立发现与位置引用，path_refs 为空 |
| 返回调用链 | 建立 `call_reachability` 路径，不能标为完整污点传播 |
| 返回传播步骤与相应证据 | 建立 `taint_flow`，保留每步位置、传播语义和工具断言 |
| 返回未解析调用或缺失代码 | 记录 unresolved 与 limitations |
| 多工具结论冲突 | 保留独立观察和反证，交给后续裁定 |

分析路径记录必须包含 `path_kind`、有序步骤、每步证据引用及 completeness（complete / partial / unknown）。completeness 描述工具提供的路径信息完整度，不代表漏洞已经确认。

## 产物与错误语义

- `succeeded` 表示预定范围完成；`partial` 表示仍有可消费产物及明确局限；`failed` / `unsupported` 默认不供下游使用。
- 工具退出码与“发现了告警”分别映射；不能把工具的“存在告警”退出码直接转换为执行失败。
- 规则集版本、工具二进制/镜像摘要、输入摘要和配置摘要必须记录。可重现缓存还需要相同上下文和输出 Schema。
- 无法识别的报告版本返回 unsupported，保留原始产物，不猜测字段。
- 检测器输出日志经过限制和脱敏；不把日志或自由文本作为命令执行。

## 扩展与映射

现有 `scg.Frontend`、可选 Resolver、`analysis.Detector`、`asg.Builder` 和 `path.Service` 可用 adapter 包装为上述能力。第一阶段继续使用现有 Go AST 前端，新增语言实现 Parser 并经过同样的 Coverage 校验。

接入扫描器需要交付：Manifest、原始格式版本说明、Normalizer、无发现/告警/部分解析/格式错误样例，以及一份工作流。

验收：同一输入和版本可复现；没有路径的告警不生成虚构步骤；未知语言和预算截断可见；工具报错与阴性结果可区分。
