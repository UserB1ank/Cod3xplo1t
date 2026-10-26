# Agent 停止质量基线

状态：由 `make bench-agent` 生成，固定脚本场景，不调用模型。2026-10-19 首次记录，对应 `d801502` 之后的循环行为。
用途：任何改动 Agent 循环（提示、工具、预算、停止条件）之后，重跑同一组场景，逐项对比这些数字，而不是凭感觉判断"更好了"。

## 怎么生成

```bash
make bench-agent
# 等价于：
# AGENT_BENCH_OUT=$(pwd)/dist/agent-baseline.json \
#   go test ./internal/agent -run TestGoldenBaseline -count=1 -v
```

- 场景文件：`internal/agent/testdata/golden/*.json`，共 20 条，每个 run 用 `ScriptedRuntime` 回放两遍，第二遍必须与第一遍逐字节一致（事件序列、计数、答案）。
- 机器可读汇总：`dist/agent-baseline.json`（构建产物目录，不提交）。
- 常规 `go test` 也会跑这 20 条并校验各自声明的计数（`TestGoldenScenarios`），所以基线不是另一套测试，它就是回归测试。

## 指标

全部由编排器观测，不是适配器自报：

| 字段 | 含义 |
|---|---|
| `status` / `stop_reason` | run 的终态与停止原因 |
| `tool_calls` | 实际执行的工具调用数（被拒绝的不计） |
| `exchanges` | 工具交换次数，每次执行一个调用 |
| `rounds` | 适配器轮数；当前协议一轮一个调用，因此等于 `exchanges + 1`（作答那一轮） |
| `novelty` | 每次交换新出现的证据 id 数，按证据去重。重复查询同一批 id 记 0，这是"停止学习"的可观测信号 |
| `invalid_calls` | 工具以错误作答（`OK=false`）的次数 |
| `truncations` | 结果被协议上限截断的次数 |
| `input_tokens` / `output_tokens` | 适配器上报的用量；脚本适配器不上报，因此本基线全部为 0 |

## 基线

| 场景 | 类别 | status | stop_reason | calls | rounds | novelty |
|---|---|---|---|---|---|---|
| `vuln-sql-concat` | seeded_vuln | SUCCEEDED | `completed` | 1 | 2 | `[2]` |
| `vuln-cmd-injection` | seeded_vuln | SUCCEEDED | `completed` | 2 | 3 | `[1, 2]` |
| `vuln-file-write` | seeded_vuln | SUCCEEDED | `completed` | 1 | 2 | `[1]` |
| `vuln-ssrf` | seeded_vuln | SUCCEEDED | `completed` | 2 | 3 | `[1, 0]` |
| `vuln-deserialization` | seeded_vuln | SUCCEEDED | `completed` | 3 | 4 | `[1, 1, 1]` |
| `safe-parameterised` | known_safe | SUCCEEDED | `completed` | 1 | 2 | `[1]` |
| `safe-constant-path` | known_safe | SUCCEEDED | `completed` | 1 | 2 | `[1]` |
| `safe-escaped-output` | known_safe | SUCCEEDED | `completed` | 2 | 3 | `[1, 1]` |
| `safe-auth-middleware` | known_safe | SUCCEEDED | `completed` | 1 | 2 | `[1]` |
| `safe-no-reachable-sink` | known_safe | SUCCEEDED | `completed` | 1 | 2 | `[1]` |
| `undecidable-interface-dispatch` | undecidable | SUCCEEDED | `completed` | 1 | 2 | `[1]` |
| `undecidable-external-dependency` | undecidable | SUCCEEDED | `completed` | 2 | 3 | `[1, 0]` |
| `undecidable-reflection` | undecidable | SUCCEEDED | `completed` | 1 | 2 | `[1]` |
| `undecidable-generated-code` | undecidable | SUCCEEDED | `completed` | 1 | 2 | `[1]` |
| `undecidable-missing-source` | undecidable | SUCCEEDED | `completed` | 1 | 2 | `[0]` |
| `boundary-unknown-field` | boundary | INVALID_OUTPUT | `invalid_output` | 0 | 1 | — |
| `boundary-confirmed-claim` | boundary | INVALID_OUTPUT | `invalid_output` | 0 | 1 | — |
| `boundary-tool-denied` | boundary | SUCCEEDED | `completed` | 1 | 2 | `[1]` |
| `boundary-tool-budget` | boundary | BUDGET_EXCEEDED | `tool_call_budget_exceeded` | 2 | 3 | `[1, 0]` |
| `boundary-truncated-result` | boundary | SUCCEEDED | `completed` | 1 | 2 | `[0]` |

汇总（20 条）：

| 指标 | 值 |
|---|---|
| 场景数 | 20（每类 5） |
| 平均 rounds | 2.25 |
| 工具调用总数 | 25 |
| 截断总数 | 1 |
| 无效调用总数 | 0（脚本工具不会失败；真实工具的错误路径见 `runner_metrics_test.go`） |
| 停止原因分布 | `completed` 17、`invalid_output` 2、`tool_call_budget_exceeded` 1 |

## 限制

- **token 为 0**：脚本适配器不上报用量，这是刻意的（见 `ScriptedRuntime.Capabilities`）。真实 token 基线需要一次带 API Key 的模型运行，属于 #49（原生工具 Schema 与预算回执）之后的工作，不在本文件里造假数据。
- **novelty 依赖工具返回的 refs**：脚本工具返回固定 refs，所以这里度量的是编排器的去重逻辑，不是图查询的真实新颖度。接入真实工具后该字段才有业务含义。
- **场景是合成的**：20 条覆盖四类停止形态，不追求漏洞样本规模；播种漏洞召回率需要真实仓库样本，见整改草案 §4。

## 改动之后怎么比

1. 改动前运行 `make bench-agent`，保存 `dist/agent-baseline.json`。
2. 改动后重跑，逐字段 diff：任何 `rounds`、`tool_calls`、`novelty`、`stop_reason` 的变化都必须能解释。
3. 期望的变化写进对应 Issue 的验收；无法解释的变化视为回归，不合并。

## 攻击面目录工具真实模型对照（2026-10-26）

`cmd/bench-tools` 对同一组 5 个固定事实任务比较旧图谱工具和加入
`repo_map` / `list_entry_points` / `list_sinks` / `get_asg_node` 后的目录工具。
旧工具先返回目录页，模型必须再查一次详情；目录工具直接返回宿主固定的完整事实。
最终答案只有在精确事实和证据 id 都通过宿主校验时才算成功。

真实运行使用部署中已启用的 `deepseek-chat`，每个场景和变体重复 2 次，共
20 个有效样本，全部通过答案 / 证据校验：

| 指标 | 旧工具 | 目录工具 |
|---|---:|---:|
| 平均 provider 轮数 | 3.70 | 2.70 |
| 圆整后平均轮数减少 |  | **1.00** |

这是合成黄金集上的工具可用性对照，证明固定事实的探索开销下降，不证明真实仓库漏洞
召回率或误报率改善。真实调用必须显式开启：

```sh
go run ./cmd/bench-tools \
  --allow-real \
  --repeats=2 \
  --postgres-dsn-file=<dsn-file> \
  --settings-key-file=<installation-key-file> \
  --out=dist/agent-tools-baseline.json
```

不带 `--allow-real` 只输出计划摘要，不解密模型设置，也不访问网络。
