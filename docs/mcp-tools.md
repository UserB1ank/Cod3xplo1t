# Codexploit MCP tools

> Scope: this page describes the implemented nine-tool read-only stdio server. The separate authenticated [project supervisor surface](project-supervisor-tools.md) provides current-project content and operations through the same formal application API. The stdio surface keeps its read-only defaults. User conversation has no intent enum or keyword router.

`codexploit-mcp` (or `cmd/mcp`) serves the Source Code Graph over the Model
Context Protocol on stdio:

```bash
go build -o bin/mcp ./cmd/mcp
bin/mcp --workspace .codexploit --db .codexploit/codexploit.db
```

The surface is closed on purpose: **nine read-only tools**, no writes, no shell,
no arbitrary file access and no free-form query language. Every tool requires a
`snapshot_id`, is bounded by the graph service's budgets and returns the
service's provenance block (`meta`) unchanged. An answer without that block must
not be cited as coverage.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `graph_summary` | `snapshot_id` | node/edge counts, resolution mix, coverage, limitations |
| `list_modules` | `snapshot_id` | modules with file, symbol and line counts |
| `list_symbols` | `snapshot_id`, `module_id?`, `kind?`, `name_contains?`, `limit?`, `offset?` | a bounded page of declarations plus the total match count |
| `get_symbol` | `snapshot_id`, `symbol_id` (id **or** qualified name) | one declaration plus `meta` |
| `get_callers` | `snapshot_id`, `symbol_id`, `max_depth?`, `max_nodes?`, `limit?` | reached callers with distance, the edges followed, and the unresolved call sites inside them |
| `get_callees` | `snapshot_id`, `symbol_id`, `max_depth?`, `max_nodes?`, `limit?` | reached callees, same shape |
| `find_call_paths` | `snapshot_id`, `source_symbol_id`, `sink_symbol_id`, `max_depth?`, `max_paths?` | bounded distinct call paths with their edge ids |
| `get_code_slice` | `snapshot_id`, `symbol_id?`, `file?`, `include?`, `max_lines?` | source excerpts with the reason each was included |
| `list_unresolved_calls` | `snapshot_id`, `caller_symbol_id?`, `limit?` | call sites whose callee could not be resolved |

`kind` is one of `function`, `method`, `type`, `interface`, `const`, `var`,
`package`; an unknown value is rejected instead of silently widening the search.
`include` is one of `declaration`, `callers`, `calls`, `neighbors`; an unknown
value is rejected instead of silently returning a declaration-only slice.

## Authentication

MCP is served over stdio by a process the operator starts, so there is no network
surface and no token: authority comes from being able to run the binary and from
the permissions of the workspace and database it opens. The REST API, which does
listen on a socket, is authenticated separately — see
[`docs/api.md`](api.md#authentication).

## Error codes

Tool failures travel as text, so each message starts with a code. The names match
the REST API's error body codes, which lets a client branch on them without
parsing prose:

| Code | Meaning |
|---|---|
| `invalid_argument` | a required argument is missing or malformed |
| `not_found` | unknown snapshot, or a snapshot without a graph or symbol |
| `tree_unavailable` | the snapshot's frozen tree is not on this machine, so no slice can be read |
| `budget_exceeded` | the query hit its time budget |
| `internal` | unexpected failure |

## What the tools deliberately do not promise

- A call path is **reachability, not dataflow**: it never shows that
  attacker-controlled data reaches the sink. `find_call_paths` states this in
  its own limitations.
- "No callers" only means no *resolved* edge points at the symbol. Prefer
  `graph_summary` first, then read `unresolved_call_sites` in every
  neighbourhood answer: those are the blind spots that bound the result.
- Coverage is per snapshot and per rule set. `meta.graph_version` changes when
  the frontends change, and results from different graph versions are not
  comparable.


## 项目工作台诊断工具（2026-10-24）

受认证的主 Agent 会话使用私有 MCP server，在原图谱工具之外登记以下只读工具；原 stdio 工具面保持兼容。宿主绑定 project/snapshot，模型不能更换归属。

| 工具 | 行为 |
| --- | --- |
| `inspect_project` | `section=source/analysis/workflow/plugins/invocations/tasks/paths/agent_runs/findings/reports/artifacts/system`；读取真实目录、阶段与错误码、工作流事件、产物摘要和脱敏存储 readiness。`id` 定位分析、工作流或调用；`limit/cursor/offset` 按适用目录分页。报告目录在当前调用页内筛选，继续读取需使用返回的 cursor。 |
| `list_source_files` | 冻结源码路径分页，支持 contains/offset/limit；不依赖已发布图谱。 |
| `read_source_file` | 文件相对路径、start_line/max_lines；最多 200 行、16 KB，拒绝逃逸、链接、敏感文件和非文本，不依赖图谱。 |
| `list_entry_points` | 按入口类型、信任边界、文件或生成器分页读取 ASG 入口；返回主体、位置、证据状态、SCG 引用和完整匹配数。 |
| `list_sinks` | 按 SQL / MyBatis / Hibernate、反序列化、表达式 / JNDI、XXE、进程、网络、文件、LDAP、模板等类别读取全部命中 sink；支持高风险目录 / 未分类分区、规则 ID、receiver 类型和是否有流筛选。未产生数据流的 sink 也保留，规则命中不表示可被利用。 |
| `get_asg_node` | 读取一个 ASG 节点、相邻边、已解析源码证据与限定；控制存在不等于有效，静态候选不等于漏洞成立。 |
| `repo_map` | 返回不超过 2,000 字节的仓库定向图：主要模块、入口边界、sink 类别、文件未解析率和精确覆盖分母。 |

source 元数据、物理源码树和图谱是否就绪分别报告；`graph_not_ready` 不等于快照丢失。攻击面目录不以“是否已有数据流”过滤，失败时保留精确总数、页码和截断原因。先检查 source/analysis，再按 workflow_run_id 和 invocation_id 追踪实际错误。新 file-job 的已知错误码保留；历史调用没有保存的底层日志不会被补造。工具结果超过 32 KiB 返回可缩小查询的完整错误，不截断 JSON。配置值、凭据、宿主路径、任意日志、SQL 和 Shell 不在此工具面。对话保留模型请求与 MCP 结果的配对记录，仍不改变漏洞裁定。

工作台输入：回车发送，Ctrl+回车在光标/选区插入换行。输入法确认和长按回车不触发发送；同一发送过程有并发栅栏。

插件诊断使用当前执行 worker 的同一 Catalog 读取启用、完整性与实测策略，禁用立即体现在 executable 中。未绑定 worker 的目录查询只报告登记信息，不据此声称可执行。
