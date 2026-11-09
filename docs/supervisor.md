# 项目主 Agent 会话（#66）

主 Agent 是项目级会话，不是路径审查任务：它有独立的 `session_id` / `run_id`，不构造 `AuditPath`，也不复用路径 TaskBuilder。正式页面“项目助手”接受自由文本，没有 intent / action_type 枚举；模型可以零工具直接回答、先澄清，或调用只读 MCP 工具。

## 会话与消息

| 路由 | 行为 |
|---|---|
| `GET /api/v1/projects/{projectID}/agent-sessions` | 最近会话、`available` 与不可用原因 |
| `POST .../agent-sessions` | 显式创建新的项目会话（绑定当前 ready 快照）；`reuse_existing=true` 时返回已有首会话，供页面首次自动引导使用 |
| `GET .../agent-sessions/{sessionID}` | 消息、运行、有序事件和固定 pin |
| `GET .../messages?after_seq=&limit=` | 有界消息历史 |
| `POST .../messages` | writer；开放文本 + `client_message_id`，返回 `202` 和 RUNNING run |
| `GET .../events?after_seq=` | 有序事件与 `next_seq` |
| `GET .../runs/{runID}` / `POST .../cancel` | 单个主 Agent run 的真实状态与停止 |

`client_message_id` 相同的发送幂等返回已记录的消息/run；同一会话只允许一个 RUNNING turn。消息、run、事件和固定 pin 保存在 `supervisor_sessions` 文档（SQLite `0038` / PostgreSQL `0020`），文档提交后才可见。会话快照由项目输入绑定，模型参数不能更换项目或 snapshot；工具调用时宿主强制注入绑定 snapshot。

每个 `POST` 默认产生新的 `session_id`，因此主 Agent 工作台和图谱页都可以手动新建会话。列表、详情、消息、运行和取消全部以路径中的 `projectID` 为作用域；同一项目可有多条互不覆盖的会话，不同项目不能互相列举或读取会话。图谱页将主 Agent 对话放在图谱右侧，在窄屏下自动移到图谱内容下方。

## MCP 工具

主 Agent 通过真实 MCP SDK 连接与 stdio 相同的 `internal/mcp` 九只只读工具：`tools/list` 列出工具，`tools/call` 执行。领域查询仍在 Go 服务中，没有在 adapter/TypeScript 重写。宿主从 advertised schema 中去掉 `snapshot_id` 并在调用前注入，所以模型不能自选快照。工具结果按 call id 配对；错误作为 `{ok:false,error}` 回灌，不伪造成功。

当前项目助手运行时为 `llm`（复用应用内模型设置），记录 model / config version / prompt version / tool schema digest / tokens。模型未配置时 API 返回 `agent_unavailable`，页面显示原因，不回退 ScriptedRuntime。Pi 的路径 Agent 与项目会话是不同运行身份；Pi 主会话适配属于后续切片。

## 边界

- 不保存隐藏推理或秘密；只保存公开答复、工具调用参数、工具结果和事件。
- 聊天文字不是路径审查的结构化结论；路径子 Agent 的 schema 2 义务校验不变。
- 工具全部只读；新写能力在 UX05/UX06 单独交付。
- 项目、身份、允许工具和预算由宿主绑定；跨项目会话/路径返回 404，reader 写请求返回 403。
