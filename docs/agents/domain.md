# Domain documentation

当前为单仓库领域文档布局，无单独CONTEXT.md/CONTEXT-MAP.md。

阅读与冲突处理：

1. AGENTS.md与用户当前明确指令控制安全、工作流和交付授权。
2. 产品模型与本轮架构：`docs/design/project-agent-architecture.md`、`docs/adr/0001-project-supervisor-interaction.md`。
3. Issue依赖/切片：`docs/design/interaction-issues.md`及GitHub最新正文/评论；接手顺序`docs/design/deepseek-handoff.md`。
4. 实现现状：`internal/`、`runtime/`、`contracts/v1/`、实际迁移/测试及`docs/architecture.md`、`docs/api.md`、`docs/agent-runtime.md`。
5. 新接口目标：`docs/design/interfaces/v1/11-project-supervisor.md`。设计状态不等于已实现API；旧契约不可静默改义。
6. 原型`web/src/prototype/`仅供交互参考，任何固定样例/计时状态不是真实执行。

术语：新项目一份源码一次审计；内部snapshot固定输入；AnalysisRun记录四阶段；主Agent session与run分开；audit/task、AuditPath、workflow_run、invocation、child_run有不同身份。工具事实、模型假设、验证裁定分层；候选/确认、优先级/严重度、阶段结束/覆盖完成互不替代。

历史P阶段和旧草案保留参考，不能据其重做已关闭Issue、恢复指令类型分类器、显式快照主流程或SQLite维护路线。
