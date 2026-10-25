# 黑盒程序传输协议

状态：候选规范，宿主尚未实现。阶段输入输出见 [stage-contracts.md](stage-contracts.md)，传输协议不能代替领域授权和产物 Schema。

## 1. file-job/v1：优先面向第三方二进制

清单固定 `runtime.kind=process`、`runtime.protocol=codexploit/file-job/v1`、包内相对 entrypoint。宿主以 argv 调用：

```text
<verified-entrypoint> --request <job-root>/job.json --response <job-root>/result.json
```

这些路径是宿主创建的临时运行路径，不写入清单或历史公开输出。宿主在 launch record 中保存可信 release/config/lease pin，不把租约令牌和秘密发送到工具。程序用结构化 JSON 读取请求。

目录：

```text
job-root/
  job.json          # 宿主只读写入，符合 file-job.schema.json 的 request
  inputs/           # 已核验输入；只读挂载
  work/             # 私有中间数据；不属于对外标准
  outputs/          # 最终输出暂存；受配额约束
  result.json       # 程序先写临时文件再原子 rename
```

数据路径相对 job-root，result.outputs[].path 相对请求的 output_directory。宿主根据绑定输入决定 tar 解包、目录挂载或文件读取；只给工具已声明端口，不提供任意本机目录。工具内部需要解包时，适配器必须遵守相同路径/链接/预算限制。

运行前 result.json 和 outputs 必须不存在；可先创建空 outputs 目录。子进程工作目录为 work，工具安装目录只读，用户 config 不能改变 entrypoint 或注入 shell。第三方正常 stdout/stderr 作为有界诊断捕获，不能当作控制协议。

生命周期：

1. 宿主核验包与输入，配置有效权限并启动适配器；无法强制所需权限则 unsupported。
2. 适配器可调用固定 CLI、脚本或库。原始输出由适配器转换到 declared outputs；不规定中间处理方式。
3. 适配器写输出，再写 result；result 的 status 必须是终态。
4. 退出码 0 + SUCCEEDED/PARTIAL 仅表示可开始验证；宿主验证全部 required 端口、摘要、Schema、Scope、引用和租约后提交终态。PARTIAL 需固定计划允许。
5. 非零退出、非法/缺失 result、取消或超时不发布标准产物；有限诊断可单独记入运行。插件自报 SUCCEEDED 不能覆盖非零退出。
6. 超时/取消由宿主停止整个进程树/作业并等待回收，撤销提交权。单纯 kill 父进程不能证明 JVM/分析器子进程已停止；所选 backend 必须说明其真实能力。

`Check` 由宿主 package driver 对固定版本执行受限探测；file-job 标准不要求每个第三方程序都有 --check。适配器可以提供独立 probe entrypoint，但该程序也必须在包内、参与摘要，不运行目标代码。

## 2. process-plugin/v2：原生双向流式协议

清单固定 `runtime.protocol=codexploit/process-plugin/v2`。JSON-RPC 2.0、UTF-8 NDJSON，每行一个完整 JSON；stdout 只传协议，stderr 为有界日志。请求 ID 为非空字符串，通知不含 id。

### 方法

| 方法 | 方向 | 参数与结果 |
|---|---|---|
| plugin.initialize | host→adapter | protocol、plugin ID/version、package/manifest digest、operation、port contracts、message/chunk/budget limits；返回完全匹配身份、operation、支持的端口和协议 |
| plugin.execute | host→adapter | invocation、operation、Scope、输入 ArtifactRef、config、budget；返回 accepted、invocation_id |
| plugin.status | host→adapter | invocation_id；返回状态、coverage、limitations、有限错误；不能凭此消息把未经验证的输出标成功 |
| plugin.cancel | host→adapter | invocation_id、reason；返回 accepted。最终取消由宿主栅栏决定 |
| plugin.event | adapter→host 通知 | invocation_id、seq（从 1 连续）、type、有限 message；宿主持久化后才能对外显示 |
| host.artifacts.read | adapter→host | invocation_id、input_port、artifact_id、offset、length；仅返回该调用输入的有界 base64 数据、eof、total |
| host.artifacts.begin | adapter→host | invocation_id、output_port、kind、schema_id、expected_bytes、expected_sha256；返回仅当前调用可用的 staging_id |
| host.artifacts.write | adapter→host | staging_id、index、base64 data；返回 accepted index；从 0 连续、不得重复/跳号 |
| host.artifacts.finish | adapter→host | staging_id；宿主检查长度/摘要并封存，返回 staged=true，不代表已发布 |
| host.artifacts.abort | adapter→host | staging_id；撤销暂存，重复请求幂等 |

initialize 不通过就不能 execute。握手不允许协议自动降级；平台未知、契约不匹配、缺少所需权限时明确 unsupported。多个 output_port 共享总预算，每个产物有独立 staging_id 和序号。

execute 接受后，adapter 持续处理 host 的 status/cancel 和读写结果，不能用一个同步全局锁等内部工具结束导致 cancel 永远无法响应。适配器可以在内部启动一次 file-job 来完成工作。

宿主确认所有 required 输出都 finish、status 为 SUCCEEDED/PARTIAL，且全部验证通过后，在同一事务提交调用状态与 ArtifactRef。重复 publish 由 invocation+请求摘要幂等；cancel/lease_lost 后任何 finish 或 status 成功都无权提交。

### 示例：只读取绑定的输入

```json
{"jsonrpc":"2.0","id":"read-1","method":"host.artifacts.read","params":{"invocation_id":"example-1","input_port":"source","artifact_id":"example-source-archive","offset":0,"length":4096}}
```

宿主只有在 invocation 的 source 端口绑定了 example-source-archive 时才能响应；任意同 Scope 但未绑定的产物也不能读取。真实摘要计算样例见 templates/fixtures 与 file-job 样例。

单条控制消息默认 1 MiB，单次数据块默认 256 KiB；base64 解码前后都检查限额。解析错误、未知方法、未知 staging_id、越界读取、跳号、超限进入失败路径，不忽略后继续宣称成功。调用级总产物预算由宿主下发，不固定为 scanner 单报告 16 MiB。

## 3. 领域端口

Agent runtime、环境 provider、验证 executor 使用各自调用协议。manifest.runtime.protocol 表示适配器协议，例如 codexploit/agent-runtime/v1；端口 schema_id 表示领域数据格式，例如 codexploit/agent-task/v1。二者不能互换。

它们可以共享包安装、Check、摘要核验与节点 readiness；但必须经领域宿主验证输入 Schema、审批/授权、预算和租约，再启动实际后端。不能因为普通 process 插件声明了 verification.evidence 就拥有目标执行权限。

source 供应也通过宿主的固定来源定义和快照事务接入；捕获与发布不直接开放给任意二进制数据库写入。

## 4. 当前 v1 兼容边界

现有 NDJSON v1 只有单份 scanner 原始报告、alerts 能力和固定限额。v2 的 operation、多输出及 staging 方法不在 v1 中。安装状态和协议兼容目录必须明确区分；缺少驱动时保持“已登记/不可执行”，不能把 v2 清单发给 v1 并返回假成功。
