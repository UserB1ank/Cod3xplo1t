# 插件开发模板

生产运行方式、打包工具、SDK 与安装步骤见 [开发手册](../../../plugins-v2.md)。阶段清单可在 v2 API 登记；领域阶段声明不会安装普通进程执行器。Joern 原生采集 recipe 不含发行二进制或 CPG 标准化算法。

# 分阶段插件开发模板

状态：候选 v2 SDK 素材，不能直接安装到当前宿主。当前 process v1 仍是 scanner-only 协议；本目录没有修改它。

## 从哪里开始

1. 从 `manifests/` 复制对应阶段清单；一个工具跨阶段时，在同一包内增加多个 operation。
2. 按 `stages.json` 固定输入输出；实现 `adapter.go.tmpl` 中的 StageHandler，或用任意语言实现等价协议。`report.json` 选择 file-job/v1，其余普通工具模板选择 process-plugin/v2；它们是同一阶段契约的两种传输，不可混发消息。
3. 已有 CLI 工具放在 `vendor/`，adapter 以 argv 数组调用。无需改第三方源码；normalizer 负责把结果转换为标准产物。
4. 使用独占 job 目录接收 `file-job.request.json`，写入 `file-job.result.json`。输入/输出路径都相对 job 根，宿主提供输入只读挂载；result 只允许输出根内路径。示例摘要由 fixtures 实际字节计算，但没有实际执行工具。
5. 正式打包时生成 files.lock.json 和可信 release 摘要，再进行安装/依赖/契约实测。模板不填伪造摘要，也不提供自动下载安装脚本。

建议工具包布局：

```text
package/
  manifest.json
  files.lock.json          # 打包器生成，不纳入自己的文件列表
  bin/adapter              # adapter 编译产物；Windows 对应 .exe
  vendor/                  # 完整第三方发行包、库、JAR 或本地程序
  queries/                 # 固定查询脚本
  normalizers/             # 输出转换器
  fixtures/                # 无秘密的契约样例
```

本目录逐阶段 manifest 是标准 profile，bin/adapter 尚未提供，必须保持未安装/未实测。Go 文件为可编译接口定义，具体阶段算法由开发者实现，没有伪造成功实现。`joern.recipe.json` 指向已实现的 Joern 多语言 parse / taint / paths 标准适配器及工作流。

## 层级目录

| 文件 | 输入输出的详细语义 |
|---|---|
| source.json | source.request → 固定源码 |
| parse.json | 固定源码 → 代码事实 |
| semantic.json | 源码 + 代码事实 → 安全事实 |
| scan.json | 源码 → 规则告警 |
| path.generate.json | 代码事实 + 安全事实 → 候选路径 |
| path.enhance.json | 候选路径 → 保留路径 + 筛选记录 |
| agent.json | 义务任务 → 逐义务答案；Agent 领域协议 |
| environment.json | 授权环境要求 → 实际环境回执；provider 领域协议 |
| verification.json | 授权计划 + 环境回执 → 验证证据；executor 领域协议 |
| report.json | 固定报告输入 → 报告 |

`manifest.schema.json` 校验候选清单结构，`file-job.schema.json` 校验本地调用/返回，`files.lock.schema.json` 校验文件摘要列表结构。`stages.json` 指定标准 profile 的必需端口；产物本体的正式 JSON Schema 和引用校验仍须按方案实施后登记，当前模板不冒充完整生产 SDK。

## 本地检查

```sh
python3 docs/design/plugin-system-v2/templates/validate.py
```

检查 JSON、阶段/端口一致性、样例文件摘要、Joern recipe、模板路径及文档链接。可另外用 Draft 2020-12 验证器核验 manifest.schema.json。不会执行第三方程序、安装包、访问数据库或调用生产服务。
