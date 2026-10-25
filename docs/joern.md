# Joern 二进制插件

`codexploit.joern@2.1.1` 提供四个标准操作：`parse`（代码解析）、`taint`（安全语义 / 污点查询）、`paths`（候选路径）、`enhance`（筛选与排序）。完整发行包作为黑盒进程接入，宿主登记版本、平台、包 / 清单摘要、完整文件锁和层级端口；适配器负责调用 Joern，宿主校验固定输入、预算、输出和来源后原子发布。

| 组件 | 固定版本 |
| --- | --- |
| Joern | 4.0.664，完整发行包的 14 个前端 |
| Eclipse Temurin JDK | 21.0.9+10 |
| PHP CLI | 8.5.12，锁定官方源码构建，供 PHP AST 解析器使用 |
| Rust compiler / Cargo / std | 1.95.0，锁定官方二进制，供 Rust 项目元数据和语法解析使用 |
| Ghidra ARM64 原生补充 | 发行 JAR 对应提交 744c5dee92，Linux ARM64 缺少的 decompiler 由固定源码构建 |
| 适配器 / 查询 | 2.1.1 / 2.0.1 |
| 传输 | `codexploit/file-job/v2`，包含宿主绑定的输入 ArtifactRef ID |

[sources.lock.json](../plugins/joern/sources.lock.json) 固定四个平台的下载 URL、大小和 SHA-256。`files.lock.json` 覆盖完整依赖、适配器、查询和规则。每次构建的 Build ID 为包摘要，同版本重建不覆盖旧构建，计划继续绑定准确摘要。仓库保存构建配方与源码，发行物保存在构建目录。已登记的旧 1.0.x Go 版本及其历史产物保留，不修改旧清单。

## 语言前端

[frontends.json](../plugins/joern/frontends.json) 登记该固定发行包实际提供的全部前端，不按扩展名最多的语言丢弃其他输入。

| 配置 `frontend` | 输入 |
| --- | --- |
| `C` | C / C++ |
| `CSHARPSRC` | C# |
| `GOLANG` | Go |
| `JAVASRC` | Java 源码 |
| `JAVA` | Java 字节码：class / jar / war / ear / apk |
| `JAVASCRIPT` | JavaScript / TypeScript，包括 JSX / TSX |
| `KOTLIN` | Kotlin |
| `PHP` | PHP |
| `PYTHONSRC` | Python |
| `RUBYSRC` | Ruby |
| `RUST` | Rust Cargo 项目 |
| `SWIFTSRC` | Swift |
| `ABAP` | ABAP，遵循上游对象命名，例如 `ztest.prog.abap` |
| `GHIDRA` | Ghidra 可识别的原生二进制，必须显式设置 `input_path` |

工作流编译的混合语言声明使用 `Mixed`。`AUTO`（默认）按冻结文件扩展名运行全部匹配的源码 / 字节码前端，每个生成一个 CPG；Ghidra 必须显式选择。Rust 需要有效 Cargo.toml，依赖必须能离线解析。上游旧别名 NEWC / JSSRC / PYTHON 在适配器内兼容映射；未随本发行包提供的前端不宣称可用。上游 [前端文档](https://docs.joern.io/frontends/) 说明了各前端的职责，具体可用项以封存发行包和本清单为准。

## 安装和部署

默认 `make run` 已直接包含 Joern；项目一键入口的固定链路、状态机及整体替换边界见 [项目主图谱引擎](analysis-engine.md)。以下本机打包和覆盖文件用于额外 worker 或显式替换发行物。

本机打包需要 Go、Python 3.11+、C 编译器、make、pkg-config。Joern / JDK / Rust 归档校验后直接提取，PHP 从锁定源码构建；不运行 Joern 或 Rust 安装器。Linux ARM64 包按 [ghidra.lock.json](../plugins/joern/ghidra.lock.json) 编译发行 JAR 对应提交的 Ghidra decompiler，补入上游未附带的 native resource；修改后的 JAR 与许可同样计入全文件摘要。归档路径和预算在解包前核对，包内不保留链接，保留上游许可。

```sh
make package-joern
# bin/plugin-packages/codexploit.joern@2.1.1；stdout 为 Release JSON
make package-joern-linux
# bin/joern-linux/codexploit.joern@2.1.1；面向 Docker 原生架构
```

支持 macOS / Linux 的 arm64 / amd64 构建配方；每个 worker 的实测状态单独登记。缓存损坏直接失败，已有输出目录拒绝覆盖。完整包约 3 GiB，宿主允许的封存包上限为 4 GiB / 64,000 文件。

把包放入 `--plugin-packages` 目录，或通过认证 API 依次登记清单、release、安装：

1. `POST /api/v2/plugins`，包含 manifest、package_digest 和来源。
2. `POST /api/v2/plugins/codexploit.joern/versions/2.1.1/releases`，提交打包生成的 Release。
3. `POST /api/v2/plugin-installations`，提交同一 Release。

插件中心展示语言、四个操作、上游版本、平台摘要与安装状态。安装不代表所有语言已实测；调用失败保留真实状态。

```sh
CODEXPLOIT_JOERN_PACKAGE_DIR="$PWD/bin/joern-linux/codexploit.joern@2.1.1" \
  docker compose -f compose.yaml -f compose.joern.yaml up -d
```

Linux 的 Rust 原生前端要求 glibc 2.39+；覆盖文件使用 Debian Trixie 运行镜像，并提供 8 GiB 可执行临时空间。每次调用会复制、校验整个包；并发调用需按包大小和工作文件增加空间。`heap_mib` 默认 1024，可设 256–4096；每个 JVM 顺序使用该上限。普通进程驱动不提供内核沙箱，网络和物理资源强隔离仍由部署环境实施。

## 四阶段接口

| 操作 / 层级 | 必需输入端口 | 输出 |
| --- | --- | --- |
| `parse` / parse | `source`: source.snapshot / source-tar/v1 | `cpg` 多份 tool.native / joern/cpg/v1；`code` code.facts / code-facts/v2 |
| `taint` / semantic | `source`；`code`；`cpg` 多份 | `flows` tool.native / native-bytes/v1；`security` security.facts / security-facts/v2 |
| `paths` / path.generate | `code`；`security`；`flows` | `paths` discovery.paths / discovery-paths/v2 |
| `enhance` / path.enhance | `paths` | 保留的 `paths`；`selection` path.enhancement / path-enhancement/v2 |

Schema ID 均带 `codexploit/` 前缀，CPG 除外。源码必须为冻结 tar。建议解析超时 900 秒、输出文件上限至少 15、输出预算至少 64 MiB，实际大型 CPG 需增加预算。语义操作接收对应解析调用的全部 CPG 和代码产物；不凭文件名选择其他快照产物。

解析参数示例：

```json
{"frontend":"AUTO","heap_mib":1024}
```

源码采集默认可能排除二进制。JAVA / GHIDRA 输入必须先通过 `limits.allow_binary` 保留在冻结快照中；被采集策略排除的文件无法由插件恢复，应先检查排除记录。

二进制示例：`{"frontend":"GHIDRA","input_path":"bin/example"}`。字节码和反汇编地址不冒充源码行号，标准位置为 null，原生信息保留在 CPG。

## 污点规则与结果

`taint` 实际运行 Joern OSS data-flow overlay 和 [reachableByFlows](https://docs.joern.io/cpgql/data-flow-steps/)，保留 source → 局部传播 → sink 参数的原生节点轨迹。`max_call_depth` 默认 4（1–10），`max_flows` 默认 100（1–1000）；超出流程、选择节点、轨迹或输出预算会失败，不发布半份报告。

可用包内固定 [rules.json](../plugins/joern/rules.json)，也可提交规则：

```json
{
  "rules": [{
    "id": "example.parameter-to-sink",
    "source": {"kind":"parameter","method":"entry","index":1},
    "sink": {"method":"sink","argument_index":1}
  }],
  "max_flows": 100,
  "max_call_depth": 4
}
```

`method` 正则匹配方法名或完整方法名。source 支持 `parameter`（index 0 表示全部非接收者参数）和 `call_return`（另可用 code_pattern 限定调用代码）；sink 为指定调用的 argument_index（1 起）。最多 32 条规则，正则长度最多 512。规则规范化后摘要写入报告和标准安全事实，规则 ID 保留在入口 / sink 分类中。

原始报告记录匹配 source / sink 数量、规则、CPG / code ArtifactRef、每条实际数据流节点、方法原生 ID、位置与有界代码片段。标准 security.facts 生成 inferred 入口、规则选定 sink、observed 静态 taint_flow 关系；候选路径以 data_flow 为依据，保留完整原始报告引用，绑定准确 code / security 产物。中途变换的、跨输入的或规则摘要不一致的报告会被拒绝。

静态数据流是候选，来源可控性、sanitizer 有效性和运行时可利用性仍未裁定。默认将全部函数参数作为潜在入口会产生较宽结果，应按语言框架配置规则。各语言 CPG 分别查询，不推断跨语言桥接；零条路径也不证明安全。文件诊断、外部依赖和动态分派仍有限，因此四个操作显式返回 PARTIAL。

## 工作流与验收

完整模板见 [workflow.json](../plugins/joern/workflow.json)：`parse → taint → paths → enhance → $publish`。工作流编译器按 Schema 和端口绑定，`cpg` 支持多产物；创建任务时显式设置 `accept_partial_nodes: ["parse","taint","paths","enhance","$publish"]`，按需设置 `analyze_candidates: false`。

源码分析不执行目标 build / test / hook：Java 禁用 delombok，Rust 禁用 proc-macro / build-script 展开和依赖联网，并在私有副本中移除可注入执行包装器的 Cargo 配置。Rust / Java / Kotlin 等没有离线依赖时会失败或报告覆盖局限，不伪造完整类型解析。

```sh
JOERN_TEST_PACKAGE="$PWD/bin/plugin-packages/codexploit.joern@2.1.1" make test-joern
```

真实二进制回归包含 Go、C / JS / Python 混合解析，三种语言的污点 / 常量对照、固定路径来源和错误输入拒绝。未提供包时明确跳过真实工具用例。完整语言前端验收与运行环境记录见 [校验记录](design/plugin-system-v2/validation.md)。
