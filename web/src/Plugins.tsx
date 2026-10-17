import { useEffect, useState } from "react";
import { Box, Play, Plus, RefreshCw } from "lucide-react";
import { ApiClient } from "./api";
import { Badge, EmptyState, Hint, Modal, Panel } from "./components";
import type { Snapshot } from "./types";
import { latestSnapshot } from "./workbench";
import type { ArtifactRef } from "./Artifacts";

interface PluginRecord {
  manifest: {
    api_version: string;
    id: string;
    version: string;
    name: string;
    description: string;
    kind: string;
    languages: string[];
    runtime: { kind: string };
    consumes: string[];
    produces: string[];
    config_schema: object;
    permissions: { network: string; source_write: boolean };
  };
  package_digest: string;
  manifest_digest: string;
  source: string;
  executable: boolean;
  reason?: string;
}
interface Invocation {
  invocation_id: string;
  status: string;
  version: number;
  error_code?: string;
  config_digest: string;
  request: {
    plugin_id: string;
    plugin_version: string;
    package_digest: string;
    scope: ArtifactRef["scope"];
    inputs: ArtifactRef[];
    config: object;
    budget: object;
  };
  outputs: ArtifactRef[];
  coverage: {
    input_files: number;
    parsed_files: number;
    partial_files: number;
    unparsed_files: number;
    unhandled_files: number;
    descriptor_files: number;
    input_bytes: number;
  };
  limitations: string[];
  created_at: string;
}
const terminal = (state: string) =>
  [
    "SUCCEEDED",
    "PARTIAL",
    "FAILED",
    "CANCELLED",
    "TIMED_OUT",
    "UNSUPPORTED",
  ].includes(state);
const labels: Record<string, string> = {
  CREATED: "等待执行",
  RUNNING: "解析中",
  SUCCEEDED: "已完成",
  PARTIAL: "部分覆盖",
  FAILED: "失败",
  CANCELLED: "已取消",
  TIMED_OUT: "超时",
  UNSUPPORTED: "不支持此输入",
};
const errorText = (error: unknown) =>
  error instanceof Error ? error.message : "插件操作失败";

export function Plugins({
  api,
  projectID,
  snapshots,
  canWrite,
  canRegister,
  revision,
  onArtifacts,
}: {
  api: ApiClient;
  projectID: string;
  snapshots: Snapshot[];
  canWrite: boolean;
  canRegister: boolean;
  revision: number;
  onArtifacts: (snapshot: string) => void;
}) {
  const [catalog, setCatalog] = useState<PluginRecord[]>([]);
  const [catalogCursor, setCatalogCursor] = useState([""]);
  const [nextCatalog, setNextCatalog] = useState("");
  const [selected, setSelected] = useState("");
  const [snapshot, setSnapshot] = useState(
    latestSnapshot(snapshots)?.snapshot_id || "",
  );
  const [input, setInput] = useState<ArtifactRef>();
  const [inputLoading, setInputLoading] = useState(false);
  const [config, setConfig] = useState("{}");
  const [maxFiles, setMaxFiles] = useState(2000);
  const [timeout, setTimeout] = useState(60);
  const [catalogTick, updateCatalog] = useState(0);
  const [runTick, updateRuns] = useState(0);
  const [runs, setRuns] = useState<Invocation[]>([]);
  const [runCursors, setRunCursors] = useState([""]);
  const [nextRun, setNextRun] = useState("");
  const [selectedRun, setSelectedRun] = useState("");
  const [detail, setDetail] = useState<Invocation>();
  const [etag, setETag] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [importing, setImporting] = useState(false);
  const [manifest, setManifest] = useState("");
  const [packageDigest, setPackageDigest] = useState("");
  const [source, setSource] = useState("manual import");
  const chosen =
    catalog.find(
      (p) => `${p.manifest.id}@${p.manifest.version}` === selected,
    ) || catalog[0];
  const prefix = `/v1/projects/${encodeURIComponent(projectID)}/snapshots/${encodeURIComponent(snapshot)}`;
  const cursor = catalogCursor[catalogCursor.length - 1];
  const runCursor = runCursors[runCursors.length - 1];
  useEffect(() => {
    if (!snapshot && snapshots.length)
      setSnapshot(latestSnapshot(snapshots)!.snapshot_id);
  }, [snapshot, snapshots]);
  useEffect(() => {
    const controller = new AbortController();
    api
      .get<{ plugins: PluginRecord[]; next_cursor: string }>(
        `/v1/plugins?limit=50&cursor=${encodeURIComponent(cursor)}`,
        controller.signal,
      )
      .then((page) => {
        setCatalog(page.plugins);
        setNextCatalog(page.next_cursor);
      })
      .catch((error) => {
        if (!controller.signal.aborted) setError(errorText(error));
      });
    return () => controller.abort();
  }, [api, cursor, catalogTick, revision]);
  useEffect(() => {
    setInput(undefined);
    setDetail(undefined);
    setSelectedRun("");
    setRuns([]);
    setRunCursors([""]);
    setError("");
    if (!snapshot) return;
    const controller = new AbortController();
    setInputLoading(true);
    (async () => {
      let cursor = "";
      for (let pages = 0; pages < 20; pages++) {
        const page = await api.get<{
          artifacts: ArtifactRef[];
          next_cursor: string;
        }>(
          `${prefix}/artifacts?limit=100&cursor=${encodeURIComponent(cursor)}`,
          controller.signal,
        );
        const archive = page.artifacts.find(
          (ref) =>
            ref.schema_id === "codexploit/source-tar/v1" &&
            ref.kind === "source.snapshot",
        );
        if (archive) {
          setInput(archive);
          return;
        }
        if (!page.next_cursor) return;
        cursor = page.next_cursor;
      }
      throw new Error(
        "已检查 2000 个产物，仍未找到源码归档，请到产物页面核对。",
      );
    })()
      .catch((error) => {
        if (!controller.signal.aborted) setError(errorText(error));
      })
      .finally(() => {
        if (!controller.signal.aborted) setInputLoading(false);
      });
    return () => controller.abort();
  }, [api, prefix, snapshot, revision]);
  useEffect(() => {
    if (!snapshot) return;
    const controller = new AbortController();
    api
      .get<{ invocations: Invocation[]; next_cursor: string }>(
        `${prefix}/plugin-invocations?limit=50&cursor=${encodeURIComponent(runCursor)}`,
        controller.signal,
      )
      .then((page) => {
        setRuns(page.invocations);
        setNextRun(page.next_cursor);
      })
      .catch((error) => {
        if (!controller.signal.aborted) setError(errorText(error));
      });
    return () => controller.abort();
  }, [api, prefix, snapshot, runCursor, runTick, revision]);
  useEffect(() => {
    if (!selectedRun) return;
    const controller = new AbortController();
    api
      .response(
        `${prefix}/plugin-invocations/${encodeURIComponent(selectedRun)}`,
        { signal: controller.signal },
      )
      .then(async (response) => {
        const body = (await response.json()) as { invocation: Invocation };
        setDetail(body.invocation);
        setETag(response.headers.get("ETag") || "");
      })
      .catch((error) => {
        if (!controller.signal.aborted) setError(errorText(error));
      });
    return () => controller.abort();
  }, [api, prefix, selectedRun, runTick]);
  useEffect(() => {
    if (
      !runs.some((run) => !terminal(run.status)) &&
      (!detail || terminal(detail.status))
    )
      return;
    const timer = setInterval(() => {
      if (!document.hidden) updateRuns((n) => n + 1);
    }, 2000);
    return () => clearInterval(timer);
  }, [runs, detail]);
  const work = async (label: string, action: () => Promise<void>) => {
    if (busy) return;
    setBusy(label);
    setError("");
    setNotice("");
    try {
      await action();
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy("");
    }
  };
  return (
    <>
      {error && (
        <div className="error-message" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="success-message" role="status">
          {notice}
        </div>
      )}
      <Panel
        title="插件目录"
        action={
          <div className="heading-actions">
            <button
              className="button secondary"
              onClick={() => updateCatalog((n) => n + 1)}
              disabled={!!busy}
            >
              <RefreshCw size={14} />
              刷新
            </button>
            <button
              className="button secondary"
              disabled={!canRegister || !!busy}
              onClick={() => {
                setError("");
                setImporting(true);
              }}
            >
              <Plus size={14} />
              导入清单
            </button>
          </div>
        }
      >
        <Hint>
          插件目录在工作区共享。执行限定当前项目和固定快照，外部清单只有安装并配置执行器后才可运行。
        </Hint>
        {catalog.length ? (
          <div className="table-scroll">
            <table className="standard-table">
              <thead>
                <tr>
                  <th>插件 / 版本</th>
                  <th>能力</th>
                  <th>运行方式 / 可用性</th>
                  <th>包摘要</th>
                </tr>
              </thead>
              <tbody>
                {catalog.map((p) => (
                  <tr key={`${p.manifest.id}@${p.manifest.version}`}>
                    <td>
                      <button
                        className="table-title"
                        aria-pressed={chosen === p}
                        onClick={() => {
                          setSelected(`${p.manifest.id}@${p.manifest.version}`);
                          setConfig("{}");
                        }}
                      >
                        {p.manifest.name}
                      </button>
                      <p className="mono">
                        {p.manifest.id} @{p.manifest.version}
                      </p>
                    </td>
                    <td>
                      {p.manifest.languages.join(" / ")} · {p.manifest.kind}
                      <p>{p.manifest.produces.join(", ")}</p>
                    </td>
                    <td>
                      {p.manifest.runtime.kind}
                      <p>
                        {p.executable
                          ? "已安装 · 可执行"
                          : "仅登记 · 未安装执行器"}
                      </p>
                    </td>
                    <td>
                      <code className="plugin-digest">{p.package_digest}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="插件目录暂无数据">
            刷新后重试，查询失败不会显示示例插件。
          </EmptyState>
        )}
        <div className="pager">
          <span>第 {catalogCursor.length} 页</span>
          <button
            disabled={catalogCursor.length < 2}
            onClick={() => setCatalogCursor((v) => v.slice(0, -1))}
          >
            上一页
          </button>
          <button
            disabled={!nextCatalog}
            onClick={() => setCatalogCursor((v) => [...v, nextCatalog])}
          >
            下一页
          </button>
        </div>
      </Panel>
      <Panel title="执行固定版本解析">
        <div className="plugin-run-form">
          <label>
            代码快照
            <select
              aria-label="插件输入快照"
              disabled={!!busy}
              value={snapshot}
              onChange={(event) => setSnapshot(event.target.value)}
            >
              {snapshots.map((s) => (
                <option key={s.snapshot_id} value={s.snapshot_id}>
                  {s.snapshot_id} · {s.commit.slice(0, 12)}
                </option>
              ))}
            </select>
          </label>
          <label>
            插件版本
            <select
              aria-label="执行插件版本"
              value={
                chosen ? `${chosen.manifest.id}@${chosen.manifest.version}` : ""
              }
              onChange={(event) => {
                setSelected(event.target.value);
                setConfig("{}");
              }}
            >
              {catalog.map((p) => (
                <option
                  key={`${p.manifest.id}@${p.manifest.version}`}
                  value={`${p.manifest.id}@${p.manifest.version}`}
                >
                  {p.manifest.id} @{p.manifest.version}
                  {p.executable ? "" : " · 不可执行"}
                </option>
              ))}
            </select>
          </label>
          <label>
            参数 JSON
            <textarea
              aria-label="插件参数 JSON"
              value={config}
              onChange={(event) => setConfig(event.target.value)}
              rows={3}
              spellCheck={false}
            />
          </label>
          <label>
            最多输入文件
            <input
              aria-label="插件文件预算"
              type="number"
              min={1}
              max={20000}
              value={maxFiles}
              onChange={(event) => setMaxFiles(event.target.valueAsNumber)}
            />
          </label>
          <label>
            超时（秒）
            <input
              aria-label="插件超时秒数"
              type="number"
              min={1}
              max={120}
              value={timeout}
              onChange={(event) => setTimeout(event.target.valueAsNumber)}
            />
          </label>
        </div>
        {chosen && (
          <details className="source-description">
            <summary>参数 Schema 与权限</summary>
            <pre className="artifact-preview">
              {JSON.stringify(chosen.manifest.config_schema, null, 2)}
            </pre>
            <p>网络：{chosen.manifest.permissions.network} · 源码写入：禁止</p>
          </details>
        )}
        <p className="source-description mono">
          {inputLoading
            ? "正在读取输入引用…"
            : input
              ? `输入：${input.id} · ${input.bytes.toLocaleString()} bytes · SHA-256 ${input.sha256}`
              : "此快照尚无源码归档，请先到产物与证据页面登记。"}
        </p>
        <div className="form-footer">
          <button
            className="button secondary"
            disabled={!snapshot}
            onClick={() => onArtifacts(snapshot)}
          >
            查看输入产物
          </button>
          <button
            className="button primary"
            disabled={
              !canWrite ||
              !!busy ||
              !chosen?.executable ||
              !input ||
              !Number.isInteger(maxFiles) ||
              maxFiles < 1 ||
              maxFiles > 20000 ||
              !Number.isInteger(timeout) ||
              timeout < 1 ||
              timeout > 120
            }
            onClick={() =>
              work("开始解析", async () => {
                const parsed = JSON.parse(config);
                const result = await api.post<{ invocation: Invocation }>(
                  `${prefix}/plugin-invocations`,
                  {
                    api_version: "codexploit/v1",
                    invocation_id: `inv-${crypto.randomUUID()}`,
                    plugin_id: chosen!.manifest.id,
                    plugin_version: chosen!.manifest.version,
                    package_digest: chosen!.package_digest,
                    scope: input!.scope,
                    inputs: [input],
                    config: parsed,
                    budget: { max_files: maxFiles, timeout_seconds: timeout },
                  },
                );
                setSelectedRun(result.invocation.invocation_id);
                setDetail(result.invocation);
                updateRuns((n) => n + 1);
                setNotice("解析调用已创建，输入与插件版本已固定。");
              })
            }
          >
            <Play size={14} />
            {busy || "开始解析"}
          </button>
        </div>
        <Hint>
          内置解析读取源码归档并生成 AST
          和代码事实。未解析、语法错误和其他语言分别计入覆盖范围，不会自动产生已确认漏洞。
        </Hint>
      </Panel>
      <Panel
        title="执行记录"
        action={
          <button
            className="button secondary"
            onClick={() => updateRuns((n) => n + 1)}
          >
            <RefreshCw size={14} />
            刷新记录
          </button>
        }
      >
        {runs.length ? (
          <div className="table-scroll">
            <table className="standard-table">
              <thead>
                <tr>
                  <th>调用 / 版本</th>
                  <th>状态</th>
                  <th>Go 完整 / 部分 / 未解析</th>
                  <th>其他输入</th>
                  <th>产物</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.invocation_id}>
                    <td>
                      <button
                        className="table-title mono"
                        onClick={() => setSelectedRun(run.invocation_id)}
                      >
                        {run.invocation_id}
                      </button>
                      <p>
                        {run.request.plugin_id} @{run.request.plugin_version}
                      </p>
                    </td>
                    <td>
                      <Badge status={run.status} label={labels[run.status]} />
                    </td>
                    <td>
                      {run.coverage.parsed_files} / {run.coverage.partial_files}{" "}
                      / {run.coverage.unparsed_files}
                    </td>
                    <td>{run.coverage.unhandled_files}</td>
                    <td>{run.outputs.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="还没有解析调用">
            选择已安装插件与快照后开始解析。
          </EmptyState>
        )}
        <div className="pager">
          <span>第 {runCursors.length} 页</span>
          <button
            disabled={runCursors.length < 2}
            onClick={() => setRunCursors((v) => v.slice(0, -1))}
          >
            上一页
          </button>
          <button
            disabled={!nextRun}
            onClick={() => setRunCursors((v) => [...v, nextRun])}
          >
            下一页
          </button>
        </div>
      </Panel>
      {detail && (
        <Panel
          title={`调用详情 · ${detail.invocation_id}`}
          action={
            <button
              className="button secondary"
              disabled={!canWrite || !!busy || terminal(detail.status) || !etag}
              onClick={() =>
                work("取消调用", async () => {
                  const result = await api.post<{ invocation: Invocation }>(
                    `${prefix}/plugin-invocations/${encodeURIComponent(detail.invocation_id)}/cancel`,
                    {},
                    undefined,
                    { "If-Match": etag },
                  );
                  setDetail(result.invocation);
                  updateRuns((n) => n + 1);
                })
              }
            >
              取消调用
            </button>
          }
        >
          <div className="source-description">
            <Badge status={detail.status} label={labels[detail.status]} />
            <p>
              包摘要：
              <code className="plugin-digest">
                {detail.request.package_digest}
              </code>
            </p>
            <p>
              参数摘要：
              <code className="plugin-digest">{detail.config_digest}</code>
            </p>
            <p>输入：{detail.request.inputs.map((ref) => ref.id).join(", ")}</p>
            {detail.error_code && (
              <p role="alert">执行结果：{detail.error_code}</p>
            )}
            <ul>
              {detail.limitations.map((note, index) => (
                <li key={index}>{note}</li>
              ))}
            </ul>
            <pre className="artifact-preview">
              {JSON.stringify(
                {
                  config: detail.request.config,
                  budget: detail.request.budget,
                  coverage: detail.coverage,
                },
                null,
                2,
              )}
            </pre>
            {detail.outputs.map((ref) => (
              <p className="mono" key={ref.id}>
                {ref.kind} · {ref.id} · {ref.bytes} bytes
              </p>
            ))}
            <button
              className="button secondary"
              onClick={() => onArtifacts(detail.request.scope.snapshot_id)}
            >
              查看 / 下载产物
            </button>
          </div>
        </Panel>
      )}
      <Modal
        open={importing}
        onClose={() => {
          if (!busy) setImporting(false);
        }}
        title="登记插件清单"
        wide
      >
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void work("导入清单", async () => {
              await api.post("/v1/plugins", {
                api_version: "codexploit/v1",
                manifest: JSON.parse(manifest),
                package_digest: packageDigest,
                source,
              });
              setImporting(false);
              updateCatalog((n) => n + 1);
              setNotice("清单已登记，可用性由宿主实际安装状态决定。");
            });
          }}
        >
          <label>
            清单 JSON
            <textarea
              aria-label="插件清单 JSON"
              required
              rows={12}
              value={manifest}
              onChange={(event) => setManifest(event.target.value)}
              spellCheck={false}
            />
          </label>
          <label>
            包 SHA-256
            <input
              aria-label="插件包摘要"
              required
              pattern="[a-f0-9]{64}"
              value={packageDigest}
              onChange={(event) => setPackageDigest(event.target.value)}
            />
          </label>
          <label>
            来源说明
            <input
              aria-label="插件来源说明"
              required
              maxLength={200}
              value={source}
              onChange={(event) => setSource(event.target.value)}
            />
          </label>
          {error && (
            <p className="error-message" role="alert">
              {error}
            </p>
          )}
          <div className="form-footer">
            <button className="button primary" disabled={!!busy}>
              <Box size={14} />
              登记清单
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
}
