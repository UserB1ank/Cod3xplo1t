import { useEffect, useRef, useState } from "react";
import { Box, Play, Plus, RefreshCw } from "lucide-react";
import { ApiClient, ApiError } from "./api";
import { preparePublication, type PublicationRequest } from "./knowledgeData";
import { Badge, EmptyState, Hint, Modal, Panel } from "./components";
import type { Snapshot } from "./types";
import { latestSnapshot } from "./workbench";
import type { ArtifactRef } from "./Artifacts";

export interface PluginRecord {
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
  installed: boolean;
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
interface DiscoveryResult {
  kind: string;
  nodes: object[];
  edges: object[];
  native_artifact: ArtifactRef;
  limitations: string[];
  paths: {
    id: string;
    path_kind: string;
    completeness: string;
    evidence_class: string;
    steps: {
      layer: string;
      from: string;
      to: string;
      kind: string;
      file?: string;
      line?: number;
    }[];
    scg_refs: string[];
    asg_refs: string[];
    evidence_refs: string[];
    limitations: string[];
  }[];
  candidates: {
    id: string;
    title: string;
    status: "candidate";
    severity_hint?: "high" | "medium" | "low";
    file: string;
    line: number;
    path_refs: string[];
    evidence_refs: string[];
    limitations: string[];
  }[];
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
  RUNNING: "分析中",
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
  onKnowledge,
}: {
  api: ApiClient;
  projectID: string;
  snapshots: Snapshot[];
  canWrite: boolean;
  canRegister: boolean;
  revision: number;
  onArtifacts: (snapshot: string) => void;
  onKnowledge: () => void;
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
  const [upstream, setUpstream] = useState("");
  const [discovery, setDiscovery] = useState<DiscoveryResult>();
  const [resultError, setResultError] = useState("");
  const [etag, setETag] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const publications = useRef(new Map<string, PublicationRequest>());
  const [published, setPublished] = useState("");
  useEffect(() => setPublished(""), [selectedRun, snapshot]);
  const [importing, setImporting] = useState(false);
  const [manifest, setManifest] = useState("");
  const [packageDigest, setPackageDigest] = useState("");
  const [source, setSource] = useState("manual import");
  const chosen =
    catalog.find(
      (p) => `${p.manifest.id}@${p.manifest.version}` === selected,
    ) ||
    catalog.find(
      (p) => p.manifest.id === "builtin.go-parser" && p.executable,
    ) ||
    catalog[0];
  const upstreamPlugin =
    chosen?.manifest.id === "builtin.security-semantics"
      ? "builtin.go-parser"
      : chosen?.manifest.id === "builtin.discovery-paths"
        ? "builtin.security-semantics"
        : "";
  const eligible = runs.filter(
    (run) =>
      run.request.plugin_id === upstreamPlugin &&
      ["SUCCEEDED", "PARTIAL"].includes(run.status) &&
      (upstreamPlugin !== "builtin.go-parser" ||
        run.request.inputs[0]?.id === input?.id),
  );
  const upstreamRun =
    eligible.find((run) => run.invocation_id === upstream) || eligible[0];
  const executionInputs: ArtifactRef[] =
    chosen?.manifest.id === "builtin.security-semantics"
      ? [
          input,
          upstreamRun?.outputs.find((ref) => ref.kind === "code.facts"),
        ].filter((ref): ref is ArtifactRef => !!ref)
      : chosen?.manifest.id === "builtin.discovery-paths"
        ? [
            upstreamRun?.outputs.find((ref) => ref.kind === "security.facts"),
            upstreamRun?.outputs.find((ref) => ref.kind === "report.document"),
          ].filter((ref): ref is ArtifactRef => !!ref)
        : input
          ? [input]
          : [];
  const inputsReady = executionInputs.length === (upstreamPlugin ? 2 : 1);
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
    setDiscovery(undefined);
    setResultError("");
    if (
      !detail ||
      !["SUCCEEDED", "PARTIAL"].includes(detail.status) ||
      !detail.outputs.some((ref) => ref.schema_id === "codexploit/discovery/v1")
    )
      return;
    const controller = new AbortController();
    api
      .get<DiscoveryResult>(
        `${prefix}/plugin-invocations/${encodeURIComponent(detail.invocation_id)}/result`,
        controller.signal,
      )
      .then(setDiscovery)
      .catch((error) => {
        if (!controller.signal.aborted) setResultError(errorText(error));
      });
    return () => controller.abort();
  }, [api, prefix, detail?.invocation_id, detail?.status]);
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
                        已登记 · {p.installed ? "已安装" : "未安装"} ·{" "}
                        {p.executable ? "可执行" : "不可执行"}
                      </p>
                      {p.reason && <small>{p.reason}</small>}
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
      <Panel title="执行固定版本分析">
        <Hint>
          1. Go 解析生成代码事实 → 2. 语义分析识别安全语义 → 3.
          路径分析生成候选。每一步显式选择固定的上游调用，调用可达与假设分别展示。
        </Hint>
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
                setUpstream("");
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
          {upstreamPlugin && (
            <label>
              上游调用（当前记录页）
              <select
                aria-label="上游分析调用"
                value={upstreamRun?.invocation_id || ""}
                onChange={(event) => setUpstream(event.target.value)}
              >
                <option value="" disabled>
                  先执行
                  {upstreamPlugin === "builtin.go-parser"
                    ? "Go 解析"
                    : "语义分析"}
                </option>
                {eligible.map((run) => (
                  <option key={run.invocation_id} value={run.invocation_id}>
                    {run.invocation_id} · {run.request.plugin_version} ·{" "}
                    {labels[run.status]}
                  </option>
                ))}
              </select>
            </label>
          )}
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
              !inputsReady ||
              !Number.isInteger(maxFiles) ||
              maxFiles < 1 ||
              maxFiles > 20000 ||
              !Number.isInteger(timeout) ||
              timeout < 1 ||
              timeout > 120
            }
            onClick={() =>
              work("开始分析", async () => {
                const parsed = JSON.parse(config);
                const result = await api.post<{ invocation: Invocation }>(
                  `${prefix}/plugin-invocations`,
                  {
                    api_version: "codexploit/v1",
                    invocation_id: `inv-${crypto.randomUUID()}`,
                    plugin_id: chosen!.manifest.id,
                    plugin_version: chosen!.manifest.version,
                    package_digest: chosen!.package_digest,
                    scope: executionInputs[0].scope,
                    inputs: executionInputs,
                    config: parsed,
                    budget: { max_files: maxFiles, timeout_seconds: timeout },
                  },
                );
                setSelectedRun(result.invocation.invocation_id);
                setDetail(result.invocation);
                updateRuns((n) => n + 1);
                setNotice("分析调用已创建，输入与插件版本已固定。");
              })
            }
          >
            <Play size={14} />
            {busy || "开始分析"}
          </button>
        </div>
        <Hint>
          {executionInputs.map((ref) => (
            <p className="mono" key={ref.id}>
              固定输入：{ref.kind} · {ref.id} · SHA-256 {ref.sha256}
            </p>
          ))}
          工具只生成候选和分级建议。调用可达不等于污点流；规则命中不代表控制有效或漏洞可利用，已有裁定不会被工具覆盖。
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
          <EmptyState title="还没有分析调用">
            先运行 Go 解析，再选择上游调用执行语义和路径分析。
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
            <details>
              <summary>
                覆盖范围、预算与局限（{detail.limitations.length} 项）
              </summary>
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
            </details>
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
            <button
              className="button primary"
              disabled={
                !canWrite ||
                !!busy ||
                !discovery ||
                !["SUCCEEDED", "PARTIAL"].includes(detail.status)
              }
              onClick={() =>
                work("发布共享图谱", async () => {
                  const id = detail.invocation_id;
                  try {
                    let request = publications.current.get(id);
                    if (!request) {
                      request = await preparePublication(
                        api,
                        projectID,
                        detail.request.scope.snapshot_id,
                        id,
                        `batch-${crypto.randomUUID()}`,
                      );
                      publications.current.set(id, request);
                    }
                    const result = await api.post<{
                      publication: { revision: string };
                    }>(
                      `/v1/projects/${encodeURIComponent(projectID)}/knowledge/publications`,
                      request,
                    );
                    setPublished(result.publication.revision);
                  } catch (error) {
                    if (
                      error instanceof ApiError &&
                      error.code === "version_conflict"
                    )
                      publications.current.delete(id);
                    throw error;
                  }
                })
              }
            >
              {detail.status === "PARTIAL"
                ? "发布部分覆盖结果"
                : "发布到共享图谱"}
            </button>
            {published && (
              <button className="text-button" onClick={onKnowledge}>
                查看已发布图谱 · {published}
              </button>
            )}
            {discovery && (
              <Hint>
                发布保留原始产物、调用来源、候选与覆盖局限。并发版本冲突会明确失败，可刷新后重试。
              </Hint>
            )}
          </div>
        </Panel>
      )}
      {resultError && (
        <div className="error-message" role="alert">
          标准结果暂不可读取：{resultError}。可到产物页面核对或下载。
        </div>
      )}
      {discovery && (
        <Panel
          title={
            discovery.native_artifact.schema_id ===
            "codexploit/scanner-alerts/v1"
              ? "进程扫描告警"
              : discovery.kind === "security.facts"
                ? "安全语义事实"
                : "候选观察与分析路径"
          }
        >
          <Hint>
            {discovery.native_artifact.schema_id ===
            "codexploit/scanner-alerts/v1"
              ? "进程扫描器报告告警位置；本切片不声明污点流或可利用性。"
              : `${discovery.nodes.length} 个安全语义节点 · ${discovery.edges.length} 条关系`}{" "}
            {discovery.paths.length} 条路径 · {discovery.candidates.length}{" "}
            个候选。严重性建议与确认状态独立，工具没有裁定权限。
          </Hint>
          {discovery.candidates.length ? (
            discovery.candidates.map((candidate) => {
              const paths = discovery.paths.filter((path) =>
                candidate.path_refs.includes(path.id),
              );
              const grades = { high: "高", medium: "中", low: "低" };
              return (
                <details className="source-description" key={candidate.id}>
                  <summary>
                    {candidate.title} · 候选 ·{" "}
                    {candidate.severity_hint
                      ? `${grades[candidate.severity_hint]}危建议`
                      : "待评估"}
                  </summary>
                  <p className="mono">
                    观察：{candidate.id} · {candidate.file}:{candidate.line}
                  </p>
                  <p>
                    证据：{candidate.evidence_refs.join(", ")} · 原始报告
                    SHA-256：{discovery.native_artifact.sha256}
                  </p>
                  {paths.map((path) => (
                    <div key={path.id}>
                      <p>
                        {path.path_kind === "call_reachability"
                          ? "调用可达"
                          : "假设"}{" "}
                        ·{" "}
                        {path.completeness === "complete"
                          ? "调用步骤完整"
                          : "部分 / 未解析"}{" "}
                        · {path.evidence_class}
                      </p>
                      <ol>
                        {path.steps.map((step, index) => (
                          <li key={index}>
                            <code>
                              {step.layer} · {step.kind} · {step.from} →{" "}
                              {step.to}
                            </code>
                            {step.file && (
                              <span>
                                {" "}
                                · {step.file}:{step.line}
                              </span>
                            )}
                          </li>
                        ))}
                      </ol>
                      <p className="mono">
                        canonical SCG：{path.scg_refs.join(", ")}
                        <br />
                        canonical ASG：{path.asg_refs.join(", ")}
                      </p>
                    </div>
                  ))}
                  <ul>
                    {candidate.limitations.map((note, index) => (
                      <li key={index}>{note}</li>
                    ))}
                  </ul>
                </details>
              );
            })
          ) : (
            <p className="source-description">
              {discovery.kind === "security.facts"
                ? "语义产物已生成，选择此上游调用继续路径分析。"
                : "本次范围未生成候选；这不代表不存在漏洞。"}
            </p>
          )}
          <details className="source-description">
            <summary>分析覆盖与局限</summary>
            <ul>
              {discovery.limitations.map((note, index) => (
                <li key={index}>{note}</li>
              ))}
            </ul>
          </details>
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
