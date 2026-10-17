import { useEffect, useRef, useState } from "react";
import { Download, FileText, RefreshCw, ShieldCheck, X } from "lucide-react";
import { ApiClient, ApiError } from "./api";
import { EmptyState, Hint, Modal, Panel } from "./components";
import type { Snapshot } from "./types";
import { latestSnapshot } from "./workbench";

export interface ArtifactRef {
  id: string;
  kind: string;
  sha256: string;
  bytes: number;
  media_type: string;
  schema_id: string;
  scope: { project_id: string; source_id: string; snapshot_id: string };
  producer: {
    plugin_id: string;
    plugin_version: string;
    invocation_id: string;
    task_id?: string;
    config_digest: string;
  };
}
type ArtifactPage = { artifacts: ArtifactRef[]; next_cursor: string };

function artifactError(error: unknown) {
  if (error instanceof ApiError) {
    if (error.code === "artifact_integrity")
      return "产物内容与发布时的摘要或大小不符，已拒绝读取。";
    if (error.code === "artifact_not_found")
      return "产物不存在、内容丢失，或不属于当前项目与快照。";
    if (error.code === "artifact_budget")
      return "产物超出读取预算，请确认大小后调整预算。";
    if (error.code === "artifact_conflict")
      return "同一产物已有不同内容，无法覆盖既有引用。";
  }
  return error instanceof Error ? error.message : "产物操作失败";
}

export function Artifacts({
  api,
  projectID,
  snapshots,
  fixedSnapshot,
  preferredSnapshot,
  canWrite,
  revision,
}: {
  api: ApiClient;
  projectID: string;
  snapshots?: Snapshot[];
  fixedSnapshot?: string;
  preferredSnapshot?: string;
  canWrite: boolean;
  revision: number;
}) {
  const [selected, setSelected] = useState(
    fixedSnapshot ||
      preferredSnapshot ||
      latestSnapshot(snapshots || [])?.snapshot_id ||
      "",
  );
  const snapshot = fixedSnapshot || selected;
  const [page, setPage] = useState<ArtifactPage>();
  const [cursors, setCursors] = useState([""]);
  const [tick, refresh] = useState(0);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [budgetMiB, setBudgetMiB] = useState(64);
  const [statuses, setStatuses] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<{ title: string; text: string }>();
  const operation = useRef<AbortController>();
  const cursor = cursors[cursors.length - 1];
  const endpoint = `/v1/projects/${encodeURIComponent(projectID)}/snapshots/${encodeURIComponent(snapshot)}/artifacts`;
  const validBudget =
    Number.isInteger(budgetMiB) && budgetMiB >= 1 && budgetMiB <= 512;
  useEffect(() => () => operation.current?.abort(), []);
  useEffect(() => {
    if (!selected && snapshots?.length)
      setSelected(latestSnapshot(snapshots)!.snapshot_id);
  }, [selected, snapshots]);
  useEffect(() => {
    setPage(undefined);
    setStatuses({});
    setError("");
    setNotice("");
    setCursors([""]);
  }, [snapshot]);
  useEffect(() => {
    if (!snapshot) return;
    const controller = new AbortController();
    setLoading(true);
    setError("");
    api
      .get<ArtifactPage>(
        `${endpoint}?limit=50&cursor=${encodeURIComponent(cursor)}`,
        controller.signal,
      )
      .then(setPage)
      .catch((error) => {
        if (!controller.signal.aborted) setError(artifactError(error));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [api, endpoint, snapshot, cursor, tick, revision]);
  const run = async (
    label: string,
    work: (signal: AbortSignal) => Promise<void>,
  ) => {
    if (busy) return;
    const controller = new AbortController();
    operation.current = controller;
    setBusy(label);
    setError("");
    setNotice("");
    try {
      await work(controller.signal);
    } catch (error) {
      setError(
        controller.signal.aborted ? "操作已取消。" : artifactError(error),
      );
    } finally {
      setBusy("");
      operation.current = undefined;
    }
  };
  const read = async (
    ref: ArtifactRef,
    signal: AbortSignal,
    maxBytes: number,
  ) => {
    const response = await api.response(
      `${endpoint}/${encodeURIComponent(ref.id)}/content?max_bytes=${maxBytes}`,
      { signal },
    );
    const reader = response.body?.getReader();
    if (!reader) throw new Error("浏览器无法读取产物流。");
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > maxBytes || size > ref.bytes)
          throw new Error("下载超出声明大小，已取消。");
        chunks.push(chunk.value);
      }
    } finally {
      await reader.cancel();
      reader.releaseLock();
    }
    if (size !== ref.bytes) throw new Error("下载未完成，内容长度不匹配。");
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const digest = [
      ...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    ]
      .map((n) => n.toString(16).padStart(2, "0"))
      .join("");
    if (digest !== ref.sha256) throw new Error("下载摘要不匹配，已拒绝保存。");
    return bytes;
  };
  const verify = (ref: ArtifactRef) =>
    run("校验产物", async (signal) => {
      try {
        await api.get(
          `${endpoint}/${encodeURIComponent(ref.id)}?max_bytes=${budgetMiB * 1048576}`,
          signal,
        );
        setStatuses((v) => ({ ...v, [ref.id]: "本次校验通过" }));
      } catch (error) {
        setStatuses((v) => ({ ...v, [ref.id]: "校验失败" }));
        throw error;
      }
    });
  const download = (ref: ArtifactRef) =>
    run("下载产物", async (signal) => {
      const bytes = await read(ref, signal, budgetMiB * 1048576);
      const url = URL.createObjectURL(
        new Blob([bytes], { type: ref.media_type }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = `${ref.id}${ref.media_type === "application/json" ? ".json" : ".tar"}`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      setStatuses((v) => ({ ...v, [ref.id]: "下载摘要已核对" }));
      setNotice("产物大小与 SHA-256 已核对，已开始保存下载。");
    });
  if (!snapshot)
    return (
      <EmptyState title="还没有可查看的快照">
        先从代码源建立快照，再查看输入产物。
      </EmptyState>
    );
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
        title="产物与证据"
        action={
          <button
            className="button secondary"
            disabled={!!busy || loading}
            onClick={() => {
              setStatuses({});
              refresh((n) => n + 1);
            }}
          >
            <RefreshCw size={14} />
            刷新目录
          </button>
        }
      >
        <div className="section-toolbar inset artifact-toolbar">
          {fixedSnapshot ? (
            <span className="mono">任务固定快照：{fixedSnapshot}</span>
          ) : (
            <label>
              代码快照
              <select
                aria-label="产物快照"
                value={snapshot}
                disabled={!!busy}
                onChange={(event) => setSelected(event.target.value)}
              >
                {(snapshots || []).map((s) => (
                  <option key={s.snapshot_id} value={s.snapshot_id}>
                    {s.snapshot_id} · {s.commit.slice(0, 16)}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label>
            读取预算（MiB）
            <input
              aria-label="产物读取预算 MiB"
              type="number"
              min={1}
              max={512}
              step={1}
              value={budgetMiB}
              disabled={!!busy}
              onChange={(event) => setBudgetMiB(event.target.valueAsNumber)}
            />
          </label>
          {busy && (
            <button
              className="button secondary"
              onClick={() => operation.current?.abort()}
            >
              <X size={14} />
              取消操作
            </button>
          )}
        </div>
        <Hint>
          展示固定快照的源码输入与分析产物，保留摘要和调用来源。漏洞证据仍可从任务发现详情查看。
        </Hint>
        {loading && !page ? (
          <p className="source-description" role="status">
            正在读取产物目录…
          </p>
        ) : !page?.artifacts.length ? (
          <EmptyState title={error ? "产物目录不可用" : "尚未登记产物"}>
            既有快照可从保留的冻结副本登记输入产物。新代码源快照会自动登记。
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table
              className="standard-table artifact-table"
              aria-busy={loading}
            >
              <thead>
                <tr>
                  <th>产物 / 内容身份</th>
                  <th>Scope 与来源</th>
                  <th>大小 / 校验</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {page.artifacts.map((ref) => (
                  <tr key={ref.id}>
                    <td>
                      <strong>
                        {ref.schema_id === "codexploit/source-tar/v1"
                          ? "冻结源码归档"
                          : ref.kind === "code.ast"
                            ? "Go 语法树"
                            : ref.kind === "code.facts"
                              ? "代码事实"
                              : ref.kind === "security.facts"
                                ? "安全语义事实"
                                : ref.kind === "discovery.paths"
                                  ? "候选分析路径"
                                  : ref.schema_id ===
                                      "codexploit/builtin-native/v1"
                                    ? "原始分析报告"
                                    : ref.schema_id ===
                                        "codexploit/source-files/v1"
                                      ? "源码文件清单"
                                      : ref.kind}
                      </strong>
                      <div className="cell-subtitle mono">{ref.id}</div>
                      <p className="mono">
                        {ref.kind} · {ref.media_type}
                      </p>
                      <div className="artifact-digest">
                        <small>SHA-256</small>
                        <code>{ref.sha256}</code>
                      </div>
                      <small>{ref.schema_id}</small>
                    </td>
                    <td>
                      <dl className="artifact-scope">
                        <dt>项目</dt>
                        <dd>{ref.scope.project_id}</dd>
                        <dt>代码源</dt>
                        <dd>{ref.scope.source_id}</dd>
                        <dt>快照</dt>
                        <dd>{ref.scope.snapshot_id}</dd>
                        <dt>Producer</dt>
                        <dd>
                          {ref.producer.plugin_id} @
                          {ref.producer.plugin_version}
                        </dd>
                        <dt>调用</dt>
                        <dd>{ref.producer.invocation_id}</dd>
                        {ref.producer.task_id && (
                          <>
                            <dt>任务</dt>
                            <dd>{ref.producer.task_id}</dd>
                          </>
                        )}
                      </dl>
                      <details>
                        <summary>配置摘要</summary>
                        <code className="artifact-config">
                          {ref.producer.config_digest}
                        </code>
                      </details>
                    </td>
                    <td>
                      <span className="mono">
                        {ref.bytes.toLocaleString()} bytes
                      </span>
                      <p role="status">{statuses[ref.id] || "未校验"}</p>
                    </td>
                    <td>
                      <div className="artifact-actions">
                        <button
                          className="button secondary"
                          disabled={!!busy || !validBudget}
                          onClick={() => verify(ref)}
                        >
                          <ShieldCheck size={14} />
                          校验
                        </button>
                        <button
                          className="button secondary"
                          disabled={
                            !!busy ||
                            ref.media_type !== "application/json" ||
                            ref.bytes > 131072
                          }
                          onClick={() =>
                            run("预览清单", async (signal) => {
                              const bytes = await read(ref, signal, 131072);
                              setPreview({
                                title: ref.id,
                                text: new TextDecoder().decode(bytes),
                              });
                              setStatuses((v) => ({
                                ...v,
                                [ref.id]: "预览摘要已核对",
                              }));
                            })
                          }
                        >
                          <FileText size={14} />
                          预览 JSON
                        </button>
                        <button
                          className="button secondary"
                          disabled={!!busy || !validBudget}
                          onClick={() => download(ref)}
                        >
                          <Download size={14} />
                          下载
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="pager">
          <span>第 {cursors.length} 页 · 每页最多 50 项</span>
          <button
            disabled={cursors.length < 2 || loading || !!busy}
            onClick={() => setCursors((v) => v.slice(0, -1))}
          >
            上一页
          </button>
          <button
            disabled={!page?.next_cursor || loading || !!busy}
            onClick={() => setCursors((v) => [...v, page!.next_cursor])}
          >
            下一页
          </button>
        </div>
        <div className="form-footer">
          <button
            className="button secondary"
            disabled={!canWrite || !!busy || loading}
            onClick={() =>
              run("登记源码产物", async (signal) => {
                await api.post(endpoint, {}, signal);
                setStatuses({});
                refresh((n) => n + 1);
                setNotice("冻结副本的源码产物已登记，已有引用保持不变。");
              })
            }
          >
            登记 / 核对源码产物
          </button>
        </div>
        <Hint>
          服务端流式读取并先核对摘要；下载后浏览器再次核对。预算上限 512
          MiB，JSON 预览上限 128 KiB。登记失败时可重试，无法覆盖不同内容。
        </Hint>
      </Panel>
      <Modal
        open={!!preview}
        onClose={() => setPreview(undefined)}
        title="产物 JSON 预览"
        wide
      >
        <p className="mono">{preview?.title}</p>
        <pre className="artifact-preview">{preview?.text}</pre>
      </Modal>
    </>
  );
}
