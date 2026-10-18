import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  Download,
  FileText,
  Loader2,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react";
import { ApiClient, ApiError } from "./api";
import { EmptyState, Hint, Panel } from "./components";
import { dateLabel, shortId } from "./domain";
import type { Snapshot } from "./types";
import { latestSnapshot, type Task } from "./workbench";
import {
  readVerifiedReport,
  reportActive,
  type ReportRecord,
  type ReportSettings,
} from "./report-client";

type History = { reports: ReportRecord[]; next_cursor: string };
type View = {
  view_id: string;
  layers: Record<string, { version?: string; status: string }>;
};
type Revision = { revision: string; created_at: string };
const stateNames: Record<string, string> = {
  CREATED: "等待生成",
  RUNNING: "生成中",
  SUCCEEDED: "已保存",
  FAILED: "生成失败",
  CANCELLED: "已取消",
  TIMED_OUT: "已超时",
  UNSUPPORTED: "不支持",
};
const errorText = (error: unknown) => {
  if (error instanceof ApiError) {
    const names: Record<string, string> = {
      report_evidence_missing:
        "发现引用的证据或路径缺失、损坏或不属于所选快照，未生成报告。",
      report_input_changed: "采集期间发现、路径或覆盖发生变化，请刷新后重试。",
      view_superseded: "所选图谱已重建，请刷新固定视图后重新生成。",
      report_interrupted: "输入采集已中断，未生成成功报告。",
      plugin_budget: "所选范围超过生成预算，请缩小范围或调整预算。",
      artifact_integrity: "保存的报告内容与摘要不一致，已拒绝读取。",
      artifact_not_found: "报告内容已丢失或不属于当前范围。",
    };
    if (names[error.code]) return names[error.code];
  }
  return error instanceof Error ? error.message : "报告操作失败";
};

export function Reports({
  api,
  projectID,
  snapshots = [],
  task,
  canWrite,
  revision = 0,
}: {
  api: ApiClient;
  projectID: string;
  snapshots?: Snapshot[];
  task?: Task;
  canWrite: boolean;
  revision?: number;
}) {
  const [selectedSnapshot, setSnapshot] = useState(
    () => task?.snapshot_id || latestSnapshot(snapshots)?.snapshot_id || "",
  );
  const snapshot = task?.snapshot_id || selectedSnapshot;
  const [view, setView] = useState<View>();
  const [revisions, setRevisions] = useState<Revision[]>([]);
  const [knowledgeRevision, setKnowledgeRevision] = useState("rev-0");
  const [format, setFormat] = useState<ReportSettings["format"]>("md");
  const [candidates, setCandidates] = useState(false);
  const [maxFindings, setMaxFindings] = useState(2000);
  const [outputMiB, setOutputMiB] = useState(16);
  const [page, setPage] = useState<History>();
  const [cursors, setCursors] = useState([""]);
  const [selected, setSelected] = useState<ReportRecord>();
  const [text, setText] = useState("");
  const [verified, setVerified] = useState("");
  const [busy, setBusy] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [tick, refresh] = useState(0);
  const [pinTick, refreshPin] = useState(0);
  const operation = useRef<AbortController>();
  const prefix = `/v1/projects/${encodeURIComponent(projectID)}`;
  const cursor = cursors[cursors.length - 1];
  const taskID = task?.audit_id;
  const validBudget =
    Number.isInteger(maxFindings) &&
    maxFindings >= 1 &&
    maxFindings <= 10000 &&
    Number.isInteger(outputMiB) &&
    outputMiB >= 1 &&
    outputMiB <= 64;
  useEffect(() => () => operation.current?.abort(), []);
  useEffect(() => {
    if (!snapshot && snapshots.length)
      setSnapshot(latestSnapshot(snapshots)!.snapshot_id);
  }, [snapshot, snapshots]);
  useEffect(() => {
    setSelected(undefined);
    setPage(undefined);
    setText("");
    setVerified("");
    setError("");
    setNotice("");
    setCursors([""]);
    if (!snapshot) return;
    const controller = new AbortController();
    setView(undefined);
    setLoading(true);
    Promise.all([
      api.post<{ view: View }>(
        `${prefix}/knowledge/views`,
        { api_version: "codexploit/v1", snapshot_id: snapshot },
        controller.signal,
      ),
      api.get<{ revisions: Revision[] }>(
        `${prefix}/knowledge/revisions?snapshot_id=${encodeURIComponent(snapshot)}&limit=200`,
        controller.signal,
      ),
    ])
      .then(([pin, versions]) => {
        if (controller.signal.aborted) return;
        setView(pin.view);
        setRevisions(versions.revisions || []);
        setKnowledgeRevision(versions.revisions[0]?.revision || "rev-0");
      })
      .catch((error) => {
        if (!controller.signal.aborted) setError(errorText(error));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [api, prefix, snapshot, taskID, revision, pinTick]);
  useEffect(() => {
    if (!snapshot) return;
    const controller = new AbortController();
    api
      .get<History>(
        `${prefix}/reports?snapshot_id=${encodeURIComponent(snapshot)}&limit=50&cursor=${encodeURIComponent(cursor)}${taskID ? `&task_id=${encodeURIComponent(taskID)}` : ""}`,
        controller.signal,
      )
      .then((result) => {
        if (!controller.signal.aborted) setPage(result);
      })
      .catch((error) => {
        if (!controller.signal.aborted) setError(errorText(error));
      });
    return () => controller.abort();
  }, [api, prefix, snapshot, taskID, cursor, tick, revision]);
  useEffect(() => {
    if (!selected || !reportActive(selected)) return;
    const controller = new AbortController();
    const poll = async () => {
      try {
        const result = await api.get<{ report: ReportRecord }>(
          `${prefix}/reports/${encodeURIComponent(selected.invocation_id)}?snapshot_id=${encodeURIComponent(snapshot)}`,
          controller.signal,
        );
        if (controller.signal.aborted) return;
        setSelected(result.report);
        if (!reportActive(result.report)) refresh((n) => n + 1);
      } catch (error) {
        if (!controller.signal.aborted) setError(errorText(error));
      }
    };
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") void poll();
    }, 1000);
    void poll();
    return () => {
      clearInterval(timer);
      controller.abort();
    };
  }, [api, prefix, snapshot, selected?.invocation_id, reportActive(selected)]);

  async function run(
    label: string,
    work: (signal: AbortSignal) => Promise<void>,
  ) {
    if (busy) return;
    const controller = new AbortController();
    operation.current = controller;
    setBusy(label);
    setError("");
    setNotice("");
    try {
      await work(controller.signal);
    } catch (error) {
      if (!controller.signal.aborted) setError(errorText(error));
      else
        setNotice(
          "当前读取或采集请求已中止；已登记调用的最终状态以报告记录为准。",
        );
    } finally {
      if (operation.current === controller) {
        operation.current = undefined;
        setBusy("");
      }
    }
  }
  function generate(event: FormEvent) {
    event.preventDefault();
    if (!view || !validBudget || !canWrite) return;
    void run("固定输入并创建报告", async (signal) => {
      const result = await api.post<{ report: ReportRecord }>(
        `${prefix}/reports`,
        {
          api_version: "codexploit/v1",
          snapshot_id: snapshot,
          task_id: taskID,
          view_id: view.view_id,
          knowledge_revision: knowledgeRevision,
          format,
          include_candidates: candidates,
          max_findings: maxFindings,
          budget: { max_output_bytes: outputMiB * 1048576 },
        },
        signal,
      );
      if (signal.aborted) return;
      setSelected(result.report);
      setText("");
      setVerified("");
      setCursors([""]);
      refresh((n) => n + 1);
      setNotice("真实输入已固定，报告状态以保存的 reporter 调用为准。");
    });
  }
  function read(download: boolean) {
    const record = selected;
    const ref = record?.outputs.find((ref) => ref.kind === "report.document");
    if (!record || record.status !== "SUCCEEDED" || !ref) return;
    void run(download ? "校验并下载报告" : "校验并读取报告", async (signal) => {
      const bytes = await readVerifiedReport(api, ref, signal);
      if (signal.aborted) return;
      setVerified(ref.id);
      if (download) {
        const url = URL.createObjectURL(
          new Blob([bytes], { type: ref.media_type }),
        );
        const link = document.createElement("a");
        link.href = url;
        link.download = `codexploit-${record.invocation_id}.${record.request.config.format}`;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        setNotice("报告大小与 SHA-256 已核对，已开始保存下载。");
      } else {
        const decoded = new TextDecoder().decode(bytes);
        setText(
          decoded.slice(0, 100000) +
            (decoded.length > 100000 ? "\n[预览已截断；下载保留完整报告]" : ""),
        );
      }
    });
  }
  function cancelReport() {
    if (!selected || !canWrite) return;
    const record = selected;
    void run("取消报告调用", async (signal) => {
      const path = `${prefix}/snapshots/${encodeURIComponent(snapshot)}/plugin-invocations/${encodeURIComponent(record.invocation_id)}`;
      const current = await api.response(path, { signal });
      const etag = current.headers.get("ETag");
      await current.arrayBuffer();
      if (!etag) throw new Error("调用缺少版本标识，请刷新后重试。");
      const result = await api.post<{ invocation: ReportRecord }>(
        `${path}/cancel`,
        {},
        signal,
        { "If-Match": etag },
      );
      if (signal.aborted) return;
      setSelected(result.invocation);
      refresh((n) => n + 1);
    });
  }
  if (!snapshot)
    return (
      <EmptyState title="还没有报告输入">
        先从代码源保存快照，再生成固定版本报告。
      </EmptyState>
    );
  const config = selected?.request.config;
  const output = selected?.outputs.find(
    (ref) => ref.kind === "report.document",
  );
  const counts = config?.counts || {};
  return (
    <div className="reports-workspace">
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
      <div className="report-layout">
        <Panel
          title="生成固定版本报告"
          eyebrow="REPORT EXPORT"
          action={
            <button
              className="text-button"
              disabled={!!busy || loading || reportActive(selected)}
              onClick={() => refreshPin((n) => n + 1)}
            >
              <RefreshCw size={13} />
              刷新输入版本
            </button>
          }
        >
          <form className="report-create" onSubmit={generate}>
            <span className="report-scope-label">
              {task ? "当前任务" : "项目 · 此快照"}
            </span>
            {task ? (
              <div className="report-fixed">
                <small>任务与固定快照</small>
                <strong>{task.name || shortId(task.audit_id)}</strong>
                <code>{snapshot}</code>
              </div>
            ) : (
              <label>
                代码快照
                <select
                  value={snapshot}
                  disabled={!!busy}
                  onChange={(e) => setSnapshot(e.target.value)}
                  aria-label="报告快照"
                >
                  {snapshots.map((s) => (
                    <option key={s.snapshot_id} value={s.snapshot_id}>
                      {shortId(s.snapshot_id)} · {s.commit.slice(0, 12)}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label>
              共享知识版本
              <select
                aria-label="报告知识版本"
                value={knowledgeRevision}
                disabled={loading || !!busy}
                onChange={(e) => setKnowledgeRevision(e.target.value)}
              >
                <option value="rev-0">不引用共享发布版本</option>
                {revisions.map((r) => (
                  <option key={r.revision} value={r.revision}>
                    {r.revision} · {dateLabel(r.created_at)}
                  </option>
                ))}
              </select>
            </label>
            <div className="report-view-pin">
              <small>固定图层</small>
              {loading ? (
                <span role="status">读取版本…</span>
              ) : view ? (
                Object.entries(view.layers).map(([name, layer]) => (
                  <span key={name}>
                    <b>{name.toUpperCase()}</b>
                    <code>{layer.version || layer.status}</code>
                  </span>
                ))
              ) : (
                <span>图谱不可用，请建立图谱后刷新。</span>
              )}
            </div>
            <fieldset className="report-format">
              <legend>导出格式</legend>
              {(
                [
                  ["md", "Markdown", "供人工审阅"],
                  ["json", "JSON", "完整结构与证据"],
                  ["sarif", "SARIF 2.1", "兼容分析工具"],
                ] as const
              ).map(([id, title, note]) => (
                <label key={id} className={format === id ? "selected" : ""}>
                  <input
                    type="radio"
                    name="report-format"
                    checked={format === id}
                    disabled={!!busy}
                    onChange={() => setFormat(id)}
                  />
                  <strong>{title}</strong>
                  <small>{note}</small>
                </label>
              ))}
            </fieldset>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={candidates}
                disabled={!!busy}
                onChange={(e) => setCandidates(e.target.checked)}
              />
              包含待验证候选，单列候选计数
            </label>
            <details className="report-budget">
              <summary>生成预算</summary>
              <div className="report-budget-fields">
                <label>
                  发现分组上限
                  <input
                    type="number"
                    min={1}
                    max={10000}
                    step={1}
                    value={maxFindings}
                    disabled={!!busy}
                    onChange={(e) => setMaxFindings(e.target.valueAsNumber)}
                  />
                </label>
                <label>
                  输出上限（MiB）
                  <input
                    type="number"
                    min={1}
                    max={64}
                    step={1}
                    value={outputMiB}
                    disabled={!!busy}
                    onChange={(e) => setOutputMiB(e.target.valueAsNumber)}
                  />
                </label>
              </div>
              <p>
                超出预算会失败，不会把截断的报告显示为成功。路径上限
                10,000，输入上限 64 MiB。
              </p>
            </details>
            <Hint>
              保存生成时的发现与分级版本。图谱版本与发现账本分别固定；选择旧图谱不会恢复过去的裁定。
            </Hint>
            {!canWrite && (
              <p className="muted">
                reader 可以查看和下载，生成报告需要 writer 权限。
              </p>
            )}
            <button
              className="button primary"
              disabled={
                !canWrite ||
                !view ||
                loading ||
                !!busy ||
                reportActive(selected) ||
                !validBudget
              }
            >
              {busy ? (
                <Loader2 size={15} className="spin" />
              ) : (
                <FileText size={15} />
              )}
              生成并保存报告
            </button>
            {busy && (
              <button
                className="button secondary"
                type="button"
                onClick={() => operation.current?.abort()}
              >
                中止当前请求
              </button>
            )}
          </form>
        </Panel>
        <Panel
          title="已保存报告"
          action={
            <button
              className="icon-button"
              aria-label="刷新报告目录"
              onClick={() => refresh((n) => n + 1)}
              disabled={!!busy}
            >
              <RefreshCw size={15} />
            </button>
          }
        >
          {!page ? (
            <p className="source-description" role="status">
              正在读取报告目录…
            </p>
          ) : !page.reports.length ? (
            <EmptyState
              title={error ? "目录读取失败或当前页为空" : "当前页没有报告"}
            >
              生成后保留固定输入、调用状态和产物摘要。可继续翻页查看。
            </EmptyState>
          ) : (
            <div className="report-history">
              {[...page.reports]
                .sort((a, b) => b.created_at.localeCompare(a.created_at))
                .map((record) => (
                  <button
                    disabled={!!busy}
                    key={record.invocation_id}
                    className={`report-history-item ${selected?.invocation_id === record.invocation_id ? "selected" : ""}`}
                    onClick={() => {
                      setSelected(record);
                      setText("");
                      setVerified("");
                    }}
                  >
                    <div>
                      <strong>
                        {record.request.config.format.toUpperCase()}
                      </strong>
                      <span
                        className={`report-state state-${record.status.toLowerCase()}`}
                      >
                        {stateNames[record.status] || record.status}
                      </span>
                    </div>
                    <span>{dateLabel(record.created_at)}</span>
                    <small>
                      {record.request.config.task_id
                        ? `任务 ${shortId(record.request.config.task_id)}`
                        : "项目 · 此快照"}{" "}
                      ·{" "}
                      {record.request.config.include_candidates
                        ? "含候选"
                        : "不含候选"}
                    </small>
                    <code>{shortId(record.invocation_id)}</code>
                  </button>
                ))}
            </div>
          )}
          <div className="pager">
            <button
              disabled={cursors.length === 1 || !!busy}
              onClick={() => setCursors((v) => v.slice(0, -1))}
            >
              上一页
            </button>
            <span>第 {cursors.length} 页</span>
            <button
              disabled={!page?.next_cursor || !!busy}
              onClick={() => setCursors((v) => [...v, page!.next_cursor])}
            >
              下一页
            </button>
          </div>
        </Panel>
      </div>
      {selected && config && (
        <Panel
          title="报告详情"
          action={
            <span
              className={`report-state state-${selected.status.toLowerCase()}`}
            >
              {stateNames[selected.status] || selected.status}
            </span>
          }
        >
          <div className="report-detail">
            <div className="report-detail-heading">
              <div>
                <code>{selected.invocation_id}</code>
                <p>
                  {config.task_id
                    ? `任务范围：${config.task_id}`
                    : "项目范围：此快照的完整分组"}
                </p>
              </div>
              <div className="heading-actions">
                {reportActive(selected) && canWrite ? (
                  <button
                    className="button secondary"
                    disabled={!!busy}
                    onClick={cancelReport}
                  >
                    <X size={15} />
                    取消生成
                  </button>
                ) : (
                  <>
                    <button
                      className="button secondary"
                      disabled={
                        selected.status !== "SUCCEEDED" || !output || !!busy
                      }
                      onClick={() => read(false)}
                    >
                      校验并预览
                    </button>
                    <button
                      className="button primary"
                      disabled={
                        selected.status !== "SUCCEEDED" || !output || !!busy
                      }
                      onClick={() => read(true)}
                    >
                      <Download size={15} />
                      校验并下载
                    </button>
                  </>
                )}
              </div>
            </div>
            <div className="report-counts">
              {[
                ["confirmed", "已确认"],
                ["candidate", "待验证候选"],
                ["refuted", "已排除"],
                ["inconclusive", "证据不足"],
                ["blocked", "验证受阻"],
              ].map(([key, label]) => (
                <div key={key}>
                  <span>{label}</span>
                  <strong>{counts[key] || 0}</strong>
                </div>
              ))}
            </div>
            <p className="source-description">
              独立分级统计：高 {counts.high || 0} · 中 {counts.medium || 0} · 低{" "}
              {counts.low || 0} · 待分级 {counts.ungraded || 0}
              。分级不改变确认状态。
            </p>
            <dl className="detail-grid">
              <dt>采集时间</dt>
              <dd>{dateLabel(config.captured_at)}</dd>
              <dt>快照</dt>
              <dd className="mono">{snapshot}</dd>
              <dt>知识版本</dt>
              <dd>
                {config.knowledge_revision === "rev-0"
                  ? "未引用共享发布版本"
                  : config.knowledge_revision}
              </dd>
              <dt>候选策略</dt>
              <dd>
                {config.include_candidates ? "包含并独立计数" : "排除候选"}
              </dd>
              <dt>Reporter</dt>
              <dd>
                {selected.request.plugin_id}@{selected.request.plugin_version}
              </dd>
              <dt>插件包摘要</dt>
              <dd className="mono">{selected.request.package_digest}</dd>
              <dt>固定输入摘要</dt>
              <dd className="mono">
                {selected.request.inputs[0]?.sha256 || "不可用"}
              </dd>
              {output && (
                <>
                  <dt>输出大小</dt>
                  <dd>
                    {output.bytes.toLocaleString()} bytes · {output.media_type}
                  </dd>
                  <dt>SHA-256</dt>
                  <dd className="mono">{output.sha256}</dd>
                </>
              )}
            </dl>
            {selected.error_code && (
              <div className="error-message" role="alert">
                {stateNames[selected.status] || selected.status} ·{" "}
                {selected.error_code}。本次没有成功报告产物。
              </div>
            )}
            {reportActive(selected) && (
              <div className="operation-status" role="status">
                <Loader2 size={15} className="spin" />
                Reporter 正在生成；完成后才会发布产物。
              </div>
            )}
            {verified && (
              <div className="success-message" role="status">
                <ShieldCheck size={15} />
                本次读取已核对完整大小与 SHA-256
              </div>
            )}
            {text && <pre className="report-preview">{text}</pre>}
          </div>
        </Panel>
      )}
    </div>
  );
}
