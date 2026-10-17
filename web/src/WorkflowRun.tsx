import { useEffect, useState } from "react";
import { ArrowRight, FileText, GitBranch, RefreshCw } from "lucide-react";
import { ApiClient } from "./api";
import { Badge, Hint, Panel } from "./components";
import type { ArtifactRef } from "./Artifacts";
import type { Plan } from "./Workflows";

export const flowStatus: { [key: string]: string } = {
  CREATED: "等待流程",
  PENDING: "未调度",
  RUNNING: "流程运行中",
  PAUSING: "暂停中",
  PAUSED: "已暂停",
  CANCELLING: "取消中",
  SUCCEEDED: "流程完成",
  PARTIAL: "部分覆盖",
  FAILED: "流程失败",
  CANCELLED: "已取消",
  TIMED_OUT: "节点超时",
  SKIPPED: "已跳过",
};
interface Event {
  seq: number;
  type: string;
  node_id?: string;
  status: string;
  created_at: string;
}
interface NodeRun {
  node_run_id: string;
  node_id: string;
  kind: string;
  status: string;
  attempt?: number;
  next_attempt_at?: string;
  last_error?: string;
  invocation_id?: string;
  inputs: ArtifactRef[];
  outputs: ArtifactRef[];
  error_code?: string;
  note?: string;
  started_at?: string;
  finished_at?: string;
  knowledge?: { revision: string; digest: string }[];
  agent_run_ids?: string[];
}
interface Execution {
  workflow_run_id: string;
  task_id: string;
  plan_id: string;
  plan_digest: string;
  status: string;
  version: number;
  nodes: NodeRun[];
  model: {
    runtime: string;
    runtime_version: string;
    config_version: string;
    model?: string;
  };
  accept_partial_nodes: string[];
  max_parallel?: number;
  max_attempts?: number;
  retry_of?: string;
  scope: ArtifactRef["scope"];
}
interface ScannerInvocation {
  invocation_id: string;
  status: string;
  version: number;
  error_code?: string;
  outputs: ArtifactRef[];
  coverage: {
    input_files: number;
    parsed_files: number;
    unparsed_files: number;
  };
  limitations: string[];
  request: {
    plugin_id: string;
    plugin_version: string;
    package_digest: string;
    inputs: ArtifactRef[];
  };
}
interface ScannerCandidate {
  id: string;
  status: "candidate";
  title: string;
  severity_hint?: "high" | "medium" | "low";
  file: string;
  line: number;
  path_refs: string[];
  evidence_refs: string[];
  limitations: string[];
}
interface ScannerResult {
  kind: string;
  candidates: ScannerCandidate[];
  native_artifact: ArtifactRef;
  limitations: string[];
  coverage: {
    input_files: number;
    parsed_files: number;
    partial_files: number;
    unparsed_files: number;
    unhandled_files: number;
    descriptor_files: number;
    input_bytes: number;
  };
}
interface ScanView {
  invocation?: ScannerInvocation;
  result?: ScannerResult;
  raw?: string;
  error?: string;
}
const kinds: { [key: string]: string } = {
  plugin: "分析插件",
  knowledge_publish: "共享知识发布",
  candidate_analysis: "候选分析",
};
export function WorkflowRun({
  api,
  projectID,
  runID,
  revision,
  onArtifacts,
  onAgentRun,
}: {
  api: ApiClient;
  projectID: string;
  runID: string;
  revision: number;
  onArtifacts: () => void;
  onAgentRun: (id: string) => void;
}) {
  const [run, setRun] = useState<Execution>();
  const [plan, setPlan] = useState<Plan>();
  const [error, setError] = useState("");
  const [tick, refresh] = useState(0);
  const [cursors, setCursors] = useState([0]);
  const [events, setEvents] = useState<Event[]>([]);
  const [next, setNext] = useState(0);
  const [scans, setScans] = useState<{ [node: string]: ScanView }>({});
  const [busy, setBusy] = useState("");
  const endpoint = `/v1/projects/${encodeURIComponent(projectID)}/workflow-runs/${encodeURIComponent(runID)}`;
  const scanKey =
    run?.nodes
      .filter(
        (node) =>
          node.invocation_id &&
          node.outputs.some((ref) => ref.kind === "scanner.alerts"),
      )
      .map((node) => `${node.node_run_id}:${node.invocation_id}`)
      .join("|") || "";
  const after = cursors.at(-1) || 0;
  useEffect(() => {
    const controller = new AbortController();
    setError("");
    (async () => {
      const value = await api.get<{ run: Execution }>(
        endpoint,
        controller.signal,
      );
      setRun(value.run);
      const pinned = await api.get<{ plan: Plan }>(
        `/v1/projects/${encodeURIComponent(projectID)}/workflow-plans/${encodeURIComponent(value.run.plan_id)}`,
        controller.signal,
      );
      setPlan(pinned.plan);
    })().catch((e) => {
      if (!controller.signal.aborted)
        setError(e instanceof Error ? e.message : "流程读取失败");
    });
    return () => controller.abort();
  }, [api, endpoint, projectID, revision, tick]);
  useEffect(() => {
    const controller = new AbortController();
    api
      .get<{ events: Event[]; next_seq: number }>(
        `${endpoint}/events?after_seq=${after}&limit=50`,
        controller.signal,
      )
      .then((page) => {
        setEvents(page.events);
        setNext(page.next_seq);
      })
      .catch((e) => {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : "事件读取失败");
      });
    return () => controller.abort();
  }, [api, endpoint, after, revision, tick]);
  useEffect(() => {
    if (!run || !scanKey) {
      setScans({});
      return;
    }
    const controller = new AbortController();
    const scannerNodes = run.nodes.filter(
      (node) =>
        node.invocation_id &&
        node.outputs.some((ref) => ref.kind === "scanner.alerts"),
    );
    const prefix = `/v1/projects/${encodeURIComponent(projectID)}/snapshots/${encodeURIComponent(run.scope.snapshot_id)}`;
    void (async () => {
      const next: { [node: string]: ScanView } = {};
      for (const node of scannerNodes) {
        if (!node.invocation_id) continue;
        try {
          const detail = await api.get<{ invocation: ScannerInvocation }>(
            `${prefix}/plugin-invocations/${encodeURIComponent(node.invocation_id)}`,
            controller.signal,
          );
          const view: ScanView = { invocation: detail.invocation };
          if (["SUCCEEDED", "PARTIAL"].includes(detail.invocation.status)) {
            view.result = await api.get<ScannerResult>(
              `${prefix}/plugin-invocations/${encodeURIComponent(node.invocation_id)}/result`,
              controller.signal,
            );
          }
          const native = detail.invocation.outputs.find(
            (ref) => ref.kind === "scanner.alerts",
          );
          if (native) {
            const response = await api.response(
              `${prefix}/artifacts/${encodeURIComponent(native.id)}/content?max_bytes=1048576`,
              { signal: controller.signal },
            );
            view.raw = await response.text();
          }
          next[node.node_run_id] = view;
        } catch (e) {
          if (!controller.signal.aborted)
            next[node.node_run_id] = {
              error: e instanceof Error ? e.message : "扫描结果读取失败",
            };
        }
      }
      if (!controller.signal.aborted) setScans(next);
    })();
    return () => controller.abort();
  }, [api, projectID, run?.workflow_run_id, scanKey, revision, tick]);
  const control = async (action: string) => {
    setBusy(action);
    setError("");
    try {
      await api.post(`${endpoint}/${action}`, {});
      refresh((t) => t + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "流程控制失败");
    } finally {
      setBusy("");
    }
  };
  const status = run?.status || "";
  const can = {
    pause: status === "CREATED" || status === "RUNNING",
    resume: status === "PAUSED" || status === "PAUSING",
    cancel: ["CREATED", "RUNNING", "PAUSING", "PAUSED"].includes(status),
    retry: status === "FAILED",
  };
  return (
    <Panel
      title="工作流执行"
      eyebrow="FIXED PLAN · REAL EXECUTION"
      action={
        <button
          className="button secondary small"
          onClick={() => refresh((t) => t + 1)}
        >
          <RefreshCw size={14} />
          刷新流程
        </button>
      }
    >
      {error && <Hint className="error-hint">{error}</Hint>}
      {!run ? (
        <Hint>正在读取流程运行记录…</Hint>
      ) : (
        <>
          <div className="workflow-run-summary">
            <div>
              <Badge status={run.status} label={flowStatus[run.status]} />
              <h3>
                {plan?.workflow.spec.name || run.plan_id} ·{" "}
                {plan?.workflow.spec.version}
              </h3>
              <code>{run.workflow_run_id}</code>
            </div>
            <button className="button secondary small" onClick={onArtifacts}>
              <FileText size={14} />
              查看真实产物
            </button>
          </div>
          <div className="workflow-controls">
            <button className="button secondary small" disabled={!can.pause || !!busy} onClick={() => control("pause")}>
              暂停
            </button>
            <button className="button secondary small" disabled={!can.resume || !!busy} onClick={() => control("resume")}>
              继续
            </button>
            <button className="button secondary small" disabled={!can.cancel || !!busy} onClick={() => control("cancel")}>
              取消
            </button>
            <button className="button secondary small" disabled={!can.retry || !!busy} onClick={() => control("retry")}>
              重试失败流程
            </button>
            <span className="muted">
              并发 {run.max_parallel ?? 2} · 节点重试上限 {run.max_attempts ?? 3}
              {run.retry_of ? ` · 重试自 ${run.retry_of}` : ""}
            </span>
          </div>
          <dl className="workflow-pins">
            <dt>固定计划</dt>
            <dd>
              {run.plan_id}
              <br />
              {run.plan_digest}
            </dd>
            <dt>独立任务</dt>
            <dd>{run.task_id}</dd>
            <dt>Scope</dt>
            <dd>
              {run.scope.project_id} / {run.scope.source_id} /{" "}
              {run.scope.snapshot_id}
            </dd>
            <dt>Runtime / 模型</dt>
            <dd>
              {run.model.runtime}@{run.model.runtime_version}{" "}
              {run.model.model || ""}
            </dd>
            <dt>模型配置版本</dt>
            <dd>{run.model.config_version}</dd>
            <dt>显式接受部分覆盖的节点</dt>
            <dd>{run.accept_partial_nodes.join(", ") || "无"}</dd>
          </dl>
          <div className="table-scroll">
            <table className="standard-table workflow-execution-table">
              <thead>
                <tr>
                  <th>节点 / 类型</th>
                  <th>状态</th>
                  <th>调用与版本</th>
                  <th>输入 / 输出与来源</th>
                </tr>
              </thead>
              <tbody>
                {run.nodes.map((node) => {
                  const fixed = plan?.nodes.find((n) => n.id === node.node_id);
                  return (
                    <tr key={node.node_run_id}>
                      <td>
                        <strong>{node.node_id}</strong>
                        <small>{kinds[node.kind]}</small>
                        <code>{node.node_run_id}</code>
                      </td>
                      <td>
                        <Badge
                          status={node.status}
                          label={flowStatus[node.status]}
                        />
                        {node.error_code && (
                          <small className="error-text">
                            {node.error_code}
                          </small>
                        )}
                        {node.note && <small>{node.note}</small>}
                      </td>
                      <td>
                        {fixed && (
                          <>
                            <strong>
                              {fixed.plugin_id}@{fixed.plugin_version}
                            </strong>
                            <details>
                              <summary>固定包 / 参数</summary>
                              <code>{fixed.plugin.package_digest}</code>
                              <code>{fixed.config_digest}</code>
                            </details>
                          </>
                        )}
                        {node.invocation_id && (
                          <code>invocation: {node.invocation_id}</code>
                        )}
                        {node.knowledge?.map((k) => (
                          <code key={k.revision}>
                            {k.revision} · {k.digest}
                          </code>
                        ))}
                        {node.agent_run_ids?.map((id) => (
                          <button
                            className="text-button"
                            key={id}
                            onClick={() => onAgentRun(id)}
                          >
                            Agent {id}
                            <ArrowRight size={12} />
                          </button>
                        ))}
                      </td>
                      <td>
                        <details>
                          <summary>
                            {node.inputs.length} 输入 → {node.outputs.length}{" "}
                            已发布输出
                          </summary>
                          {node.inputs.map((a) => (
                            <Artifact
                              key={`in-${a.id}`}
                              refValue={a}
                              direction="输入"
                            />
                          ))}
                          {node.outputs.map((a) => (
                            <Artifact
                              key={`out-${a.id}`}
                              refValue={a}
                              direction="输出"
                            />
                          ))}
                        </details>
                        {node.started_at && (
                          <small>
                            {new Date(node.started_at).toLocaleString()}
                          </small>
                        )}
                        {node.finished_at && (
                          <small>
                            结束{" "}
                            {new Date(node.finished_at).toLocaleTimeString()}
                          </small>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {run.nodes
            .filter((node) => scans[node.node_run_id])
            .map((node) => {
              const scan = scans[node.node_run_id];
              const candidates = scan.result?.candidates || [];
              const grades: { [key: string]: string } = {
                high: "高",
                medium: "中",
                low: "低",
              };
              return (
                <div className="workflow-run-scanner" key={node.node_run_id}>
                  <h3>
                    <FileText size={15} />
                    进程扫描告警 · {node.node_id}
                  </h3>
                  {scan.error && <Hint className="error-hint">{scan.error}</Hint>}
                  {scan.invocation && (
                    <>
                      <p className="source-description mono">
                        来源：{scan.invocation.request.plugin_id}@
                        {scan.invocation.request.plugin_version} ·{" "}
                        {scan.invocation.invocation_id} · 状态{" "}
                        {flowStatus[scan.invocation.status] ||
                          scan.invocation.status}
                        {scan.invocation.error_code
                          ? ` · ${scan.invocation.error_code}`
                          : ""}
                      </p>
                      <p className="source-description mono">
                        覆盖：输入 {scan.invocation.coverage.input_files} ·
                        已解析 {scan.invocation.coverage.parsed_files} · 未解析{" "}
                        {scan.invocation.coverage.unparsed_files} · 包{" "}
                        {scan.invocation.request.package_digest.slice(0, 16)}…
                      </p>
                      <p className="source-description mono">
                        知识发布：
                        {run.nodes.find((n) => n.node_id === "$publish")
                          ?.knowledge?.length
                          ? run.nodes
                              .find((n) => n.node_id === "$publish")!
                              .knowledge!.map((k) => `${k.revision} · ${k.digest.slice(0, 16)}…`)
                              .join(", ")
                          : "尚未发布（$publish 被跳过或失败）"}
                      </p>
                    </>
                  )}
                  {scan.result && (
                    <>
                      <Hint>
                        {candidates.length} 个标准候选 · 原始报告{" "}
                        {scan.result.native_artifact.bytes} B · SHA-256{" "}
                        {scan.result.native_artifact.sha256.slice(0, 16)}… ·
                        原始产物 {scan.result.native_artifact.id}
                      </Hint>
                      {candidates.length ? (
                        <div className="table-scroll">
                          <table className="standard-table">
                            <thead>
                              <tr>
                                <th>分级建议</th>
                                <th>告警 / 位置</th>
                                <th>证据与来源</th>
                                <th>局限</th>
                              </tr>
                            </thead>
                            <tbody>
                              {candidates.map((candidate) => (
                                <tr key={candidate.id}>
                                  <td>
                                    {candidate.severity_hint
                                      ? `${grades[candidate.severity_hint]}危建议`
                                      : "待评估"}
                                  </td>
                                  <td>
                                    <strong>{candidate.title}</strong>
                                    <code>
                                      {candidate.file}:{candidate.line}
                                    </code>
                                    <small>{candidate.id}</small>
                                  </td>
                                  <td>
                                    <code>
                                      {candidate.evidence_refs.join(", ")}
                                    </code>
                                    <small>
                                      插件{" "}
                                      {scan.invocation?.request.plugin_id}@
                                      {scan.invocation?.request.plugin_version}
                                    </small>
                                  </td>
                                  <td>
                                    <details>
                                      <summary>
                                        {candidate.limitations.length} 项
                                      </summary>
                                      <ul>
                                        {candidate.limitations.map(
                                          (note, index) => (
                                            <li key={index}>{note}</li>
                                          ),
                                        )}
                                      </ul>
                                    </details>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <Hint>
                          本次范围没有标准告警；这不代表目标代码不存在漏洞。
                        </Hint>
                      )}
                      <details className="source-description">
                        <summary>
                          原始报告与覆盖局限 ·{" "}
                          {scan.result.native_artifact.schema_id}
                        </summary>
                        <pre className="artifact-preview">
                          {scan.raw || "原始报告不可用"}
                        </pre>
                        <ul>
                          {scan.result.limitations.map((note, index) => (
                            <li key={index}>{note}</li>
                          ))}
                        </ul>
                      </details>
                    </>
                  )}
                </div>
              );
            })}
          <div className="workflow-run-events">
            <h3>
              <GitBranch size={15} />
              节点事件 · 有序持久化记录
            </h3>
            <div className="table-scroll">
              <table className="standard-table">
                <thead>
                  <tr>
                    <th>序号</th>
                    <th>事件</th>
                    <th>节点</th>
                    <th>状态</th>
                    <th>时间</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.seq}>
                      <td>{e.seq}</td>
                      <td>{e.type}</td>
                      <td>{e.node_id || "流程"}</td>
                      <td>{flowStatus[e.status] || e.status}</td>
                      <td>{new Date(e.created_at).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="workflow-pagination">
              <button
                className="text-button"
                disabled={cursors.length === 1}
                onClick={() => setCursors((c) => c.slice(0, -1))}
              >
                上一页事件
              </button>
              <span>第 {cursors.length} 页</span>
              <button
                className="text-button"
                disabled={events.length < 50 || next <= after}
                onClick={() => setCursors((c) => [...c, next])}
              >
                下一页事件
              </button>
            </div>
          </div>
          <Hint>
            流程状态与候选结论分别记录。暂停只阻断新节点，活动节点会在边界完成；取消等待执行器终态；重试仅对失败运行生效并复用已完成的节点产物。旧路径调度不会接管该任务。
          </Hint>
        </>
      )}
    </Panel>
  );
}
function Artifact({
  refValue: a,
  direction,
}: {
  refValue: ArtifactRef;
  direction: string;
}) {
  return (
    <div className="workflow-run-artifact">
      <strong>
        {direction} · {a.kind}
      </strong>
      <code>{a.id}</code>
      <small>
        {a.schema_id} · {a.bytes} B
      </small>
      <code>SHA-256 {a.sha256}</code>
    </div>
  );
}
