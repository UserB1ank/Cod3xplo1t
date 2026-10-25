import {
  Fragment,
  useId,
  useRef,
  useCallback,
  useEffect,
  useState,
  type KeyboardEvent,
} from "react";
import {
  ArrowDown,
  ArrowUp,
  ChevronRight,
  GitBranch,
  ListChecks,
  Loader2,
  Network,
  RefreshCw,
  Search,
} from "lucide-react";
import { ApiClient, ApiError } from "./api";
import { CodeBlock, EmptyState, Hint, Modal, Panel } from "./components";
import type { PathSubtask, Snapshot } from "./types";
import {
  layoutEntryGraph,
  callGraphNeighborhood,
  type CallNeighborhood,
} from "./entry-graph";
import { latestSnapshot } from "./workbench";
import { readRevisionDirectory } from "./knowledgeData";

type Layer = "entries" | "scg" | "asg" | "paths";

interface LayerInfo {
  status: "available" | "not_built" | "unavailable";
  version?: string;
  built_at?: string;
  detail?: string;
  tasks?: number;
  analyses?: number;
  items?: number;
}

interface View {
  view_id: string;
  revision: string;
  scope: { project_id: string; snapshot_id: string };
  layers: Partial<Record<Layer, LayerInfo>>;
  engine: { name: string; version: string };
  coverage: Record<string, number>;
  limitations: string[];
}

interface Meta {
  view_id: string;
  revision: string;
  layer: Layer;
  versions: Record<string, string>;
  total: number;
  truncated: boolean;
  truncation_reason?: string;
  omitted?: number;
  limitations?: string[];
}

interface Symbol {
  symbol_id: string;
  name: string;
  qualified_name: string;
  kind: string;
  file: string;
  start_line: number;
  end_line: number;
}

interface AttackNode {
  node_id: string;
  kind: string;
  label: string;
  subject: string;
  file?: string;
  line?: number;
  confidence?: string;
  generator?: string;
  module_id?: string;
  detail?: Record<string, string>;
  scg_refs?: string[];
  evidence_status?: string;
}

interface ASGEdge {
  edge_id: string;
  from: string;
  to: string;
  kind: string;
  evidence_status?: string;
  confidence?: string;
  generator?: string;
  scg_refs?: string[];
  detail?: Record<string, string>;
}

interface Neighborhood {
  root: AttackNode;
  nodes: AttackNode[];
  edges: ASGEdge[];
  unresolved_edges: number;
  meta: Meta;
  limitations: string[];
}

interface AuditRef {
  audit_id: string;
  name?: string;
  status?: string;
  paths: number;
}

interface AuditPath {
  path_id: string;
  audit_id: string;
  snapshot_id: string;
  entry_subject: string;
  entry_node_id?: string;
  target_subject: string;
  target_kind: string;
  path_kind: string;
  path_status: string;
  status: string;
  steps?: {
    layer: string;
    subject?: string;
    file?: string;
    line?: number;
    kind: string;
    evidence?: string;
  }[];
  scg_refs?: string[];
  limitations?: string[];
  score?: {
    priority: number;
    support: number;
    risk: number;
    utility: number;
    score_version?: number;
    weights?: Record<string, number>;
  };
  selection?: {
    selection: "selected" | "filtered";
    reason: string;
    filter_code?: string;
    score_version: number;
    weights_digest: string;
    source_path_id: string;
    producer_plugin?: string;
  };
  features?: { reasons?: Record<string, string> };
}

interface AnalysisRef {
  analysis_id: string;
  producer: {
    plugin_id: string;
    plugin_version: string;
    invocation_id: string;
  };
  path_count: number;
  has_paths: boolean;
  native_artifact: { id: string; sha256: string };
  limitations: string[];
}

interface Provenance {
  analyses?: AnalysisRef[];
  fact_id: string;
  kind: "symbol" | "asg_node";
  versions: Record<string, string>;
  producer: {
    plugin_id: string;
    plugin_version: string;
    invocation_id: string;
    config_digest: string;
  };
  location?: { file: string; start_line: number; end_line: number };
  tasks: AuditRef[];
  artifacts?: { id: string; kind: string; sha256: string; bytes: number }[];
  node?: { node: AttackNode; derived_from?: { id: string; kind?: string }[] };
}

interface Slice {
  slice: {
    sections: {
      reason: string;
      symbol?: string;
      file: string;
      start_line: number;
      end_line: number;
      lines: string[];
      truncated: boolean;
      total_lines?: number;
      note?: string;
    }[];
    limitations: string[];
  };
  meta: Meta;
}

function shortEntryName(label: string) {
  const parts = label.replace(/\/+$/, "").split(/[./]/).filter(Boolean);
  return parts[parts.length - 1] || label;
}

function entryTitle(node: AttackNode) {
  const label = (node.label || "").split(" · ")[0];
  const location = label.match(/^(.*\.go):(\d+)$/);
  if (location) return `${location[1].split("/").pop()}:${location[2]}`;
  return shortEntryName(label || node.subject || node.node_id);
}

function sourceNote(note?: string) {
  if (!note) return "";
  if (note.includes("function end was not recorded"))
    return "图谱未记录函数结束行；这里按行窗口读取，不伪造函数边界。";
  if (note.includes("declaration as recorded"))
    return "图谱记录的声明位置。";
  if (note.includes("requested file window"))
    return "按行窗口读取的固定源码片段。";
  return note;
}

const layerLabels: Record<Layer, string> = {
  entries: "程序入口",
  scg: "源码图谱",
  asg: "攻击面",
  paths: "候选路径",
};

const layerHints: Record<Layer, string> = {
  entries: "按入口查看 1–2 跳模块与调用关系，再进入源码与证据。",
  scg: "符号、调用关系与真实源码位置。",
  asg: "从源码事实提取的入口、敏感操作与控制。",
  paths: "固定快照的任务与直接插件分析发布的候选路径，可选择交给 Agent。",
};

function failureText(error: unknown) {
  if (error instanceof ApiError) {
    if (error.code === "view_superseded")
      return "图谱在该视图固定之后已重建，请刷新图谱。";
    if (error.code === "knowledge_unavailable")
      return "该快照尚未构建代码图谱。";
    if (error.code === "layer_unavailable") return error.message;
    if (error.code === "knowledge_not_found")
      return "视图不存在，或不属于当前项目与快照。";
    return error.message;
  }
  return error instanceof Error ? error.message : "图谱查询失败";
}

function useQuery<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: unknown[],
) {
  const [state, setState] = useState<{
    data?: T;
    error?: string;
    loading: boolean;
  }>({ loading: true });
  useEffect(() => {
    const controller = new AbortController();
    setState({ loading: true });
    load(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setState({ data, loading: false });
      })
      .catch((error) => {
        if (controller.signal.aborted) return;
        setState({ error: failureText(error), loading: false });
      });
    return () => controller.abort();
  }, deps);
  return state;
}

function MetaBar({ meta }: { meta: Meta }) {
  return (
    <div className="knowledge-meta">
      <span>
        版本固定{" "}
        <code className="mono">{meta.versions.scg || meta.revision}</code>
      </span>
      <span>共 {meta.total} 条</span>
      {meta.truncated ? (
        <span className="knowledge-warning">
          结果被截断
          {meta.truncation_reason ? `（${meta.truncation_reason}）` : ""}
        </span>
      ) : null}
      {meta.omitted ? (
        <span className="knowledge-warning">
          已省略 {meta.omitted} 条旧版本记录
        </span>
      ) : null}
    </div>
  );
}

export function Knowledge({
  api,
  projectID,
  snapshots,
  revision,
  canWrite,
  agentAvailable,
  mode = "graph",
  onWorkbench,
}: {
  api: ApiClient;
  projectID: string;
  snapshots: Snapshot[];
  revision: number;
  canWrite: boolean;
  agentAvailable: boolean;
  mode?: "graph" | "paths";
  onWorkbench?: (selectionID?: string) => void;
}) {
  const [selectedSnapshot, setSelectedSnapshot] = useState("");
  const snapshot =
    snapshots.find((item) => item.snapshot_id === selectedSnapshot) ||
    latestSnapshot(snapshots);
  const snapshotID = snapshot?.snapshot_id || "";
  const [layer, setLayer] = useState<Layer>(
    mode === "paths" ? "paths" : "entries",
  );
  const [view, setView] = useState<View>();
  const [viewError, setViewError] = useState("");
  const [viewLoading, setViewLoading] = useState(false);
  const openController = useRef<AbortController>();
  const [openCount, setOpenCount] = useState(0);
  const [selectedSymbol, setSelectedSymbol] = useState<Symbol>();
  const [selectedNode, setSelectedNode] = useState<AttackNode>();
  const [selectedEntry, setSelectedEntry] = useState<AttackNode>();
  const [selectedPath, setSelectedPath] = useState<AuditPath>();

  const openView = useCallback(() => {
    if (!snapshotID) return;
    openController.current?.abort();
    const controller = new AbortController();
    openController.current = controller;
    setViewLoading(true);
    setViewError("");
    api
      .post<{ view: View }>(
        `/v1/projects/${projectID}/knowledge/views`,
        {
          api_version: "codexploit/v1",
          snapshot_id: snapshotID,
        },
        controller.signal,
      )
      .then((page) => {
        if (!controller.signal.aborted) setView(page.view);
      })
      .catch((error) => {
        if (controller.signal.aborted) return;
        setView(undefined);
        setViewError(failureText(error));
      })
      .finally(() => {
        if (!controller.signal.aborted) setViewLoading(false);
      });
  }, [api, projectID, snapshotID]);

  useEffect(() => {
    setView(undefined);
    setSelectedSymbol(undefined);
    setSelectedNode(undefined);
    setSelectedEntry(undefined);
    setSelectedPath(undefined);
    openView();
    return () => openController.current?.abort();
  }, [openView, revision, openCount]);

  if (!snapshotID) {
    return (
      <EmptyState title="等待源码输入就绪">
        创建项目时会自动保存源码。请在项目总览查看输入状态，再开始图谱化分析。
      </EmptyState>
    );
  }

  const layerState =
    layer === "entries" ? view?.layers.asg : view?.layers[layer];
  const layerReady = layerState?.status === "available";

  return (
    <>
      <div className="knowledge-toolbar">
        <div>
          <Network size={16} />
          <strong>代码版本</strong>
          <select
            aria-label="图谱代码版本"
            value={snapshotID}
            onChange={(event) => setSelectedSnapshot(event.target.value)}
          >
            {[...snapshots].reverse().map((item) => (
              <option value={item.snapshot_id} key={item.snapshot_id}>
                {item.commit.slice(0, 12)} · {item.created_at.slice(0, 10)}
              </option>
            ))}
          </select>
        </div>
        <div className="knowledge-layers" role="tablist" aria-label="图谱图层">
          {(mode === "paths"
            ? (["paths"] as Layer[])
            : (["entries", "scg", "asg"] as Layer[])
          ).map((name) => {
            const state = view?.layers[name];
            return (
              <button
                key={name}
                role="tab"
                aria-selected={layer === name}
                className={`knowledge-layer ${layer === name ? "selected" : ""}`}
                onClick={() => setLayer(name)}
                title={layerHints[name]}
              >
                {layerLabels[name]}
                {state ? (
                  <span className={`layer-dot ${state.status}`}>
                    {state.status === "available"
                      ? ""
                      : state.status === "not_built"
                        ? "未构建"
                        : "不可用"}
                  </span>
                ) : null}
              </button>
            );
          })}
        </div>
        <span className="knowledge-keyhint muted">
          <ArrowUp size={12} />
          <ArrowDown size={12} /> 选择节点，回车打开
        </span>
        <button
          className="button"
          onClick={() => setOpenCount((n) => n + 1)}
          disabled={viewLoading}
        >
          <RefreshCw size={15} className={viewLoading ? "spin" : ""} /> 刷新图谱
        </button>
      </div>

      {viewLoading ? (
        <Panel title="正在读取图谱">
          <div className="knowledge-loading">
            <Loader2 className="spin" size={18} /> 读取该快照的图层版本…
          </div>
        </Panel>
      ) : viewError ? (
        <Panel title="图谱不可用">
          <Hint>{viewError}</Hint>
          <button className="button" onClick={openView}>
            <RefreshCw size={15} /> 重试
          </button>
        </Panel>
      ) : view ? (
        <>
          <CoverageStrip view={view} />
          <details className="knowledge-version-details">
            <summary>
              知识版本与工具来源 <span className="mono">{view.revision}</span>
            </summary>
            <PublicationPanel
              api={api}
              projectID={projectID}
              snapshotID={snapshotID}
            />
          </details>
          {layerState && layerState.status !== "available" ? (
            <Panel title={layerLabels[layer]}>
              <EmptyState
                title={layerState.detail || `${layerLabels[layer]}不可用`}
              >
                {layer === "asg"
                  ? "构建代码源快照时勾选攻击面，或等待后续版本补齐。"
                  : layer === "paths"
                    ? "可从插件中心发布路径分析结果，或从任务生成候选路径。"
                    : null}
              </EmptyState>
            </Panel>
          ) : layer === "entries" ? (
            <div className="entry-explorer panel">
              <EntryPanel
                api={api}
                projectID={projectID}
                view={view}
                onSelect={setSelectedEntry}
                selected={selectedEntry}
              />
              <section
                className="entry-explorer-main"
                aria-label="入口局部图谱"
              >
                {selectedEntry ? (
                  <EntryInspector
                    key={selectedEntry.node_id}
                    api={api}
                    projectID={projectID}
                    view={view}
                    entry={selectedEntry}
                  />
                ) : (
                  <EmptyState title="选择程序入口">
                    从左侧入口开始，查看局部调用关系与源码。
                  </EmptyState>
                )}
              </section>
            </div>
          ) : layer === "scg" ? (
            <SymbolPanel
              api={api}
              projectID={projectID}
              view={view}
              onSelect={setSelectedSymbol}
              selected={selectedSymbol}
            />
          ) : layer === "asg" ? (
            <NodePanel
              api={api}
              projectID={projectID}
              view={view}
              onSelect={setSelectedNode}
              selected={selectedNode}
            />
          ) : (
            <PathPanel
              api={api}
              projectID={projectID}
              view={view}
              onSelect={setSelectedPath}
              selected={selectedPath}
              canWrite={canWrite}
              agentAvailable={agentAvailable}
              onWorkbench={onWorkbench}
            />
          )}
          {view.limitations.length ? (
            <details className="limitations">
              <summary>覆盖说明与限制</summary>
              <ul>
                {view.limitations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </details>
          ) : null}
        </>
      ) : null}

      <Modal
        open={!!selectedSymbol}
        onClose={() => setSelectedSymbol(undefined)}
        title="源码与来源"
        wide
        variant="drawer"
      >
        {selectedSymbol && view ? (
          <SymbolInspector
            api={api}
            projectID={projectID}
            view={view}
            symbol={selectedSymbol}
          />
        ) : null}
      </Modal>
      <Modal
        open={!!selectedNode}
        onClose={() => setSelectedNode(undefined)}
        title="攻击面节点与来源"
        wide
        variant="drawer"
      >
        {selectedNode && view ? (
          <NodeInspector
            api={api}
            projectID={projectID}
            view={view}
            node={selectedNode}
          />
        ) : null}
      </Modal>
      <Modal
        open={!!selectedPath}
        onClose={() => setSelectedPath(undefined)}
        title="审计路径"
        wide
        variant="drawer"
      >
        {selectedPath && view ? (
          <PathInspector
            api={api}
            projectID={projectID}
            view={view}
            row={selectedPath}
          />
        ) : null}
      </Modal>
    </>
  );
}

function CoverageStrip({ view }: { view: View }) {
  const parsed = view.coverage.files_parsed ?? 0;
  const total = view.coverage.files_in_snapshot ?? 0;
  return (
    <div className="task-stat-strip knowledge-coverage">
      <div>
        <span>源码文件</span>
        <strong>
          {parsed}/{total}
        </strong>
      </div>
      <div>
        <span>部分或未解析</span>
        <strong>
          {(view.coverage.files_unparsed ?? 0) +
            (view.coverage.files_partial ?? 0)}
        </strong>
      </div>
      <div>
        <span>跳过符号</span>
        <strong>{view.coverage.symbols_skipped ?? 0}</strong>
      </div>
      <div>
        <span>共享任务 / 直接路径分析</span>
        <strong>
          {view.layers.paths?.tasks ?? 0} / {view.layers.paths?.analyses ?? 0}
        </strong>
      </div>
      <div>
        <span>引擎</span>
        <strong className="mono">{view.engine.version}</strong>
      </div>
    </div>
  );
}

interface PublishedFact {
  id: string;
  kind: string;
  label: string;
  location?: { file: string; start_line: number; end_line: number };
  confidence?: string;
  observations: {
    observation_id: string;
    producer: {
      plugin_id: string;
      plugin_version: string;
      invocation_id: string;
      task_id?: string;
      config_digest: string;
    };
    attributes?: Record<string, string>;
    evidence_refs?: string[];
  }[];
}

// PublicationPanel shows the immutable versions a producer published and every
// observation behind one fact, so two tools that disagree stay visible.
function PublicationPanel({
  api,
  projectID,
  snapshotID,
}: {
  api: ApiClient;
  projectID: string;
  snapshotID: string;
}) {
  const revisions = useQuery(
    (signal) => readRevisionDirectory(api, projectID, snapshotID, signal),
    [api, projectID, snapshotID],
  );
  const [selected, setSelected] = useState("");
  const [expanded, setExpanded] = useState("");
  const latest = revisions.data?.revisions[revisions.data.revisions.length - 1];
  const active =
    revisions.data?.revisions.find((item) => item.revision === selected) ||
    latest;
  const { cursor, page, next, back, reset } = usePager();
  useEffect(() => {
    reset();
    setExpanded("");
  }, [active?.view.view_id, reset]);
  const facts = useQuery(
    (signal) =>
      active
        ? api.get<{ facts: PublishedFact[]; next_cursor: string }>(
            `/v1/projects/${projectID}/knowledge/revisions/${encodeURIComponent(active.view.view_id)}/facts?snapshot_id=${encodeURIComponent(snapshotID)}&limit=50&cursor=${encodeURIComponent(cursor)}`,
            signal,
          )
        : Promise.resolve({ facts: [], next_cursor: "" }),
    [api, projectID, snapshotID, active?.view.view_id, cursor],
  );
  return (
    <Panel
      title="共享知识版本"
      action={
        revisions.data?.revisions.length ? (
          <select
            aria-label="已发布知识版本"
            value={active?.revision || ""}
            onChange={(event) => setSelected(event.target.value)}
          >
            {revisions.data.revisions.map((item) => (
              <option value={item.revision} key={item.revision}>
                {item.revision} · {item.producer.plugin_id}@
                {item.producer.plugin_version}
              </option>
            ))}
          </select>
        ) : null
      }
    >
      {revisions.error ? (
        <Hint>{revisions.error}</Hint>
      ) : revisions.loading ? (
        <div className="knowledge-loading">
          <Loader2 className="spin" size={16} /> 读取发布版本…
        </div>
      ) : !revisions.data?.revisions.length ? (
        <Hint>
          该快照还没有发布版本。在插件中心完成语义或路径分析并发布后，这里会列出不可变版本和来源。
        </Hint>
      ) : facts.error ? (
        <Hint>{facts.error}</Hint>
      ) : facts.loading ? (
        <div className="knowledge-loading">
          <Loader2 className="spin" size={16} /> 读取已发布事实…
        </div>
      ) : !facts.data?.facts.length ? (
        <EmptyState title="该版本没有事实">发布批次只包含覆盖说明。</EmptyState>
      ) : (
        <>
          <div className="table-scroll">
            <table className="standard-table knowledge-table">
              <thead>
                <tr>
                  <th>事实</th>
                  <th>类型</th>
                  <th>代码位置</th>
                  <th>来源</th>
                </tr>
              </thead>
              <tbody>
                {facts.data.facts.map((fact) => (
                  <Fragment key={fact.id}>
                    <tr>
                      <td>
                        <strong>{fact.label || fact.id}</strong>
                        <span className="mono muted">{fact.id}</span>
                      </td>
                      <td>{fact.kind}</td>
                      <td className="mono">
                        {fact.location
                          ? `${fact.location.file}:${fact.location.start_line}`
                          : "—"}
                      </td>
                      <td>
                        <button
                          className="text-button"
                          aria-expanded={expanded === fact.id}
                          onClick={() =>
                            setExpanded(expanded === fact.id ? "" : fact.id)
                          }
                        >
                          {fact.observations.length} 个观察
                        </button>
                      </td>
                    </tr>
                    {expanded === fact.id ? (
                      <tr className="knowledge-observation-row">
                        <td colSpan={4}>
                          <ul className="knowledge-observations">
                            {fact.observations.map((observation) => (
                              <li key={observation.observation_id}>
                                <span className="mono">
                                  {observation.producer.plugin_id}@
                                  {observation.producer.plugin_version}
                                </span>
                                {observation.producer.task_id ? (
                                  <span className="muted">
                                    {" "}
                                    · 任务 {observation.producer.task_id}
                                  </span>
                                ) : null}
                                <p className="mono">
                                  调用 {observation.producer.invocation_id}
                                </p>
                                <p className="mono">
                                  配置 {observation.producer.config_digest}
                                </p>
                                {observation.evidence_refs?.length ? (
                                  <p className="mono">
                                    证据 {observation.evidence_refs.join(" · ")}
                                  </p>
                                ) : null}
                                {observation.attributes ? (
                                  <dl>
                                    {Object.entries(observation.attributes).map(
                                      ([key, value]) => (
                                        <div key={key}>
                                          <dt>{key}</dt>
                                          <dd className="mono">{value}</dd>
                                        </div>
                                      ),
                                    )}
                                  </dl>
                                ) : null}
                              </li>
                            ))}
                          </ul>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
          <div className="knowledge-meta">
            <span>
              版本固定 <code className="mono">{active?.revision}</code>
            </span>
            <span>本页 {facts.data.facts.length} 条事实</span>
            <span>批次 {active?.batch_id}</span>
          </div>
          <div className="knowledge-pager">
            <button className="button" disabled={page === 0} onClick={back}>
              上一页
            </button>
            <span>第 {page + 1} 页</span>
            <button
              className="button"
              disabled={!facts.data.next_cursor}
              onClick={() => next(facts.data?.next_cursor || "")}
            >
              下一页
            </button>
          </div>
        </>
      )}
    </Panel>
  );
}

function usePager() {
  const [cursors, setCursors] = useState<string[]>([""]);
  const cursor = cursors[cursors.length - 1] || "";
  const reset = useCallback(() => setCursors([""]), []);
  const next = useCallback(
    (value: string) =>
      setCursors((stack) => (value ? [...stack, value] : stack)),
    [],
  );
  const back = useCallback(
    () =>
      setCursors((stack) => (stack.length > 1 ? stack.slice(0, -1) : stack)),
    [],
  );
  return { cursor, page: cursors.length - 1, next, back, reset };
}

function pathReviewState(item?: PathSubtask) {
  if (!item) return "待选择";
  switch (item.state) {
    case "SUCCEEDED":
    case "CONCLUDED":
      return "审查已完成 · 已创建任务";
    case "FAILED":
    case "INVALID_OUTPUT":
      return "审查失败 · 已创建任务";
    case "PAUSED":
      return "审查已暂停 · 已创建任务";
    case "CANCELLED":
      return "审查已停止 · 已创建任务";
    case "RUNNING":
    case "ANALYZING":
    case "QUEUED":
      return "审查进行中 · 已创建任务";
    default:
      return `已创建任务 · ${item.state}`;
  }
}

function SourceReader({
  api,
  base,
  snapshotID,
  initial,
  focusLine,
  artifactHint,
}: {
  api: ApiClient;
  base: string;
  snapshotID: string;
  initial: Slice;
  focusLine: number;
  artifactHint?: string;
}) {
  const first = initial.slice.sections[0];
  const [window, setWindow] = useState<{
    file: string;
    start: number;
    end: number;
  }>();
  const [focus, setFocus] = useState(focusLine);
  useEffect(() => {
    setWindow(undefined);
    setFocus(focusLine);
  }, [focusLine, initial]);
  const loaded = useQuery<Slice | undefined>(
    (signal) =>
      window
        ? api.get<Slice>(
            `${base}/code-slice?file=${encodeURIComponent(window.file)}&start_line=${window.start}&end_line=${window.end}&max_lines=400&max_sections=1`,
            signal,
          )
        : Promise.resolve(undefined),
    [api, base, window?.file, window?.start, window?.end],
  );
  const active = window ? loaded.data : initial;
  const section = active?.slice.sections[0];
  if (!section) return <Hint>固定快照中没有可读取的源码窗口。</Hint>;
  const total = section.total_lines || 0;
  const atStart = section.start_line <= 1;
  const atEnd = total > 0 && section.end_line >= total;
  const open = (start: number, end: number) =>
    setWindow({
      file: section.file,
      start: Math.max(1, start),
      end: Math.max(start, end),
    });
  const focusInSection =
    focus >= section.start_line && focus <= section.end_line;
  return (
    <div className="source-reader">
      <div className="source-reader-bar">
        <span className="mono">
          {section.file}:{section.start_line}–{section.end_line}
          {total ? ` / ${total} 行` : ""}
        </span>
        <span className="source-reader-actions">
          <button
            className="button secondary"
            type="button"
            disabled={atStart}
            onClick={() => open(section.start_line - 80, section.start_line - 1)}
          >
            <ArrowUp size={13} /> 前 80 行
          </button>
          <button
            className="button secondary"
            type="button"
            disabled={atEnd}
            onClick={() => open(section.end_line + 1, section.end_line + 80)}
          >
            <ArrowDown size={13} /> 后 80 行
          </button>
          <button
            className="button secondary"
            type="button"
            disabled={atStart && atEnd}
            onClick={() => open(1, 400)}
          >
            文件开头
          </button>
        </span>
      </div>
      {section.note && (
        <p className="source-reader-note">{sourceNote(section.note)}</p>
      )}
      {section.truncated && (
        <p className="source-reader-note">
          本窗口按行数预算截断，继续阅读不会伪造函数边界。
        </p>
      )}
      {artifactHint && <p className="source-reader-note">{artifactHint}</p>}
      {loaded.error && <Hint>{loaded.error}</Hint>}
      {loaded.loading && (
        <div className="knowledge-loading">
          <Loader2 className="spin" size={14} /> 读取相邻源码…
        </div>
      )}
      <CodeBlock
        file={section.file}
        lines={section.lines.map((content, offset) => ({
          line: section.start_line + offset,
          content,
          highlight: focusInSection && section.start_line + offset === focus,
        }))}
      />
      {!atEnd && (
        <div className="source-reader-more">
          <span>还有后续源码；按行窗口继续读取。</span>
          <button
            className="text-button"
            type="button"
            onClick={() => open(section.end_line + 1, section.end_line + 80)}
          >
            继续向后 <ChevronRight size={13} />
          </button>
        </div>
      )}
      <span className="source-reader-pin">
        固定快照 <code className="mono">{snapshotID}</code>
      </span>
    </div>
  );
}

function EntryPanel({
  api,
  projectID,
  view,
  onSelect,
  selected,
}: {
  api: ApiClient;
  projectID: string;
  view: View;
  onSelect: (node: AttackNode) => void;
  selected?: AttackNode;
}) {
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const { cursor, page, next, back, reset } = usePager();
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(query);
      reset();
    }, 250);
    return () => clearTimeout(timer);
  }, [query, reset]);
  const data = useQuery(
    (signal) =>
      api.get<{ nodes: AttackNode[]; next_cursor: string; meta: Meta }>(
        `/v1/projects/${projectID}/knowledge/views/${view.view_id}/nodes?kind=EntryPoint&q=${encodeURIComponent(search)}&limit=20&cursor=${encodeURIComponent(cursor)}`,
        signal,
      ),
    [api, projectID, view.view_id, search, cursor],
  );
  useEffect(() => {
    if (
      data.data?.nodes.length &&
      !data.data.nodes.some((node) => node.node_id === selected?.node_id)
    )
      onSelect(data.data.nodes[0]);
  }, [data.data, selected?.node_id, onSelect]);
  const duplicateCounts = new Map<string, number>();
  for (const node of data.data?.nodes || []) {
    const key = `${node.subject}|${node.file || ""}|${node.line || 0}|${node.generator || ""}`;
    duplicateCounts.set(key, (duplicateCounts.get(key) || 0) + 1);
  }
  return (
    <Panel
      title="程序入口"
      action={
        <div className="search-input">
          <Search size={15} />
          <input
            aria-label="搜索入口"
            placeholder="搜索路由、命令或输入入口…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
      }
    >
      {data.error ? (
        <Hint>{data.error}</Hint>
      ) : data.loading ? (
        <div className="knowledge-loading">
          <Loader2 className="spin" size={16} /> 读取入口目录…
        </div>
      ) : !data.data?.nodes.length ? (
        <EmptyState title="没有匹配的入口">
          该快照没有构建攻击面，或搜索词没有命中入口。入口缺失不会用示例图替代。
        </EmptyState>
      ) : (
        <>
          <div className="program-entry-list">
            {data.data.nodes.map((node) => (
              <button
                key={node.node_id}
                aria-pressed={selected?.node_id === node.node_id}
                className={selected?.node_id === node.node_id ? "selected" : ""}
                title={[
                  node.label,
                  node.file ? `${node.file}:${node.line || 0}` : "",
                  node.generator ? `来源 ${node.generator}` : "",
                  node.module_id ? `规则 ${node.module_id}` : "",
                  node.evidence_status ? `证据 ${node.evidence_status}` : "",
                  `ID ${node.node_id}`,
                ]
                  .filter(Boolean)
                  .join(" · ")}
                onClick={() => onSelect(node)}
              >
                <span className="entry-kind">
                  {node.subject.startsWith("http_route:")
                    ? "HTTP 入口"
                    : "程序入口"}
                </span>
                <span className="entry-title-line">
                  <strong>{entryTitle(node)}</strong>
                  {(duplicateCounts.get(
                    `${node.subject}|${node.file || ""}|${node.line || 0}|${node.generator || ""}`,
                  ) || 0) > 1 && (
                    <span
                      className="entry-duplicate"
                      title="相同源码位置与来源的独立观察；ID 未合并"
                    >
                      同名 ×
                      {duplicateCounts.get(
                        `${node.subject}|${node.file || ""}|${node.line || 0}|${node.generator || ""}`,
                      )}
                    </span>
                  )}
                </span>
                <code className="entry-qualified">{node.label}</code>
                <small>
                  {node.file ? `${node.file}:${node.line || 0}` : "源码未解析"}
                  {node.generator ? ` · ${node.generator}` : ""}
                  {node.module_id ? ` · ${node.module_id}` : ""}
                  {node.confidence ? ` · ${node.confidence}` : ""}
                </small>
              </button>
            ))}
          </div>
          <div className="knowledge-pager">
            <button className="button" disabled={page === 0} onClick={back}>
              上一页
            </button>
            <span>第 {page + 1} 页</span>
            <button
              className="button"
              disabled={!data.data.next_cursor}
              onClick={() => next(data.data?.next_cursor || "")}
            >
              下一页
            </button>
          </div>
          <MetaBar meta={data.data.meta} />
        </>
      )}
    </Panel>
  );
}

function EntryInspector({
  api,
  projectID,
  view,
  entry,
}: {
  api: ApiClient;
  projectID: string;
  view: View;
  entry: AttackNode;
}) {
  const base = `/v1/projects/${projectID}/knowledge/views/${view.view_id}`;
  const [focus, setFocus] = useState(entry);
  const [center, setCenter] = useState(entry);
  const [depth, setDepth] = useState(2);
  const [graphKind, setGraphKind] = useState<"calls" | "semantic">(
    entry.scg_refs?.some((id) => id.startsWith("sym-")) ? "calls" : "semantic",
  );
  const rootSymbol = center.scg_refs?.find((id) => id.startsWith("sym-"));
  const [edge, setEdge] = useState<ASGEdge>();
  const [copyStatus, setCopyStatus] = useState("");
  const neighborhood = useQuery(
    async (signal) => {
      if (graphKind === "calls" && rootSymbol) {
        const result = await api.get<{
          neighborhood: CallNeighborhood;
          meta: Meta;
        }>(
          `${base}/neighborhood?symbol_id=${encodeURIComponent(rootSymbol)}&direction=callees&depth=${depth}&max_nodes=30`,
          signal,
        );
        const graph = callGraphNeighborhood(result.neighborhood);
        return {
          neighborhood: {
            ...graph,
            meta: {
              ...result.meta,
              truncated: result.meta.truncated || graph.meta.truncated,
            },
          } as Neighborhood,
          meta: result.meta,
        };
      }
      return api.get<{ neighborhood: Neighborhood; meta: Meta }>(
        `${base}/asg-neighborhood?node_id=${encodeURIComponent(center.node_id)}&depth=${depth}&max_nodes=30`,
        signal,
      );
    },
    [api, base, center.node_id, depth, rootSymbol, graphKind],
  );
  useEffect(() => {
    const graph = neighborhood.data?.neighborhood;
    if (
      graph &&
      graph.root.node_id ===
        (graphKind === "calls" ? rootSymbol : center.node_id) &&
      !graph.nodes.some((node) => node.node_id === focus.node_id)
    )
      setFocus(graph.root);
  }, [neighborhood.data, focus.node_id, graphKind, rootSymbol, center.node_id]);
  const symbolRef = focus.scg_refs?.find((id) => id.startsWith("sym-"));
  const slice = useQuery<Slice | undefined>(
    (signal) =>
      symbolRef
        ? api.get<Slice>(
            `${base}/code-slice?symbol_id=${encodeURIComponent(symbolRef)}&max_lines=80&max_sections=1&context_lines=6`,
            signal,
          )
        : focus.file
          ? api
              .post<{ sections: { start_line: number; lines: string[] }[] }>(
                `/snapshots/${view.scope.snapshot_id}/graph/slice`,
                {
                  file: focus.file,
                  start_line: Math.max(1, (focus.line || 1) - 5),
                  end_line: (focus.line || 1) + 15,
                  max_lines: 25,
                },
                signal,
              )
              .then((value) => ({
                slice: {
                  sections: value.sections.map((section) => ({
                    reason: "focus",
                    file: focus.file || "",
                    start_line: section.start_line,
                    end_line:
                      section.start_line + (section.lines?.length || 1) - 1,
                    lines: section.lines || [],
                    truncated: false,
                  })),
                  limitations: [],
                },
                meta: {
                  view_id: view.view_id,
                  revision: view.revision,
                  layer: "asg",
                  versions: {},
                  total: 0,
                  truncated: false,
                  snapshot_id: view.scope.snapshot_id,
                  coverage: {},
                } as Meta,
              }))
          : Promise.resolve(undefined),
    [
      api,
      base,
      symbolRef,
      focus.file,
      focus.line,
      view.scope.snapshot_id,
      view.view_id,
      view.revision,
    ],
  );
  const nodes = neighborhood.data?.neighborhood.nodes || [];
  const edges = neighborhood.data?.neighborhood.edges || [];
  const nodeByID = new Map(nodes.map((node) => [node.node_id, node]));
  return (
    <>
      <div className="inspector-heading">
        <div>
          <strong>{center.label}</strong>
          <span className="muted mono">{center.subject}</span>
        </div>
        <label className="graph-depth">
          展开深度{" "}
          <select
            aria-label="图谱展开深度"
            value={depth}
            onChange={(event) => setDepth(Number(event.target.value))}
          >
            <option value={1}>1 层</option>
            <option value={2}>2 层</option>
          </select>
        </label>
      </div>
      <div
        className="local-graph-tabs"
        role="group"
        aria-label="局部图谱关系类型"
      >
        <button
          aria-pressed={graphKind === "calls"}
          disabled={!entry.scg_refs?.some((id) => id.startsWith("sym-"))}
          onClick={() => {
            setGraphKind("calls");
            setCenter(entry);
            setFocus(entry);
            setEdge(undefined);
          }}
        >
          函数调用关系
        </button>
        <button
          aria-pressed={graphKind === "semantic"}
          onClick={() => {
            setGraphKind("semantic");
            setCenter(entry);
            setFocus(entry);
            setEdge(undefined);
          }}
        >
          安全语义关系
        </button>
      </div>
      <div className="entry-focus-bar">
        <span className="mono">
          {focus.file ? `${focus.file}:${focus.line || 0}` : "源码位置未解析"}
        </span>
        <span className="muted">
          {depth} 跳 · {edges.length} 条关系 · {nodes.length} 个节点
        </span>
      </div>
      {neighborhood.error ? (
        <Hint>{neighborhood.error}</Hint>
      ) : neighborhood.loading ? (
        <div className="knowledge-loading">
          <Loader2 className="spin" size={16} /> 展开局部图谱…
        </div>
      ) : (
        <>
          {neighborhood.data?.neighborhood.meta.truncated && (
            <Hint>
              局部图谱被节点预算截断；请从较小的节点继续展开，未显示不代表不存在。
            </Hint>
          )}
          {!!neighborhood.data?.neighborhood.unresolved_edges && (
            <Hint>
              有 {neighborhood.data.neighborhood.unresolved_edges}{" "}
              {graphKind === "calls"
                ? "处调用未解析，外部或动态调用仍需审查。"
                : "条关系端点未能在预算内解析。"}
            </Hint>
          )}
          <LocalEntryGraph
            calls={graphKind === "calls"}
            nodes={nodes}
            edges={edges}
            root={
              neighborhood.data?.neighborhood.root.node_id || center.node_id
            }
            selected={focus.node_id}
            selectedEdge={edge?.edge_id}
            onNode={(node) => {
              setFocus(node);
              setEdge(undefined);
            }}
            onEdge={setEdge}
          />
          {edge && (
            <div className="selected-relation">
              <strong>{edge.kind}</strong>
              <span>
                {nodeByID.get(edge.from)?.label || edge.from} →{" "}
                {nodeByID.get(edge.to)?.label || edge.to}
              </span>
              <small>
                证据：{edge.evidence_status || "未记录"} · 置信：
                {edge.confidence || "未记录"}
              </small>
            </div>
          )}
          <div className="entry-selection-bar">
            <span>
              <strong>{focus.label}</strong>
              <small>
                {focus.kind === "Function" ? "源码符号" : focus.kind} ·{" "}
                {focus.evidence_status ||
                  (graphKind === "calls" ? "固定代码版本" : "证据状态未记录")}
              </small>
            </span>
            <div>
              <button
                className="button secondary"
                disabled={
                  focus.node_id === center.node_id ||
                  focus.node_id === rootSymbol
                }
                onClick={() => {
                  setCenter(focus);
                  setEdge(undefined);
                }}
              >
                从此节点继续展开 <ChevronRight size={13} />
              </button>
              <button
                className="text-button"
                onClick={() => {
                  void navigator.clipboard
                    ?.writeText(focus.subject || focus.label || focus.node_id)
                    .then(() => setCopyStatus("已复制完整名称"))
                    .catch(() => setCopyStatus("复制失败，请手动选择文本"));
                }}
              >
                复制完整名称
              </button>
              {center.node_id !== entry.node_id && (
                <button
                  className="text-button"
                  onClick={() => {
                    setCenter(entry);
                    setFocus(entry);
                  }}
                >
                  返回入口
                </button>
              )}
            </div>
          </div>
          {copyStatus && (
            <p className="source-reader-note" role="status">
              {copyStatus}
            </p>
          )}
          <details className="graph-accessible-list">
            <summary>节点与关系清单 · {nodes.length} 个节点</summary>
            <Panel title="相邻节点" className="knowledge-inspector-panel">
              {!nodes.filter((node) => node.node_id !== focus.node_id)
                .length ? (
                <Hint>该入口没有可展开的出边。</Hint>
              ) : (
                <div className="entry-node-list">
                  {nodes
                    .filter((node) => node.node_id !== focus.node_id)
                    .map((node) => (
                      <button
                        key={node.node_id}
                        className="entry-node"
                        onClick={() => {
                          setEdge(undefined);
                          setFocus(node);
                        }}
                      >
                        <span>
                          <strong>{node.label || node.subject}</strong>
                          <small className="mono">{node.subject}</small>
                        </span>
                        <span className="muted mono">
                          {node.file
                            ? `${node.file}:${node.line || 0}`
                            : "未解析"}
                        </span>
                        <ChevronRight size={14} />
                      </button>
                    ))}
                </div>
              )}
            </Panel>
            <Panel title="关系与证据" className="knowledge-inspector-panel">
              {!edges.length ? (
                <Hint>没有可展示的攻击面关系。</Hint>
              ) : (
                <>
                  <div className="entry-edge-list">
                    {edges.map((item) => (
                      <button
                        key={item.edge_id}
                        className={
                          edge?.edge_id === item.edge_id ? "active" : ""
                        }
                        onClick={() => setEdge(item)}
                      >
                        <span className="mono">{item.kind}</span>
                        <span>
                          {nodeByID.get(item.from)?.label || item.from} →{" "}
                          {nodeByID.get(item.to)?.label || item.to}
                        </span>
                        <span className="muted">
                          {item.evidence_status || "—"} /{" "}
                          {item.confidence || "—"}
                        </span>
                      </button>
                    ))}
                  </div>
                  {edge && (
                    <dl className="knowledge-provenance">
                      <div>
                        <dt>关系</dt>
                        <dd className="mono">{edge.kind}</dd>
                      </div>
                      <div>
                        <dt>证据</dt>
                        <dd>{edge.evidence_status || "未记录"}</dd>
                      </div>
                      <div>
                        <dt>置信</dt>
                        <dd>{edge.confidence || "未记录"}</dd>
                      </div>
                      <div>
                        <dt>SCG 引用</dt>
                        <dd className="mono">
                          {edge.scg_refs?.join(" · ") || "无"}
                        </dd>
                      </div>
                    </dl>
                  )}
                </>
              )}
            </Panel>
          </details>
          <Panel title="源码与静态证据" className="knowledge-inspector-panel source-panel">
            {slice.error ? (
              <Hint>{slice.error}</Hint>
            ) : slice.loading ? (
              <div className="knowledge-loading">
                <Loader2 className="spin" size={16} /> 读取源码…
              </div>
            ) : slice.data?.slice.sections.length ? (
              <SourceReader
                api={api}
                base={base}
                snapshotID={view.scope.snapshot_id}
                initial={slice.data}
                focusLine={focus.line || 0}
                artifactHint={
                  focus.kind === "SensitiveOperation"
                    ? "该位置是敏感操作，读取前后文核对控制与调用点。"
                    : undefined
                }
              />
            ) : (
              <Hint>
                该节点没有可读取的源码位置；证据状态为{" "}
                {focus.evidence_status || "未记录"}。
              </Hint>
            )}
          </Panel>
          <details className="limitations">
            <summary>局部图谱局限</summary>
            <ul>
              {(neighborhood.data?.neighborhood.limitations || []).map(
                (item) => (
                  <li key={item}>{item}</li>
                ),
              )}
            </ul>
          </details>
        </>
      )}
    </>
  );
}

function LocalEntryGraph({
  calls,
  nodes,
  edges,
  root,
  selected,
  selectedEdge,
  onNode,
  onEdge,
}: {
  calls?: boolean;
  nodes: AttackNode[];
  edges: ASGEdge[];
  root: string;
  selected: string;
  selectedEdge?: string;
  onNode: (node: AttackNode) => void;
  onEdge: (edge: ASGEdge) => void;
}) {
  const marker = useId().replace(/:/g, "");
  const graph = layoutEntryGraph(root, nodes, edges);
  const positions = new Map(graph.nodes.map((node) => [node.id, node]));
  const byID = new Map(nodes.map((node) => [node.node_id, node]));
  return (
    <div className="entry-graph-wrap">
      <div
        className="entry-graph-canvas"
        tabIndex={0}
        role="region"
        aria-label="局部调用关系图，可横向滚动"
      >
        <svg
          width={graph.width}
          height={graph.height}
          viewBox={`0 0 ${graph.width} ${graph.height}`}
          aria-label="入口节点及有向关系"
        >
          <defs>
            <marker
              id={marker}
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" />
            </marker>
          </defs>
          {edges
            .filter(
              (edge) => positions.has(edge.from) && positions.has(edge.to),
            )
            .map((edge) => {
              const a = positions.get(edge.from)!;
              const b = positions.get(edge.to)!;
              const forward = b.x > a.x;
              const x1 = a.x + 206;
              const x2 = b.x;
              const y1 = a.y + 31;
              const y2 = b.y + 31;
              const d = forward
                ? `M${x1},${y1} C${x1 + 40},${y1} ${x2 - 40},${y2} ${x2 - 4},${y2}`
                : `M${a.x + 100},${a.y} C${a.x + 100},${a.y - 34} ${b.x + 100},${b.y - 34} ${b.x + 100},${b.y - 4}`;
              return (
                <g
                  key={edge.edge_id}
                  className={`graph-edge ${selectedEdge === edge.edge_id ? "selected" : ""}`}
                  role="button"
                  tabIndex={0}
                  aria-label={`${byID.get(edge.from)?.label} 到 ${byID.get(edge.to)?.label}：${edge.kind}`}
                  onClick={() => onEdge(edge)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onEdge(edge);
                    }
                  }}
                >
                  <title>
                    {edge.kind} · {edge.evidence_status || "证据未记录"}
                  </title>
                  <path className="edge-hit" d={d} />
                  <path
                    className="edge-line"
                    d={d}
                    markerEnd={`url(#${marker})`}
                  />
                </g>
              );
            })}
          {graph.nodes.map((position) => {
            const node = byID.get(position.id)!;
            return (
              <g
                key={position.id}
                transform={`translate(${position.x},${position.y})`}
                className={`graph-node ${selected === node.node_id ? "selected" : ""} ${node.kind}`}
                role="button"
                tabIndex={0}
                aria-label={`${node.label}，${node.kind}，查看源码`}
                onClick={() => onNode(node)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onNode(node);
                  }
                }}
              >
                <title>
                  {node.label} · {node.subject}
                </title>
                <rect width="206" height="62" rx="6" />
                <circle cx="14" cy="18" r="3" />
                <text x="25" y="22">
                  {(node.label || node.subject).length > 22
                    ? (node.label || node.subject).slice(0, 21) + "…"
                    : node.label || node.subject}
                </text>
                <text className="graph-node-detail" x="14" y="44">
                  {node.kind === "EntryPoint"
                    ? "程序入口"
                    : node.kind === "SensitiveOperation"
                      ? "敏感操作"
                      : node.kind === "SecurityControl"
                        ? "安全控制"
                        : node.kind === "Function"
                          ? "函数 / 方法"
                          : node.kind}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      <div className="entry-graph-legend">
        {calls ? (
          <span>● 函数 / 方法 · 连线为已解析调用</span>
        ) : (
          <>
            <span>● 程序入口</span>
            <span>● 安全控制</span>
            <span>● 敏感操作</span>
          </>
        )}
        <small>点击节点查看源码 · 点击连线查看证据</small>
      </div>
    </div>
  );
}

function SymbolPanel({
  api,
  projectID,
  view,
  onSelect,
  selected,
}: {
  api: ApiClient;
  projectID: string;
  view: View;
  onSelect: (symbol: Symbol) => void;
  selected?: Symbol;
}) {
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const { cursor, page, next, back, reset } = usePager();
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(query);
      reset();
    }, 250);
    return () => clearTimeout(timer);
  }, [query, reset]);
  const data = useQuery(
    (signal) =>
      api.get<{ symbols: Symbol[]; next_cursor: string; meta: Meta }>(
        `/v1/projects/${projectID}/knowledge/views/${view.view_id}/symbols?q=${encodeURIComponent(search)}&limit=50&cursor=${encodeURIComponent(cursor)}`,
        signal,
      ),
    [api, projectID, view.view_id, search, cursor],
  );
  return (
    <Panel
      title="源码符号"
      action={
        <div className="search-input">
          <Search size={15} />
          <input
            aria-label="搜索源码符号"
            placeholder="搜索函数、类型、方法…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
      }
    >
      {data.error ? (
        <Hint>{data.error}</Hint>
      ) : data.loading ? (
        <div className="knowledge-loading">
          <Loader2 className="spin" size={16} /> 读取源码图谱…
        </div>
      ) : !data.data?.symbols.length ? (
        <EmptyState title="没有匹配的符号">
          该快照的图谱可能为空，或搜索词没有命中。
        </EmptyState>
      ) : (
        <>
          <div className="table-scroll">
            <table className="standard-table knowledge-table">
              <thead>
                <tr>
                  <th>符号</th>
                  <th>类型</th>
                  <th>源码位置</th>
                </tr>
              </thead>
              <tbody>
                {data.data.symbols.map((symbol) => (
                  <tr
                    key={symbol.symbol_id}
                    data-guide-row
                    tabIndex={0}
                    aria-selected={selected?.symbol_id === symbol.symbol_id}
                    className={
                      selected?.symbol_id === symbol.symbol_id ? "selected" : ""
                    }
                    onClick={() => onSelect(symbol)}
                    onKeyDown={guideKeys}
                  >
                    <td className="mono">
                      {symbol.qualified_name || symbol.name}
                    </td>
                    <td>{symbol.kind}</td>
                    <td className="mono">
                      {symbol.file}:{symbol.start_line}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="knowledge-pager">
            <button className="button" disabled={page === 0} onClick={back}>
              上一页
            </button>
            <span>第 {page + 1} 页</span>
            <button
              className="button"
              disabled={!data.data.next_cursor}
              onClick={() => next(data.data?.next_cursor || "")}
            >
              下一页
            </button>
          </div>
          <MetaBar meta={data.data.meta} />
        </>
      )}
    </Panel>
  );
}

function NodePanel({
  api,
  projectID,
  view,
  onSelect,
  selected,
}: {
  api: ApiClient;
  projectID: string;
  view: View;
  onSelect: (node: AttackNode) => void;
  selected?: AttackNode;
}) {
  const [kind, setKind] = useState("");
  const { cursor, next, reset } = usePager();
  useEffect(() => reset(), [kind, reset]);
  const data = useQuery(
    (signal) =>
      api.get<{ nodes: AttackNode[]; next_cursor: string; meta: Meta }>(
        `/v1/projects/${projectID}/knowledge/views/${view.view_id}/nodes?limit=50${kind ? `&kind=${encodeURIComponent(kind)}` : ""}&cursor=${encodeURIComponent(cursor)}`,
        signal,
      ),
    [api, projectID, view.view_id, kind, cursor],
  );
  return (
    <Panel
      title="攻击面节点"
      action={
        <select
          aria-label="节点类型"
          value={kind}
          onChange={(event) => setKind(event.target.value)}
        >
          <option value="">全部类型</option>
          <option value="EntryPoint">入口</option>
          <option value="SensitiveOperation">敏感操作</option>
          <option value="AttackerControlledInput">外部输入</option>
          <option value="SecurityControl">安全控制</option>
          <option value="TrustBoundary">信任边界</option>
          <option value="Asset">资产</option>
        </select>
      }
    >
      {data.error ? (
        <Hint>{data.error}</Hint>
      ) : data.loading ? (
        <div className="knowledge-loading">
          <Loader2 className="spin" size={16} /> 读取攻击面…
        </div>
      ) : !data.data?.nodes.length ? (
        <EmptyState title="没有匹配的节点">该快照的攻击面图谱为空。</EmptyState>
      ) : (
        <>
          <div className="table-scroll">
            <table className="standard-table knowledge-table">
              <thead>
                <tr>
                  <th>节点</th>
                  <th>类型</th>
                  <th>源码位置</th>
                  <th>置信</th>
                </tr>
              </thead>
              <tbody>
                {data.data.nodes.map((node) => (
                  <tr
                    key={node.node_id}
                    data-guide-row
                    tabIndex={0}
                    aria-selected={selected?.node_id === node.node_id}
                    className={
                      selected?.node_id === node.node_id ? "selected" : ""
                    }
                    onClick={() => onSelect(node)}
                    onKeyDown={guideKeys}
                  >
                    <td>
                      <strong>{node.label}</strong>
                      <span className="mono muted">{node.subject}</span>
                    </td>
                    <td>{node.kind}</td>
                    <td className="mono">
                      {node.file ? `${node.file}:${node.line || 0}` : "—"}
                    </td>
                    <td>{node.confidence || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="knowledge-pager">
            <button
              className="button"
              disabled={!data.data.next_cursor}
              onClick={() => next(data.data?.next_cursor || "")}
            >
              下一页
            </button>
          </div>
          <MetaBar meta={data.data.meta} />
        </>
      )}
    </Panel>
  );
}

function PathPanel({
  api,
  projectID,
  view,
  onSelect,
  selected,
  canWrite,
  agentAvailable,
  onWorkbench,
}: {
  api: ApiClient;
  projectID: string;
  view: View;
  onSelect: (row: AuditPath) => void;
  selected?: AuditPath;
  canWrite: boolean;
  agentAvailable: boolean;
  onWorkbench?: (selectionID?: string) => void;
}) {
  const [focusID, setFocusID] = useState("");
  const [query, setQuery] = useState("");
  const [audit, setAudit] = useState("");
  const [checked, setChecked] = useState<string[]>([]);
  const [subtasks, setSubtasks] = useState<PathSubtask[]>([]);
  const [selecting, setSelecting] = useState(false);
  const [selectionError, setSelectionError] = useState("");
  const { cursor, page, next, back, reset } = usePager();
  useEffect(() => reset(), [audit, reset]);
  const existing = useQuery(
    (signal) =>
      agentAvailable
        ? api.pathSelections(projectID, undefined, signal)
        : Promise.resolve({ selections: [] as PathSubtask[] }),
    [api, projectID, view.view_id, agentAvailable],
  );
  const existingByPath = new Map(
    (existing.data?.selections || []).map((item) => [item.path_id, item]),
  );
  for (const item of subtasks) existingByPath.set(item.path_id, item);
  const data = useQuery(
    (signal) =>
      api.get<{
        paths: AuditPath[];
        audits: AuditRef[];
        analyses?: AnalysisRef[];
        next_cursor: string;
        meta: Meta;
      }>(
        `/v1/projects/${projectID}/knowledge/views/${view.view_id}/paths?limit=50${audit ? (audit.startsWith("analysis:") ? `&analysis_id=${encodeURIComponent(audit.slice(9))}` : `&audit_id=${encodeURIComponent(audit)}`) : ""}&cursor=${encodeURIComponent(cursor)}`,
        signal,
      ),
    [api, projectID, view.view_id, audit, cursor],
  );
  const filtered = (data.data?.paths || []).filter((row) =>
    `${row.entry_subject} ${row.target_subject} ${row.path_id}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const focus = filtered.find((row) => row.path_id === focusID) || filtered[0];
  return (
    <div className="review-paths-grid">
      <Panel
        title="候选审查路径"
        action={
          <div className="path-selection-actions">
            <select
              aria-label="路径来源"
              value={audit}
              onChange={(event) => setAudit(event.target.value)}
            >
              <option value="">全部任务与直接分析</option>
              {(data.data?.audits || []).map((item) => (
                <option value={item.audit_id} key={item.audit_id}>
                  {item.name || item.audit_id}（{item.paths} 条）
                </option>
              ))}
              {(data.data?.analyses || [])
                .filter((item) => item.has_paths)
                .map((item) => (
                  <option
                    value={`analysis:${item.analysis_id}`}
                    key={item.analysis_id}
                  >
                    {item.producer.plugin_id} · {item.analysis_id}（
                    {item.path_count} 条）
                  </option>
                ))}
            </select>
            <button
              className="button primary"
              disabled={
                !canWrite || !agentAvailable || !checked.length || selecting
              }
              title={
                agentAvailable
                  ? "为所选路径生成可独立控制的 Agent 运行"
                  : "当前部署未配置可用 Agent"
              }
              onClick={() => {
                if (!checked.length) return;
                setSelecting(true);
                setSelectionError("");
                api
                  .selectPaths(projectID, checked)
                  .then((result) => {
                    setSubtasks(result.selections);
                    setChecked([]);
                  })
                  .catch((error) => setSelectionError(failureText(error)))
                  .finally(() => setSelecting(false));
              }}
            >
              {selecting ? (
                <Loader2 size={14} className="spin" />
              ) : (
                <ListChecks size={14} />
              )}
              开始审查 {checked.length > 0 ? `(${checked.length})` : ""}
            </button>
          </div>
        }
      >
        <div className="path-list-toolbar">
          <div className="search-input">
            <Search size={14} />
            <input
              aria-label="搜索候选路径"
              placeholder="搜索当前页的入口、目标或路径…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <span className="muted">已选择 {checked.length} / 5 条路径</span>
        </div>
        {data.error ? (
          <Hint>{data.error}</Hint>
        ) : data.loading ? (
          <div className="knowledge-loading">
            <Loader2 className="spin" size={16} /> 读取审计路径…
          </div>
        ) : !data.data?.paths.length ? (
          <EmptyState title="没有匹配的路径">
            该快照尚未发布候选路径，或当前筛选没有命中。
          </EmptyState>
        ) : (
          <>
            <div className="review-path-list">
              {filtered.length ? (
                filtered.map((row) => (
                  <article
                    key={row.path_id}
                    className={`review-path-row ${focus?.path_id === row.path_id ? "focused" : ""} ${checked.includes(row.path_id) ? "checked" : ""}`}
                  >
                    <input
                      type="checkbox"
                      aria-label={`选择路径 ${row.path_id}`}
                      checked={checked.includes(row.path_id)}
                      disabled={
                        existingByPath.has(row.path_id) ||
                        !canWrite ||
                        !agentAvailable ||
                        (!checked.includes(row.path_id) && checked.length >= 5)
                      }
                      onChange={(event) =>
                        setChecked((current) =>
                          event.target.checked
                            ? [...current, row.path_id]
                            : current.filter((id) => id !== row.path_id),
                        )
                      }
                    />
                    <button
                      aria-pressed={focus?.path_id === row.path_id}
                      onClick={() => setFocusID(row.path_id)}
                    >
                      <span>
                        <strong>
                          {row.target_subject.includes("sql_execution")
                            ? "数据库查询路径"
                            : row.target_subject.includes("process_execution")
                              ? "命令执行路径"
                              : row.target_subject.replace(/^sink:/, "") ||
                                "敏感操作路径"}
                        </strong>
                        <span className="path-priority">
                          优先级{" "}
                          {row.score ? row.score.priority.toFixed(2) : "未评分"}
                        </span>
                      </span>
                      <code>
                        {row.entry_subject} → {row.target_subject}
                      </code>
                      <p>{row.selection?.reason || "该路径尚未记录筛选依据"}</p>
                      <small>
                        {row.steps?.length || 0} 步 ·{" "}
                        {row.path_status || row.path_kind} ·{" "}
                        {existingByPath.has(row.path_id)
                          ? pathReviewState(existingByPath.get(row.path_id))
                          : "待选择"}
                      </small>
                    </button>
                  </article>
                ))
              ) : (
                <EmptyState title="当前页没有匹配的路径">
                  调整搜索词，或切换路径来源。
                </EmptyState>
              )}
            </div>
            <div className="knowledge-pager">
              <button className="button" disabled={page === 0} onClick={back}>
                上一页
              </button>
              <span>第 {page + 1} 页</span>
              <button
                className="button"
                disabled={!data.data.next_cursor}
                onClick={() => next(data.data?.next_cursor || "")}
              >
                下一页
              </button>
            </div>
            <MetaBar meta={data.data.meta} />
            {selectionError && <Hint>{selectionError}</Hint>}
            {!agentAvailable && (
              <Hint>
                当前部署未配置可用
                Agent，仍可浏览路径和源码，但不能生成审查子任务。
              </Hint>
            )}
            {subtasks.length > 0 && (
              <div className="path-subtasks">
                <span className="subtle-label">
                  已生成 {subtasks.length} 个审查子任务
                </span>
                <button
                  className="button primary"
                  onClick={() => onWorkbench?.(subtasks[0]?.selection_id)}
                >
                  进入 Agent 工作台 <ChevronRight size={14} />
                </button>
                {subtasks.map((item) => (
                  <div key={item.selection_id}>
                    <span className="mono">{item.selection_id}</span>
                    <span>{item.path_id}</span>
                    <span>{item.state}</span>
                    <span className="mono">{item.run_id}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </Panel>
      <aside className="panel review-path-detail">
        <span className="eyebrow">PATH CONTEXT</span>
        <h2>路径与筛选依据</h2>
        {focus ? (
          <>
            <p className="mono">{focus.path_id}</p>
            <h3>从入口到敏感操作</h3>
            <ol>
              {(focus.steps || []).slice(0, 12).map((step, index) => (
                <li key={index}>
                  <strong>{step.subject || step.kind}</strong>
                  <small>
                    {step.file
                      ? `${step.file}:${step.line || 0}`
                      : step.evidence || "位置未解析"}
                  </small>
                </li>
              ))}
            </ol>
            {(focus.steps?.length || 0) > 12 && <p>其余节点见完整证据。</p>}
            <h3>为什么审查这条路径</h3>
            <p>{focus.selection?.reason || "旧路径未提供筛选原因。"}</p>
            <h3>工具来源</h3>
            <p>{focus.selection?.producer_plugin || "未记录"}</p>
            <h3>证据边界</h3>
            <p>{focus.path_status} · {focus.path_kind === "data_flow" ? "Joern 静态数据流候选；来源可控性、控制有效性和可利用性待审查。" : "调用可达性不代表已证明数据传播。"}</p>
            {focus.limitations?.map((item) => (
              <p key={item}>{item}</p>
            ))}
            <button
              className="button secondary"
              onClick={() => onSelect(focus)}
            >
              查看完整证据 <ChevronRight size={13} />
            </button>
            {existingByPath.has(focus.path_id) && (
              <button
                className="text-button"
                onClick={() =>
                  onWorkbench?.(
                    existingByPath.get(focus.path_id)?.selection_id,
                  )
                }
              >
                进入工作台 <ChevronRight size={13} />
              </button>
            )}
          </>
        ) : (
          <p>路径生成后，可在这里查看来源、筛选理由和源码证据。</p>
        )}
      </aside>
    </div>
  );
}

// guideKeys implements roving keyboard selection: arrow keys move focus between
// rows, Enter opens the focused row.
function guideKeys(event: KeyboardEvent<HTMLTableRowElement>) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    event.currentTarget.click();
    return;
  }
  if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
  event.preventDefault();
  const rows = Array.from(
    event.currentTarget
      .closest("table")
      ?.querySelectorAll<HTMLTableRowElement>("[data-guide-row]") || [],
  );
  const index = rows.indexOf(event.currentTarget);
  const next =
    rows[
      event.key === "ArrowDown"
        ? Math.min(rows.length - 1, index + 1)
        : Math.max(0, index - 1)
    ];
  next?.focus();
}

function ProvenancePanel({ provenance }: { provenance: Provenance }) {
  return (
    <dl className="knowledge-provenance">
      <div>
        <dt>生成插件</dt>
        <dd className="mono">
          {provenance.producer.plugin_id}@{provenance.producer.plugin_version}
        </dd>
      </div>
      <div>
        <dt>调用</dt>
        <dd className="mono">{provenance.producer.invocation_id}</dd>
      </div>
      <div>
        <dt>配置摘要</dt>
        <dd className="mono">{provenance.producer.config_digest}</dd>
      </div>
      <div>
        <dt>快照版本</dt>
        <dd className="mono">
          {Object.entries(provenance.versions)
            .map(([key, value]) => `${key}:${value}`)
            .join(" · ")}
        </dd>
      </div>
      <div>
        <dt>共享任务</dt>
        <dd>
          {provenance.tasks.length
            ? provenance.tasks
                .map((task) => task.name || task.audit_id)
                .join("、")
            : "暂无共享任务"}
        </dd>
      </div>
      {provenance.artifacts?.length ? (
        <div>
          <dt>原始产物</dt>
          <dd className="mono">
            {provenance.artifacts
              .map(
                (artifact) =>
                  `${artifact.kind} ${artifact.sha256.slice(0, 12)}…`,
              )
              .join(" · ")}
          </dd>
        </div>
      ) : null}
      {provenance.analyses?.length ? (
        <div>
          <dt>直接分析来源</dt>
          <dd>
            <ul>
              {provenance.analyses.map((analysis) => (
                <li key={analysis.analysis_id}>
                  <span className="mono">
                    {analysis.producer.plugin_id}@
                    {analysis.producer.plugin_version}
                  </span>
                  <p className="mono">{analysis.analysis_id}</p>
                  <p className="mono">
                    {analysis.native_artifact.id} ·{" "}
                    {analysis.native_artifact.sha256}
                  </p>
                </li>
              ))}
            </ul>
          </dd>
        </div>
      ) : null}
    </dl>
  );
}

function SymbolInspector({
  api,
  projectID,
  view,
  symbol,
}: {
  api: ApiClient;
  projectID: string;
  view: View;
  symbol: Symbol;
}) {
  const base = `/v1/projects/${projectID}/knowledge/views/${view.view_id}`;
  const slice = useQuery<Slice | undefined>(
    (signal) =>
      api.get<Slice>(
        `${base}/code-slice?symbol_id=${encodeURIComponent(symbol.symbol_id)}&max_lines=80&max_sections=3`,
        signal,
      ),
    [api, base, symbol.symbol_id],
  );
  const callers = useQuery(
    (signal) =>
      api.get<{
        neighborhood: { root: Symbol; nodes: { symbol: Symbol }[]; meta: Meta };
      }>(
        `${base}/neighborhood?symbol_id=${encodeURIComponent(symbol.symbol_id)}&direction=callers&depth=1&max_nodes=20`,
        signal,
      ),
    [api, base, symbol.symbol_id],
  );
  const provenance = useQuery(
    (signal) =>
      api.get<{ provenance: Provenance }>(
        `${base}/provenance?fact_id=${encodeURIComponent(symbol.symbol_id)}`,
        signal,
      ),
    [api, base, symbol.symbol_id],
  );
  return (
    <>
      <div className="inspector-heading">
        <strong className="mono">{symbol.qualified_name}</strong>
        <span className="muted">
          {symbol.file}:{symbol.start_line}–{symbol.end_line} · {symbol.kind}
        </span>
      </div>
      {slice.error ? <Hint>{slice.error}</Hint> : null}
      {slice.data?.slice.sections.map((section, index) => (
        <CodeBlock
          key={index}
          file={`${section.file}（${section.reason}${section.truncated ? "，已截断" : ""}）`}
          lines={section.lines.map((content, offset) => ({
            content,
            line: section.start_line + offset,
            highlight: section.start_line + offset === symbol.start_line,
          }))}
        />
      ))}
      <Panel title="调用方" className="knowledge-inspector-panel">
        {callers.error ? (
          <Hint>{callers.error}</Hint>
        ) : callers.loading ? (
          <div className="knowledge-loading">
            <Loader2 className="spin" size={15} /> 读取调用关系…
          </div>
        ) : !callers.data?.neighborhood.nodes.length ? (
          <Hint>该符号在当前图谱中没有解析出的调用方。</Hint>
        ) : (
          <ul className="knowledge-list">
            {callers.data.neighborhood.nodes.map((node) => (
              <li key={node.symbol.symbol_id} className="mono">
                {node.symbol.qualified_name}
              </li>
            ))}
          </ul>
        )}
      </Panel>
      <Panel title="来源" className="knowledge-inspector-panel">
        {provenance.error ? (
          <Hint>{provenance.error}</Hint>
        ) : provenance.data ? (
          <ProvenancePanel provenance={provenance.data.provenance} />
        ) : null}
      </Panel>
    </>
  );
}

function NodeInspector({
  api,
  projectID,
  view,
  node,
}: {
  api: ApiClient;
  projectID: string;
  view: View;
  node: AttackNode;
}) {
  const base = `/v1/projects/${projectID}/knowledge/views/${view.view_id}`;
  const provenance = useQuery(
    (signal) =>
      api.get<{ provenance: Provenance }>(
        `${base}/provenance?fact_id=${encodeURIComponent(node.node_id)}`,
        signal,
      ),
    [api, base, node.node_id],
  );
  return (
    <>
      <div className="inspector-heading">
        <strong>{node.label}</strong>
        <span className="muted mono">{node.subject}</span>
      </div>
      <dl className="knowledge-provenance">
        <div>
          <dt>类型</dt>
          <dd>{node.kind}</dd>
        </div>
        <div>
          <dt>源码位置</dt>
          <dd className="mono">
            {node.file ? `${node.file}:${node.line || 0}` : "未解析"}
          </dd>
        </div>
        <div>
          <dt>生成规则</dt>
          <dd className="mono">{node.generator || "—"}</dd>
        </div>
        <div>
          <dt>置信</dt>
          <dd>{node.confidence || "—"}</dd>
        </div>
      </dl>
      <Panel title="来源" className="knowledge-inspector-panel">
        {provenance.error ? (
          <Hint>{provenance.error}</Hint>
        ) : provenance.data ? (
          <ProvenancePanel provenance={provenance.data.provenance} />
        ) : null}
      </Panel>
    </>
  );
}

function PathInspector({
  api,
  projectID,
  view,
  row,
}: {
  api: ApiClient;
  projectID: string;
  view: View;
  row: AuditPath;
}) {
  const base = `/v1/projects/${projectID}/knowledge/views/${view.view_id}`;
  const provenance = useQuery(
    (signal) =>
      api.get<{ provenance: Provenance }>(
        `${base}/provenance?fact_id=${encodeURIComponent(row.entry_node_id || row.entry_subject)}`,
        signal,
      ),
    [api, base, row.entry_node_id, row.entry_subject],
  );
  return (
    <>
      <div className="inspector-heading">
        <strong className="mono">
          {row.entry_subject} → {row.target_subject}
        </strong>
        <span className="muted">
          {row.target_kind} · {row.status}
        </span>
      </div>
      <Panel title="证据等级与评分" className="knowledge-inspector-panel">
        <dl className="knowledge-provenance">
          <div>
            <dt>路径类型</dt>
            <dd>
              {row.path_kind || "—"} · {row.path_status || "—"}
            </dd>
          </div>
          <div>
            <dt>优先级</dt>
            <dd>
              {row.score ? row.score.priority.toFixed(4) : "旧路径未记录评分"}
              {row.score?.score_version
                ? ` · 评分版本 ${row.score.score_version}`
                : ""}
            </dd>
          </div>
          <div>
            <dt>筛选</dt>
            <dd>{row.selection?.reason || "旧路径未记录筛选来源"}</dd>
          </div>
          {row.selection?.filter_code ? (
            <div>
              <dt>过滤代码</dt>
              <dd className="mono">{row.selection.filter_code}</dd>
            </div>
          ) : null}
          <div>
            <dt>任务映射</dt>
            <dd className="mono">{row.audit_id}</dd>
          </div>
        </dl>
        <Hint>优先级只用于调度；调用可达不是污点流；筛选不是安全证明。</Hint>
        {row.limitations?.length ? (
          <details className="limitations">
            <summary>局限与未决</summary>
            <ul>
              {row.limitations.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </details>
        ) : null}
      </Panel>
      <Panel title="路径步骤" className="knowledge-inspector-panel">
        {!row.steps?.length ? (
          <Hint>该路径没有记录的步骤。</Hint>
        ) : (
          <ol className="knowledge-steps">
            {row.steps.map((step, index) => (
              <li key={index}>
                <span className="mono">{step.layer}</span>{" "}
                {step.subject || `${step.kind}`}
                {step.file ? (
                  <span className="muted mono">
                    {" "}
                    {`${step.file}:${step.line || 0}`}
                  </span>
                ) : null}
              </li>
            ))}
          </ol>
        )}
      </Panel>
      <Panel title="来源" className="knowledge-inspector-panel">
        {provenance.error ? (
          <Hint>无法解析该入口的来源：{provenance.error}</Hint>
        ) : provenance.data ? (
          <ProvenancePanel provenance={provenance.data.provenance} />
        ) : null}
      </Panel>
    </>
  );
}
