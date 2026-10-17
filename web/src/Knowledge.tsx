import { Fragment, useCallback, useEffect, useState, type KeyboardEvent } from "react";
import { ArrowDown, ArrowUp, Loader2, Network, RefreshCw, Search } from "lucide-react";
import { ApiClient, ApiError } from "./api";
import { CodeBlock, EmptyState, Hint, Modal, Panel } from "./components";
import type { Snapshot } from "./types";
import { latestSnapshot } from "./workbench";

type Layer = "scg" | "asg" | "paths";

interface LayerInfo {
  status: "available" | "not_built" | "unavailable";
  version?: string;
  built_at?: string;
  detail?: string;
  tasks?: number;
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
  entry_subject: string;
  target_subject: string;
  target_kind: string;
  status: string;
  steps?: { layer: string; subject?: string; file?: string; line?: number; kind: string }[];
  scg_refs?: string[];
}

interface Provenance {
  fact_id: string;
  kind: "symbol" | "asg_node";
  versions: Record<string, string>;
  producer: { plugin_id: string; plugin_version: string; invocation_id: string; config_digest: string };
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
      note?: string;
    }[];
    limitations: string[];
  };
  meta: Meta;
}

const layerLabels: Record<Layer, string> = {
  scg: "源码图谱",
  asg: "攻击面",
  paths: "审计路径",
};

const layerHints: Record<Layer, string> = {
  scg: "符号、调用关系与真实源码位置。",
  asg: "从源码事实提取的入口、敏感操作与控制。",
  paths: "共享该快照的任务生成的审计路径。",
};

function failureText(error: unknown) {
  if (error instanceof ApiError) {
    if (error.code === "view_superseded") return "图谱在该视图固定之后已重建，请重新固定版本。";
    if (error.code === "knowledge_unavailable") return "该快照尚未构建代码图谱。";
    if (error.code === "layer_unavailable") return error.message;
    if (error.code === "knowledge_not_found") return "视图不存在，或不属于当前项目与快照。";
    return error.message;
  }
  return error instanceof Error ? error.message : "图谱查询失败";
}

function useQuery<T>(load: (signal: AbortSignal) => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<{ data?: T; error?: string; loading: boolean }>({ loading: true });
  useEffect(() => {
    const controller = new AbortController();
    setState({ loading: true });
    load(controller.signal)
      .then((data) => setState({ data, loading: false }))
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
        版本固定 <code className="mono">{meta.versions.scg || meta.revision}</code>
      </span>
      <span>共 {meta.total} 条</span>
      {meta.truncated ? (
        <span className="knowledge-warning">
          结果被截断{meta.truncation_reason ? `（${meta.truncation_reason}）` : ""}
        </span>
      ) : null}
      {meta.omitted ? <span className="knowledge-warning">已省略 {meta.omitted} 条旧版本记录</span> : null}
    </div>
  );
}

export function Knowledge({
  api,
  projectID,
  snapshots,
  revision,
}: {
  api: ApiClient;
  projectID: string;
  snapshots: Snapshot[];
  revision: number;
}) {
  const [selectedSnapshot, setSelectedSnapshot] = useState("");
  const snapshot = snapshots.find((item) => item.snapshot_id === selectedSnapshot) || latestSnapshot(snapshots);
  const snapshotID = snapshot?.snapshot_id || "";
  const [layer, setLayer] = useState<Layer>("scg");
  const [view, setView] = useState<View>();
  const [viewError, setViewError] = useState("");
  const [viewLoading, setViewLoading] = useState(false);
  const [openCount, setOpenCount] = useState(0);
  const [selectedSymbol, setSelectedSymbol] = useState<Symbol>();
  const [selectedNode, setSelectedNode] = useState<AttackNode>();
  const [selectedPath, setSelectedPath] = useState<AuditPath>();

  const openView = useCallback(() => {
    if (!snapshotID) return;
    setViewLoading(true);
    setViewError("");
    api
      .post<{ view: View }>(`/v1/projects/${projectID}/knowledge/views`, {
        api_version: "codexploit/v1",
        snapshot_id: snapshotID,
      })
      .then((page) => setView(page.view))
      .catch((error) => {
        setView(undefined);
        setViewError(failureText(error));
      })
      .finally(() => setViewLoading(false));
  }, [api, projectID, snapshotID]);

  useEffect(() => {
    setView(undefined);
    setSelectedSymbol(undefined);
    setSelectedNode(undefined);
    setSelectedPath(undefined);
    openView();
  }, [openView, revision, openCount]);

  if (!snapshotID) {
    return (
      <EmptyState title="项目尚未生成快照">
        先在代码源页面生成一个快照，任务与图谱都会引用它。
      </EmptyState>
    );
  }

  const layerState = view?.layers[layer];
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
          {(Object.keys(layerLabels) as Layer[]).map((name) => {
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
                  <span className={`layer-dot ${state.status}`}>{state.status === "available" ? "" : state.status === "not_built" ? "未构建" : "不可用"}</span>
                ) : null}
              </button>
            );
          })}
        </div>
        <span className="knowledge-keyhint muted">
          <ArrowUp size={12} />
          <ArrowDown size={12} /> 选择节点，回车打开
        </span>
        <button className="button" onClick={() => setOpenCount((n) => n + 1)} disabled={viewLoading}>
          <RefreshCw size={15} className={viewLoading ? "spin" : ""} /> 重新固定版本
        </button>
      </div>

      {viewLoading ? (
        <Panel title="正在固定图谱版本">
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
          <PublicationPanel api={api} projectID={projectID} snapshotID={snapshotID} />
          {layerState && layerState.status !== "available" ? (
            <Panel title={layerLabels[layer]}>
              <EmptyState title={layerState.detail || `${layerLabels[layer]}不可用`}>
                {layer === "asg"
                  ? "构建代码源快照时勾选攻击面，或等待后续版本补齐。"
                  : layer === "paths"
                    ? "路径来自共享该快照的任务；先创建任务生成审计路径。"
                    : null}
              </EmptyState>
            </Panel>
          ) : layer === "scg" ? (
            <SymbolPanel
              api={api}
              projectID={projectID}
              view={view}
              onSelect={setSelectedSymbol}
              selected={selectedSymbol}
            />
          ) : layer === "asg" ? (
            <NodePanel api={api} projectID={projectID} view={view} onSelect={setSelectedNode} selected={selectedNode} />
          ) : (
            <PathPanel api={api} projectID={projectID} view={view} onSelect={setSelectedPath} selected={selectedPath} />
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
          <SymbolInspector api={api} projectID={projectID} view={view} symbol={selectedSymbol} />
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
          <NodeInspector api={api} projectID={projectID} view={view} node={selectedNode} />
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
          <PathInspector api={api} projectID={projectID} view={view} row={selectedPath} />
        ) : null}
      </Modal>
    </>
  );
}

function CoverageStrip({ view }: { view: View }) {
  const parsed = view.coverage.files_parsed ?? 0;
  const total = view.coverage.files_in_snapshot ?? 0;
  return (
    <div className="task-stat-strip">
      <div>
        <span>源码文件</span>
        <strong>
          {parsed}/{total}
        </strong>
      </div>
      <div>
        <span>未解析</span>
        <strong>{(view.coverage.files_unparsed ?? 0) + (view.coverage.files_partial ?? 0)}</strong>
      </div>
      <div>
        <span>跳过符号</span>
        <strong>{view.coverage.symbols_skipped ?? 0}</strong>
      </div>
      <div>
        <span>共享任务</span>
        <strong>{view.layers.paths?.tasks ?? 0}</strong>
      </div>
      <div>
        <span>引擎</span>
        <strong className="mono">{view.engine.version}</strong>
      </div>
    </div>
  );
}

interface RevisionSummary {
  revision: string;
  revision_no: number;
  batch_id: string;
  producer: { plugin_id: string; plugin_version: string; task_id?: string };
  created_at: string;
  view: { view_id: string; revision: string; scope: { project_id: string; snapshot_id: string } };
}

interface PublishedFact {
  id: string;
  kind: string;
  label: string;
  location?: { file: string; start_line: number; end_line: number };
  confidence?: string;
  observations: {
    observation_id: string;
    producer: { plugin_id: string; plugin_version: string; invocation_id: string; task_id?: string; config_digest: string };
    attributes?: Record<string, string>;
    evidence_refs?: string[];
  }[];
}

// PublicationPanel shows the immutable versions a producer published and every
// observation behind one fact, so two tools that disagree stay visible.
function PublicationPanel({ api, projectID, snapshotID }: { api: ApiClient; projectID: string; snapshotID: string }) {
  const revisions = useQuery(
    (signal) => api.get<{ revisions: RevisionSummary[] }>(`/v1/projects/${projectID}/knowledge/revisions?snapshot_id=${encodeURIComponent(snapshotID)}&limit=100`, signal),
    [api, projectID, snapshotID],
  );
  const [selected, setSelected] = useState("");
  const [expanded, setExpanded] = useState("");
  const latest = revisions.data?.revisions[revisions.data.revisions.length - 1];
  const active = revisions.data?.revisions.find((item) => item.revision === selected) || latest;
  const facts = useQuery(
    (signal) =>
      active
        ? api.get<{ facts: PublishedFact[]; next_cursor: string }>(
            `/v1/projects/${projectID}/knowledge/revisions/${encodeURIComponent(active.view.view_id)}/facts?snapshot_id=${encodeURIComponent(snapshotID)}&limit=50`,
            signal,
          )
        : Promise.resolve({ facts: [], next_cursor: "" }),
    [api, projectID, snapshotID, active?.view.view_id],
  );
  return (
    <Panel
      title="共享知识版本"
      action={
        revisions.data?.revisions.length ? (
          <select aria-label="已发布知识版本" value={active?.revision || ""} onChange={(event) => setSelected(event.target.value)}>
            {revisions.data.revisions.map((item) => (
              <option value={item.revision} key={item.revision}>
                {item.revision} · {item.producer.plugin_id}@{item.producer.plugin_version}
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
        <Hint>该快照还没有发布版本。任务完成语义分析并发布后，这里会列出不可变版本和来源。</Hint>
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
                      <td className="mono">{fact.location ? `${fact.location.file}:${fact.location.start_line}` : "—"}</td>
                      <td>
                        <button
                          className="text-button"
                          aria-expanded={expanded === fact.id}
                          onClick={() => setExpanded(expanded === fact.id ? "" : fact.id)}
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
                                  {observation.producer.plugin_id}@{observation.producer.plugin_version}
                                </span>
                                {observation.producer.task_id ? <span className="muted"> · 任务 {observation.producer.task_id}</span> : null}
                                {observation.attributes ? (
                                  <dl>
                                    {Object.entries(observation.attributes).map(([key, value]) => (
                                      <div key={key}>
                                        <dt>{key}</dt>
                                        <dd className="mono">{value}</dd>
                                      </div>
                                    ))}
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
            <span>共 {facts.data.facts.length} 条事实</span>
            <span>批次 {active?.batch_id}</span>
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
  const next = useCallback((value: string) => setCursors((stack) => (value ? [...stack, value] : stack)), []);
  const back = useCallback(() => setCursors((stack) => (stack.length > 1 ? stack.slice(0, -1) : stack)), []);
  return { cursor, page: cursors.length - 1, next, back, reset };
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
                    className={selected?.symbol_id === symbol.symbol_id ? "selected" : ""}
                    onClick={() => onSelect(symbol)}
                    onKeyDown={guideKeys}
                  >
                    <td className="mono">{symbol.qualified_name || symbol.name}</td>
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
            <button className="button" disabled={!data.data.next_cursor} onClick={() => next(data.data?.next_cursor || "")}>
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
        <select aria-label="节点类型" value={kind} onChange={(event) => setKind(event.target.value)}>
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
                    className={selected?.node_id === node.node_id ? "selected" : ""}
                    onClick={() => onSelect(node)}
                    onKeyDown={guideKeys}
                  >
                    <td>
                      <strong>{node.label}</strong>
                      <span className="mono muted">{node.subject}</span>
                    </td>
                    <td>{node.kind}</td>
                    <td className="mono">{node.file ? `${node.file}:${node.line || 0}` : "—"}</td>
                    <td>{node.confidence || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="knowledge-pager">
            <button className="button" disabled={!data.data.next_cursor} onClick={() => next(data.data?.next_cursor || "")}>
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
}: {
  api: ApiClient;
  projectID: string;
  view: View;
  onSelect: (row: AuditPath) => void;
  selected?: AuditPath;
}) {
  const [audit, setAudit] = useState("");
  const { cursor, next, reset } = usePager();
  useEffect(() => reset(), [audit, reset]);
  const data = useQuery(
    (signal) =>
      api.get<{ paths: AuditPath[]; audits: AuditRef[]; next_cursor: string; meta: Meta }>(
        `/v1/projects/${projectID}/knowledge/views/${view.view_id}/paths?limit=50${audit ? `&audit_id=${encodeURIComponent(audit)}` : ""}&cursor=${encodeURIComponent(cursor)}`,
        signal,
      ),
    [api, projectID, view.view_id, audit, cursor],
  );
  return (
    <Panel
      title="审计路径"
      action={
        <select aria-label="任务" value={audit} onChange={(event) => setAudit(event.target.value)}>
          <option value="">全部共享任务</option>
          {(data.data?.audits || []).map((item) => (
            <option value={item.audit_id} key={item.audit_id}>
              {item.name || item.audit_id}（{item.paths} 条）
            </option>
          ))}
        </select>
      }
    >
      {data.error ? (
        <Hint>{data.error}</Hint>
      ) : data.loading ? (
        <div className="knowledge-loading">
          <Loader2 className="spin" size={16} /> 读取审计路径…
        </div>
      ) : !data.data?.paths.length ? (
        <EmptyState title="没有匹配的路径">
          该快照的共享任务还没有生成审计路径，或当前筛选没有命中。
        </EmptyState>
      ) : (
        <>
          <div className="table-scroll">
            <table className="standard-table knowledge-table">
              <thead>
                <tr>
                  <th>入口</th>
                  <th>目标</th>
                  <th>类型</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                {data.data.paths.map((row) => (
                  <tr
                    key={row.path_id}
                    data-guide-row
                    tabIndex={0}
                    aria-selected={selected?.path_id === row.path_id}
                    className={selected?.path_id === row.path_id ? "selected" : ""}
                    onClick={() => onSelect(row)}
                    onKeyDown={guideKeys}
                  >
                    <td className="mono">{row.entry_subject}</td>
                    <td className="mono">{row.target_subject}</td>
                    <td>{row.target_kind}</td>
                    <td>{row.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="knowledge-pager">
            <button className="button" disabled={!data.data.next_cursor} onClick={() => next(data.data?.next_cursor || "")}>
              下一页
            </button>
          </div>
          <MetaBar meta={data.data.meta} />
        </>
      )}
    </Panel>
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
    event.currentTarget.closest("table")?.querySelectorAll<HTMLTableRowElement>("[data-guide-row]") || [],
  );
  const index = rows.indexOf(event.currentTarget);
  const next = rows[event.key === "ArrowDown" ? Math.min(rows.length - 1, index + 1) : Math.max(0, index - 1)];
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
        <dd className="mono">{Object.entries(provenance.versions).map(([key, value]) => `${key}:${value}`).join(" · ")}</dd>
      </div>
      <div>
        <dt>共享任务</dt>
        <dd>
          {provenance.tasks.length
            ? provenance.tasks.map((task) => task.name || task.audit_id).join("、")
            : "暂无共享任务"}
        </dd>
      </div>
      {provenance.artifacts?.length ? (
        <div>
          <dt>原始产物</dt>
          <dd className="mono">
            {provenance.artifacts.map((artifact) => `${artifact.kind} ${artifact.sha256.slice(0, 12)}…`).join(" · ")}
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
  const slice = useQuery(
    (signal) => api.get<Slice>(`${base}/code-slice?symbol_id=${encodeURIComponent(symbol.symbol_id)}&max_lines=80&max_sections=3`, signal),
    [api, base, symbol.symbol_id],
  );
  const callers = useQuery(
    (signal) =>
      api.get<{ neighborhood: { root: Symbol; nodes: { symbol: Symbol }[]; meta: Meta } }>(
        `${base}/neighborhood?symbol_id=${encodeURIComponent(symbol.symbol_id)}&direction=callers&depth=1&max_nodes=20`,
        signal,
      ),
    [api, base, symbol.symbol_id],
  );
  const provenance = useQuery(
    (signal) => api.get<{ provenance: Provenance }>(`${base}/provenance?fact_id=${encodeURIComponent(symbol.symbol_id)}`, signal),
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
        {provenance.error ? <Hint>{provenance.error}</Hint> : provenance.data ? <ProvenancePanel provenance={provenance.data.provenance} /> : null}
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
    (signal) => api.get<{ provenance: Provenance }>(`${base}/provenance?fact_id=${encodeURIComponent(node.node_id)}`, signal),
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
          <dd className="mono">{node.file ? `${node.file}:${node.line || 0}` : "未解析"}</dd>
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
        {provenance.error ? <Hint>{provenance.error}</Hint> : provenance.data ? <ProvenancePanel provenance={provenance.data.provenance} /> : null}
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
    (signal) => api.get<{ provenance: Provenance }>(`${base}/provenance?fact_id=${encodeURIComponent(row.entry_subject)}`, signal),
    [api, base, row.entry_subject],
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
      <Panel title="路径步骤" className="knowledge-inspector-panel">
        {!row.steps?.length ? (
          <Hint>该路径没有记录的步骤。</Hint>
        ) : (
          <ol className="knowledge-steps">
            {row.steps.map((step, index) => (
              <li key={index}>
                <span className="mono">{step.layer}</span> {step.subject || `${step.kind}`}
                {step.file ? <span className="muted mono"> {`${step.file}:${step.line || 0}`}</span> : null}
              </li>
            ))}
          </ol>
        )}
      </Panel>
      <Panel title="来源" className="knowledge-inspector-panel">
        {provenance.error ? <Hint>无法解析该入口的来源：{provenance.error}</Hint> : provenance.data ? <ProvenancePanel provenance={provenance.data.provenance} /> : null}
      </Panel>
    </>
  );
}

