import { useEffect, useRef, useState } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  Check,
  Code2,
  GitBranch,
  Plus,
  RefreshCw,
  Save,
  Upload,
} from "lucide-react";
import { ApiClient, ApiError } from "./api";
import { Hint, Panel } from "./components";
import type { Snapshot } from "./types";
import type { ArtifactRef } from "./Artifacts";
import type { PluginRecord } from "./Plugins";
import { latestSnapshot } from "./workbench";

type Node = {
  id: string;
  plugin_id: string;
  plugin_version: string;
  needs: string[];
  config: object;
  timeout_seconds: number;
};
type Spec = {
  api_version: string;
  id: string;
  version: string;
  name: string;
  description: string;
  inputs: string[];
  nodes: Node[];
};
type Record = {
  project_id: string;
  spec: Spec;
  digest: string;
  created_at: string;
  head_digest: string;
};
type Diagnostic = { path: string; code: string; message: string };
type CompiledNode = Node & {
  plugin: PluginRecord;
  config_digest: string;
  inputs: {
    kind: string;
    from: string;
    source: "root" | "node";
    schema_id: string;
    producer_plugin?: string;
  }[];
  outputs: string[];
};
type Validation = {
  valid: boolean;
  diagnostics: Diagnostic[];
  nodes: CompiledNode[];
};
export type Plan = {
  plan_id: string;
  digest: string;
  compiler_version: string;
  workflow: Record;
  scope: ArtifactRef["scope"];
  language: string;
  knowledge: { revision: string; digest: string };
  max_input_bytes: number;
  inputs: ArtifactRef[];
  nodes: CompiledNode[];
};
const kinds = [
  "source.snapshot",
  "code.ast",
  "code.facts",
  "security.facts",
  "scanner.alerts",
  "discovery.paths",
  "discovery.findings",
  "knowledge.view",
  "report.document",
];
const starter: Spec = {
  api_version: "codexploit/v1",
  id: "discovery",
  version: "1.0.0",
  name: "漏洞挖掘流程",
  description: "固定源码 → 语法解析 → 安全语义 → 候选路径",
  inputs: ["source.snapshot"],
  nodes: [
    {
      id: "parse",
      plugin_id: "builtin.go-parser",
      plugin_version: "1.1.0",
      needs: [],
      config: {},
      timeout_seconds: 60,
    },
    {
      id: "semantic",
      plugin_id: "builtin.security-semantics",
      plugin_version: "1.0.0",
      needs: ["parse"],
      config: {},
      timeout_seconds: 60,
    },
    {
      id: "paths",
      plugin_id: "builtin.discovery-paths",
      plugin_version: "1.0.0",
      needs: ["semantic"],
      config: {},
      timeout_seconds: 60,
    },
  ],
};
const format = (value: unknown) => JSON.stringify(value, null, 2);
const errorText = (error: unknown) =>
  error instanceof ApiError && error.code === "workflow_conflict"
    ? "版本已存在、版本号未提升或 head 已更新。请刷新目录，保留草稿后提升版本号再保存。"
    : error instanceof Error
      ? error.message
      : "工作流操作失败";
function graphSpec(text: string): Spec | undefined {
  try {
    const s = JSON.parse(text) as Spec;
    if (
      typeof s.id !== "string" ||
      typeof s.version !== "string" ||
      typeof s.name !== "string" ||
      typeof s.description !== "string" ||
      !Array.isArray(s.inputs) ||
      !s.inputs.every((k) => typeof k === "string") ||
      !Array.isArray(s.nodes) ||
      !s.nodes.every(
        (n) =>
          n &&
          typeof n.id === "string" &&
          typeof n.plugin_id === "string" &&
          typeof n.plugin_version === "string" &&
          Array.isArray(n.needs) &&
          n.needs.every((k) => typeof k === "string") &&
          n.config !== null &&
          typeof n.config === "object" &&
          !Array.isArray(n.config) &&
          typeof n.timeout_seconds === "number",
      )
    )
      return;
    return s;
  } catch {
    return;
  }
}
function download(value: unknown, name: string) {
  const url = URL.createObjectURL(
    new Blob([format(value)], { type: "application/json" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function Workflows({
  api,
  projectID,
  snapshots,
  canWrite,
  revision,
}: {
  api: ApiClient;
  projectID: string;
  snapshots: Snapshot[];
  canWrite: boolean;
  revision: number;
}) {
  const endpoint = `/v1/projects/${encodeURIComponent(projectID)}/workflows`;
  const [rows, setRows] = useState<Record[]>([]);
  const [cursors, setCursors] = useState([""]);
  const [next, setNext] = useState("");
  const [tick, refresh] = useState(0);
  const [catalog, setCatalog] = useState<PluginRecord[]>([]);
  const [text, setText] = useState(format(starter));
  const [mode, setMode] = useState("graph");
  const [selected, setSelected] = useState(0);
  const [saved, setSaved] = useState<Record>();
  const [validation, setValidation] = useState<Validation>();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");
  const [snapshot, setSnapshot] = useState(
    latestSnapshot(snapshots)?.snapshot_id || "",
  );
  const [artifacts, setArtifacts] = useState<ArtifactRef[]>([]);
  const [roots, setRoots] = useState<{ [kind: string]: string }>({});
  const [language, setLanguage] = useState("Go");
  const [knowledge, setKnowledge] = useState("latest");
  const [budget, setBudget] = useState(64);
  const [plan, setPlan] = useState<Plan>();
  const [planID, setPlanID] = useState(
    () => sessionStorage.getItem(`workflow-plan:${projectID}`) || "",
  );
  const input = useRef<HTMLInputElement>(null);
  const draft = graphSpec(text);
  const node = draft?.nodes[selected];
  const scanner = catalog.find(
    (p) => p.executable && p.manifest.produces.includes("scanner.alerts"),
  );
  const unchanged = !!saved && format(draft) === format(saved.spec);
  const cursor = cursors.at(-1) || "";
  const artifactEndpoint = `/v1/projects/${encodeURIComponent(projectID)}/snapshots/${encodeURIComponent(snapshot)}/artifacts`;
  useEffect(() => {
    setValidation(undefined);
  }, [text]);
  useEffect(() => {
    const controller = new AbortController();
    api
      .get<{ workflows: Record[]; next_cursor: string }>(
        `${endpoint}?limit=30&cursor=${encodeURIComponent(cursor)}`,
        controller.signal,
      )
      .then((page) => {
        setRows(page.workflows);
        setNext(page.next_cursor);
      })
      .catch((e) => {
        if (!controller.signal.aborted) setError(errorText(e));
      });
    return () => controller.abort();
  }, [api, endpoint, cursor, tick, revision]);
  useEffect(() => {
    const controller = new AbortController();
    (async () => {
      const result: PluginRecord[] = [];
      let cursor = "";
      do {
        const page = await api.get<{
          plugins: PluginRecord[];
          next_cursor: string;
        }>(
          `/v1/plugins?limit=100&cursor=${encodeURIComponent(cursor)}`,
          controller.signal,
        );
        result.push(...page.plugins);
        cursor = page.next_cursor;
      } while (cursor && result.length < 1000);
      if (cursor)
        throw new Error("插件目录超过 1000 项，请通过 JSON 指定完整插件版本。");
      setCatalog(result);
    })().catch((e) => {
      if (!controller.signal.aborted) setError(errorText(e));
    });
    return () => controller.abort();
  }, [api, revision]);
  useEffect(() => {
    if (!snapshot) {
      setArtifacts([]);
      return;
    }
    const controller = new AbortController();
    setArtifacts([]);
    setRoots({});
    (async () => {
      let cursor = "";
      const result: ArtifactRef[] = [];
      do {
        const page = await api.get<{
          artifacts: ArtifactRef[];
          next_cursor: string;
        }>(
          `${artifactEndpoint}?limit=100&cursor=${encodeURIComponent(cursor)}`,
          controller.signal,
        );
        result.push(...page.artifacts);
        cursor = page.next_cursor;
      } while (cursor && result.length < 1000);
      if (cursor) throw new Error("产物超过 1000 项，请选择范围更小的快照。");
      setArtifacts(result);
      const root = result.find(
        (r) => r.schema_id === "codexploit/source-tar/v1",
      );
      if (root) setRoots({ "source.snapshot": root.id });
    })().catch((e) => {
      if (!controller.signal.aborted) setError(errorText(e));
    });
    return () => controller.abort();
  }, [api, artifactEndpoint, snapshot, tick, revision]);
  useEffect(() => {
    const id = sessionStorage.getItem(`workflow-plan:${projectID}`);
    if (!id) return;
    const controller = new AbortController();
    api
      .get<{ plan: Plan }>(
        `/v1/projects/${encodeURIComponent(projectID)}/workflow-plans/${encodeURIComponent(id)}`,
        controller.signal,
      )
      .then((r) => setPlan(r.plan))
      .catch((e) => {
        if (!controller.signal.aborted) setError(errorText(e));
      });
    return () => controller.abort();
  }, [api, projectID]);
  function update(s: Spec) {
    setText(format(s));
  }
  function updateNode(change: Partial<Node>) {
    if (draft && node)
      update({
        ...draft,
        nodes: draft.nodes.map((n, i) =>
          i === selected ? { ...n, ...change } : n,
        ),
      });
  }
  async function action(name: string, operation: () => Promise<void>) {
    setBusy(name);
    setError("");
    setNotice("");
    try {
      await operation();
    } catch (e) {
      setError(errorText(e));
      if (e instanceof ApiError && e.diagnostics)
        setValidation({ valid: false, diagnostics: e.diagnostics, nodes: [] });
    } finally {
      setBusy("");
    }
  }
  async function save() {
    const spec = JSON.parse(text) as Spec;
    const existing = rows.find((r) => r.spec.id === spec.id);
    const result = await api.post<{ workflow: Record }>(endpoint, {
      api_version: "codexploit/v1",
      spec,
      expected_head: existing?.head_digest || "",
    });
    setSaved(result.workflow);
    setText(format(result.workflow.spec));
    refresh((t) => t + 1);
    setNotice(`已保存不可变版本 ${spec.version}。后续修改请提升版本号。`);
  }
  async function loadPlan() {
    const result = await api.get<{ plan: Plan }>(
      `/v1/projects/${encodeURIComponent(projectID)}/workflow-plans/${encodeURIComponent(planID)}`,
    );
    setPlan(result.plan);
    sessionStorage.setItem(`workflow-plan:${projectID}`, result.plan.plan_id);
  }
  return (
    <div className="workflow-workspace">
      {error && <Hint className="error-hint">{error}</Hint>}
      {notice && <Hint>{notice}</Hint>}
      <Panel
        title="工作流版本"
        eyebrow="VERSIONED WORKFLOWS"
        action={
          <div className="workflow-actions">
            <button
              className="button secondary small"
              disabled={!!busy}
              onClick={() => refresh((t) => t + 1)}
            >
              <RefreshCw size={14} />
              刷新
            </button>
            <button
              className="button secondary small"
              disabled={!!busy}
              onClick={() => {
                setText(format(starter));
                setSaved(undefined);
                setSelected(0);
                setNotice("新草稿已载入，请使用独立 ID 或提升版本号。");
              }}
            >
              <Plus size={14} />
              新建草稿
            </button>
          </div>
        }
      >
        <div className="workflow-version-list">
          {!rows.length && (
            <p className="muted">
              当前页没有已保存版本。可从下方草稿开始，或导入 WorkflowSpec JSON。
            </p>
          )}
          {rows.map((r) => (
            <button
              key={`${r.spec.id}@${r.spec.version}`}
              className={`workflow-version ${saved?.digest === r.digest ? "active" : ""}`}
              disabled={!!busy}
              onClick={() => {
                setSaved(r);
                setText(format(r.spec));
                setSelected(0);
                setNotice(
                  "已载入版本；编辑会成为本地草稿，保存时需提升版本号。",
                );
              }}
            >
              <span>
                <strong>{r.spec.name}</strong>
                <code>
                  {r.spec.id} · {r.spec.version}
                </code>
              </span>
              <span className="workflow-head">
                {r.head_digest === r.digest ? "当前版本" : "历史版本"}
              </span>
            </button>
          ))}
        </div>
        <div className="workflow-pagination">
          <button
            className="text-button"
            disabled={cursors.length === 1 || !!busy}
            onClick={() => setCursors((c) => c.slice(0, -1))}
          >
            上一页
          </button>
          <span>第 {cursors.length} 页</span>
          <button
            className="text-button"
            disabled={!next || !!busy}
            onClick={() => setCursors((c) => [...c, next])}
          >
            下一页
          </button>
        </div>
      </Panel>
      <Panel
        title={draft?.name || "工作流草稿"}
        eyebrow="WORKFLOW EDITOR"
        action={
          <div className="workflow-actions">
            <button
              className={`button secondary small ${mode === "graph" ? "active" : ""}`}
              disabled={!draft}
              onClick={() => setMode("graph")}
            >
              <GitBranch size={14} />
              流程视图
            </button>
            <button
              className="button secondary small"
              onClick={() => setMode("json")}
            >
              <Code2 size={14} />
              JSON
            </button>
            <button
              className="button secondary small"
              disabled={!!busy || !canWrite}
              onClick={() => input.current?.click()}
            >
              <Upload size={14} />
              导入
            </button>
            <button
              className="button secondary small"
              onClick={() =>
                void action("export", async () =>
                  download(JSON.parse(text), "workflow.json"),
                )
              }
            >
              <ArrowDownToLine size={14} />
              导出草稿
            </button>
          </div>
        }
      >
        <input
          type="file"
          ref={input}
          hidden
          accept="application/json,.json"
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (!file) return;
            void action("import", async () => {
              if (file.size > 256 * 1024)
                throw new Error("工作流文件不能超过 256 KiB。");
              const raw = await file.text();
              JSON.parse(raw);
              setText(raw);
              setMode(graphSpec(raw) ? "graph" : "json");
              setSelected(0);
              setSaved(undefined);
              setNotice("已导入本地草稿。校验后保存为项目版本。");
            });
          }}
        />
        <fieldset className="workflow-fieldset" disabled={!!busy || !canWrite}>
          {mode === "json" || !draft ? (
            <label className="workflow-json">
              WorkflowSpec JSON
              <textarea
                aria-label="工作流 JSON"
                rows={24}
                spellCheck={false}
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
            </label>
          ) : (
            <>
              <div className="workflow-metadata">
                <label>
                  工作流 ID
                  <input
                    value={draft.id}
                    onChange={(e) => update({ ...draft, id: e.target.value })}
                  />
                </label>
                <label>
                  版本号
                  <input
                    value={draft.version}
                    onChange={(e) =>
                      update({ ...draft, version: e.target.value })
                    }
                  />
                </label>
                <label>
                  名称
                  <input
                    value={draft.name}
                    onChange={(e) => update({ ...draft, name: e.target.value })}
                  />
                </label>
                <label>
                  说明
                  <input
                    value={draft.description}
                    onChange={(e) =>
                      update({ ...draft, description: e.target.value })
                    }
                  />
                </label>
              </div>
              <div className="workflow-root-types">
                <span>根输入类型</span>
                {kinds.map((kind) => (
                  <label key={kind}>
                    <input
                      type="checkbox"
                      checked={draft.inputs.includes(kind)}
                      onChange={(e) =>
                        update({
                          ...draft,
                          inputs: e.target.checked
                            ? [...draft.inputs, kind]
                            : draft.inputs.filter((k) => k !== kind),
                        })
                      }
                    />
                    {kind}
                  </label>
                ))}
              </div>
              <div className="workflow-editor-grid">
                <div className="workflow-canvas">
                  <div className="workflow-root-node">
                    <GitBranch size={18} />
                    <div>
                      <strong>固定快照输入</strong>
                      <code>{draft.inputs.join(" · ") || "未声明根输入"}</code>
                    </div>
                  </div>
                  {draft.nodes.map((n, i) => (
                    <div className="workflow-node-slot" key={i}>
                      <span className="workflow-connector">↓</span>
                      <button
                        className={`workflow-node ${selected === i ? "selected" : ""}`}
                        onClick={() => setSelected(i)}
                      >
                        <span className="workflow-node-number">
                          {String(i + 1).padStart(2, "0")}
                        </span>
                        <span>
                          <strong>{n.id}</strong>
                          <code>
                            {n.plugin_id}@{n.plugin_version}
                          </code>
                          <small>
                            直接依赖：{n.needs.join(", ") || "无"} ·{" "}
                            {n.timeout_seconds}s
                          </small>
                        </span>
                        <ArrowRight size={16} />
                      </button>
                    </div>
                  ))}
                  <div className="workflow-add-row">
                    <button
                      className="button secondary workflow-add"
                      disabled={draft.nodes.length >= 32}
                      onClick={() => {
                        let id = `step${draft.nodes.length + 1}`;
                        while (draft.nodes.some((n) => n.id === id)) id += "x";
                        update({
                          ...draft,
                          nodes: [...draft.nodes, { ...starter.nodes[0], id }],
                        });
                        setSelected(draft.nodes.length);
                      }}
                    >
                      <Plus size={14} />
                      添加节点
                    </button>
                    {scanner && (
                      <button
                        className="button secondary workflow-add"
                        disabled={
                          draft.nodes.length >= 32 ||
                          draft.nodes.some(
                            (n) => n.plugin_id === scanner.manifest.id,
                          )
                        }
                        onClick={() => {
                          let id = "scan";
                          while (draft.nodes.some((n) => n.id === id))
                            id += "x";
                          update({
                            ...draft,
                            nodes: [
                              ...draft.nodes,
                              {
                                id,
                                plugin_id: scanner.manifest.id,
                                plugin_version: scanner.manifest.version,
                                needs: [],
                                config: { max_alerts: 200 },
                                timeout_seconds: 60,
                              },
                            ],
                          });
                          setSelected(draft.nodes.length);
                        }}
                      >
                        <Plus size={14} />
                        加入进程扫描器
                      </button>
                    )}
                  </div>
                  <p className="workflow-canvas-note">
                    {scanner
                      ? `已安装 ${scanner.manifest.name}。扫描器读取固定快照并只报告告警位置，不执行目标代码。`
                      : "未安装进程扫描器包；部署目录提供已登记包后此处会出现快捷入口。"}
                  </p>
                  <p className="workflow-canvas-note">
                    按编辑顺序展示。编译器根据显式依赖生成拓扑顺序。
                  </p>
                </div>
                <div className="workflow-inspector">
                  {node ? (
                    <>
                      <div className="eyebrow">NODE INSPECTOR</div>
                      <label>
                        节点 ID
                        <input
                          value={node.id}
                          onChange={(e) => {
                            const old = node.id;
                            const id = e.target.value;
                            update({
                              ...draft,
                              nodes: draft.nodes.map((n, i) =>
                                i === selected
                                  ? { ...n, id }
                                  : {
                                      ...n,
                                      needs: n.needs.map((k) =>
                                        k === old ? id : k,
                                      ),
                                    },
                              ),
                            });
                          }}
                        />
                      </label>
                      <label>
                        插件与版本
                        <select
                          value={`${node.plugin_id}@${node.plugin_version}`}
                          onChange={(e) => {
                            const [plugin_id, plugin_version] =
                              e.target.value.split("@");
                            updateNode({
                              plugin_id,
                              plugin_version,
                              config: {},
                            });
                          }}
                        >
                          {!catalog.some(
                            (p) =>
                              `${p.manifest.id}@${p.manifest.version}` ===
                              `${node.plugin_id}@${node.plugin_version}`,
                          ) && (
                            <option>
                              {node.plugin_id}@{node.plugin_version}
                            </option>
                          )}
                          {catalog.map((p) => (
                            <option
                              key={`${p.manifest.id}@${p.manifest.version}`}
                              value={`${p.manifest.id}@${p.manifest.version}`}
                            >
                              {p.manifest.id}@{p.manifest.version}
                              {p.executable ? "" : "（执行器未安装）"}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label>
                        节点超时（秒）
                        <input
                          type="number"
                          min={5}
                          max={120}
                          value={node.timeout_seconds}
                          onChange={(e) =>
                            updateNode({
                              timeout_seconds: Number(e.target.value),
                            })
                          }
                        />
                      </label>
                      <div className="workflow-dependencies">
                        <span>直接依赖</span>
                        {draft.nodes
                          .filter((_, i) => i !== selected)
                          .map((n, i) => (
                            <label key={i}>
                              <input
                                type="checkbox"
                                checked={node.needs.includes(n.id)}
                                onChange={(e) =>
                                  updateNode({
                                    needs: e.target.checked
                                      ? [...node.needs, n.id]
                                      : node.needs.filter((k) => k !== n.id),
                                  })
                                }
                              />
                              {n.id}
                            </label>
                          ))}
                        {!draft.nodes.some((_, i) => i !== selected) && (
                          <small>当前无其他节点</small>
                        )}
                      </div>
                      <NodeConfig
                        key={`${selected}:${node.plugin_id}:${node.plugin_version}:${mode}`}
                        value={node.config}
                        onChange={(config) => updateNode({ config })}
                      />
                      <details>
                        <summary>插件参数 Schema</summary>
                        <pre>
                          {format(
                            catalog.find(
                              (p) =>
                                p.manifest.id === node.plugin_id &&
                                p.manifest.version === node.plugin_version,
                            )?.manifest.config_schema || {},
                          )}
                        </pre>
                      </details>
                      <button
                        className="text-button danger"
                        onClick={() => {
                          update({
                            ...draft,
                            nodes: draft.nodes
                              .filter((_, i) => i !== selected)
                              .map((n) => ({
                                ...n,
                                needs: n.needs.filter((k) => k !== node.id),
                              })),
                          });
                          setSelected(0);
                        }}
                      >
                        移除节点
                      </button>
                    </>
                  ) : (
                    <p>添加一个节点，配置插件与依赖。</p>
                  )}
                </div>
              </div>
            </>
          )}
        </fieldset>
        <div className="workflow-editor-footer">
          <span>
            {saved
              ? `基于 ${saved.spec.id}@${saved.spec.version}${unchanged ? " · 已保存" : " · 有未保存修改"}`
              : "本地草稿"}
          </span>
          <div className="workflow-actions">
            <button
              className="button secondary small"
              disabled={!!busy}
              onClick={() =>
                void action("validate", async () => {
                  const result = await api.post<Validation>(
                    `${endpoint}/validate`,
                    { api_version: "codexploit/v1", spec: JSON.parse(text) },
                  );
                  setValidation(result);
                })
              }
            >
              <Check size={14} />
              校验草稿
            </button>
            <button
              className="button small"
              disabled={!!busy || !canWrite}
              onClick={() => void action("save", save)}
            >
              <Save size={14} />
              保存版本
            </button>
            <button
              className="text-button"
              disabled={!saved || !!busy}
              onClick={() =>
                void action("export", async () => {
                  const response = await api.response(
                    `${endpoint}/${encodeURIComponent(saved!.spec.id)}/versions/${encodeURIComponent(saved!.spec.version)}/export`,
                  );
                  download(await response.json(), "workflow-version.json");
                })
              }
            >
              导出已保存版本
            </button>
          </div>
        </div>
        {validation && (
          <div
            className={`workflow-validation ${validation.valid ? "valid" : "invalid"}`}
            role="status"
          >
            {validation.valid ? (
              <>
                <Check size={16} />
                校验通过 · {validation.nodes.map((n) => n.id).join(" → ")}
              </>
            ) : (
              <>
                <strong>校验未通过</strong>
                <ul>
                  {validation.diagnostics.map((d, i) => (
                    <li key={i}>
                      <code>{d.path}</code>
                      <span>
                        {d.code} · {d.message}
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
      </Panel>
      <Panel title="编译固定计划" eyebrow="COMPILE & PIN">
        <div className="workflow-compile-form">
          <label>
            源码快照
            <select
              aria-label="编译快照"
              value={snapshot}
              onChange={(e) => setSnapshot(e.target.value)}
            >
              <option value="">选择快照</option>
              {snapshots.map((s) => (
                <option key={s.snapshot_id} value={s.snapshot_id}>
                  {s.snapshot_id}
                </option>
              ))}
            </select>
          </label>
          <label>
            声明语言
            <input
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
            />
          </label>
          <label>
            知识版本
            <input
              value={knowledge}
              onChange={(e) => setKnowledge(e.target.value)}
              placeholder="latest 或 rev-N"
            />
          </label>
          <label>
            根输入预算（MiB）
            <input
              type="number"
              min={1}
              max={256}
              value={budget}
              onChange={(e) => setBudget(Number(e.target.value))}
            />
          </label>
          {(draft?.inputs || []).map((kind) => (
            <label className="workflow-root-binding" key={kind}>
              根输入 · {kind}
              <select
                value={roots[kind] || ""}
                onChange={(e) =>
                  setRoots((r) => ({ ...r, [kind]: e.target.value }))
                }
              >
                <option value="">选择已登记产物</option>
                {artifacts
                  .filter((a) => a.kind === kind)
                  .map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.schema_id} · {a.id} · {a.bytes} B
                    </option>
                  ))}
              </select>
            </label>
          ))}
          <div className="workflow-compile-note">
            latest
            在编译时解析一次并固定。语言为操作人声明；实际覆盖范围由后续工具调用报告。
          </div>
          <div className="workflow-actions">
            <button
              className="button secondary small"
              disabled={!canWrite || !snapshot || !!busy}
              onClick={() =>
                void action("artifacts", async () => {
                  await api.post(artifactEndpoint, null);
                  refresh((t) => t + 1);
                  setNotice("已登记真实快照产物。");
                })
              }
            >
              登记快照输入
            </button>
            <button
              className="button small"
              disabled={
                !canWrite ||
                !unchanged ||
                !snapshot ||
                !!busy ||
                !Number.isFinite(budget) ||
                budget < 1 ||
                budget > 256
              }
              onClick={() =>
                void action("compile", async () => {
                  const result = await api.post<{ plan: Plan }>(
                    `${endpoint}/${encodeURIComponent(saved!.spec.id)}/versions/${encodeURIComponent(saved!.spec.version)}/compile`,
                    {
                      api_version: "codexploit/v1",
                      snapshot_id: snapshot,
                      inputs: (draft?.inputs || [])
                        .map((k) => roots[k])
                        .filter(Boolean),
                      language,
                      knowledge_revision: knowledge,
                      max_input_bytes: Math.floor(budget * 1024 * 1024),
                    },
                  );
                  setPlan(result.plan);
                  setValidation({
                    valid: true,
                    diagnostics: [],
                    nodes: result.plan.nodes,
                  });
                  setPlanID(result.plan.plan_id);
                  sessionStorage.setItem(
                    `workflow-plan:${projectID}`,
                    result.plan.plan_id,
                  );
                  setNotice("固定计划已保存。此操作仅编译，不启动扫描。");
                })
              }
            >
              <GitBranch size={14} />
              编译已保存版本
            </button>
          </div>
        </div>
        {!unchanged && (
          <Hint>
            请选择一个已保存版本；如有草稿修改，请先提升版本号并保存。
          </Hint>
        )}
        <div className="workflow-plan-lookup">
          <label>
            读取已保存计划
            <input
              aria-label="计划 ID"
              placeholder="plan-…"
              value={planID}
              onChange={(e) => setPlanID(e.target.value)}
            />
          </label>
          <button
            className="button secondary small"
            disabled={!planID || !!busy}
            onClick={() => void action("read", loadPlan)}
          >
            读取计划
          </button>
        </div>
        {plan && (
          <div className="workflow-plan">
            <div className="workflow-plan-heading">
              <div>
                <span className="eyebrow">IMMUTABLE PLAN</span>
                <h3>
                  {plan.workflow.spec.name} · {plan.workflow.spec.version}
                </h3>
                <code>{plan.plan_id}</code>
              </div>
              <button
                className="button secondary small"
                onClick={() => download(plan, "workflow-plan.json")}
              >
                <ArrowDownToLine size={14} />
                导出计划
              </button>
            </div>
            <dl className="workflow-pins">
              <dt>计划摘要</dt>
              <dd>{plan.digest}</dd>
              <dt>定义摘要</dt>
              <dd>{plan.workflow.digest}</dd>
              <dt>固定 Scope</dt>
              <dd>
                {plan.scope.project_id} / {plan.scope.source_id} /{" "}
                {plan.scope.snapshot_id}
              </dd>
              <dt>知识版本</dt>
              <dd>
                {plan.knowledge.revision} · {plan.knowledge.digest}
              </dd>
              <dt>编译器 / 声明语言 / 输入预算</dt>
              <dd>
                {plan.compiler_version} / {plan.language} /{" "}
                {plan.max_input_bytes} B
              </dd>
            </dl>
            <div className="workflow-plan-roots">
              {plan.inputs.map((a) => (
                <div key={a.id}>
                  <strong>
                    {a.kind} · {a.schema_id}
                  </strong>
                  <code>
                    {a.id} · {a.bytes} B · SHA-256 {a.sha256}
                  </code>
                </div>
              ))}
            </div>
            <div className="table-scroll">
              <table className="workflow-plan-table">
                <thead>
                  <tr>
                    <th>顺序 / 节点</th>
                    <th>固定插件</th>
                    <th>类型输入绑定</th>
                    <th>输出 / 超时</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.nodes.map((n, i) => (
                    <tr key={n.id}>
                      <td>
                        {i + 1}. {n.id}
                        <small>依赖：{n.needs.join(", ") || "无"}</small>
                      </td>
                      <td>
                        {n.plugin_id}@{n.plugin_version}
                        <details>
                          <summary>查看包、清单与配置摘要</summary>
                          <code>package {n.plugin.package_digest}</code>
                          <code>manifest {n.plugin.manifest_digest}</code>
                          <code>config {n.config_digest}</code>
                          <pre>{format(n.config)}</pre>
                        </details>
                      </td>
                      <td>
                        {n.inputs.map((b) => (
                          <div key={b.kind}>
                            <code>{b.kind}</code> ←{" "}
                            {b.source === "root" ? "根输入" : b.from}
                            <small>
                              {b.schema_id}
                              {b.producer_plugin
                                ? ` · ${b.producer_plugin}`
                                : ""}
                            </small>
                          </div>
                        ))}
                      </td>
                      <td>
                        {n.outputs.join(" · ")}
                        <small>{n.timeout_seconds} 秒</small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Hint>
              计划只记录已校验的绑定和固定版本。任务执行属于后续工作流运行功能。
            </Hint>
          </div>
        )}
      </Panel>
    </div>
  );
}
function NodeConfig({
  value,
  onChange,
}: {
  value: object;
  onChange: (v: object) => void;
}) {
  const [text, setText] = useState(format(value));
  const [error, setError] = useState("");
  useEffect(() => {
    setText(format(value));
  }, [value]);
  return (
    <label>
      插件参数 JSON
      <textarea
        aria-label="节点参数 JSON"
        rows={5}
        value={text}
        spellCheck={false}
        onChange={(e) => {
          setText(e.target.value);
          try {
            const parsed = JSON.parse(e.target.value);
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
              throw new Error("参数应为 JSON 对象");
            setError("");
            onChange(parsed);
          } catch {
            setError("参数尚未应用：请输入有效 JSON 对象。");
          }
        }}
      />
      {error && <span role="alert">{error}</span>}
    </label>
  );
}
