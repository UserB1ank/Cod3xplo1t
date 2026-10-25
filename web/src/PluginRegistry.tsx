import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import {
  ArrowDown,
  ArrowRight,
  Binary,
  Bot,
  Box,
  Boxes,
  Braces,
  Check,
  CheckCircle2,
  ChevronRight,
  Code2,
  Copy,
  Download,
  FileText,
  Fingerprint,
  FlaskConical,
  GitBranch,
  ListFilter,
  Package,
  Play,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Unplug,
  X,
} from "lucide-react";
import { ApiClient } from "./api";
import { EmptyState, Modal } from "./components";
import type { ArtifactRef } from "./Artifacts";
import type { Snapshot } from "./types";
import { latestSnapshot } from "./workbench";
import {
  filterPlugins,
  pluginGroups,
  registryState,
  stageInputs,
  stageManifestTemplate,
  type RegistryRecord,
  type RegistryStage,
  type PluginRelease,
  type PluginInstallation,
  type StagePort,
} from "./plugin-registry";

export function pluginTabKeys(event: KeyboardEvent<HTMLElement>) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const tabs = Array.from(
    event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]'),
  );
  const index = tabs.indexOf(event.target as HTMLButtonElement);
  if (index < 0) return;
  const next =
    event.key === "Home"
      ? 0
      : event.key === "End"
        ? tabs.length - 1
        : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) %
          tabs.length;
  event.preventDefault();
  tabs[next]?.focus();
  tabs[next]?.click();
}

const stageIcons: Record<string, typeof Box> = {
  source: Boxes,
  parse: Code2,
  semantic: Shield,
  scan: Search,
  "path.generate": GitBranch,
  "path.enhance": ListFilter,
  agent: Bot,
  environment: Box,
  verification: FlaskConical,
  report: FileText,
};
const kindLabels: Record<string, string> = {
  "source.request": "代码源定义",
  "source.snapshot": "固定源码",
  "code.facts": "代码事实",
  "security.facts": "安全语义",
  "scanner.alerts": "扫描告警",
  "discovery.paths": "候选路径",
  "path.enhancement": "筛选与评分",
  "agent.task": "审查任务",
  "agent.answer": "审查答案",
  "environment.request": "环境规格",
  "environment.receipt": "环境回执",
  "verification.plan": "验证计划",
  "verification.evidence": "验证证据",
  "report.input": "固定报告输入",
  "report.document": "报告文档",
  "tool.native": "工具原生产物",
};
function displayReason(reason: string) {
  const messages: Record<string, string> = {
    "Manifest registered; this package has no installed execution adapter":
      "清单已登记，当前节点尚未安装此发行包。",
    "Package installed; this host has no execution adapter for its runtime":
      "发行包已安装，当前宿主未配置对应执行器。",
    "Package was uninstalled": "已卸载执行登记，历史调用与产物保留。",
    "Installation is disabled": "已禁用此版本的新调用。",
    "Package integrity is not verified": "完整性尚未通过，请核验部署包。",
  };
  return messages[reason] || reason;
}
const errorText = (error: unknown) =>
  error instanceof Error ? error.message : String(error);
const dateText = (value?: string) =>
  value
    ? new Date(value).toLocaleString("zh-CN", { hour12: false })
    : "尚未检查";
function StageIcon({ stage, size = 17 }: { stage?: string; size?: number }) {
  const Icon = stageIcons[stage || ""] || Package;
  return <Icon size={size} strokeWidth={1.6} aria-hidden="true" />;
}
function StateLabel({ record }: { record: RegistryRecord }) {
  const state = registryState(record);
  return (
    <span className={`pc-state ${state.tone}`}>
      <i />
      {state.label}
    </span>
  );
}
function downloadTemplate(stage: RegistryStage) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(stageManifestTemplate(stage), null, 2) + "\n"], {
      type: "application/json",
    }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = `${stage.stage}.manifest.json`;
  link.click();
  URL.revokeObjectURL(url);
}
function PortList({
  ports,
  direction,
}: {
  ports: StagePort[];
  direction: string;
}) {
  return (
    <div className="pc-port-list">
      {ports.map((port) => (
        <div className="pc-port" key={port.name}>
          <div>
            <span className="pc-port-symbol">
              {direction === "输入" ? (
                <ArrowRight size={14} />
              ) : (
                <ArrowDown size={14} />
              )}
            </span>
            <strong>{kindLabels[port.kind] || port.kind}</strong>
            <code>{port.name}</code>
            <small>
              {port.required ? "必需" : "可选"} ·{" "}
              {port.cardinality === "many" ? "多项" : "单项"}
            </small>
          </div>
          <code>{port.schema_id}</code>
        </div>
      ))}
    </div>
  );
}

export function PluginRegistry({
  api,
  canRegister,
  canWrite,
  projectID,
  snapshots,
  onLegacyExecute,
  onInvoked,
  onWorkflow,
  onReports,
}: {
  api: ApiClient;
  canRegister: boolean;
  canWrite: boolean;
  projectID: string;
  snapshots: Snapshot[];
  onLegacyExecute: (record: RegistryRecord) => void;
  onInvoked: (snapshot: string, invocation: string) => void;
  onWorkflow: () => void;
  onReports: () => void;
}) {
  const [records, setRecords] = useState<RegistryRecord[]>([]);
  const [stages, setStages] = useState<RegistryStage[]>([]);
  const [platform, setPlatform] = useState({ os: "", arch: "" });
  const [stage, setStage] = useState("");
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState("");
  const [selection, select] = useState("");
  const [version, setVersion] = useState("");
  const [detailTab, setDetailTab] = useState("overview");
  const [tick, refresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [copied, setCopied] = useState("");
  const [importing, setImporting] = useState(false);
  const [manifest, setManifest] = useState("");
  const [packageDigest, setPackageDigest] = useState("");
  const [templateStage, setTemplateStage] = useState("parse");
  const [runRecord, setRunRecord] = useState<RegistryRecord>();
  const [releases, setReleases] = useState<PluginRelease[]>([]);
  const [installations, setInstallations] = useState<PluginInstallation[]>([]);
  const [installLoading, setInstallLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  const groups = useMemo(() => pluginGroups(records), [records]);
  const rows = useMemo(
    () => filterPlugins(groups, { query, stage, state: stateFilter }),
    [groups, query, stage, stateFilter],
  );
  const group = groups.find((row) => row.id === selection);
  const chosen =
    group?.versions.find((row) => row.manifest.version === version) ||
    group?.current;
  const currentStage = stages.find((row) => row.stage === stage);
  const chosenStage = stages.find((row) => row.stage === chosen?.stages?.[0]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    (async () => {
      const all: RegistryRecord[] = [];
      let cursor = "";
      do {
        const page = await api.get<{
          plugins: RegistryRecord[];
          next_cursor: string;
        }>(
          `/v2/plugins?limit=100&cursor=${encodeURIComponent(cursor)}`,
          controller.signal,
        );
        all.push(...page.plugins);
        cursor = page.next_cursor;
        if (all.length >= 1000 && cursor)
          throw new Error("插件目录超过 1000 项，请联系管理员缩小登记范围。");
      } while (cursor);
      const catalog = await api.get<{
        stages: RegistryStage[];
        host: { os: string; arch: string };
      }>("/v2/plugin-stages", controller.signal);
      setRecords(all);
      setStages(catalog.stages);
      setPlatform(catalog.host);
    })()
      .catch((err) => {
        if (!controller.signal.aborted) setError(errorText(err));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [api, tick]);
  useEffect(() => {
    if (!chosen || detailTab !== "installation") return;
    const controller = new AbortController();
    setInstallLoading(true);
    setDetailError("");
    setReleases([]);
    setInstallations([]);
    Promise.all([
      api.get<{ releases: PluginRelease[] }>(
        `/v2/plugins/${encodeURIComponent(chosen.manifest.id)}/versions/${encodeURIComponent(chosen.manifest.version)}/releases`,
        controller.signal,
      ),
      api.get<{ installations: PluginInstallation[] }>(
        "/v2/plugin-installations",
        controller.signal,
      ),
    ])
      .then(([releasePage, installPage]) => {
        setReleases(releasePage.releases);
        setInstallations(
          installPage.installations.filter(
            (row) =>
              row.release.plugin_id === chosen.manifest.id &&
              row.release.plugin_version === chosen.manifest.version &&
              row.release.package_digest === chosen.package_digest,
          ),
        );
      })
      .catch((err) => {
        if (!controller.signal.aborted) setDetailError(errorText(err));
      })
      .finally(() => {
        if (!controller.signal.aborted) setInstallLoading(false);
      });
    return () => controller.abort();
  }, [
    api,
    chosen?.manifest.id,
    chosen?.manifest.version,
    chosen?.package_digest,
    detailTab,
    tick,
  ]);
  async function perform(label: string, action: () => Promise<void>) {
    setBusy(label);
    setError("");
    setNotice("");
    try {
      await action();
      refresh((n) => n + 1);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy("");
    }
  }
  async function copy(label: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
    } catch {
      setError("无法写入剪贴板，请手动选择并复制摘要。");
    }
  }
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(""), 1800);
    return () => clearTimeout(timer);
  }, [copied]);
  async function policy(action: "check" | "toggle" | "uninstall") {
    const row = chosen?.installation;
    if (!row) throw new Error("没有当前节点的安装记录。");
    const endpoint = `/v2/plugin-installations/${encodeURIComponent(row.id)}`;
    await api.response(action === "check" ? `${endpoint}/check` : endpoint, {
      method:
        action === "check" ? "POST" : action === "toggle" ? "PATCH" : "DELETE",
      headers: { "If-Match": `"installation-${row.id}-v${row.version}"` },
      ...(action === "toggle"
        ? { body: JSON.stringify({ enabled: !row.enabled }) }
        : {}),
    });
    setNotice(
      action === "check"
        ? "完整性检查已完成，请查看当前结果。"
        : action === "uninstall"
          ? "已卸载执行登记，历史调用与产物保留。"
          : row.enabled
            ? "已禁用新调用，正在执行的调用不受影响。"
            : "已启用新调用。",
    );
  }
  async function install() {
    if (!chosen) return;
    const release: PluginRelease = {
      plugin_id: chosen.manifest.id,
      plugin_version: chosen.manifest.version,
      os: platform.os,
      arch: platform.arch,
      package_digest: chosen.package_digest,
      manifest_digest: chosen.manifest_digest,
    };
    await api.post(
      `/v2/plugins/${encodeURIComponent(release.plugin_id)}/versions/${encodeURIComponent(release.plugin_version)}/releases`,
      release,
    );
    await api.post("/v2/plugin-installations", release);
    setNotice("已核验并安装部署包，功能实测将在真实调用后记录。");
  }
  function execute() {
    if (!chosen) return;
    select("");
    if (chosen.manifest.api_version === "codexploit/plugin/v2")
      setRunRecord(chosen);
    else onLegacyExecute(chosen);
  }
  const integrityLabels: Record<string, string> = {
    verified: "已验证",
    failed: "校验失败",
    unknown: "未校验",
  };
  const probeLabels: Record<string, string> = {
    passed: "已通过",
    failed: "未通过",
    not_run: "未实测",
  };
  const legacyDomain =
    chosen?.manifest.id === "builtin.reporter"
      ? "report"
      : chosen?.manifest.id === "builtin.path-enhancer"
        ? "workflow"
        : "";
  return (
    <div className="pc-catalog">
      <div className="pc-catalog-heading">
        <div>
          <h2>
            工具目录 <span>{groups.length}</span>
          </h2>
          <p>插件在工作区共享，执行使用当前项目的固定输入。</p>
        </div>
        <div className="pc-actions">
          <button
            className="button secondary"
            aria-label="刷新插件目录"
            disabled={loading || !!busy}
            onClick={() => refresh((n) => n + 1)}
          >
            <RefreshCw size={14} />
            刷新
          </button>
          <button
            className="button primary"
            disabled={!canRegister}
            title={!canRegister ? "需要管理员权限" : undefined}
            onClick={() => {
              setImporting(true);
              setError("");
            }}
          >
            <Plus size={15} />
            接入插件
          </button>
        </div>
      </div>
      {error && (
        <div className="error-message" role="alert">
          {error}
          <button className="text-button" onClick={() => refresh((n) => n + 1)}>
            重新加载
          </button>
        </div>
      )}
      {notice && (
        <div className="success-message" role="status">
          <CheckCircle2 size={15} />
          {notice}
        </div>
      )}
      <div className="pc-browser">
        <aside className="pc-stages" aria-label="插件阶段筛选">
          <button
            className={!stage ? "selected" : ""}
            aria-pressed={!stage}
            onClick={() => setStage("")}
          >
            <Package size={17} />
            <span>全部插件</span>
            <small>{groups.length}</small>
          </button>
          <p>分析与发现</p>
          {stages.slice(0, 6).map((item) => (
            <button
              key={item.stage}
              className={stage === item.stage ? "selected" : ""}
              aria-pressed={stage === item.stage}
              onClick={() => setStage(item.stage)}
            >
              <StageIcon stage={item.stage} />
              <span>{item.label}</span>
              <small>
                {
                  groups.filter((row) =>
                    row.versions.some((version) =>
                      version.stages?.includes(item.stage),
                    ),
                  ).length
                }
              </small>
            </button>
          ))}
          <p>审查与交付</p>
          {stages.slice(6).map((item) => (
            <button
              key={item.stage}
              className={stage === item.stage ? "selected" : ""}
              aria-pressed={stage === item.stage}
              onClick={() => setStage(item.stage)}
            >
              <StageIcon stage={item.stage} />
              <span>{item.label}</span>
              <small>
                {
                  groups.filter((row) =>
                    row.versions.some((version) =>
                      version.stages?.includes(item.stage),
                    ),
                  ).length
                }
              </small>
            </button>
          ))}
          <div className="pc-worker-note">
            <span className="pc-node-dot" />
            当前节点
            <code>{platform.os && `${platform.os} / ${platform.arch}`}</code>
          </div>
        </aside>
        <section className="pc-results" aria-label="插件目录">
          <div className="pc-list-tools">
            <label className="pc-search">
              <Search size={16} />
              <input
                aria-label="搜索插件"
                placeholder="搜索名称或插件 ID…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              {query && (
                <button aria-label="清空搜索" onClick={() => setQuery("")}>
                  <X size={13} />
                </button>
              )}
            </label>
            <label className="pc-filter">
              <SlidersHorizontal size={14} />
              <select
                aria-label="插件状态筛选"
                value={stateFilter}
                onChange={(e) => setStateFilter(e.target.value)}
              >
                <option value="">全部状态</option>
                <option value="ready">可执行</option>
                <option value="uninstalled">待安装</option>
                <option value="disabled">已禁用</option>
                <option value="integrity">校验失败</option>
                <option value="probe">实测失败</option>
                <option value="unavailable">暂不可执行</option>
              </select>
            </label>
          </div>
          {currentStage && (
            <div className="pc-stage-context">
              <div>
                <StageIcon stage={stage} />
                <strong>{currentStage.label}</strong>
                <code>{stage}</code>
              </div>
              <p>
                {currentStage.inputs
                  .map((p) => kindLabels[p.kind] || p.kind)
                  .join(" + ")}
                <ArrowRight size={13} />
                {currentStage.outputs
                  .map((p) => kindLabels[p.kind] || p.kind)
                  .join(" + ")}
              </p>
            </div>
          )}
          {loading && !records.length ? (
            <div
              className="pc-skeleton"
              role="status"
              aria-label="正在加载插件目录"
            >
              {[0, 1, 2, 3, 4].map((n) => (
                <div key={n}>
                  <i />
                  <span />
                  <b />
                </div>
              ))}
            </div>
          ) : rows.length ? (
            <div className="pc-table-scroll">
              <table className="pc-table">
                <thead>
                  <tr>
                    <th>插件</th>
                    <th>归属阶段</th>
                    <th>当前节点</th>
                    <th>版本</th>
                    <th aria-label="查看详情" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.id}>
                      <td>
                        <button
                          className="pc-plugin-link"
                          onClick={() => {
                            select(row.id);
                            setVersion(row.current.manifest.version);
                            setDetailTab("overview");
                            setError("");
                            setNotice("");
                          }}
                        >
                          <span className="pc-plugin-icon">
                            <StageIcon
                              stage={row.current.stages?.[0]}
                              size={19}
                            />
                          </span>
                          <span>
                            <strong>{row.current.manifest.name}</strong>
                            <code>{row.id}</code>
                          </span>
                        </button>
                      </td>
                      <td>
                        <span className="pc-stage-name">
                          {stages.find(
                            (s) => s.stage === row.current.stages?.[0],
                          )?.label || "未登记"}
                        </span>
                        {row.current.stages?.length > 1 && (
                          <small>
                            另 {row.current.stages.length - 1} 个阶段
                          </small>
                        )}
                      </td>
                      <td>
                        <StateLabel record={row.current} />
                        <small>
                          {row.current.installation?.probe === "passed"
                            ? "功能实测通过"
                            : row.current.installation?.probe === "failed"
                              ? "查看失败原因"
                              : row.current.executable
                                ? "功能尚未实测"
                                : ""}
                        </small>
                      </td>
                      <td>
                        <code className="pc-version">
                          {row.current.manifest.version}
                        </code>
                        <small>{row.versions.length} 个版本</small>
                      </td>
                      <td>
                        <button
                          className="icon-button"
                          aria-label={`查看 ${row.current.manifest.name}`}
                          onClick={() => {
                            select(row.id);
                            setVersion(row.current.manifest.version);
                            setDetailTab("overview");
                          }}
                        >
                          <ChevronRight size={15} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title={
                error
                  ? "目录暂不可读取"
                  : query || stage || stateFilter
                    ? "没有匹配的插件"
                    : "尚未登记插件"
              }
            >
              {query || stateFilter
                ? "调整搜索或状态筛选，查看其他工具。"
                : stage
                  ? "此阶段尚未登记工具，可接入符合该阶段契约的插件。"
                  : "接入插件清单后，在这里管理版本、安装状态和固定输入执行。"}
              {(query || stateFilter) && (
                <button
                  className="text-button"
                  onClick={() => {
                    setQuery("");
                    setStateFilter("");
                  }}
                >
                  清除筛选
                </button>
              )}
            </EmptyState>
          )}
          <footer className="pc-list-footer">
            <span>
              {rows.length} 个插件 · {records.length} 个登记版本
            </span>
            <span>
              <Fingerprint size={13} />
              版本与包摘要固定
            </span>
          </footer>
        </section>
      </div>
      <Modal
        open={!!chosen}
        onClose={() => {
          if (!busy) select("");
        }}
        title="插件详情"
        variant="drawer"
        wide
      >
        {chosen && (
          <div className="pc-detail">
            <header className="pc-detail-heading">
              <span className="pc-plugin-icon large">
                <StageIcon stage={chosen.stages?.[0]} size={25} />
              </span>
              <div>
                <h3>{chosen.manifest.name}</h3>
                <code>{chosen.manifest.id}</code>
                <div className="pc-detail-tags">
                  <span>
                    {chosenStage?.label || chosen.stages?.join(" / ")}
                  </span>
                  <span>
                    {chosen.manifest.runtime.kind === "builtin"
                      ? "内置工具"
                      : chosen.manifest.runtime.kind === "process"
                        ? "进程插件"
                        : "领域适配器"}
                  </span>
                  <StateLabel record={chosen} />
                </div>
              </div>
            </header>
            <label className="pc-version-select">
              查看版本
              <select
                value={chosen.manifest.version}
                onChange={(e) => {
                  setVersion(e.target.value);
                  setError("");
                  setNotice("");
                }}
              >
                {group?.versions.map((row) => (
                  <option
                    key={row.manifest.version}
                    value={row.manifest.version}
                  >
                    {row.manifest.version}
                    {row.executable ? " · 可执行" : ""}
                  </option>
                ))}
              </select>
              <small>{group?.versions.length} 个已登记版本</small>
            </label>
            <div
              className="pc-detail-tabs"
              role="tablist"
              aria-label="插件详情"
              onKeyDown={pluginTabKeys}
            >
              {[
                ["overview", "概览"],
                ["contracts", "输入与输出"],
                ["installation", "安装与版本"],
              ].map(([key, label]) => (
                <button
                  key={key}
                  role="tab"
                  aria-selected={detailTab === key}
                  tabIndex={detailTab === key ? 0 : -1}
                  onClick={() => setDetailTab(key)}
                >
                  {label}
                </button>
              ))}
            </div>
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
            {detailTab === "overview" && (
              <div className="pc-detail-section" role="tabpanel">
                <p className="pc-description">
                  {chosen.manifest.description || "此插件尚未填写说明。"}
                </p>
                <dl className="pc-health">
                  <div>
                    <dt>
                      <Box size={14} />
                      节点安装
                    </dt>
                    <dd>{chosen.installed ? "已安装" : "未安装"}</dd>
                  </div>
                  <div>
                    <dt>
                      <ShieldCheck size={14} />
                      完整性
                    </dt>
                    <dd
                      className={
                        chosen.installation?.integrity === "failed"
                          ? "pc-danger"
                          : ""
                      }
                    >
                      {
                        integrityLabels[
                          chosen.installation?.integrity || "unknown"
                        ]
                      }
                    </dd>
                  </div>
                  <div>
                    <dt>
                      <FlaskConical size={14} />
                      功能实测
                    </dt>
                    <dd>
                      {probeLabels[chosen.installation?.probe || "not_run"]}
                    </dd>
                  </div>
                  <div>
                    <dt>
                      <SlidersHorizontal size={14} />
                      调用策略
                    </dt>
                    <dd>
                      {chosen.installation
                        ? chosen.installation.enabled
                          ? "已启用"
                          : "已禁用"
                        : "未配置"}
                    </dd>
                  </div>
                </dl>
                {chosen.reason && (
                  <p className="pc-reason">{displayReason(chosen.reason)}</p>
                )}
                <dl className="pc-definition">
                  <div>
                    <dt>支持语言</dt>
                    <dd>
                      {chosen.manifest.languages?.join(" / ") || "未声明"}
                    </dd>
                  </div>
                  <div>
                    <dt>执行协议</dt>
                    <dd>
                      <code>
                        {chosen.manifest.runtime.protocol || "builtin/v1"}
                      </code>
                    </dd>
                  </div>
                  <div>
                    <dt>最近检查</dt>
                    <dd>{dateText(chosen.installation?.checked_at)}</dd>
                  </div>
                </dl>
                {!!chosen.manifest.tools?.length && (
                  <section className="pc-tools">
                    <h4>
                      <Binary size={15} />
                      随包工具
                    </h4>
                    {chosen.manifest.tools.map((tool) => (
                      <div key={tool.id}>
                        <strong>
                          {tool.id}
                          <code>{tool.version}</code>
                        </strong>
                        <code>{tool.entrypoint}</code>
                      </div>
                    ))}
                  </section>
                )}
                <p className="pc-footnote">
                  功能实测由真实调用结果记录，与文件完整性校验独立。
                  {chosen.manifest.operations?.every(
                    (op) => op.profile === "native",
                  ) && "此版本仅输出原生产物，接入标准节点前需要契约转换。"}
                </p>
              </div>
            )}
            {detailTab === "contracts" && (
              <div className="pc-detail-section" role="tabpanel">
                {chosen.manifest.operations?.length ? (
                  chosen.manifest.operations.map((op) => (
                    <section className="pc-operation" key={op.id}>
                      <header>
                        <h4>{op.id}</h4>
                        <code>{op.stage}</code>
                        <span>
                          {op.profile === "native" ? "原生输出" : "标准契约"}
                        </span>
                      </header>
                      <h5>输入</h5>
                      <PortList ports={op.inputs} direction="输入" />
                      <h5>输出</h5>
                      <PortList ports={op.outputs} direction="输出" />
                      <details>
                        <summary>参数 Schema</summary>
                        <pre>{JSON.stringify(op.config_schema, null, 2)}</pre>
                      </details>
                    </section>
                  ))
                ) : (
                  <section className="pc-operation">
                    <p className="pc-footnote">
                      此版本通过兼容适配器提供固定契约。
                    </p>
                    <h5>输入</h5>
                    {chosen.manifest.consumes?.map((kind) => (
                      <p className="pc-legacy-port" key={kind}>
                        <ArrowRight size={14} />
                        {kindLabels[kind] || kind}
                        <code>{kind}</code>
                      </p>
                    ))}
                    <h5>输出</h5>
                    {chosen.manifest.produces?.map((kind) => (
                      <p className="pc-legacy-port" key={kind}>
                        <ArrowDown size={14} />
                        {kindLabels[kind] || kind}
                        <code>{kind}</code>
                      </p>
                    ))}
                  </section>
                )}
              </div>
            )}
            {detailTab === "installation" && (
              <div className="pc-detail-section" role="tabpanel">
                <h4>不可变身份</h4>
                {[
                  ["清单 SHA-256", chosen.manifest_digest],
                  ["发行包 SHA-256", chosen.package_digest],
                ].map(([label, value]) => (
                  <div className="pc-digest" key={label}>
                    <span>{label}</span>
                    <button
                      className="icon-button"
                      aria-label={`复制${label}`}
                      onClick={() => void copy(label, value)}
                    >
                      {copied === label ? (
                        <Check size={14} />
                      ) : (
                        <Copy size={14} />
                      )}
                    </button>
                    <code>{value}</code>
                  </div>
                ))}
                <h4>节点安装</h4>
                {installLoading ? (
                  <p role="status" className="pc-footnote">
                    正在读取安装记录…
                  </p>
                ) : detailError ? (
                  <div role="alert" className="error-message">
                    {detailError}
                  </div>
                ) : installations.length ? (
                  installations.map((row) => (
                    <div className="pc-node-record" key={row.id}>
                      <div>
                        <span className="pc-node-dot" />
                        <strong>
                          {row.release.os} / {row.release.arch}
                        </strong>
                        <span>
                          {row.installed
                            ? row.enabled
                              ? "已启用"
                              : "已禁用"
                            : "已卸载"}
                        </span>
                      </div>
                      <code>{row.worker_id}</code>
                      <p>
                        完整性 {integrityLabels[row.integrity]} · 实测{" "}
                        {probeLabels[row.probe]} · {dateText(row.checked_at)}
                      </p>
                    </div>
                  ))
                ) : (
                  <p className="pc-footnote">此发行包尚无节点安装记录。</p>
                )}
                <h4>
                  平台发行包 <span className="pc-count">{releases.length}</span>
                </h4>
                {releases.map((release, index) => (
                  <div
                    className="pc-release"
                    key={`${release.os}-${release.arch}-${index}`}
                  >
                    <strong>
                      {release.os} / {release.arch}
                    </strong>
                    <code title={release.package_digest}>
                      {release.package_digest.slice(0, 16)}…
                    </code>
                    <span>
                      {release.package_digest === chosen.package_digest
                        ? "当前包"
                        : "历史构建"}
                    </span>
                  </div>
                ))}
                {chosen.installation &&
                  chosen.manifest.runtime.kind === "process" && (
                    <details className="pc-uninstall">
                      <summary>卸载执行登记</summary>
                      <p>
                        保留发行包、历史调用和证据。存在活动调用时无法卸载。
                      </p>
                      <button
                        className="button secondary"
                        disabled={!canRegister || !!busy || !chosen.installed}
                        onClick={() =>
                          void perform("uninstall", () => policy("uninstall"))
                        }
                      >
                        <Unplug size={14} />
                        卸载此版本
                      </button>
                    </details>
                  )}
              </div>
            )}
            <footer className="pc-detail-footer">
              <div className="pc-actions">
                {chosen.installation && chosen.installed && (
                  <>
                    <button
                      className="button secondary"
                      disabled={!canRegister || !!busy}
                      onClick={() =>
                        void perform("check", () => policy("check"))
                      }
                    >
                      <ShieldCheck size={14} />
                      {busy === "check" ? "正在核验…" : "校验完整性"}
                    </button>
                    <button
                      className="button secondary"
                      disabled={
                        !canRegister ||
                        !!busy ||
                        (!chosen.installation.enabled &&
                          chosen.installation.integrity !== "verified")
                      }
                      onClick={() =>
                        void perform("toggle", () => policy("toggle"))
                      }
                    >
                      {chosen.installation.enabled ? "禁用" : "启用"}
                    </button>
                  </>
                )}
                {!chosen.installed &&
                  chosen.manifest.runtime.kind === "process" && (
                    <button
                      className="button secondary"
                      disabled={!canRegister || !!busy}
                      onClick={() => void perform("install", install)}
                    >
                      <Download size={14} />
                      {busy === "install" ? "正在安装…" : "安装部署包"}
                    </button>
                  )}
              </div>
              {legacyDomain ? (
                <button
                  className="button primary"
                  onClick={() => {
                    select("");
                    legacyDomain === "report" ? onReports() : onWorkflow();
                  }}
                >
                  {legacyDomain === "report"
                    ? "生成审计报告"
                    : "在工作流中使用"}
                  <ArrowRight size={14} />
                </button>
              ) : (
                <button
                  className="button primary"
                  disabled={!canWrite || !!busy || !chosen.executable}
                  onClick={execute}
                >
                  <Play size={14} />
                  执行插件
                </button>
              )}
            </footer>
          </div>
        )}
      </Modal>
      <Modal
        open={importing}
        onClose={() => {
          if (!busy) setImporting(false);
        }}
        title="接入插件"
        wide
      >
        <form
          className="pc-import"
          onSubmit={(e) => {
            e.preventDefault();
            void perform("import", async () => {
              const page = await api.post<{ plugin: RegistryRecord }>(
                "/v2/plugins",
                {
                  api_version: "codexploit/v2",
                  manifest: JSON.parse(manifest),
                  package_digest: packageDigest,
                  source: "manual registry",
                },
              );
              setImporting(false);
              select(page.plugin.manifest.id);
              setVersion(page.plugin.manifest.version);
              setDetailTab("overview");
              setNotice("定义已登记。部署并核验发行包后即可安装。");
            });
          }}
        >
          <p>
            登记固定版本、归属阶段与输入输出。清单登记完成后，安装和功能实测分别记录。
          </p>
          <div className="pc-template">
            <label>
              阶段模板
              <select
                value={templateStage}
                onChange={(e) => setTemplateStage(e.target.value)}
              >
                {stages.map((item) => (
                  <option key={item.stage} value={item.stage}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="button secondary"
              type="button"
              onClick={() => {
                const item = stages.find((s) => s.stage === templateStage);
                if (item)
                  setManifest(
                    JSON.stringify(stageManifestTemplate(item), null, 2),
                  );
              }}
            >
              <Braces size={14} />
              载入模板
            </button>
          </div>
          <label>
            清单 JSON
            <textarea
              aria-label="v2 插件清单 JSON"
              required
              rows={12}
              spellCheck={false}
              value={manifest}
              onChange={(e) => setManifest(e.target.value)}
            />
          </label>
          <label>
            预期发行包 SHA-256
            <input
              aria-label="v2 插件包摘要"
              required
              pattern="[a-f0-9]{64}"
              value={packageDigest}
              onChange={(e) => setPackageDigest(e.target.value)}
              placeholder="打包工具输出的 64 位摘要"
            />
          </label>
          <small>
            安装时只读取管理员配置的部署目录，清单不触发在线下载或安装脚本。
          </small>
          {error && (
            <div className="error-message" role="alert">
              {error}
            </div>
          )}
          <footer>
            <button
              className="button secondary"
              type="button"
              onClick={() => setImporting(false)}
              disabled={!!busy}
            >
              取消
            </button>
            <button className="button primary" disabled={!!busy}>
              <Plus size={14} />
              {busy === "import" ? "正在登记…" : "登记固定版本"}
            </button>
          </footer>
        </form>
      </Modal>
      <PluginRunDialog
        api={api}
        record={runRecord}
        snapshots={snapshots}
        projectID={projectID}
        onClose={() => setRunRecord(undefined)}
        onInvoked={(snapshot, id) => {
          setRunRecord(undefined);
          onInvoked(snapshot, id);
        }}
      />
    </div>
  );
}

function stageLabel(stage: string) {
  return (
    {
      parse: "解析",
      semantic: "语义与污点",
      "path.generate": "路径生成",
      "path.enhance": "路径筛选",
      scan: "扫描",
      report: "报告",
      source: "源码",
      agent: "Agent",
      environment: "环境",
      verification: "验证",
    } as Record<string, string>
  )[stage] || stage;
}

function artifactChoice(ref: ArtifactRef) {
  const source = ref.producer?.plugin_id
    ? `${ref.producer.plugin_id}@${ref.producer.plugin_version}`
    : "来源未记录";
  return `${kindLabels[ref.kind] || ref.kind} · ${source} · ${ref.id.slice(-10)} · ${ref.bytes.toLocaleString()} B`;
}

function PluginRunDialog({
  api,
  record,
  snapshots,
  projectID,
  onClose,
  onInvoked,
}: {
  api: ApiClient;
  record?: RegistryRecord;
  snapshots: Snapshot[];
  projectID: string;
  onClose: () => void;
  onInvoked: (snapshot: string, id: string) => void;
}) {
  const [snapshot, setSnapshot] = useState("");
  const [operationID, setOperation] = useState("");
  const [artifacts, setArtifacts] = useState<ArtifactRef[]>([]);
  const [selected, setSelected] = useState<Record<string, string | string[]>>(
    {},
  );
  const [config, setConfig] = useState("{}");
  const [timeout, setTimeout] = useState(300);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const operation =
    record?.manifest.operations?.find((op) => op.id === operationID) ||
    record?.manifest.operations?.[0];
  const frontendChoices = (operation?.config_schema as { properties?: { frontend?: { enum?: string[] } } })?.properties?.frontend?.enum;
  const latest = latestSnapshot(snapshots);
  useEffect(() => {
    if (record) {
      setSnapshot(latest?.snapshot_id || "");
      setOperation(record.manifest.operations?.[0]?.id || "");
      setConfig("{}");
      setSelected({});
      setError("");
    }
  }, [record]);
  useEffect(() => {
    setSelected({});
    setArtifacts([]);
    if (!record || !snapshot) return;
    const controller = new AbortController();
    setLoading(true);
    (async () => {
      const refs: ArtifactRef[] = [];
      let cursor = "";
      do {
        const page = await api.get<{
          artifacts: ArtifactRef[];
          next_cursor: string;
        }>(
          `/v1/projects/${encodeURIComponent(projectID)}/snapshots/${encodeURIComponent(snapshot)}/artifacts?limit=100&cursor=${encodeURIComponent(cursor)}`,
          controller.signal,
        );
        refs.push(...page.artifacts);
        cursor = page.next_cursor;
        if (refs.length >= 2000 && cursor)
          throw new Error("产物超过 2000 项，请缩小输入范围。");
      } while (cursor);
      setArtifacts(refs);
    })()
      .catch((err) => {
        if (!controller.signal.aborted) setError(errorText(err));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [api, record, snapshot, projectID]);
  const eligible = (port: NonNullable<typeof operation>["inputs"][number]) =>
    artifacts.filter(
      (ref) => ref.kind === port.kind && ref.schema_id === port.schema_id,
    );
  useEffect(() => {
    if (!operation) return;
    setSelected((current) => {
      let changed = false;
      const next = { ...current };
      for (const port of operation.inputs) {
        if (next[port.name] || port.cardinality === "many") continue;
        const matches = artifacts.filter(
          (ref) => ref.kind === port.kind && ref.schema_id === port.schema_id,
        );
        if (matches.length === 1) {
          next[port.name] = matches[0].id;
          changed = true;
        }
      }
      return changed ? next : current;
    });
  }, [artifacts, operation?.id]);
  let configValue: Record<string, unknown> | undefined;
  let configError = "";
  try {
    const parsed = JSON.parse(config);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      configError = "参数必须是 JSON 对象。";
    else configValue = parsed as Record<string, unknown>;
  } catch {
    configError = "参数不是有效 JSON；请修正后再提交。";
  }
  const checks: { ok: boolean; label: string; detail?: string }[] = [];
  checks.push({
    ok: !!snapshot,
    label: snapshot ? "已绑定固定源码快照" : "缺少固定源码快照",
  });
  if (operation) {
    for (const port of operation.inputs) {
      const matches = eligible(port);
      const value = selected[port.name];
      const count = Array.isArray(value) ? value.length : value ? 1 : 0;
      const ok = port.required
        ? matches.length === 1 && count === 1
        : count > 0 || matches.length === 0;
      checks.push({
        ok,
        label: ok
          ? `${kindLabels[port.kind] || port.kind} ${port.name} 已准备`
          : port.required
            ? matches.length === 0
              ? `${kindLabels[port.kind] || port.kind} 没有符合契约的固定输入`
              : `${kindLabels[port.kind] || port.kind} 需要显式选择一项`
            : `${kindLabels[port.kind] || port.kind} 可选输入尚未选择`,
        detail: port.schema_id,
      });
    }
  }
  checks.push({
    ok: !configError,
    label: configError || "参数 JSON 已通过本地校验",
  });
  checks.push({
    ok: Number.isFinite(timeout) && timeout >= 1 && timeout <= 3600,
    label:
      Number.isFinite(timeout) && timeout >= 1 && timeout <= 3600
        ? `执行预算 ${timeout} 秒`
        : "超时必须是 1–3600 秒",
  });
  if (record) {
    checks.push({
      ok: record.executable && record.installed,
      label: record.executable && record.installed
        ? "固定版本已安装且可执行"
        : "当前版本未安装或不可执行；提交会被拒绝",
    });
  }
  const prepared = checks.every((check) => check.ok);
  const blockedCount = checks.filter((check) => !check.ok).length;
  return (
    <Modal
      open={!!record}
      onClose={() => {
        if (!busy) onClose();
      }}
      title="准备执行固定版本"
      wide
    >
      {record && operation && (
        <form
          className="pc-run-dialog"
          onSubmit={(e) => {
            e.preventDefault();
            if (!prepared || busy) return;
            setBusy(true);
            setError("");
            try {
              const input = stageInputs(operation, artifacts, selected);
              if (!input.inputs.length) throw new Error("请选择固定输入。");
              if (!configValue) throw new Error(configError || "参数无效。");
              void api
                .post<{
                  invocation: { invocation_id: string };
                }>(
                  `/v1/projects/${encodeURIComponent(projectID)}/snapshots/${encodeURIComponent(snapshot)}/plugin-invocations`,
                  {
                    api_version: "codexploit/v1",
                    plugin_id: record.manifest.id,
                    plugin_version: record.manifest.version,
                    package_digest: record.package_digest,
                    operation_id: operation.id,
                    scope: input.inputs[0].scope,
                    ...input,
                    config: configValue,
                    budget: { timeout_seconds: timeout },
                  },
                )
                .then((page) => onInvoked(snapshot, page.invocation.invocation_id))
                .catch((err) => setError(errorText(err)))
                .finally(() => setBusy(false));
            } catch (err) {
              setError(errorText(err));
              setBusy(false);
            }
          }}
        >
          <div className="pc-run-body">
            <div className="pc-run-identity">
              <Package size={18} />
              <strong>{record.manifest.name}</strong>
              <code>{record.manifest.version}</code>
            </div>
            <p className="pc-muted">
              先核对固定输入和执行准备状态，再提交。机器 operation 与 Schema ID
              保留在辅助位置；本页不会扩大插件声明的权限。
            </p>
            <div
              className={`pc-run-ready-banner ${prepared ? "ready" : "blocked"}`}
              role="status"
            >
              {prepared ? (
                <CheckCircle2 size={16} />
              ) : (
                <Unplug size={16} />
              )}
              <strong>
                {prepared
                  ? "准备就绪，可以提交"
                  : `还有 ${blockedCount} 项准备状态未满足`}
              </strong>
              <span>
                {prepared
                  ? "固定输入、参数与执行预算已通过本地校验。"
                  : "下方准备状态列出每项原因；未满足时提交按钮不可用。"}
              </span>
            </div>
            <label>
              操作
              <small className="mono">
                operation · {operation.id} · {operation.capability}
              </small>
              <select
                value={operation.id}
                onChange={(e) => {
                  setOperation(e.target.value);
                  setSelected({});
                  setConfig("{}");
                }}
              >
                {record.manifest.operations?.map((op) => (
                  <option key={op.id} value={op.id}>
                    {stageLabel(op.stage)} · {op.id}
                  </option>
                ))}
              </select>
            </label>
            <label>
              固定输入快照
              <select
                required
                value={snapshot}
                onChange={(e) => setSnapshot(e.target.value)}
              >
                <option value="">选择当前项目的固定快照</option>
                {snapshots.map((item) => (
                  <option key={item.snapshot_id} value={item.snapshot_id}>
                    {item.created_at.slice(0, 10)} · {item.commit.slice(0, 12)}{" "}
                    · {item.snapshot_id}
                  </option>
                ))}
              </select>
            </label>
            {loading ? (
              <p role="status">正在读取固定产物…</p>
            ) : (
              operation.inputs.map((port) => {
                const matches = eligible(port);
                return (
                  <label key={port.name}>
                    {kindLabels[port.kind] || port.kind}{" "}
                    <small>
                      {port.required ? "必需" : "可选"} · {matches.length}{" "}
                      个符合契约
                    </small>
                    <select
                      multiple={port.cardinality === "many"}
                      required={port.required}
                      value={
                        selected[port.name] ||
                        (port.cardinality === "many" ? [] : "")
                      }
                      onChange={(e) =>
                        setSelected((value) => ({
                          ...value,
                          [port.name]:
                            port.cardinality === "many"
                              ? Array.from(e.target.selectedOptions).map(
                                  (o) => o.value,
                                )
                              : e.target.value,
                        }))
                      }
                    >
                      {port.cardinality !== "many" && (
                        <option value="">
                          {matches.length === 1
                            ? "使用唯一匹配的固定产物"
                            : matches.length === 0
                              ? "没有符合契约的固定产物"
                              : "选择一项固定产物"}
                        </option>
                      )}
                      {matches.map((ref) => (
                        <option value={ref.id} key={ref.id}>
                          {artifactChoice(ref)}
                        </option>
                      ))}
                    </select>
                    <small className="mono">{port.schema_id}</small>
                    {matches.length === 0 && (
                      <small className="pc-run-blocked">
                        当前快照没有 {port.kind} / {port.schema_id}{" "}
                        产物；请先完成上游分析，或选择其他快照。
                      </small>
                    )}
                  </label>
                );
              })
            )}
            {Array.isArray(frontendChoices) && (
              <label>
                语言前端
                <select
                  value={(() => { try { return (configValue?.frontend as string) || "AUTO"; } catch { return "AUTO"; } })()}
                  onChange={(e) => {
                    if (!configValue) {
                      setError("请先修正参数 JSON，再切换语言前端。");
                      return;
                    }
                    setConfig(
                      JSON.stringify(
                        { ...configValue, frontend: e.target.value },
                        null,
                        2,
                      ),
                    );
                  }}
                >
                  {frontendChoices.map((value: string) => (
                    <option key={value} value={value}>
                      {value === "AUTO" ? "自动识别全部匹配语言" : value}
                    </option>
                  ))}
                </select>
                <small>
                  混合项目会生成多个 CPG；Ghidra 二进制分析需在参数中指定
                  input_path。
                </small>
              </label>
            )}
            {record.manifest.id === "codexploit.joern" &&
              operation.id === "taint" && (
                <p className="pc-muted">
                  基于 Joern 数据流查询 source → sink。可在参数中设置 rules、max_flows
                  和 max_call_depth；未填写 rules
                  时使用包内固定规则。结果为候选，原始报告保留完整节点轨迹。
                </p>
              )}
            <label>
              参数 JSON
              <textarea
                spellCheck={false}
                rows={5}
                value={config}
                aria-invalid={!!configError}
                onChange={(e) => setConfig(e.target.value)}
              />
              <small className={configError ? "pc-run-blocked" : "pc-muted"}>
                {configError || "常用参数可直接编辑；完整 Schema 在下方高级入口。"}
              </small>
            </label>
            <details>
              <summary>完整参数 Schema（高级）</summary>
              <pre>{JSON.stringify(operation.config_schema, null, 2)}</pre>
            </details>
            <label>
              超时（秒）
              <input
                type="number"
                min={1}
                max={3600}
                required
                value={Number.isFinite(timeout) ? timeout : ""}
                onChange={(e) => setTimeout(e.target.valueAsNumber)}
              />
            </label>
            <div className="pc-run-permissions">
              <strong>权限边界</strong>
              <span>
                网络 {record.manifest.permissions?.network || "未声明"} · 源码写入{" "}
                {record.manifest.permissions?.source_write ? "允许" : "不允许"} ·
                目标执行 不开放
              </span>
            </div>
            <div className="pc-run-readiness" role="status" aria-live="polite">
              <strong>准备状态</strong>
              <ul>
                {checks.map((check, index) => (
                  <li className={check.ok ? "ready" : "blocked"} key={index}>
                    {check.ok ? (
                      <CheckCircle2 size={14} />
                    ) : (
                      <Unplug size={14} />
                    )}
                    <span>
                      {check.label}
                      {check.detail && <small className="mono">{check.detail}</small>}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
            <p className="pc-footnote">
              输入快照、插件版本和发行包摘要随调用固定。原生输出只作为原生证据保存。
            </p>
            {error && (
              <div className="error-message" role="alert">
                {error}
              </div>
            )}
          </div>
          <footer>
            <button
              className="button secondary"
              type="button"
              disabled={busy}
              onClick={onClose}
            >
              取消
            </button>
            <button
              className="button primary"
              disabled={busy || loading || !prepared}
              title={prepared ? "提交固定输入与版本" : "仍有准备状态未满足"}
            >
              <Play size={14} />
              {busy ? "正在创建调用…" : "开始执行"}
            </button>
          </footer>
        </form>
      )}
    </Modal>
  );
}

export function PluginStandards({ api }: { api: ApiClient }) {
  const [stages, setStages] = useState<RegistryStage[]>([]);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState("parse");
  const [tick, retry] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setError("");
    api
      .get<{ stages: RegistryStage[] }>("/v2/plugin-stages", controller.signal)
      .then((page) => setStages(page.stages))
      .catch((err) => {
        if (!controller.signal.aborted) setError(errorText(err));
      });
    return () => controller.abort();
  }, [api, tick]);
  const stage = stages.find((item) => item.stage === selected) || stages[0];
  return (
    <section className="pc-standards">
      <div className="pc-catalog-heading">
        <div>
          <h2>按契约接入工具</h2>
          <p>宿主规定阶段输入与输出，工具内部实现保持独立。</p>
        </div>
      </div>
      {error && (
        <div className="error-message" role="alert">
          {error}
          <button className="text-button" onClick={() => retry((n) => n + 1)}>
            重试
          </button>
        </div>
      )}
      <ol className="pc-development-steps">
        <li>
          <span>1</span>
          <strong>选择阶段</strong>
          <small>确认输入与输出</small>
        </li>
        <li>
          <span>2</span>
          <strong>实现适配器</strong>
          <small>接入二进制或领域服务</small>
        </li>
        <li>
          <span>3</span>
          <strong>封存发行包</strong>
          <small>固定版本与全文件摘要</small>
        </li>
        <li>
          <span>4</span>
          <strong>登记并实测</strong>
          <small>安装、核验、真实执行</small>
        </li>
      </ol>
      <div className="pc-standard-layout">
        <nav aria-label="接口阶段">
          {stages.map((item) => (
            <button
              key={item.stage}
              className={stage?.stage === item.stage ? "selected" : ""}
              aria-pressed={stage?.stage === item.stage}
              onClick={() => setSelected(item.stage)}
            >
              <StageIcon stage={item.stage} />
              {item.label}
              <code>{item.stage}</code>
            </button>
          ))}
        </nav>
        {stage && (
          <section className="pc-standard-detail">
            <header>
              <div>
                <h3>{stage.label}</h3>
                <code>{stage.stage}</code>
              </div>
              <button
                className="button secondary"
                onClick={() => downloadTemplate(stage)}
              >
                <Download size={14} />
                下载开发模板
              </button>
            </header>
            <h4>标准输入</h4>
            <PortList ports={stage.inputs} direction="输入" />
            <h4>标准输出</h4>
            <PortList ports={stage.outputs} direction="输出" />
            <p className="pc-transport-note">
              <ShieldCheck size={16} />
              {stage.transport === "plugin_execute"
                ? "通过 file-job 或 NDJSON 进程协议接入，宿主核验后发布完整产物。"
                : "此阶段使用领域服务的授权与生命周期，普通进程清单不授予执行权限。"}
            </p>
            <details>
              <summary>
                <Braces size={14} />
                清单模板
              </summary>
              <pre>{JSON.stringify(stageManifestTemplate(stage), null, 2)}</pre>
            </details>
          </section>
        )}
      </div>
      <section className="pc-binary-note">
        <span className="pc-plugin-icon">
          <Terminal size={22} />
        </span>
        <div>
          <h3>第三方二进制，同样按阶段接入</h3>
          <p>
            将工具、适配器与依赖一起封存。Joern Go 适配器已提供原生
            CPG 和标准代码事实，可在目录中安装并用于解析节点。
          </p>
          <code>pluginpack --directory &lt;package&gt; --seal</code>
        </div>
        <span className="pc-tag">CLI / JAR / Binary</span>
      </section>
    </section>
  );
}
