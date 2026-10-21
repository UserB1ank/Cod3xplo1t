import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Circle,
  Code2,
  FileText,
  FolderGit2,
  GitBranch,
  History,
  Loader2,
  Network,
  Pencil,
  Play,
  RefreshCw,
  ShieldCheck,
  SkipForward,
  Trash2,
  XCircle,
} from "lucide-react";
import type { AnalysisRun, AnalysisRunStage, Project, ProjectInput, Snapshot } from "./types";
import {
  canStartAnalysis,
  formatBytes,
  projectInputLabel,
  projectInputSourceLabel,
  projectInputState,
} from "./project-management";

const stages = [
  ["parse", "代码图谱构建", "解析符号、模块和调用关系"],
  ["semantic", "安全语义与攻击面识别", "识别入口、敏感操作与安全控制"],
  ["paths", "候选路径生成", "从入口搜索通往敏感操作的路径"],
  ["enhance", "路径筛选与评分", "去重、评分并记录筛选依据"],
] as const;

function short(value?: string) {
  if (!value) return "—";
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function runStateLabel(state: string) {
  switch (state) {
    case "QUEUED":
      return "排队中";
    case "RUNNING":
      return "运行中";
    case "PAUSED":
      return "已暂停";
    case "CANCELLING":
      return "正在停止";
    case "SUCCEEDED":
      return "已完成";
    case "PARTIAL":
      return "部分覆盖";
    case "FAILED":
      return "失败";
    case "CANCELLED":
      return "已停止";
    default:
      return state;
  }
}

function terminal(state?: string) {
  return !!state && ["SUCCEEDED", "PARTIAL", "FAILED", "CANCELLED"].includes(state);
}

function stageStateLabel(status: string) {
  switch (status) {
    case "SUCCEEDED":
      return "已完成";
    case "RUNNING":
      return "当前阶段";
    case "PARTIAL":
      return "部分覆盖";
    case "FAILED":
      return "失败";
    case "SKIPPED":
      return "已跳过";
    case "CANCELLED":
      return "已停止";
    default:
      return "等待";
  }
}

function StageIcon({ status }: { status: string }) {
  if (status === "SUCCEEDED") return <CheckCircle2 size={15} className="stage-dot" />;
  if (status === "RUNNING") return <Loader2 size={15} className="stage-dot spin" />;
  if (status === "PARTIAL") return <AlertTriangle size={15} className="stage-dot" />;
  if (status === "FAILED") return <XCircle size={15} className="stage-dot" />;
  if (status === "SKIPPED") return <SkipForward size={15} className="stage-dot" />;
  return <Circle size={15} className="stage-dot" />;
}

function StageDetail({ stage }: { stage: AnalysisRunStage }) {
  if (!stage.invocation_id && !stage.error_code && !stage.note && !stage.outputs?.length && !stage.knowledge?.length) {
    return null;
  }
  return (
    <details className="stage-detail">
      <summary>阶段详情</summary>
      <dl>
        <dt>工具</dt>
        <dd>
          {stage.plugin_id || "—"}
          {stage.plugin_version ? `@${stage.plugin_version}` : ""}
        </dd>
        <dt>调用</dt>
        <dd className="mono">{short(stage.invocation_id)}</dd>
        <dt>产物</dt>
        <dd>
          {stage.inputs?.length || 0} 入 / {stage.outputs?.length || 0} 出
        </dd>
        {stage.knowledge?.length ? (
          <>
            <dt>知识版本</dt>
            <dd>{stage.knowledge.map((item) => item.revision).join("、")}</dd>
          </>
        ) : null}
        {stage.error_code ? (
          <>
            <dt>错误</dt>
            <dd>{stage.error_code}</dd>
          </>
        ) : null}
      </dl>
      {stage.note && <p className="muted">{stage.note}</p>}
      {!!stage.outputs?.length && (
        <p className="muted mono">
          {stage.outputs.map((item) => item.id).join("、")}
        </p>
      )}
      {!!stage.knowledge?.length && (
        <p className="muted mono">
          {stage.knowledge.map((item) => item.digest.slice(0, 16)).join("、")}
        </p>
      )}
    </details>
  );
}

export function ProjectHome({
  project,
  input,
  snapshots,
  taskCount,
  findingCount,
  reportCount,
  runs,
  agentAvailable,
  canWrite,
  busy,
  onEdit,
  onDelete,
  onSources,
  onNavigate,
  onStartAnalysis,
  onCancelAnalysis,
  onRefresh,
}: {
  project: Project;
  input?: ProjectInput;
  snapshots: Snapshot[];
  taskCount: number;
  findingCount: number;
  reportCount: number;
  runs: AnalysisRun[];
  agentAvailable: boolean;
  canWrite: boolean;
  busy: boolean;
  onEdit: () => void;
  onDelete: () => void;
  onSources: () => void;
  onNavigate: (view: string) => void;
  onStartAnalysis: (agentAssisted: boolean) => void;
  onCancelAnalysis: () => void;
  onRefresh: () => void;
}) {
  const state = projectInputState(input);
  const legacy = state === "legacy";
  const ready = canStartAnalysis(input);
  const latest = runs[0];
  const [selectedID, setSelectedID] = useState("");
  const [agentAssisted, setAgentAssisted] = useState(false);
  const selected = runs.find((run) => run.analysis_run_id === selectedID) || latest;
  const active = !!latest && !terminal(latest.state);
  const completed = !!selected && (selected.state === "SUCCEEDED" || selected.state === "PARTIAL");
  const snapshot = input?.snapshot_id
    ? snapshots.find((value) => value.snapshot_id === input.snapshot_id)
    : snapshots[0];

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(onRefresh, 3000);
    return () => window.clearInterval(timer);
  }, [active, onRefresh]);

  useEffect(() => {
    if (latest) setSelectedID(latest.analysis_run_id);
  }, [latest?.analysis_run_id]);

  const stats = [
    ["源码文件", input?.files ? String(input.files) : legacy ? "见代码源" : "—", input?.files ? formatBytes(input.bytes) : "创建时自动保存"],
    ["审查任务", String(taskCount), taskCount ? "按路径独立记录" : "等待选择审查路径"],
    ["发现", String(findingCount), "候选与已确认分开"],
    ["固定报告", String(reportCount), reportCount ? "历史版本保留" : "尚未生成"],
  ];
  return (
    <>
      <section className={`project-input-strip ${state}`}>
        <span className="project-input-icon">
          {state === "ready" ? <CheckCircle2 size={18} /> : state === "failed" ? <AlertTriangle size={18} /> : <Code2 size={18} />}
        </span>
        <div>
          <strong>{projectInputSourceLabel(input)}</strong>
          <small>
            {legacy
              ? "旧项目保留原有代码源、快照与任务引用，不会自动挑选最新版本。"
              : state === "ready"
                ? `审计输入已固定到快照 ${snapshot?.snapshot_id?.slice(0, 20) || input?.snapshot_id?.slice(0, 20) || ""}…`
                : state === "failed"
                  ? "失败详情来自服务端；重试会重新绑定同一项目的一次审计输入。"
                  : "正在后台保存源码并生成不可变快照，不会自动开始分析。"}
          </small>
        </div>
        <span className={`input-state ${state}`}>{projectInputLabel(input)}</span>
        <div className="project-input-actions">
          <button className="button secondary" disabled={busy} onClick={onSources}>
            <FolderGit2 size={15} />
            {state === "failed" ? "重试或查看输入" : "查看源码输入"}
          </button>
          {canWrite && (
            <>
              <button className="button secondary" disabled={busy} onClick={onEdit}>
                <Pencil size={15} />
                编辑项目
              </button>
              <button className="button danger icon-only" aria-label="删除项目" title="删除项目" disabled={busy} onClick={onDelete}>
                <Trash2 size={16} />
              </button>
            </>
          )}
        </div>
      </section>

      <div className="project-stat-grid">
        {stats.map(([label, value, hint]) => (
          <div className="project-stat" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
            <small>{hint}</small>
          </div>
        ))}
      </div>

      <section className="panel analysis-pipeline">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">GRAPH PREPARATION</span>
            <h2>图谱化分析</h2>
          </div>
          <span className={`input-state ${selected ? selected.state.toLowerCase() : state}`}>
            {selected ? runStateLabel(selected.state) : ready ? "源码已就绪" : "等待输入"}
          </span>
        </div>
        <p className="panel-description">
          {legacy
            ? "这是旧多来源项目，继续使用既有任务与图谱流程。新的单源码项目在创建时就绑定一份输入。"
            : "四阶段默认由传统分析工具完成，不需要模型配置。开始前不会自动启动 Agent，也不会提前把分析标记为完成。"}
        </p>
        {selected && (
          <div className={`analysis-run-summary ${selected.state.toLowerCase()}`}>
            <div>
              <strong>{runStateLabel(selected.state)}</strong>
              <small>
                分析 {short(selected.analysis_run_id)} · 计划 {short(selected.plan_id)} ·{" "}
                {selected.agent_assisted ? "Agent 辅助" : "无模型默认"}
              </small>
            </div>
            <div>
              <span>{selected.path_count} 条候选路径</span>
              <small>
                覆盖 {selected.coverage.entry_points_examined} 入口 / {selected.coverage.chains_resolved} 调用链
                {selected.coverage.truncated ? " · 部分覆盖" : ""}
              </small>
            </div>
            {selected.failure_message && <p className="failure-text">{selected.failure_message}</p>}
          </div>
        )}
        <div className="stage-grid">
          {stages.map(([key, title, detail], index) => {
            const stage = selected?.stages.find((value) => value.key === key);
            const status = stage?.status || "PENDING";
            return (
              <div className={`stage-card ${status.toLowerCase()}`} key={key}>
                <span className="stage-number">{String(index + 1).padStart(2, "0")}</span>
                <div>
                  <h3>{title}</h3>
                  <p>{detail}</p>
                  <small>
                    {stageStateLabel(status)}
                    {stage?.plugin_id ? ` · ${stage.plugin_id}@${stage.plugin_version || ""}` : ""}
                  </small>
                  {stage?.error_code && <p className="stage-error">{stage.error_code}</p>}
                  {stage && <StageDetail stage={stage} />}
                </div>
                <StageIcon status={status} />
              </div>
            );
          })}
        </div>
        {selected?.stages.find((stage) => stage.key === "publish") && (
          <div className="analysis-publish-line">
            <History size={14} />
            <span>
              共享知识发布：{runStateLabel(selected.stages.find((stage) => stage.key === "publish")?.status || "PENDING")}
              {selected.knowledge.length ? ` · ${selected.knowledge.map((item) => item.revision).join("、")}` : ""}
            </span>
          </div>
        )}
        {selected?.stages.find((stage) => stage.key === "analyze") && (
          <div className="analysis-publish-line">
            <History size={14} />
            <span>
              Agent 辅助分析：
              {runStateLabel(selected.stages.find((stage) => stage.key === "analyze")?.status || "PENDING")}
              {selected.stages.find((stage) => stage.key === "analyze")?.agent_run_ids?.length
                ? ` · ${selected.stages.find((stage) => stage.key === "analyze")!.agent_run_ids!.length} 个 Agent 运行`
                : ""}
            </span>
          </div>
        )}
        <div className="analysis-actions">
          {legacy ? (
            <button className="button secondary" onClick={() => onNavigate("sources")}>
              查看旧代码源
              <ArrowRight size={15} />
            </button>
          ) : (
            <>
              <button
                className="button primary"
                disabled={!ready || busy || active || !canWrite}
                onClick={() => onStartAnalysis(agentAssisted)}
              >
                {active ? <Loader2 size={15} className="spin" /> : <Play size={15} />}
                {active ? "分析进行中" : latest ? "重新开始分析" : "开始图谱化分析"}
              </button>
              {active && canWrite && (
                <button className="button secondary" disabled={busy} onClick={onCancelAnalysis}>
                  <XCircle size={15} />
                  停止分析
                </button>
              )}
              <label className="analysis-agent-toggle" title={agentAvailable ? "仅在你明确选择时启动 Agent 分析" : "当前部署未配置可用 Agent"}>
                <input
                  type="checkbox"
                  checked={agentAssisted}
                  disabled={!agentAvailable || active || busy}
                  onChange={(event) => setAgentAssisted(event.target.checked)}
                />
                Agent 辅助（可选）
              </label>
              <span className="muted">
                {!ready
                  ? "源码输入就绪后即可开始。"
                  : active
                    ? "页面会读取真实阶段状态；完成后才显示完成。"
                    : agentAvailable
                      ? "默认不启动模型；勾选后才尝试 Agent 辅助。"
                      : "当前部署未配置 Agent，四阶段仍可独立完成。"}
              </span>
            </>
          )}
        </div>
        {completed && (
          <div className="analysis-complete-actions">
            <button className="button secondary" onClick={() => onNavigate("knowledge")}>
              <Network size={15} />
              查看局部图谱
            </button>
            <button className="button secondary" onClick={() => onNavigate("tasks")}>
              <GitBranch size={15} />
              查看审查路径
            </button>
            {selected?.coverage.truncated && <p className="hint-inline">当前为部分覆盖；展开的阶段详情和覆盖说明是预算或截断的真实原因。</p>}
          </div>
        )}
        {runs.length > 1 && (
          <div className="analysis-history">
            <span className="subtle-label">历史运行</span>
            {runs.slice(0, 6).map((run) => (
              <button
                key={run.analysis_run_id}
                className={selected?.analysis_run_id === run.analysis_run_id ? "active" : ""}
                onClick={() => setSelectedID(run.analysis_run_id)}
              >
                <span>{runStateLabel(run.state)}</span>
                <small className="mono">{short(run.analysis_run_id)}</small>
              </button>
            ))}
          </div>
        )}
      </section>

      <section className="panel project-outputs">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">AUDIT OUTPUTS</span>
            <h2>项目产出</h2>
          </div>
          <button className="text-button" onClick={() => onNavigate("tasks")}>
            全部任务
            <ArrowRight size={14} />
          </button>
        </div>
        <div className="output-grid">
          <button className="output-card" onClick={() => onNavigate("knowledge")}>
            <Network size={20} />
            <span>
              <strong>代码图谱</strong>
              <small>{completed ? "已发布固定知识版本" : "等待图谱化分析"}</small>
            </span>
            <ArrowRight size={15} />
          </button>
          <button className="output-card" onClick={() => onNavigate("tasks")}>
            <GitBranch size={20} />
            <span>
              <strong>审查路径</strong>
              <small>{selected?.path_count ? `${selected.path_count} 条候选路径` : "分析完成后生成"}</small>
            </span>
            <ArrowRight size={15} />
          </button>
          <button className="output-card" onClick={() => onNavigate("findings")}>
            <ShieldCheck size={20} />
            <span>
              <strong>发现与证据</strong>
              <small>{findingCount ? `${findingCount} 条记录` : "尚未生成"}</small>
            </span>
            <ArrowRight size={15} />
          </button>
          <button className="output-card" onClick={() => onNavigate("reports")}>
            <FileText size={20} />
            <span>
              <strong>固定报告</strong>
              <small>{reportCount ? `${reportCount} 份报告` : "尚未生成"}</small>
            </span>
            <ArrowRight size={15} />
          </button>
        </div>
        {!ready && !legacy && (
          <p className="muted project-output-note">
            <RefreshCw size={13} />
            {state === "failed" ? "输入失败不会留下“已就绪”的项目；可重试或删除。" : "页面会自动刷新输入状态，无需手动固定快照。"}
          </p>
        )}
      </section>
    </>
  );
}
