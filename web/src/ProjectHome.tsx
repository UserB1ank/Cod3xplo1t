import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Circle,
  Code2,
  FileText,
  FolderGit2,
  GitBranch,
  Network,
  Pencil,
  Play,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import type { Project, ProjectInput, Snapshot } from "./types";
import {
  canStartAnalysis,
  formatBytes,
  projectInputLabel,
  projectInputSourceLabel,
  projectInputState,
} from "./project-management";

const stages = [
  ["代码图谱构建", "解析符号、模块和调用关系"],
  ["安全语义与攻击面识别", "识别入口、敏感操作与安全控制"],
  ["候选路径生成", "从入口搜索通往敏感操作的路径"],
  ["路径筛选与评分", "去重、评分并记录筛选依据"],
] as const;

export function ProjectHome({
  project,
  input,
  snapshots,
  taskCount,
  findingCount,
  reportCount,
  canWrite,
  busy,
  onEdit,
  onDelete,
  onSources,
  onNavigate,
}: {
  project: Project;
  input?: ProjectInput;
  snapshots: Snapshot[];
  taskCount: number;
  findingCount: number;
  reportCount: number;
  canWrite: boolean;
  busy: boolean;
  onEdit: () => void;
  onDelete: () => void;
  onSources: () => void;
  onNavigate: (view: string) => void;
}) {
  const state = projectInputState(input);
  const legacy = state === "legacy";
  const ready = canStartAnalysis(input);
  const snapshot = input?.snapshot_id
    ? snapshots.find((value) => value.snapshot_id === input.snapshot_id)
    : snapshots[0];
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
          <span className={`input-state ${state === "ready" ? "ready" : state}`}>
            {ready ? "源码已就绪" : state === "failed" ? "输入失败" : state === "importing" ? "正在保存输入" : "等待开始"}
          </span>
        </div>
        <p className="panel-description">
          {legacy
            ? "这是旧多来源项目，继续使用既有任务与图谱流程。新的单源码项目在创建时就绑定一份输入。"
            : "四阶段默认由传统分析工具完成，不需要模型配置。开始前不会自动启动 Agent，也不会提前把分析标记为完成。"}
        </p>
        <div className="stage-grid">
          {stages.map(([title, detail], index) => (
            <div className="stage-card" key={title}>
              <span className="stage-number">{String(index + 1).padStart(2, "0")}</span>
              <div>
                <h3>{title}</h3>
                <p>{detail}</p>
                <small>{ready ? "等待开始" : "未开始"}</small>
              </div>
              <Circle size={15} className="stage-dot" />
            </div>
          ))}
        </div>
        <div className="analysis-actions">
          {legacy ? (
            <button className="button secondary" onClick={() => onNavigate("sources")}>
              查看旧代码源
              <ArrowRight size={15} />
            </button>
          ) : (
            <>
              <button className="button primary" disabled title="四阶段分析执行将在下一交付接入">
                <Play size={15} />
                开始图谱化分析
              </button>
              <span className="muted">
                {ready
                  ? "四阶段执行将在下一交付接入；当前版本只保存输入与真实快照。"
                  : "源码输入就绪后即可开始。"}
              </span>
            </>
          )}
        </div>
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
              <small>{ready ? "等待图谱化分析" : "尚未构建"}</small>
            </span>
            <ArrowRight size={15} />
          </button>
          <button className="output-card" onClick={() => onNavigate("tasks")}>
            <GitBranch size={20} />
            <span>
              <strong>审查路径</strong>
              <small>{ready ? "分析完成后生成" : "尚未生成"}</small>
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
