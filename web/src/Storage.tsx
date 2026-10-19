import { useEffect, useState } from "react";
import { Database, RefreshCw } from "lucide-react";
import type { ApiClient } from "./api";
import { Hint, Panel } from "./components";
import { readStorageStatus, type StorageStatus } from "./storageData";

const capabilityNames: Record<string, string> = {
  projects: "项目目录",
  sources: "文件夹 / Git 代码源",
  snapshots: "固定快照目录",
  artifacts: "产物索引与校验下载",
  inventory: "源码清单与基础识别",
  knowledge: "SCG / ASG / 路径与共享知识",
  plugins: "插件登记与执行",
  tasks: "任务与运行记录",
  findings: "发现分组与分级审计",
  workflows: "工作流与执行恢复",
  reports: "固定版本报告",
};
const locationNames: Record<string, string> = {
  catalog: "结构化业务状态",
  artifact_content: "产物内容",
  accounts: "账号与会话",
  model_settings: "模型设置",
};
const driverNames = {
  postgres: "PostgreSQL",
  sqlite: "SQLite",
  memory: "内存",
};

export function Storage({
  api,
  isAdmin,
}: {
  api: ApiClient;
  isAdmin: boolean;
}) {
  const [status, setStatus] = useState<StorageStatus>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [tick, refresh] = useState(0);
  useEffect(() => {
    if (!isAdmin) return;
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setStatus(undefined);
    readStorageStatus(api, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setStatus(value);
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setError(error instanceof Error ? error.message : "读取存储状态失败");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [api, isAdmin, tick]);
  if (!isAdmin) return <Hint>数据存储状态仅管理员可查看。</Hint>;
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">DATA STORAGE</div>
          <h1>数据存储</h1>
          <p>查看当前服务实际接通的存储能力与数据库 readiness。</p>
        </div>
        <button
          className="button secondary"
          disabled={loading}
          onClick={() => refresh((n) => n + 1)}
        >
          <RefreshCw size={16} className={loading ? "spin" : ""} />
          {loading ? "正在探测…" : "重新探测"}
        </button>
      </div>
      {error && (
        <div role="alert" className="error-message">
          {error}
        </div>
      )}
      {status && (
        <>
          <div className="metric-strip storage-metrics">
            <div>
              <span>数据库</span>
              <strong>{driverNames[status.driver]}</strong>
              <small>
                {status.profile === "execution"
                  ? "任务与工作流 · 实验部署"
                  : status.profile !== "complete"
                    ? "知识模式 · 实验部署"
                    : "完整开发模式"}
              </small>
            </div>
            <div>
              <span>READINESS</span>
              <strong
                className={
                  status.readiness === "ready" ? "text-accent" : "high"
                }
              >
                {status.readiness === "ready" ? "已就绪" : "不可用"}
              </strong>
              <small>连接与已接线目录结构实时探测</small>
            </div>
            <div>
              <span>目录迁移版本</span>
              <strong className="mono">{status.schema_version}</strong>
              <small>
                {status.durable ? "持久化目录" : "进程退出后目录丢失"}
              </small>
            </div>
          </div>
          {status.readiness !== "ready" && (
            <div role="alert" className="error-message">
              存储未就绪，请检查数据库服务与迁移状态后重新探测。
            </div>
          )}
          {status.profile !== "complete" && (
            <Hint>
              {status.profile === "execution"
                ? "PostgreSQL 已接通任务、工作流、发现、证据与报告。执行领取使用数据库租约与栅栏；账号、会话、模型设置和产物内容仍由应用工作区管理，共享认证与设置尚未接线。"
                : "PostgreSQL 已接通目录、直接插件分析、固定图谱与多来源发布。任务、工作流、发现分级和报告尚未接线，对应操作会被拒绝。"}
            </Hint>
          )}
          <div className="two-columns storage-columns">
            <Panel title="实际接线能力">
              <div className="capability-list">
                {Object.entries(capabilityNames).map(([name, label]) => (
                  <div key={name}>
                    <span>{label}</span>
                    <span
                      className={
                        status.capabilities[name] ? "text-accent" : "muted"
                      }
                    >
                      {status.capabilities[name] ? "已接通" : "尚未接线"}
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
            <Panel title="数据保存位置">
              <dl>
                {Object.entries(status.locations).map(([name, location]) => (
                  <div key={name}>
                    <dt>{locationNames[name] || name}</dt>
                    <dd>
                      {location === "workspace"
                        ? "应用工作区"
                        : driverNames[location as keyof typeof driverNames] ||
                          location}
                    </dd>
                  </div>
                ))}
              </dl>
              <Hint>
                账号、会话和模型设置继续由应用工作区管理。
                {status.profile !== "complete" &&
                  "当前 PostgreSQL 模式仅用于单应用实例。"}
                产物内容保留在工作区，目录保存不可变索引。
              </Hint>
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
