import { useEffect, useState } from "react";
import { FileCode2, FolderOpen, GitBranch, Loader2, Plus } from "lucide-react";
import { ApiClient, ApiError } from "./api";
import { EmptyState, Hint, Modal, Panel } from "./components";
import type { Project } from "./types";

export interface CodeSource {
  api_version: "codexploit/v1";
  id: string;
  project_id: string;
  name: string;
  kind: "local_folder";
  location: string;
  ref: string;
  version: number;
  snapshot?: string;
  files: number;
  revision: number;
}

export async function readSources(
  api: ApiClient,
  project: string,
  signal?: AbortSignal,
) {
  const result: CodeSource[] = [];
  let cursor = "";
  const seen = new Set<string>();
  do {
    const page = await api.get<{ sources: CodeSource[]; next_cursor: string }>(
      `/v1/projects/${encodeURIComponent(project)}/sources?limit=200&cursor=${encodeURIComponent(cursor)}`,
      signal,
    );
    result.push(...page.sources);
    cursor = page.next_cursor || "";
    if (cursor && seen.has(cursor))
      throw new Error("代码源分页游标未推进，请刷新重试。");
    seen.add(cursor);
  } while (cursor);
  return result;
}

export function sourceInput(project: string, name: string, location: string) {
  return {
    api_version: "codexploit/v1",
    id: `src-${crypto.randomUUID()}`,
    project_id: project,
    name,
    kind: "local_folder",
    location,
    ref: "",
  };
}

interface SnapshotDetails {
  snapshot_id: string;
  source_id?: string;
  source_version?: number;
  files: number;
  skipped_total: number;
  limitations: string[];
  commit: string;
}

function message(error: unknown) {
  if (error instanceof ApiError) {
    if (error.code === "source_mount_unavailable")
      return "源码挂载不可用，请检查容器的 /repos 挂载或服务的 --local-source-root 设置。";
    if (error.code === "invalid_source_path")
      return "目录不存在或超出登记的挂载范围，请检查 /repos 下的目录。";
    if (error.code === "source_changed")
      return "复制期间源码发生变化，未发布快照。请在目录稳定后重试。";
  }
  return error instanceof Error ? error.message : "读取代码源失败";
}

export function Sources({
  api,
  project,
  revision,
  canWrite,
  onRefresh,
  onTask,
  onLegacySnapshot,
}: {
  api: ApiClient;
  project: Project;
  revision: number;
  canWrite: boolean;
  onRefresh: () => void;
  onTask: (snapshot: string) => void;
  onLegacySnapshot: () => void;
}) {
  const [sources, setSources] = useState<CodeSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [adding, setAdding] = useState(false);
  const [selected, setSelected] = useState<string>();
  const [details, setDetails] = useState<SnapshotDetails>();
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    readSources(api, project.id, controller.signal)
      .then(setSources)
      .catch((e) => {
        if (!controller.signal.aborted) setError(message(e));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [api, project.id, revision]);
  useEffect(() => {
    setDetails(undefined);
    if (!selected) return;
    const controller = new AbortController();
    api
      .get<{ snapshot: SnapshotDetails }>(
        `/snapshots/${encodeURIComponent(selected)}`,
        controller.signal,
      )
      .then((r) => setDetails(r.snapshot))
      .catch((e) => {
        if (!controller.signal.aborted) setError(message(e));
      });
    return () => controller.abort();
  }, [api, selected]);
  const run = async (id: string, action: () => Promise<void>) => {
    if (busy) return;
    setBusy(id);
    setError("");
    setNotice("");
    try {
      await action();
      onRefresh();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy("");
    }
  };
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
        title="本地文件夹"
        eyebrow="PROJECT CODE SOURCES"
        action={
          <button
            className="button primary"
            disabled={!canWrite || !!busy}
            onClick={() => setAdding(true)}
          >
            <Plus size={15} />
            添加代码源
          </button>
        }
      >
        <div className="source-description">
          <Hint>
            文件夹模式读取当前文件内容，包括未提交修改。每次更新生成不可变快照，已有任务继续绑定原版本。
          </Hint>
        </div>
        {loading ? (
          <p className="source-description" role="status">
            正在读取代码源…
          </p>
        ) : !sources.length ? (
          <EmptyState title="尚未添加本地代码源">
            添加已挂载到 /repos 下的目录；同一项目可管理多个代码源。
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="path-table source-table">
              <thead>
                <tr>
                  <th>代码源</th>
                  <th>读取方式 / 目录</th>
                  <th>最新快照</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((source) => (
                  <tr key={source.id}>
                    <td>
                      <strong>{source.name}</strong>
                      <small className="source-secondary">{source.id}</small>
                    </td>
                    <td>
                      <span className="source-kind">
                        <FolderOpen size={14} />
                        本地文件夹
                      </span>
                      <code className="source-secondary">
                        {source.location}
                      </code>
                      <small className="source-secondary">
                        定义 v{source.version} · 内容寻址
                      </small>
                    </td>
                    <td>
                      {source.snapshot ? (
                        <>
                          <button
                            className="text-button"
                            onClick={() => setSelected(source.snapshot)}
                          >
                            {source.snapshot.slice(0, 21)}…
                          </button>
                          <small className="source-secondary">
                            {source.files} 个文件 · 第 {source.revision}{" "}
                            次快照发布
                          </small>
                        </>
                      ) : (
                        <span className="muted">尚未生成</span>
                      )}
                    </td>
                    <td>
                      <div className="source-actions">
                        <button
                          className="button secondary"
                          disabled={!canWrite || !!busy}
                          onClick={() =>
                            run(source.id, async () => {
                              const result = await api.post<{
                                snapshot: SnapshotDetails;
                              }>(
                                `/v1/sources/${encodeURIComponent(source.id)}/snapshots`,
                                {
                                  project_id: project.id,
                                  source_version: source.version,
                                  build_graph: true,
                                  build_asg: true,
                                },
                              );
                              setNotice(
                                `已建立真实快照：${result.snapshot.files} 个文件，省略 ${result.snapshot.skipped_total} 项。`,
                              );
                              setSelected(result.snapshot.snapshot_id);
                            })
                          }
                        >
                          {busy === source.id ? (
                            <Loader2 className="spin" size={14} />
                          ) : (
                            <GitBranch size={14} />
                          )}
                          {source.snapshot
                            ? "更新快照与图谱"
                            : "生成快照与图谱"}
                        </button>
                        <button
                          className="button secondary"
                          disabled={!canWrite || !!busy || !source.snapshot}
                          onClick={() =>
                            source.snapshot && onTask(source.snapshot)
                          }
                        >
                          新建任务
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {project.source && (
        <Panel
          title="原项目默认代码源"
          action={
            <button
              className="button secondary"
              disabled={!canWrite || !!busy}
              onClick={onLegacySnapshot}
            >
              <GitBranch size={14} />
              更新原代码版本
            </button>
          }
        >
          <div className="source-description">
            <code>{project.source}</code>
            <p className="muted">
              保留既有自动识别和版本语义；可另行登记为本地文件夹。旧任务、快照和图谱
              ID 保持不变。
            </p>
          </div>
        </Panel>
      )}
      <Modal
        open={adding}
        onClose={() => {
          if (!busy) setAdding(false);
        }}
        title="添加本地代码源"
      >
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const form = event.currentTarget;
            const data = new FormData(form);
            run("add", async () => {
              await api.post(
                `/v1/projects/${encodeURIComponent(project.id)}/sources`,
                sourceInput(
                  project.id,
                  String(data.get("name")),
                  String(data.get("location")),
                ),
              );
              form.reset();
              setAdding(false);
              setNotice("代码源已保存，可生成快照并创建任务。");
            });
          }}
        >
          <label>
            代码源名称
            <input
              name="name"
              maxLength={100}
              required
              placeholder="例如：支付服务源码"
            />
          </label>
          <label>
            容器内目录
            <input
              name="location"
              required
              pattern="/repos/.+"
              placeholder="/repos/service"
            />
          </label>
          <Hint>
            先把目录只读挂载到 /repos 下。目录内的 .git
            不会改变文件夹读取方式；不会运行目标代码。
          </Hint>
          {error && (
            <div role="alert" className="error-message">
              {error}
            </div>
          )}
          <div className="form-footer">
            <button className="button primary" disabled={!!busy}>
              {busy === "add" ? "正在保存…" : "添加代码源"}
            </button>
          </div>
        </form>
      </Modal>
      <Modal
        open={!!selected}
        onClose={() => setSelected(undefined)}
        title="代码源快照与覆盖范围"
        wide
      >
        {!details ? (
          <p role="status">正在读取真实快照…</p>
        ) : (
          <>
            <dl className="source-snapshot">
              <dt>快照</dt>
              <dd>
                <code>{details.snapshot_id}</code>
              </dd>
              <dt>代码源</dt>
              <dd>
                {details.source_id} · 定义 v{details.source_version}
              </dd>
              <dt>内容版本</dt>
              <dd>
                <code>{details.commit}</code>
              </dd>
              <dt>覆盖范围</dt>
              <dd>
                {details.files} 个文件 · 省略 {details.skipped_total} 项
              </dd>
            </dl>
            <h3>
              <FileCode2 size={15} />
              覆盖局限
            </h3>
            <ul>
              {(details.limitations || []).map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            <div className="form-footer">
              <button
                className="button primary"
                disabled={!canWrite}
                onClick={() => {
                  setSelected(undefined);
                  onTask(details.snapshot_id);
                }}
              >
                使用此快照新建任务
              </button>
            </div>
          </>
        )}
        {error && (
          <div role="alert" className="error-message">
            {error}
          </div>
        )}
      </Modal>
    </>
  );
}
