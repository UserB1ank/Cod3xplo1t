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
  kind: "local_folder" | "git_repository";
  location: string;
  ref: string;
  credential_ref?: string;
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

export function sourceInput(
  project: string,
  name: string,
  location: string,
  kind: CodeSource["kind"] = "local_folder",
  ref = "",
  credentialRef = "",
) {
  return {
    api_version: "codexploit/v1",
    id: `src-${crypto.randomUUID()}`,
    project_id: project,
    name,
    kind,
    location,
    ref: kind === "local_folder" ? "" : ref,
    ...(kind === "git_repository" && credentialRef
      ? { credential_ref: credentialRef }
      : {}),
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
  requested_ref?: string;
}

function message(error: unknown) {
  if (error instanceof ApiError) {
    const gitErrors: Record<string, string> = {
      network_disabled: "服务端尚未启用 Git 网络访问，请配置 --allow-network。",
      credential_unavailable:
        "凭据引用不存在、文件不可读或配置不完整；SSH 还需登记身份文件和 known_hosts。",
      git_access_denied:
        "仓库拒绝访问，或凭据引用不属于当前项目和站点。请检查授权与主机密钥。",
      git_revision_not_found: "分支、标签或提交不存在，无法固定代码版本。",
      git_fetch_failed: "仓库获取失败，请检查地址、证书和服务是否可达。",
    };
    if (gitErrors[error.code]) return gitErrors[error.code];
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
  const [kind, setKind] = useState<CodeSource["kind"]>("local_folder");
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
        title="项目代码源"
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
            文件夹读取当前文件；Git
            按分支、标签或提交固定版本。每次更新生成不可变快照，已有任务继续使用原版本。
          </Hint>
        </div>
        {loading ? (
          <p className="source-description" role="status">
            正在读取代码源…
          </p>
        ) : !sources.length ? (
          <EmptyState title="尚未添加代码源">
            添加 /repos 下的目录或 Git 仓库；同一项目可管理多个代码源。
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="path-table source-table">
              <thead>
                <tr>
                  <th>代码源</th>
                  <th>读取方式 / 位置</th>
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
                        {source.kind === "git_repository" ? (
                          <GitBranch size={14} />
                        ) : (
                          <FolderOpen size={14} />
                        )}
                        {source.kind === "git_repository"
                          ? "Git 仓库"
                          : "本地文件夹"}
                      </span>
                      <code className="source-secondary">
                        {source.location}
                      </code>
                      <small className="source-secondary">
                        定义 v{source.version} ·{" "}
                        {source.kind === "git_repository"
                          ? `请求 ${source.ref}`
                          : "内容寻址"}
                      </small>
                      {source.credential_ref && (
                        <small className="source-secondary">
                          凭据引用：{source.credential_ref}
                        </small>
                      )}
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
        title="添加代码源"
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
                  kind,
                  String(data.get("ref") || ""),
                  String(data.get("credential_ref") || ""),
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
            代码源类型
            <select
              value={kind}
              onChange={(event) =>
                setKind(event.target.value as CodeSource["kind"])
              }
            >
              <option value="local_folder">本地文件夹</option>
              <option value="git_repository">Git 仓库</option>
            </select>
          </label>
          <label>
            {kind === "local_folder" ? "容器内目录" : "Git 仓库 URL"}
            <input
              name="location"
              required
              pattern={
                kind === "local_folder" ? "/repos/.+" : "(https|ssh)://.+"
              }
              placeholder={
                kind === "local_folder"
                  ? "/repos/service"
                  : "https://forge.example.invalid/team/service.git"
              }
            />
          </label>
          {kind === "git_repository" && (
            <>
              <label>
                分支、标签或提交
                <input
                  name="ref"
                  required
                  defaultValue="main"
                  maxLength={256}
                />
              </label>
              <label>
                凭据引用（可选）
                <input
                  name="credential_ref"
                  maxLength={160}
                  placeholder="已在服务端登记的引用 ID"
                />
              </label>
            </>
          )}
          <Hint>
            {kind === "local_folder"
              ? "先把目录只读挂载到 /repos 下。目录内的 .git 不会改变读取方式。"
              : "仓库 URL 不能包含账号、密钥或查询参数。网络与凭据权限由服务端校验；SSH 需凭据引用。"}{" "}
            不会运行目标仓库代码。
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
              <dt>请求版本</dt>
              <dd>{details.requested_ref || "当前文件内容"}</dd>
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
