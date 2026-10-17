import { useEffect, useState } from "react";
import {
  Archive,
  ChevronRight,
  Pause,
  Pin,
  Play,
  Plus,
  Search,
  Tags,
  Undo2,
  X,
} from "lucide-react";
import { ApiClient, ApiError } from "./api";
import { Badge, EmptyState, Hint, Modal, Panel } from "./components";
import { flowStatus } from "./WorkflowRun";
import { dateLabel, shortId } from "./domain";
import {
  gradeNames,
  taskGradeCounts,
  taskState,
  type Grade,
  type ProjectFinding,
  type Task,
} from "./workbench";

type Catalog = { categories: string[]; version: number; etag: string };
type TaskPage = { tasks: Task[]; total: number };
const pageSize = 50;

function message(error: unknown) {
  if (error instanceof ApiError) {
    if (error.status === 412)
      return "数据已被其他客户端修改，请刷新后再操作；分类管理请重新打开后保存。";
    if (error.code === "category_in_use")
      return "此分类仍有任务使用，请先将这些任务移到其他分类或未分类。";
    if (error.code === "task_not_idle")
      return "请先暂停调度，并等待活动路径、Agent 和验证运行全部结束后再归档。";
    if (error.code === "task_archived")
      return "请先恢复归档任务，再明确恢复调度。";
  }
  return error instanceof Error ? error.message : "任务操作失败";
}

export function ProjectTasks({
  api,
  projectID,
  revision,
  findings,
  partial,
  onOpen,
  onCreate,
  canWrite,
  onChanged,
}: {
  api: ApiClient;
  projectID: string;
  revision: number;
  findings: ProjectFinding[];
  partial: boolean;
  onOpen: (id: string) => void;
  onCreate: () => void;
  canWrite: boolean;
  onChanged: () => void;
}) {
  const [query, setQuery] = useState("");
  const [state, setState] = useState("");
  const [category, setCategory] = useState("all");
  const [archived, setArchived] = useState(false);
  const [page, setPage] = useState(0);
  const [data, setData] = useState<TaskPage>({ tasks: [], total: 0 });
  const [catalog, setCatalog] = useState<Catalog>();
  const [loading, setLoading] = useState(true);
  const [tick, refresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [managing, setManaging] = useState(false);
  const [draft, setDraft] = useState<string[]>([]);
  const [draftETag, setDraftETag] = useState("");
  const endpoint = `/projects/${encodeURIComponent(projectID)}`;
  useEffect(() => {
    const timer = setInterval(() => {
      if (!document.hidden && !busy && !managing) refresh((n) => n + 1);
    }, 5000);
    return () => clearInterval(timer);
  }, [busy, managing]);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    const params = new URLSearchParams({
      limit: String(pageSize),
      offset: String(page * pageSize),
      sort: "organized",
      archived: String(archived),
    });
    if (query) params.set("q", query);
    if (state) params.set("state", state);
    if (category === "uncategorized") params.set("category", "");
    if (category.startsWith("category:"))
      params.set("category", category.slice(9));
    api
      .get<TaskPage>(`${endpoint}/tasks?${params}`, controller.signal)
      .then(setData)
      .catch((e) => {
        if (!controller.signal.aborted) setError(message(e));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [api, endpoint, revision, tick, page, query, state, category, archived]);
  useEffect(() => {
    const controller = new AbortController();
    api
      .response(`${endpoint}/task-categories`, { signal: controller.signal })
      .then(
        async (response) =>
          ({
            ...(await response.json()),
            etag: response.headers.get("ETag") || "",
          }) as Catalog,
      )
      .then(setCatalog)
      .catch((e) => {
        if (!controller.signal.aborted) setError(message(e));
      });
    return () => controller.abort();
  }, [api, endpoint, revision, tick]);
  useEffect(() => {
    if (!loading && page > 0 && page * pageSize >= data.total)
      setPage(Math.max(0, Math.ceil(data.total / pageSize) - 1));
  }, [data.total, page, loading]);
  useEffect(() => {
    if (
      catalog &&
      category.startsWith("category:") &&
      !catalog.categories.includes(category.slice(9))
    ) {
      setCategory("all");
      setPage(0);
    }
  }, [catalog, category]);
  const run = async (work: () => Promise<unknown>, success: string) => {
    if (busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await work();
      setNotice(success);
      refresh((n) => n + 1);
      onChanged();
    } catch (e) {
      setError(message(e));
      refresh((n) => n + 1);
    } finally {
      setBusy(false);
    }
  };
  const edit = (
    task: Task,
    patch: { pinned?: boolean; category?: string; archived?: boolean },
  ) =>
    run(() => {
      if (!task.etag) throw new Error("任务缺少版本标识，请刷新重试。");
      return api.response(
        `${endpoint}/tasks/${encodeURIComponent(task.audit_id)}`,
        {
          method: "PATCH",
          body: JSON.stringify(patch),
          headers: { "If-Match": task.etag },
        },
      );
    }, "任务整理结果已保存。");
  const scheduling = (task: Task) =>
    run(
      () => {
        if (!task.etag) throw new Error("任务缺少版本标识，请刷新重试。");
        return api.post(
          `/tasks/${encodeURIComponent(task.audit_id)}/${task.paused ? "resume" : "pause"}`,
          {},
          undefined,
          { "If-Match": task.etag },
        );
      },
      task.paused ? "已恢复调度。" : "已暂停领取新路径；已开始的调用允许结束。",
    );
  return (
    <>
      {error && (
        <div role="alert" className="error-message">
          {error}
        </div>
      )}
      {notice && (
        <div role="status" className="success-message">
          {notice}
        </div>
      )}
      <Panel
        title="挖掘任务"
        action={
          <button
            className="button secondary"
            disabled={!canWrite || busy || !catalog?.etag}
            onClick={() => {
              setDraft([...(catalog?.categories || [])]);
              setDraftETag(catalog?.etag || "");
              setError("");
              setManaging(true);
            }}
          >
            <Tags size={15} />
            分类管理
          </button>
        }
      >
        <div
          className="tabs task-archive-tabs"
          role="tablist"
          aria-label="任务归档范围"
        >
          {[false, true].map((value) => (
            <button
              key={String(value)}
              role="tab"
              aria-selected={archived === value}
              className={archived === value ? "active" : ""}
              onClick={() => {
                setArchived(value);
                setState("");
                setPage(0);
              }}
            >
              {value ? "已归档" : "当前任务"}
            </button>
          ))}
        </div>
        <div className="section-toolbar inset">
          <div className="search-input">
            <Search size={15} />
            <input
              aria-label="搜索任务"
              placeholder="搜索任务名称、目标或 ID…"
              value={query}
              maxLength={200}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(0);
              }}
            />
          </div>
          <select
            aria-label="任务状态筛选"
            value={state}
            onChange={(event) => {
              setState(event.target.value);
              setPage(0);
            }}
          >
            <option value="">全部状态</option>
            {!archived && (
              <>
                <option value="QUEUED">待处理</option>
                <option value="RUNNING">运行中</option>
                <option value="PAUSED">已暂停</option>
                <option value="CONCLUDED">已完成</option>
                <option value="BLOCKED">受阻</option>
                <option value="FAILED">执行失败</option>
                <option value="EMPTY">无候选路径</option>
              </>
            )}
          </select>
          <select
            aria-label="任务分类筛选"
            value={category}
            onChange={(event) => {
              setCategory(event.target.value);
              setPage(0);
            }}
          >
            <option value="all">全部分类</option>
            <option value="uncategorized">未分类</option>
            {catalog?.categories.map((name) => (
              <option key={name} value={`category:${name}`}>
                {name}
              </option>
            ))}
          </select>
          <span className="subtle-label">{data.total} 个任务</span>
        </div>
        {loading && !data.tasks.length ? (
          <p className="source-description" role="status">
            正在读取任务…
          </p>
        ) : !data.tasks.length ? (
          <EmptyState
            title="暂无匹配任务"
            action={
              !archived && (
                <button
                  className="button secondary"
                  disabled={!canWrite}
                  onClick={onCreate}
                >
                  <Plus size={15} />
                  新建任务
                </button>
              )
            }
          >
            调整搜索或筛选条件。归档保留任务、证据和图谱引用。
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="standard-table task-table" aria-busy={loading}>
              <thead>
                <tr>
                  <th>任务 / 目标</th>
                  <th>分类</th>
                  <th>代码版本</th>
                  <th>状态</th>
                  <th>路径进度</th>
                  <th>高 / 中 / 低危</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {data.tasks.map((task) => {
                  const name = task.name || `任务 ${shortId(task.audit_id)}`;
                  const grades = taskGradeCounts(findings, task.audit_id);
                  const complete =
                    (task.counts_by_status.CONCLUDED || 0) +
                    (task.counts_by_status.HYPOTHESIS_FORMED || 0) +
                    (task.counts_by_status.CANCELLED || 0);
                  return (
                    <tr key={task.audit_id}>
                      <td>
                        <button
                          className="table-title"
                          onClick={() => onOpen(task.audit_id)}
                        >
                          {task.pinned && <Pin size={12} />} {name}
                        </button>
                        <p className="cell-subtitle" title={task.objective}>
                          {task.objective || "基于攻击面生成的候选路径"}
                        </p>
                        <small className="muted">
                          {dateLabel(task.created_at)}
                        </small>
                      </td>
                      <td>
                        <select
                          className="task-category-select"
                          aria-label={`任务分类 ${name}`}
                          value={task.category || ""}
                          disabled={!canWrite || busy || !catalog}
                          onChange={(event) =>
                            edit(task, { category: event.target.value })
                          }
                        >
                          <option value="">未分类</option>
                          {catalog?.categories.map((category) => (
                            <option key={category}>{category}</option>
                          ))}
                        </select>
                      </td>
                      <td className="mono">{shortId(task.snapshot_id, 7)}</td>
                      <td>
                        <Badge
                          status={taskState(task)}
                          label={
                            task.workflow_status
                              ? flowStatus[task.workflow_status]
                              : task.archived
                                ? "已归档"
                                : taskState(task) === "EMPTY"
                                  ? "无候选路径"
                                  : undefined
                          }
                        />
                      </td>
                      <td className="mono">
                        {complete} / {task.path_count}
                      </td>
                      <td>
                        <div className="grade-counts">
                          {(["high", "medium", "low"] as Grade[]).map(
                            (grade) => (
                              <span
                                className={grade}
                                key={grade}
                                title={gradeNames[grade]}
                              >
                                {partial ? "…" : grades[grade]}
                              </span>
                            ),
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="task-organization-actions">
                          <button
                            className="icon-button"
                            aria-label={`${task.pinned ? "取消置顶" : "置顶"} ${name}`}
                            title={task.pinned ? "取消置顶" : "置顶"}
                            disabled={!canWrite || busy}
                            onClick={() => edit(task, { pinned: !task.pinned })}
                          >
                            <Pin
                              size={16}
                              fill={task.pinned ? "currentColor" : "none"}
                            />
                          </button>
                          <button
                            className="icon-button"
                            aria-label={`${task.paused ? "恢复调度" : "暂停调度"} ${name}`}
                            title={
                              task.archived
                                ? "先恢复归档任务"
                                : task.paused
                                  ? "恢复调度"
                                  : "暂停调度"
                            }
                            disabled={
                              !canWrite ||
                              busy ||
                              task.archived ||
                              ["CREATED", "RUNNING"].includes(
                                task.workflow_status || "",
                              )
                            }
                            onClick={() => scheduling(task)}
                          >
                            {task.paused ? (
                              <Play size={16} />
                            ) : (
                              <Pause size={16} />
                            )}
                          </button>
                          <span
                            title={
                              task.archived
                                ? "恢复后仍保持暂停"
                                : task.can_archive
                                  ? "归档并保留全部数据"
                                  : "先暂停调度，并等待活动路径和运行结束"
                            }
                          >
                            <button
                              className="icon-button"
                              aria-label={`${task.archived ? "恢复任务" : "归档任务"} ${name}`}
                              disabled={
                                !canWrite ||
                                busy ||
                                (!task.archived && !task.can_archive)
                              }
                              onClick={() =>
                                edit(task, { archived: !task.archived })
                              }
                            >
                              {task.archived ? (
                                <Undo2 size={16} />
                              ) : (
                                <Archive size={16} />
                              )}
                            </button>
                          </span>
                          <button
                            className="icon-button"
                            aria-label={`打开任务 ${name}`}
                            onClick={() => onOpen(task.audit_id)}
                          >
                            <ChevronRight size={16} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <div className="pager">
          <span>
            共 {data.total} 条 · 第 {page + 1} /{" "}
            {Math.max(1, Math.ceil(data.total / pageSize))} 页
          </span>
          <button
            disabled={!page || loading}
            onClick={() => setPage((n) => n - 1)}
          >
            上一页
          </button>
          <button
            disabled={(page + 1) * pageSize >= data.total || loading}
            onClick={() => setPage((n) => n + 1)}
          >
            下一页
          </button>
        </div>
        <Hint>
          置顶任务优先显示。归档前需暂停并等待活动执行结束；恢复任务不会自动恢复调度。
        </Hint>
        {partial && (
          <Hint>漏洞来源尚未全部载入，任务行暂不显示不完整的等级计数。</Hint>
        )}
      </Panel>
      <Modal
        open={managing}
        onClose={() => {
          if (!busy) setManaging(false);
        }}
        title="任务分类管理"
      >
        <p className="muted">
          项目内共享，最多 32 个分类。删除在用分类前，请先调整任务分类。
        </p>
        <div className="task-category-draft">
          {draft.map((name) => (
            <span key={name}>
              {name}
              <button
                className="icon-button"
                aria-label={`移除分类 ${name}`}
                disabled={busy}
                onClick={() =>
                  setDraft((values) => values.filter((value) => value !== name))
                }
              >
                <X size={13} />
              </button>
            </span>
          ))}
        </div>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const form = event.currentTarget;
            const name = String(
              new FormData(form).get("category") || "",
            ).trim();
            if (
              !name ||
              draft.some((value) => value.toLowerCase() === name.toLowerCase())
            ) {
              setError("分类名称不能为空或重复。");
              return;
            }
            setDraft((values) => [...values, name]);
            setError("");
            form.reset();
          }}
        >
          <label>
            新增分类
            <input
              name="category"
              required
              maxLength={30}
              placeholder="例如：鉴权与访问控制"
            />
          </label>
          <button
            className="button secondary"
            disabled={busy || draft.length >= 32}
          >
            <Plus size={14} />
            添加到列表
          </button>
        </form>
        {error && (
          <div role="alert" className="error-message">
            {error}
          </div>
        )}
        <div className="form-footer">
          <button
            className="button primary"
            disabled={!canWrite || busy || !draftETag}
            onClick={() =>
              run(async () => {
                await api.response(`${endpoint}/task-categories`, {
                  method: "PUT",
                  headers: { "If-Match": draftETag },
                  body: JSON.stringify({ categories: draft }),
                });
                setManaging(false);
              }, "项目分类已保存。")
            }
          >
            {busy ? "正在保存…" : "保存分类"}
          </button>
        </div>
      </Modal>
    </>
  );
}
