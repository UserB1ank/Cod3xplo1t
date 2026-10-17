import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import {
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  BookOpen,
  Box,
  Check,
  ChevronRight,
  Code2,
  FileCode2,
  FileText,
  FolderGit2,
  GitBranch,
  Layers,
  Loader2,
  LockKeyhole,
  LogOut,
  Network,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  TriangleAlert,
  Workflow,
} from "lucide-react";
import { ApiClient } from "./api";
import { LLMSettings } from "./LLMSettings";
import { Sources, sourceInput, readSources, type CodeSource } from "./Sources";
import { ProjectTasks } from "./TaskList";
import { Artifacts } from "./Artifacts";
import { Plugins } from "./Plugins";
import { Workflows, type Plan } from "./Workflows";
import { WorkflowRun, flowStatus } from "./WorkflowRun";
import { Knowledge } from "./Knowledge";
import {
  Badge,
  CodeBlock,
  EmptyState,
  Hint,
  Modal,
  Panel,
  PathTable,
} from "./components";
import { dateLabel, eventNames, findingStatus, shortId } from "./domain";
import type {
  AuditEvent,
  AuditPath,
  FindingDetail,
  GraphSummary,
  Project,
  Run,
  Snapshot,
} from "./types";
import {
  gradeNames,
  latestSnapshot,
  readRoute,
  routeHash,
  taskGradeCounts,
  taskState,
  type FindingPage,
  type Grade,
  type Identity,
  type ProjectFinding,
  type Route,
  type Task,
} from "./workbench";

type Resource<T> = { data?: T; error?: string; loading: boolean };
function useResource<T>(
  read: (signal: AbortSignal) => Promise<T>,
  deps: unknown[],
): Resource<T> {
  const [state, set] = useState<Resource<T>>({ loading: true });
  useEffect(() => {
    const controller = new AbortController();
    set((previous) => ({ data: previous.data, loading: true }));
    read(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) set({ data, loading: false });
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          set({
            error: error instanceof Error ? error.message : "请求失败",
            loading: false,
          });
      });
    return () => controller.abort();
  }, deps);
  return state;
}
const errorText = (error: unknown) =>
  error instanceof Error ? error.message : "操作失败";
const taskName = (task: Task) =>
  task.name || `挖掘任务 ${shortId(task.audit_id)}`;
function GradeBadge({ grade }: { grade?: string }) {
  return (
    <span className={`grade ${grade || "ungraded"}`}>
      {gradeNames[grade as Grade] || "待分级"}
    </span>
  );
}
function Loading() {
  return (
    <div className="loading" role="status">
      <Loader2 className="spin" size={20} />
      正在读取工作区…
    </div>
  );
}
function Failure({ message }: { message: string }) {
  return (
    <div className="error-message" role="alert">
      <TriangleAlert size={16} />
      {message}
    </div>
  );
}
function Pager({
  page,
  total,
  size = 50,
  onChange,
}: {
  page: number;
  total: number;
  size?: number;
  onChange: (page: number) => void;
}) {
  return (
    <div className="pager">
      <span>
        共 {total} 条 · 第 {page + 1} / {Math.max(1, Math.ceil(total / size))}{" "}
        页
      </span>
      <button disabled={!page} onClick={() => onChange(page - 1)}>
        上一页
      </button>
      <button
        disabled={(page + 1) * size >= total}
        onClick={() => onChange(page + 1)}
      >
        下一页
      </button>
    </div>
  );
}

export default function App() {
  const [api, setApi] = useState<ApiClient>();
  const [identity, setIdentity] = useState<Identity>();
  const [route, setRoute] = useState<Route>(() => readRoute(location.hash));
  const [revision, refresh] = useState(0);
  const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [dialog, setDialog] = useState("");
  const [taskSnapshot, setTaskSnapshot] = useState<string>();
  const [inspectPath, setInspectPath] = useState<AuditPath>();
  const [inspectFinding, setInspectFinding] = useState<string>();
  const navigate = useCallback((next: Route) => {
    location.hash = routeHash(next);
  }, []);
  useEffect(() => {
    const listener = () => {
      setRoute(readRoute(location.hash));
      setError("");
      setNotice("");
      setInspectPath(undefined);
      setInspectFinding(undefined);
    };
    window.addEventListener("hashchange", listener);
    return () => window.removeEventListener("hashchange", listener);
  }, []);
  const projects = useResource(
    async (signal) => (api ? (await api.projects(signal)).projects || [] : []),
    [api, revision],
  );
  const project = projects.data?.find((p) => p.id === route.project);
  const snapshots = useResource(
    async (signal) =>
      api && route.project
        ? (
            await api.get<{ snapshots: Snapshot[] }>(
              `/snapshots?project_id=${encodeURIComponent(route.project)}`,
              signal,
            )
          ).snapshots || []
        : [],
    [api, route.project, revision],
  );
  const tasks = useResource(
    async (signal) => {
      const tasks: Task[] = [];
      if (!api || !route.project) return { tasks, total: 0 };
      let total = 0;
      do {
        const page = await api.get<{ tasks: Task[]; total: number }>(
          `/projects/${encodeURIComponent(route.project)}/tasks?limit=200&offset=${tasks.length}`,
          signal,
        );
        total = page.total;
        if (!page.tasks.length) break;
        tasks.push(...page.tasks);
      } while (tasks.length < total);
      return { tasks, total };
    },
    [api, route.project, revision],
  );
  const findings = useResource(
    async (signal) =>
      api && route.project
        ? api.get<FindingPage>(
            `/projects/${encodeURIComponent(route.project)}/findings?limit=1000`,
            signal,
          )
        : { findings: [], total: 0, counts: {}, truncated: false },
    [api, route.project, revision],
  );
  const task = tasks.data?.tasks.find((t) => t.audit_id === route.task);
  const action = async (
    label: string,
    work: () => Promise<unknown>,
    done?: () => void,
  ) => {
    if (busy) return;
    setBusy(label);
    setError("");
    setNotice("");
    try {
      await work();
      refresh((n) => n + 1);
      setNotice(`${label}完成`);
      done?.();
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy("");
    }
  };
  if (!api || !identity)
    return (
      <Connect
        onConnect={(client, who) => {
          setApi(client);
          setIdentity(who);
        }}
      />
    );
  const canWrite = identity.can_write;
  const navItems = [
    { id: "overview", label: "项目概览", icon: Layers },
    { id: "tasks", label: "挖掘任务", icon: Workflow },
    { id: "sources", label: "代码源", icon: FolderGit2 },
    { id: "knowledge", label: "共享知识图谱", icon: Network },
    { id: "findings", label: "项目漏洞库", icon: ShieldCheck },
    { id: "artifacts", label: "产物与证据", icon: FileText },
    { id: "plugins", label: "插件中心", icon: Box },
    { id: "workflows", label: "工作流", icon: GitBranch },
    { id: "settings", label: "项目设置", icon: Settings2 },
  ];
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#/projects">
          <span className="brand-mark">
            <Code2 size={22} />
          </span>
          <span>
            codexploit<small>CODE VULNERABILITY LAB</small>
          </span>
        </a>
        <button
          className={`nav-item all-projects ${!route.project && route.view !== "settings" ? "selected" : ""}`}
          onClick={() => navigate({ view: "projects" })}
        >
          <FolderGit2 size={17} />
          全部项目
          <ChevronRight size={14} />
        </button>
        {identity.role === "admin" && identity.features.llm_settings && (
          <button
            className={`nav-item ${!route.project && route.view === "settings" ? "selected" : ""}`}
            onClick={() => navigate({ view: "settings" })}
          >
            <Settings2 size={17} />
            模型设置
          </button>
        )}
        {route.project && (
          <>
            <div className="nav-label">当前项目</div>
            <div className="project-selector">
              <Box size={16} />
              <span>{project?.name || "载入项目…"}</span>
            </div>
            <nav>
              {navItems.map((item) => (
                <button
                  key={item.id}
                  className={`nav-item ${route.task ? (item.id === "tasks" ? "selected" : "") : route.view === item.id ? "selected" : ""}`}
                  onClick={() =>
                    navigate({ project: route.project, view: item.id })
                  }
                >
                  <item.icon size={17} />
                  {item.label}
                </button>
              ))}
            </nav>
            <div className="sidebar-note">
              <BookOpen size={16} />
              <strong>知识在项目内共享</strong>
              <p>任务独立运行，代码事实与证据保留版本和来源。</p>
            </div>
          </>
        )}
        <div className="sidebar-bottom">
          <span className="connection-dot connected" />
          <span>
            {identity.name}
            <small>{identity.role} · 已连接</small>
          </span>
          <button
            aria-label="退出登录"
            className="icon-button"
            onClick={async () => {
              try {
                await api.post("/auth/logout", {});
                setApi(undefined);
                setIdentity(undefined);
              } catch (error) {
                setError(errorText(error));
              }
            }}
          >
            <LogOut size={16} />
          </button>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumbs">
            <a href="#/projects">项目</a>
            {route.project && (
              <>
                <ChevronRight size={13} />
                <a
                  href={routeHash({ project: route.project, view: "overview" })}
                >
                  {project?.name || "…"}
                </a>
              </>
            )}
            {route.task && (
              <>
                <ChevronRight size={13} />
                <span>{task ? taskName(task) : "任务详情"}</span>
              </>
            )}
          </div>
          <div className="topbar-right">
            {identity.role === "admin" && identity.features.llm_settings && (
              <button
                className="text-button"
                onClick={() => navigate({ view: "settings" })}
              >
                <Settings2 size={16} />
                模型设置
              </button>
            )}
            <span className="environment">
              <span />
              本地工作区
            </span>
            <button
              className="icon-button"
              aria-label="刷新数据"
              onClick={() => refresh((n) => n + 1)}
            >
              <RefreshCw size={16} />
            </button>
          </div>
        </header>
        <main>
          {(error ||
            projects.error ||
            snapshots.error ||
            tasks.error ||
            findings.error) && (
            <Failure
              message={
                error ||
                projects.error ||
                snapshots.error ||
                tasks.error ||
                findings.error ||
                ""
              }
            />
          )}
          {notice && (
            <div className="success-message" role="status">
              <Check size={15} />
              {notice}
              <button aria-label="关闭提示" onClick={() => setNotice("")}>
                ×
              </button>
            </div>
          )}
          {busy && (
            <div className="operation-status" role="status">
              <Loader2 size={16} className="spin" />
              {busy}中，请保持页面打开…
            </div>
          )}
          {!route.project && route.view === "settings" ? (
            <LLMSettings
              api={api}
              identity={identity}
              onSaved={async () => {
                setIdentity(await api.get<Identity>("/me"));
                refresh((n) => n + 1);
              }}
            />
          ) : !route.project ? (
            <Projects
              api={api}
              revision={revision}
              projects={projects.data || []}
              loading={projects.loading}
              canWrite={canWrite}
              onCreate={() => setDialog("project")}
              onOpen={(id) => navigate({ project: id, view: "tasks" })}
            />
          ) : projects.loading && !project ? (
            <Loading />
          ) : !project ? (
            <EmptyState title="项目不存在">
              返回项目列表选择一个可用项目。
            </EmptyState>
          ) : route.task && !tasks.loading && tasks.data && !task ? (
            <EmptyState title="任务不属于当前项目">
              返回项目任务列表选择一个可用任务。
            </EmptyState>
          ) : route.task ? (
            <TaskWorkbench
              key={route.task}
              api={api}
              route={route}
              canWrite={canWrite}
              identity={identity}
              revision={revision}
              busy={busy}
              action={action}
              onPath={setInspectPath}
              onFinding={setInspectFinding}
              onBack={() => navigate({ project: project.id, view: "tasks" })}
              onTab={(view) => navigate({ ...route, view })}
            />
          ) : (
            <>
              <div className="page-heading">
                <div>
                  <div className="eyebrow">PROJECT WORKSPACE</div>
                  <h1>
                    {route.view === "overview"
                      ? project.name
                      : navItems.find((n) => n.id === route.view)?.label ||
                        "挖掘任务"}
                  </h1>
                  <p>
                    {route.view === "tasks"
                      ? "为每一次挖掘设定目标，复用项目已积累的知识。"
                      : route.view === "workflows"
                        ? "编辑插件流程，保存不可变版本，编译固定输入与知识版本的计划。"
                        : route.view === "knowledge"
                          ? "项目级代码事实与攻击面，供所有任务共同查询。"
                          : route.view === "artifacts"
                            ? "查看固定快照的输入产物、内容摘要和来源，核对后下载。"
                            : route.view === "findings"
                              ? "汇总任务发现，按证据结论与漏洞严重度查看。"
                              : route.view === "sources"
                                ? "管理文件夹与 Git 仓库，固定源码版本，再选择代码基线创建任务。"
                                : project.source || "项目代码源独立管理。"}
                  </p>
                </div>
                <div className="heading-actions">
                  {project.source && route.view !== "sources" && (
                    <button
                      className="button secondary"
                      disabled={!canWrite || !!busy}
                      onClick={() => setDialog("snapshot")}
                    >
                      <GitBranch size={15} />
                      更新代码版本
                    </button>
                  )}
                  <button
                    className="button primary"
                    disabled={!canWrite || !!busy || !snapshots.data?.length}
                    onClick={() => {
                      setTaskSnapshot(undefined);
                      setDialog("task");
                    }}
                  >
                    <Plus size={16} />
                    新建任务
                  </button>
                </div>
              </div>
              {route.view === "sources" ? (
                <Sources
                  key={project.id}
                  api={api}
                  project={project}
                  revision={revision}
                  canWrite={canWrite && !busy}
                  onRefresh={() => refresh((n) => n + 1)}
                  onLegacySnapshot={() => setDialog("snapshot")}
                  onArtifacts={(snapshot) =>
                    navigate({
                      project: project.id,
                      view: "artifacts",
                      snapshot,
                    })
                  }
                  onTask={(snapshot) => {
                    setTaskSnapshot(snapshot);
                    setDialog("task");
                  }}
                />
              ) : route.view === "workflows" ? (
                <Workflows
                  key={project.id}
                  api={api}
                  projectID={project.id}
                  snapshots={snapshots.data || []}
                  canWrite={canWrite}
                  revision={revision}
                />
              ) : route.view === "plugins" ? (
                <Plugins
                  key={project.id}
                  api={api}
                  projectID={project.id}
                  snapshots={snapshots.data || []}
                  revision={revision}
                  canWrite={canWrite}
                  canRegister={identity.role === "admin"}
                  onArtifacts={(snapshot) =>
                    navigate({
                      project: project.id,
                      view: "artifacts",
                      snapshot,
                    })
                  }
                />
              ) : route.view === "artifacts" ? (
                <Artifacts
                  key={`${project.id}:${route.snapshot || ""}`}
                  api={api}
                  projectID={project.id}
                  snapshots={snapshots.data || []}
                  preferredSnapshot={route.snapshot}
                  revision={revision}
                  canWrite={canWrite}
                />
              ) : route.view === "knowledge" ? (
                <Knowledge
                  key={project.id}
                  api={api}
                  projectID={project.id}
                  snapshots={snapshots.data || []}
                  revision={revision}
                />
              ) : route.view === "findings" ? (
                <FindingLibrary
                  key={project.id}
                  api={api}
                  projectID={project.id}
                  revision={revision}
                  onFinding={setInspectFinding}
                />
              ) : route.view === "settings" ? (
                <ProjectSettings
                  project={project}
                  identity={identity}
                  snapshots={snapshots.data || []}
                />
              ) : (
                <>
                  <Metrics
                    counts={findings.data?.counts || {}}
                    tasks={tasks.data?.total || 0}
                  />
                  {route.view === "overview" && (
                    <div className="overview-intro">
                      <div>
                        <span className="eyebrow">SHARED KNOWLEDGE</span>
                        <h2>一次建立，持续积累。</h2>
                        <p>
                          {snapshots.data?.length || 0} 个代码版本 ·{" "}
                          {tasks.data?.total || 0}{" "}
                          个挖掘任务。任务运行记录独立保存，发现与证据汇入项目知识库。
                        </p>
                        <button
                          className="text-button"
                          onClick={() =>
                            navigate({ project: project.id, view: "knowledge" })
                          }
                        >
                          打开知识图谱
                          <ArrowRight size={15} />
                        </button>
                      </div>
                      <Network size={88} strokeWidth={0.7} />
                    </div>
                  )}
                  <ProjectTasks
                    key={project.id}
                    api={api}
                    projectID={project.id}
                    revision={revision}
                    onChanged={() => refresh((n) => n + 1)}
                    findings={findings.data?.findings || []}
                    partial={
                      !!findings.data?.truncated ||
                      (findings.data?.total || 0) >
                        (findings.data?.findings.length || 0)
                    }
                    onOpen={(id) =>
                      navigate({
                        project: project.id,
                        task: id,
                        view: "overview",
                      })
                    }
                    onCreate={() => setDialog("task")}
                    canWrite={canWrite && !!snapshots.data?.length}
                  />
                  {!snapshots.data?.length && !snapshots.loading && (
                    <Hint>
                      项目尚无图谱。点击“更新代码版本”建立首个快照、源码图谱和攻击面，再创建任务。
                    </Hint>
                  )}
                </>
              )}
            </>
          )}
        </main>
        <footer>
          CODEXPLOIT<span>证据驱动的代码漏洞挖掘</span>
          <span className="footer-right">项目 → 任务 → 发现</span>
        </footer>
      </div>
      <Modal
        open={dialog === "project"}
        onClose={() => setDialog("")}
        title="创建挖掘项目"
      >
        <ProjectForm
          busy={!!busy}
          network={identity.features.network}
          onSubmit={(values) =>
            action(
              "建立项目与图谱",
              async () => {
                if (values.kind !== "legacy_auto") {
                  const created = await api.post<{ project: Project }>(
                    "/v1/projects",
                    { api_version: "codexploit/v1", name: values.name },
                  );
                  navigate({ project: created.project.id, view: "sources" });
                  const input = await api.post<{ source: CodeSource }>(
                    `/v1/projects/${created.project.id}/sources`,
                    sourceInput(
                      created.project.id,
                      values.name,
                      values.source,
                      values.kind as CodeSource["kind"],
                      values.ref,
                      values.credentialRef,
                    ),
                  );
                  await api.post(`/v1/sources/${input.source.id}/snapshots`, {
                    project_id: created.project.id,
                    source_version: input.source.version,
                    build_graph: true,
                    build_asg: true,
                  });
                  return;
                }
                const created = await api.post<{ project: Project }>(
                  "/projects",
                  { name: values.name, source: values.source },
                );
                navigate({ project: created.project.id, view: "tasks" });
                await api.post(`/projects/${created.project.id}/snapshots`, {
                  ref: values.ref || "HEAD",
                  build_graph: true,
                  build_asg: true,
                });
              },
              () => setDialog(""),
            )
          }
        />
      </Modal>
      <Modal
        open={dialog === "snapshot"}
        onClose={() => setDialog("")}
        title="建立项目代码版本"
      >
        <SnapshotForm
          busy={!!busy}
          onSubmit={(ref) =>
            project &&
            action(
              "构建快照与共享图谱",
              () =>
                api.post(`/projects/${project.id}/snapshots`, {
                  ref: ref || "HEAD",
                  build_graph: true,
                  build_asg: true,
                }),
              () => setDialog(""),
            )
          }
        />
      </Modal>
      <Modal
        open={dialog === "task"}
        onClose={() => setDialog("")}
        title="创建挖掘任务"
      >
        <TaskForm
          key={`${dialog}:${project?.id}:${taskSnapshot}`}
          api={api}
          projectID={project?.id}
          preferredSnapshot={taskSnapshot}
          canAnalyze={identity.features.agent}
          snapshots={snapshots.data || []}
          busy={!!busy}
          onSubmit={(values) =>
            project &&
            action(
              "创建任务",
              async () => {
                const created = await api.post<{ task: Task }>(
                  `/projects/${project.id}/tasks`,
                  values,
                );
                navigate({
                  project: project.id,
                  task: created.task.audit_id,
                  view: "overview",
                });
              },
              () => setDialog(""),
            )
          }
        />
      </Modal>
      <Modal
        open={!!inspectPath}
        onClose={() => setInspectPath(undefined)}
        title="审计路径与源码证据"
        wide
        variant="drawer"
      >
        {inspectPath && (
          <PathInspector
            api={api}
            path={inspectPath}
            canWrite={canWrite}
            onChange={() => refresh((n) => n + 1)}
          />
        )}
      </Modal>
      <Modal
        open={!!inspectFinding}
        onClose={() => setInspectFinding(undefined)}
        title="漏洞详情"
        wide
        variant="drawer"
      >
        {inspectFinding && (
          <FindingInspector
            api={api}
            id={inspectFinding}
            canWrite={canWrite}
            onChange={() => refresh((n) => n + 1)}
          />
        )}
      </Modal>
    </div>
  );
}

function Connect({
  onConnect,
}: {
  onConnect: (api: ApiClient, identity: Identity) => void;
}) {
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loginMode, setLoginMode] = useState<{
    password_login: boolean;
    setup_required: boolean;
  }>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let cancelled = false;
    const client = new ApiClient({ base: "/api", token: "" });
    client
      .get<{ password_login: boolean; setup_required: boolean }>("/auth/status")
      .then(async (mode) => {
        if (cancelled) return;
        setLoginMode(mode);
        if (mode.password_login && !mode.setup_required) {
          try {
            const identity = await client.get<Identity>("/me");
            if (!cancelled) onConnect(client, identity);
          } catch {
            /* Show login when there is no active session. */
          }
        }
      })
      .catch((error) => {
        if (!cancelled) setError(errorText(error));
      });
    return () => {
      cancelled = true;
    };
  }, []);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const api = new ApiClient({
        base: "/api",
        token: loginMode?.password_login ? "" : token.trim(),
      });
      if (loginMode?.password_login) {
        if (loginMode.setup_required) {
          if (password !== confirm) throw new Error("两次输入的密码不一致。");
          await api.post("/auth/setup", { username, password });
          setLoginMode({ password_login: true, setup_required: false });
        }
        await api.post("/auth/login", { username, password });
      }
      const identity = await api.get<Identity>("/me");
      onConnect(api, identity);
      setToken("");
      setPassword("");
      setConfirm("");
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="connect-shell">
      <div className="connect-story">
        <a className="brand" href="#/projects">
          <span className="brand-mark">
            <Code2 size={25} />
          </span>
          codexploit
        </a>
        <div>
          <div className="eyebrow">CODE VULNERABILITY LAB</div>
          <h1>
            从代码关系，
            <br />
            找到漏洞证据。
          </h1>
          <p>
            项目积累知识，任务推进探索。
            <br />
            让每一条发现都能回到代码与证据。
          </p>
          <div className="connect-chain">
            <span>项目</span>
            <ChevronRight />
            <span>任务</span>
            <ChevronRight />
            <span>发现</span>
          </div>
        </div>
        <span className="muted">
          共享知识图谱 · 独立任务执行 · 高 / 中 / 低危分级
        </span>
      </div>
      <form className="connect-form" onSubmit={submit}>
        <span className="login-icon">
          <LockKeyhole size={23} />
        </span>
        <h2>
          {!loginMode
            ? "正在连接工作区…"
            : loginMode.setup_required
              ? "创建管理员账号"
              : "登录工作区"}
        </h2>
        <p>
          {loginMode?.setup_required
            ? "首次启动，请设置管理员账号和密码。"
            : "登录后进入漏洞挖掘工作台。"}
        </p>
        {loginMode?.password_login ? (
          <>
            <label>
              账号
              <input
                required
                name="username"
                autoComplete="username"
                minLength={3}
                maxLength={64}
                pattern="[a-zA-Z0-9_-]{3,64}"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="输入账号"
              />
            </label>
            <label>
              密码
              <input
                required
                name="password"
                type="password"
                autoComplete={
                  loginMode.setup_required ? "new-password" : "current-password"
                }
                minLength={loginMode.setup_required ? 12 : undefined}
                maxLength={128}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={
                  loginMode.setup_required ? "设置 12–128 位密码" : "输入密码"
                }
              />
            </label>
            {loginMode.setup_required && (
              <label>
                确认密码
                <input
                  required
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  maxLength={128}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="再次输入密码"
                />
              </label>
            )}
          </>
        ) : (
          loginMode && (
            <label>
              访问 Token
              <input
                type="password"
                autoComplete="off"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="输入服务端配置的 API Token"
              />
            </label>
          )
        )}
        <small>
          {loginMode?.password_login
            ? "密码以加盐摘要保存在服务端。登录会话最长保留 12 小时，可主动退出。"
            : "凭据仅保留在当前页面内存中。本地匿名开发模式可留空。"}
        </small>
        {error && <Failure message={error} />}
        <button className="button primary" disabled={busy || !loginMode}>
          {busy ? (
            <Loader2 className="spin" size={17} />
          ) : (
            <ArrowRight size={17} />
          )}
          {loginMode?.setup_required ? "创建账号并进入工作区" : "登录工作区"}
        </button>
        <a
          className="text-button"
          href="/prototype/#tasks"
          style={{ marginTop: 18, justifyContent: "center" }}
        >
          查看设计原型（示例数据）
          <ArrowRight size={14} />
        </a>
      </form>
    </div>
  );
}

function Projects({
  api,
  revision,
  projects,
  loading,
  canWrite,
  onCreate,
  onOpen,
}: {
  api: ApiClient;
  revision: number;
  projects: Project[];
  loading: boolean;
  canWrite: boolean;
  onCreate: () => void;
  onOpen: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const selected = projects.filter((p) =>
    `${p.name} ${p.source}`.toLowerCase().includes(query.toLowerCase()),
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">VULNERABILITY RESEARCH</div>
          <h1>挖掘，从项目开始。</h1>
          <p>集中管理代码仓库，为每次探索保留完整上下文。</p>
        </div>
        <button
          className="button primary"
          disabled={!canWrite}
          onClick={onCreate}
        >
          <Plus size={17} />
          创建项目
        </button>
      </div>
      <div className="section-toolbar">
        <div className="search-input">
          <Search size={16} />
          <input
            aria-label="搜索项目"
            placeholder="搜索项目或仓库…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <span className="muted">{projects.length} 个项目</span>
      </div>
      {loading ? (
        <Loading />
      ) : !selected.length ? (
        <EmptyState
          title={query ? "没有匹配的项目" : "建立第一个挖掘项目"}
          action={
            !query && (
              <button
                className="button primary"
                disabled={!canWrite}
                onClick={onCreate}
              >
                <Plus size={15} />
                创建项目
              </button>
            )
          }
        >
          导入仓库后，建立共享图谱，再按目标创建挖掘任务。
        </EmptyState>
      ) : (
        <div className="project-grid">
          {selected.map((project) => (
            <ProjectCard
              key={project.id}
              api={api}
              project={project}
              revision={revision}
              onOpen={() => onOpen(project.id)}
            />
          ))}
        </div>
      )}
    </>
  );
}

function ProjectCard({
  api,
  project,
  revision,
  onOpen,
}: {
  api: ApiClient;
  project: Project;
  revision: number;
  onOpen: () => void;
}) {
  const summary = useResource(
    async (signal) => {
      const [tasks, findings] = await Promise.all([
        api.get<{ total: number }>(
          `/projects/${project.id}/tasks?limit=1`,
          signal,
        ),
        api.get<FindingPage>(
          `/projects/${project.id}/findings?limit=1`,
          signal,
        ),
      ]);
      return { tasks: tasks.total, findings };
    },
    [api, project.id, revision],
  );
  return (
    <button className="project-card" onClick={onOpen}>
      <div className="project-card-top">
        <span className="project-monogram">
          <FolderGit2 size={23} />
        </span>
        <ArrowRight size={18} />
      </div>
      <h2>{project.name}</h2>
      <p className="mono">{project.source}</p>
      <div className="project-card-stats">
        <span>{summary.data?.tasks ?? "—"} 个任务</span>
        <div className="grade-counts">
          {(["high", "medium", "low"] as Grade[]).map((grade) => (
            <span title={gradeNames[grade]} className={grade} key={grade}>
              {summary.data?.findings.counts[grade] ?? "—"}
            </span>
          ))}
        </div>
      </div>
      {summary.error && (
        <small className="muted">统计读取失败，进入项目后可重试</small>
      )}
      {summary.data?.findings.truncated && (
        <small className="muted">漏洞统计为部分结果</small>
      )}
      <div className="project-card-footer">
        <span>
          <Network size={13} />
          项目共享图谱
        </span>
        <span>{dateLabel(project.updated_at)}</span>
      </div>
    </button>
  );
}

function Metrics({
  counts,
  tasks,
}: {
  counts: Record<string, number>;
  tasks: number;
}) {
  return (
    <div className="metric-strip">
      {[
        {
          label: "挖掘任务",
          value: tasks,
          className: "",
          note: "项目内独立执行",
        },
        ...(["high", "medium", "low"] as Grade[]).map((grade) => ({
          label: `${gradeNames[grade]}漏洞`,
          value: counts[grade] || 0,
          className: grade,
          note: "已确认 · 项目去重统计",
        })),
      ].map((item) => (
        <div className={`metric ${item.className}`} key={item.label}>
          <span className="metric-label">{item.label}</span>
          <strong className="metric-number">
            {String(item.value).padStart(2, "0")}
          </strong>
          <span className="metric-note">{item.note}</span>
        </div>
      ))}
    </div>
  );
}

type Action = (
  label: string,
  work: () => Promise<unknown>,
  done?: () => void,
) => Promise<void>;
function TaskWorkbench({
  api,
  route,
  identity,
  canWrite,
  revision,
  busy,
  action,
  onPath,
  onFinding,
  onBack,
  onTab,
}: {
  api: ApiClient;
  route: Route;
  identity: Identity;
  canWrite: boolean;
  revision: number;
  busy: string;
  action: Action;
  onPath: (path: AuditPath) => void;
  onFinding: (id: string) => void;
  onBack: () => void;
  onTab: (view: string) => void;
}) {
  const [tick, setTick] = useState(0);
  const [page, setPage] = useState(0);
  const [runPage, setRunPage] = useState(0);
  const [selectedRun, setSelectedRun] = useState("");
  useEffect(() => {
    const timer = setInterval(() => {
      if (!document.hidden) setTick((n) => n + 1);
    }, 5000);
    return () => clearInterval(timer);
  }, [route.task]);
  useEffect(() => {
    setPage(0);
    setRunPage(0);
    setSelectedRun("");
  }, [route.task]);
  const task = useResource(
    (signal) => api.get<Task>(`/tasks/${route.task}`, signal),
    [api, route.task, revision, tick],
  );
  const paths = useResource(
    (signal) =>
      api.get<{ paths: AuditPath[]; total: number }>(
        `/audits/${route.task}/paths?limit=50&offset=${page * 50}&sort=priority`,
        signal,
      ),
    [api, route.task, page, revision, tick],
  );
  const runs = useResource(
    (signal) =>
      identity.features.agent
        ? api.get<{ runs: Run[]; total: number }>(
            `/runs?audit_id=${route.task}&limit=50&offset=${runPage * 50}`,
            signal,
          )
        : Promise.resolve({ runs: [], total: 0 }),
    [api, route.task, runPage, revision, tick, identity.features.agent],
  );
  const tabs = [
    { id: "overview", label: "总览" },
    { id: "process", label: "执行过程" },
    { id: "exploration", label: "探索链路" },
    { id: "findings", label: "漏洞发现" },
    { id: "report", label: "报告" },
    { id: "artifacts", label: "产物与证据" },
  ];
  const current = task.data;
  if (!current && task.loading) return <Loading />;
  if (task.error) return <Failure message={task.error} />;
  if (!current) return null;
  const changeScheduling = () =>
    action(current.paused ? "恢复调度" : "暂停调度", async () => {
      const read = await api.response(`/tasks/${current.audit_id}`);
      const etag = read.headers.get("ETag");
      await read.arrayBuffer();
      if (!etag) throw new Error("任务缺少版本标识");
      return api.post(
        `/tasks/${current.audit_id}/${current.paused ? "resume" : "pause"}`,
        {},
        undefined,
        { "If-Match": etag },
      );
    });
  return (
    <>
      <button className="back-link" onClick={onBack}>
        <ArrowLeft size={14} />
        项目任务列表
      </button>
      <div className="page-heading task-heading">
        <div>
          <div className="task-title-line">
            <h1>{taskName(current)}</h1>
            <Badge
              status={taskState(current)}
              label={
                current.workflow_status
                  ? flowStatus[current.workflow_status]
                  : current.archived
                    ? "已归档"
                    : taskState(current) === "EMPTY"
                      ? "无候选路径"
                      : undefined
              }
            />
          </div>
          <p>{current.objective || "从攻击面出发，挖掘并验证代码漏洞。"}</p>
          <div className="task-meta">
            <span>
              <GitBranch size={13} />
              {shortId(current.snapshot_id)}
            </span>
            <span>
              <Network size={13} />
              复用项目图谱
            </span>
            <span title={current.source_id}>
              <FolderGit2 size={13} />
              {current.source_id
                ? `${current.source_id} · 定义 v${current.source_version}`
                : "原项目代码源"}
            </span>
            <span>{dateLabel(current.created_at)}</span>
          </div>
        </div>
        <div className="heading-actions">
          <button
            className="button secondary"
            disabled={
              !canWrite ||
              !!busy ||
              current.archived ||
              ["CREATED", "RUNNING"].includes(current.workflow_status || "")
            }
            onClick={changeScheduling}
          >
            {current.paused ? <Play size={15} /> : <Pause size={15} />}
            {current.paused ? "恢复调度" : "暂停调度"}
          </button>
          <button
            className="button primary"
            disabled={
              !canWrite ||
              !!busy ||
              current.paused ||
              current.archived ||
              !identity.features.agent ||
              current.workflow_status === "RUNNING" ||
              current.workflow_status === "CREATED" ||
              !(current.counts_by_status.QUEUED > 0)
            }
            onClick={() =>
              action("执行下一条路径", () =>
                api.post(`/audits/${current.audit_id}/runs`, { max_runs: 1 }),
              )
            }
          >
            <Play size={15} />
            执行下一条
          </button>
        </div>
      </div>
      {!identity.features.agent && (
        <Hint>
          Agent 未配置。可以查看图谱和审计路径；启动服务时配置 CLI Agent
          适配器后可执行挖掘。
        </Hint>
      )}
      {current.archived && (
        <Hint>
          任务已归档，任务、证据与图谱仍可查看。请到项目任务列表恢复归档后再恢复调度。
        </Hint>
      )}
      {current.paused && (
        <Hint>
          任务已暂停领取新路径。已经开始的调用允许结束；恢复调度后继续处理待执行路径。
        </Hint>
      )}
      <div className="tabs" role="tablist" aria-label="任务详情">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            aria-selected={route.view === tab.id}
            className={route.view === tab.id ? "active" : ""}
            onClick={() => onTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {current.workflow_run_id &&
        ["overview", "process"].includes(route.view) && (
          <WorkflowRun
            key={current.workflow_run_id}
            api={api}
            projectID={route.project!}
            runID={current.workflow_run_id}
            revision={revision + tick}
            onArtifacts={() => onTab("artifacts")}
            onAgentRun={(id) => {
              setSelectedRun(id);
              onTab("process");
            }}
          />
        )}
      {paths.error && <Failure message={paths.error} />}
      {runs.error && <Failure message={runs.error} />}
      {route.view === "artifacts" ? (
        <Artifacts
          api={api}
          projectID={route.project!}
          fixedSnapshot={current.snapshot_id}
          revision={revision}
          canWrite={canWrite}
        />
      ) : route.view === "process" ? (
        <>
          <Panel
            title="Agent 运行"
            action={<span className="subtle-label">每 5 秒刷新</span>}
          >
            {runs.data?.runs.length ? (
              <div className="table-scroll">
                <table className="standard-table">
                  <thead>
                    <tr>
                      <th>运行</th>
                      <th>状态</th>
                      <th>工具调用</th>
                      <th>Token 输入 / 输出</th>
                      <th>停止原因</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {runs.data.runs.map((run) => (
                      <tr key={run.run_id}>
                        <td className="mono">{shortId(run.run_id)}</td>
                        <td>
                          <Badge status={run.status} />
                        </td>
                        <td>{run.tool_calls}</td>
                        <td className="mono">
                          {run.input_tokens} / {run.output_tokens}
                        </td>
                        <td>{run.stop_reason || "—"}</td>
                        <td>
                          <button
                            className="text-button"
                            onClick={() => setSelectedRun(run.run_id)}
                          >
                            查看事件
                            <ChevronRight size={14} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState title="尚无 Agent 运行">
                启动一条路径后，可在这里查看工具调用和运行事件。
              </EmptyState>
            )}
            <Pager
              page={runPage}
              total={runs.data?.total || 0}
              onChange={setRunPage}
            />
          </Panel>
          <Panel
            title={
              selectedRun ? `运行事件 · ${shortId(selectedRun)}` : "任务事件"
            }
          >
            <EventFeed
              api={api}
              endpoint={
                selectedRun
                  ? `/runs/${selectedRun}/events`
                  : `/audits/${current.audit_id}/events`
              }
            />
          </Panel>
        </>
      ) : route.view === "findings" ? (
        <TaskFindings
          api={api}
          projectID={route.project!}
          taskID={current.audit_id}
          revision={revision + tick}
          onFinding={onFinding}
        />
      ) : route.view === "report" ? (
        <Reports
          api={api}
          task={current}
          enabled={identity.features.verification}
        />
      ) : (
        <>
          {route.view === "overview" && (
            <>
              <div className="task-stat-strip">
                <div>
                  <span>候选路径</span>
                  <strong>{current.path_count}</strong>
                </div>
                <div>
                  <span>待执行</span>
                  <strong>{current.counts_by_status.QUEUED || 0}</strong>
                </div>
                <div>
                  <span>已形成假设</span>
                  <strong>
                    {current.counts_by_status.HYPOTHESIS_FORMED || 0}
                  </strong>
                </div>
                <div>
                  <span>工具调用上限 / 路径</span>
                  <strong>{current.budget.max_tool_calls}</strong>
                </div>
              </div>
              <div className="two-columns">
                <Panel title="挖掘范围">
                  <dl>
                    <dt>代码基线</dt>
                    <dd className="mono">{current.snapshot_id}</dd>
                    <dt>入口或敏感操作目录</dt>
                    <dd>{current.scope?.join("、") || "整个仓库"}</dd>
                    <dt>并发上限</dt>
                    <dd>{current.limits.max_active_leases} 条路径</dd>
                    <dt>分析深度</dt>
                    <dd>{current.budget.max_depth} 跳</dd>
                  </dl>
                </Panel>
                <Panel title="证据与覆盖">
                  <p className="panel-copy">
                    当前图谱已检查 {current.coverage.entry_points_examined}{" "}
                    个入口，解析 {current.coverage.chains_resolved}{" "}
                    条调用链。调用可达性仍需验证才能形成漏洞结论。
                  </p>
                  {current.coverage.truncated && (
                    <Hint>分析触及预算，覆盖范围不完整。</Hint>
                  )}
                  <p className="panel-copy muted">
                    同项目同版本的其他任务发现，会作为带来源和状态的只读知识提供给
                    Agent。
                  </p>
                </Panel>
              </div>
            </>
          )}
          <Panel
            title={
              route.view === "exploration" ? "探索路径" : "待探索的代码路径"
            }
            action={<span className="subtle-label">按调度优先级排序</span>}
          >
            <PathTable paths={paths.data?.paths || []} onSelect={onPath} />
            <Pager
              page={page}
              total={paths.data?.total || 0}
              onChange={setPage}
            />
          </Panel>
          <Hint>
            调度优先级用于安排探索顺序。漏洞严重度由影响评估独立分为高、中、低。
          </Hint>
        </>
      )}
    </>
  );
}

function EventFeed({ api, endpoint }: { api: ApiClient; endpoint: string }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState("");
  const cursor = useRef(0);
  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    cursor.current = 0;
    setEvents([]);
    setError("");
    async function poll() {
      if (pending || document.hidden) return;
      pending = true;
      try {
        const page = await api.get<{
          events: AuditEvent[];
          next_after_seq: number;
        }>(
          `${endpoint}?after_seq=${cursor.current}&limit=100`,
          controller.signal,
        );
        if (!controller.signal.aborted) {
          const incoming = page.events || [];
          cursor.current = Math.max(cursor.current, page.next_after_seq || 0);
          setEvents((old) => {
            const ids = new Set(old.map((e) => e.event_id));
            return [
              ...old,
              ...incoming.filter((e) => !ids.has(e.event_id)),
            ].slice(-500);
          });
          setError("");
        }
      } catch (error) {
        if (!controller.signal.aborted) setError(errorText(error));
      } finally {
        pending = false;
      }
    }
    void poll();
    const timer = setInterval(() => void poll(), 3000);
    return () => {
      clearInterval(timer);
      controller.abort();
    };
  }, [api, endpoint]);
  return (
    <>
      {error && <Failure message={error} />}
      {events.length ? (
        <div className="event-feed">
          {events.map((event) => (
            <details key={event.event_id}>
              <summary>
                <span className="event-marker" />
                <strong>{eventNames[event.type] || event.type}</strong>
                <span>
                  {event.reason ||
                    event.summary ||
                    shortId(event.path_id || event.run_id)}
                </span>
                <time>{dateLabel(event.created_at)}</time>
              </summary>
              <pre>{JSON.stringify(event, null, 2)}</pre>
            </details>
          ))}
        </div>
      ) : (
        <EmptyState title="等待运行事件">
          事件按游标增量读取，自动保留最近 500 条。
        </EmptyState>
      )}
    </>
  );
}

interface Symbol {
  symbol_id: string;
  name: string;
  qualified_name: string;
  kind: string;
  file: string;
  start_line: number;
}
function FindingLibrary({
  api,
  projectID,
  revision,
  onFinding,
}: {
  api: ApiClient;
  projectID: string;
  revision: number;
  onFinding: (id: string) => void;
}) {
  const [grade, setGrade] = useState("");
  const [status, setStatus] = useState("confirmed");
  const [page, setPage] = useState(0);
  const data = useResource(
    (signal) =>
      api.get<FindingPage>(
        `/projects/${projectID}/findings?limit=50&offset=${page * 50}&severity=${grade}&status=${status}`,
        signal,
      ),
    [api, projectID, revision, grade, status, page],
  );
  return (
    <>
      <div className="section-toolbar">
        <div className="filter-group">
          <select
            aria-label="漏洞确认状态"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(0);
            }}
          >
            <option value="confirmed">已确认漏洞</option>
            <option value="">全部结论</option>
            {Object.entries(findingStatus)
              .filter(([key]) => key !== "confirmed")
              .map(([key, value]) => (
                <option key={key} value={key}>
                  {value}
                </option>
              ))}
          </select>
          <select
            aria-label="漏洞严重度"
            value={grade}
            onChange={(e) => {
              setGrade(e.target.value);
              setPage(0);
            }}
          >
            <option value="">全部等级</option>
            {Object.entries(gradeNames).map(([key, value]) => (
              <option key={key} value={key}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <span className="muted">同版本、同路径、同结论的重复发现合并展示</span>
      </div>
      {data.error && <Failure message={data.error} />}
      <Panel title="项目漏洞库">
        {data.loading ? (
          <Loading />
        ) : (
          <FindingTable
            findings={data.data?.findings || []}
            onFinding={onFinding}
          />
        )}
        <Pager page={page} total={data.data?.total || 0} onChange={setPage} />
      </Panel>
      {data.data?.truncated && (
        <Hint>本次汇总达到 10,000 条来源上限，统计为部分结果。</Hint>
      )}
      {!!data.data?.counts.ungraded && (
        <Hint>
          {data.data.counts.ungraded}{" "}
          条已确认发现尚未评估严重度，可在详情中设置高、中、低等级。
        </Hint>
      )}
    </>
  );
}
function TaskFindings({
  api,
  projectID,
  taskID,
  revision,
  onFinding,
}: {
  api: ApiClient;
  projectID: string;
  taskID: string;
  revision: number;
  onFinding: (id: string) => void;
}) {
  const data = useResource(
    (signal) =>
      api.get<FindingPage>(
        `/projects/${projectID}/findings?task_id=${taskID}&limit=1000`,
        signal,
      ),
    [api, projectID, taskID, revision],
  );
  return (
    <Panel title="本任务漏洞发现">
      {data.error && <Failure message={data.error} />}
      {data.loading ? (
        <Loading />
      ) : (
        <FindingTable
          findings={data.data?.findings || []}
          onFinding={onFinding}
        />
      )}
      {(data.data?.total || 0) > 1000 && (
        <Hint>当前展示前 1000 条，请在项目漏洞库筛选并分页查看。</Hint>
      )}
    </Panel>
  );
}
function FindingTable({
  findings,
  onFinding,
}: {
  findings: ProjectFinding[];
  onFinding: (id: string) => void;
}) {
  return findings.length ? (
    <div className="table-scroll">
      <table className="standard-table">
        <thead>
          <tr>
            <th>等级</th>
            <th>漏洞 / 假设</th>
            <th>确认状态</th>
            <th>来源任务</th>
            <th>代码版本</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.finding_id}>
              <td>
                <GradeBadge grade={f.severity} />
              </td>
              <td>
                <button
                  className="table-title"
                  onClick={() => onFinding(f.finding_id)}
                >
                  {f.title}
                </button>
                <p className="cell-subtitle mono">{shortId(f.finding_id)}</p>
              </td>
              <td>
                <Badge status={f.status} />
              </td>
              <td>{new Set(f.sources.map((s) => s.task_id)).size} 个任务</td>
              <td className="mono">{shortId(f.snapshot_id, 6)}</td>
              <td>
                <button
                  className="icon-button"
                  aria-label={`查看漏洞 ${f.title}`}
                  onClick={() => onFinding(f.finding_id)}
                >
                  <ChevronRight size={16} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <EmptyState title="暂无匹配发现">
      候选假设需要验证证据才能确认。任务结束也可能没有发现漏洞。
    </EmptyState>
  );
}

function FindingInspector({
  api,
  id,
  canWrite,
  onChange,
}: {
  api: ApiClient;
  id: string;
  canWrite: boolean;
  onChange: () => void;
}) {
  const [revision, refresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const data = useResource(
    (signal) => api.get<FindingDetail>(`/knowledge/findings/${id}`, signal),
    [api, id, revision],
  );
  const finding = data.data?.finding;
  async function grade(severity: string) {
    if (!severity) return;
    setBusy(true);
    setError("");
    try {
      const read = await api.response(`/knowledge/findings/${id}`);
      const etag = read.headers.get("ETag");
      await read.arrayBuffer();
      if (!etag) throw new Error("发现缺少版本标识");
      await api.response(`/findings/${id}/severity`, {
        method: "PATCH",
        headers: { "If-Match": etag },
        body: JSON.stringify({ severity }),
      });
      refresh((n) => n + 1);
      onChange();
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      {(data.error || error) && <Failure message={error || data.error || ""} />}
      {data.loading && <Loading />}
      {finding && (
        <>
          <div className="detail-title">
            <GradeBadge grade={finding.severity} />
            <Badge status={finding.status} />
            <h2>{finding.title}</h2>
          </div>
          <label className="inline-field">
            漏洞严重度
            <select
              aria-label="设置漏洞严重度"
              disabled={!canWrite || busy}
              value={finding.severity || ""}
              onChange={(e) => void grade(e.target.value)}
            >
              <option value="">待评估</option>
              {Object.entries(gradeNames).map(([key, value]) => (
                <option value={key} key={key}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <dl>
            <dt>来源任务</dt>
            <dd className="mono">{finding.audit_id}</dd>
            <dt>代码版本</dt>
            <dd className="mono">{finding.snapshot_id}</dd>
            <dt>关联路径</dt>
            <dd className="mono">{finding.path_id}</dd>
          </dl>
          <h3>复现步骤</h3>
          <pre className="evidence-content">
            {finding.reproduce_steps || "尚无已保存的复现步骤。"}
          </pre>
          {(["supporting", "contradicting", "inconclusive"] as const).map(
            (kind) => (
              <section key={kind} className="evidence-group">
                <h3>
                  {
                    {
                      supporting: "支持证据",
                      contradicting: "反驳证据",
                      inconclusive: "未决证据",
                    }[kind]
                  }{" "}
                  <span>{data.data?.evidence[kind]?.length || 0}</span>
                </h3>
                {data.data?.evidence[kind]?.map((e) => (
                  <details key={e.evidence_id}>
                    <summary>
                      <FileCode2 size={14} />
                      {e.file || e.tool} {e.line ? `:${e.line}` : ""}
                      <span className="mono">{shortId(e.evidence_id)}</span>
                    </summary>
                    <pre>{e.content}</pre>
                  </details>
                ))}
              </section>
            ),
          )}
          {finding.limitations?.length > 0 && (
            <details className="limitations">
              <summary>结论限制</summary>
              <ul>
                {finding.limitations.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </>
  );
}

function PathInspector({
  api,
  path,
  canWrite,
  onChange,
}: {
  api: ApiClient;
  path: AuditPath;
  canWrite: boolean;
  onChange: () => void;
}) {
  const [active, setActive] = useState(path.steps.find((s) => s.file));
  const [revision, refresh] = useState(0);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const current = useResource(
    (signal) => api.path(path.path_id, signal),
    [api, path.path_id, revision],
  );
  const hypotheses = useResource(
    (signal) =>
      api.get<{
        hypotheses: {
          hypothesis_id: string;
          statement: string;
          severity_hint?: string;
        }[];
      }>(`/paths/${path.path_id}/hypotheses?limit=50`, signal),
    [api, path.path_id, revision],
  );
  const code = useResource(
    (signal) =>
      active?.file
        ? api.post<{ sections: { start_line: number; lines: string[] }[] }>(
            `/snapshots/${path.snapshot_id}/graph/slice`,
            {
              file: active.file,
              start_line: Math.max(1, (active.line || 1) - 5),
              end_line: (active.line || 1) + 12,
              max_lines: 30,
            },
            signal,
          )
        : Promise.resolve({ sections: [] }),
    [api, path.snapshot_id, active],
  );
  const status = current.data?.path.status || path.status;
  const mutate = async (work: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    try {
      await work();
      refresh((n) => n + 1);
      onChange();
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <div className="detail-title">
        <Badge status={status} />
        <span className="mono">{shortId(path.path_id)}</span>
        <h2>
          {path.entry_subject} <ArrowRight size={17} /> {path.target_subject}
        </h2>
      </div>
      {(error || current.error || code.error) && (
        <Failure message={error || current.error || code.error || ""} />
      )}
      <div className="trace-list">
        {path.steps.map((step, i) => (
          <button
            key={i}
            className={active === step ? "active" : ""}
            onClick={() => setActive(step)}
          >
            <span className="trace-index">{i + 1}</span>
            <span>
              <small>
                {step.kind} · {step.layer}
              </small>
              <strong>{step.subject || step.to}</strong>
              <code>
                {step.file
                  ? `${step.file}:${step.line || 1}`
                  : step.evidence || "源位置未解析"}
              </code>
            </span>
            <ChevronRight size={15} />
          </button>
        ))}
      </div>
      {code.loading && <Loading />}
      {code.data?.sections.map((section, i) => (
        <CodeBlock
          key={i}
          file={active?.file || ""}
          lines={(section.lines || []).map((content, n) => ({
            line: section.start_line + n,
            content,
            highlight: section.start_line + n === active?.line,
          }))}
        />
      ))}
      <div className="detail-actions">
        {["QUEUED", "ANALYZING", "LOCAL_EXPLORING"].includes(status) && (
          <button
            className="button secondary"
            disabled={!canWrite || busy}
            onClick={() =>
              void mutate(() => api.changePath(path.path_id, "pause"))
            }
          >
            <Pause size={14} />
            暂停此路径
          </button>
        )}
        {["PAUSED", "BLOCKED", "FAILED", "INTERRUPTED"].includes(status) && (
          <button
            className="button secondary"
            disabled={!canWrite || busy}
            onClick={() =>
              void mutate(() => api.changePath(path.path_id, "resume"))
            }
          >
            <Play size={14} />
            恢复此路径
          </button>
        )}
      </div>
      <h3>结构化假设</h3>
      {hypotheses.error && <Failure message={hypotheses.error} />}
      {hypotheses.data?.hypotheses?.map((h) => (
        <div className="hypothesis" key={h.hypothesis_id}>
          <p>{h.statement}</p>
          <div className="detail-actions">
            <button
              className="button secondary"
              disabled={!canWrite || busy}
              onClick={() =>
                void mutate(() =>
                  api.post(`/hypotheses/${h.hypothesis_id}/finding`, {}),
                )
              }
            >
              登记候选发现
            </button>
            <button
              className="button secondary"
              disabled={!canWrite || busy}
              onClick={() =>
                void mutate(() =>
                  api.post(`/hypotheses/${h.hypothesis_id}/verifications`, {
                    scope: {
                      repository: path.snapshot_id,
                      snapshot_id: path.snapshot_id,
                      allow_network: false,
                    },
                  }),
                )
              }
            >
              请求静态验证
            </button>
          </div>
        </div>
      ))}
      {!hypotheses.data?.hypotheses?.length && (
        <p className="muted">Agent 尚未为此路径形成假设。</p>
      )}
      <Hint>调用关系展示已保存的实际步骤。验证结论以证据记录为准。</Hint>
    </>
  );
}

function Reports({
  api,
  task,
  enabled,
}: {
  api: ApiClient;
  task: Task;
  enabled: boolean;
}) {
  const [format, setFormat] = useState("md");
  const [candidates, setCandidates] = useState(false);
  const [text, setText] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function generate(download = false) {
    setBusy(true);
    setError("");
    try {
      const body = await api.report(task.audit_id, format, candidates);
      setText(body);
      if (download) {
        const url = URL.createObjectURL(
          new Blob([body], {
            type:
              format === "md"
                ? "text/markdown;charset=utf-8"
                : "application/json;charset=utf-8",
          }),
        );
        const a = document.createElement("a");
        a.href = url;
        a.download = `codexploit-${task.audit_id}.${format === "sarif" ? "sarif" : format}`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Panel title="漏洞挖掘报告">
      <div className="report-options">
        <label>
          导出格式
          <select
            value={format}
            onChange={(e) => {
              setFormat(e.target.value);
              setText("");
            }}
          >
            <option value="md">Markdown</option>
            <option value="json">JSON</option>
            <option value="sarif">SARIF</option>
          </select>
        </label>
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={candidates}
            onChange={(e) => {
              setCandidates(e.target.checked);
              setText("");
            }}
          />
          包含待验证候选
        </label>
        <button
          className="button secondary"
          disabled={busy || !enabled}
          onClick={() => void generate()}
        >
          预览报告
        </button>
        <button
          className="button primary"
          disabled={busy || !enabled}
          onClick={() => void generate(true)}
        >
          <ArrowDownToLine size={15} />
          下载报告
        </button>
      </div>
      {!enabled && (
        <Hint>
          当前服务未配置验证层，报告接口不可用。已有发现仍可在项目漏洞库查看。
        </Hint>
      )}
      {error && <Failure message={error} />}
      {text ? (
        <pre className="report-preview">{text}</pre>
      ) : (
        <EmptyState title="将发现整理为可交付报告">
          保留漏洞等级、确认结论、代码基线与证据引用。
        </EmptyState>
      )}
    </Panel>
  );
}

function ProjectSettings({
  project,
  identity,
  snapshots,
}: {
  project: Project;
  identity: Identity;
  snapshots: Snapshot[];
}) {
  return (
    <div className="two-columns">
      <Panel title="项目配置">
        <dl>
          <dt>项目名称</dt>
          <dd>{project.name}</dd>
          <dt>代码仓库</dt>
          <dd className="mono">{project.source}</dd>
          <dt>代码版本</dt>
          <dd>{snapshots.length} 个快照</dd>
          <dt>存储方式</dt>
          <dd>服务端工作区 · SQLite</dd>
          <dt>知识共享</dt>
          <dd>项目内共享，任务固定代码版本</dd>
        </dl>
      </Panel>
      <Panel title="服务能力">
        <div className="capability-list">
          {[
            { id: "agent", label: "Agent 挖掘执行" },
            { id: "verification", label: "漏洞证据验证" },
            { id: "scheduler", label: "常驻任务调度" },
            { id: "network", label: "远程仓库访问" },
          ].map((item) => (
            <div key={item.id}>
              <span>{item.label}</span>
              <span
                className={identity.features[item.id] ? "text-accent" : "muted"}
              >
                {identity.features[item.id] ? "已启用" : "未启用"}
              </span>
            </div>
          ))}
        </div>
        <Hint>
          运行能力通过服务端启动参数配置。当前访问角色：{identity.role}。
        </Hint>
      </Panel>
    </div>
  );
}

function FormFooter({ busy, label }: { busy: boolean; label: string }) {
  return (
    <div className="form-footer">
      <button className="button primary" disabled={busy}>
        {busy ? (
          <Loader2 className="spin" size={16} />
        ) : (
          <ArrowRight size={16} />
        )}
        {busy ? "正在处理…" : label}
      </button>
    </div>
  );
}
function ProjectForm({
  busy,
  network,
  onSubmit,
}: {
  busy: boolean;
  network: boolean;
  onSubmit: (values: {
    name: string;
    source: string;
    ref: string;
    kind: string;
    credentialRef: string;
  }) => void;
}) {
  const [kind, setKind] = useState("local_folder");
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const form = new FormData(e.currentTarget);
        onSubmit({
          name: String(form.get("name")),
          source: String(form.get("source")),
          ref: String(form.get("ref")),
          kind,
          credentialRef: String(form.get("credential_ref") || ""),
        });
      }}
    >
      <label>
        项目名称
        <input
          required
          maxLength={100}
          name="name"
          placeholder="例如：订单服务漏洞挖掘"
        />
      </label>
      <label>
        代码源类型
        <select value={kind} onChange={(event) => setKind(event.target.value)}>
          <option value="local_folder">本地文件夹 · 读取当前文件</option>
          <option value="git_repository">Git 仓库 · 固定提交</option>
          <option value="legacy_auto">既有自动识别入口</option>
        </select>
      </label>
      <label>
        {kind === "local_folder"
          ? "容器内代码目录"
          : kind === "git_repository"
            ? "Git 仓库 URL"
            : "代码仓库"}
        <input
          required
          name="source"
          pattern={
            kind === "local_folder"
              ? "/repos/.+"
              : kind === "git_repository"
                ? "(https|ssh)://.+"
                : undefined
          }
          placeholder={
            kind === "local_folder"
              ? "/repos/service"
              : network
                ? "仓库地址或服务端目录"
                : "服务端可读取的代码目录"
          }
        />
      </label>
      <small>
        Docker 中请使用挂载后的容器路径，例如 /repos/service。
        {network
          ? "已启用远程 Git 仓库访问。"
          : "远程 Git 访问需通过 --allow-network 启用。"}
      </small>
      {kind !== "local_folder" && (
        <label>
          代码版本
          <input
            name="ref"
            defaultValue="HEAD"
            placeholder="分支、标签或 Commit"
          />
        </label>
      )}
      {kind === "git_repository" && (
        <label>
          凭据引用（可选）
          <input
            name="credential_ref"
            maxLength={160}
            placeholder="已在服务端登记的引用 ID"
          />
        </label>
      )}
      <Hint>
        创建项目后，将固定代码快照并构建共享图谱。分析过程只读取源码。
        {kind === "local_folder" &&
          "包含未提交修改；目录内的 .git 不会切换读取方式。"}
      </Hint>
      <FormFooter busy={busy} label="创建项目并建立图谱" />
    </form>
  );
}
function SnapshotForm({
  busy,
  onSubmit,
}: {
  busy: boolean;
  onSubmit: (ref: string) => void;
}) {
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(String(new FormData(e.currentTarget).get("ref")));
      }}
    >
      <p className="muted">已有任务继续使用原代码基线，新任务可选择新版本。</p>
      <label>
        代码版本
        <input name="ref" defaultValue="HEAD" required />
      </label>
      <FormFooter busy={busy} label="建立快照与图谱" />
    </form>
  );
}
function TaskForm({
  api,
  projectID,
  preferredSnapshot,
  canAnalyze,
  snapshots,
  busy,
  onSubmit,
}: {
  api: ApiClient;
  projectID?: string;
  preferredSnapshot?: string;
  canAnalyze: boolean;
  snapshots: Snapshot[];
  busy: boolean;
  onSubmit: (values: unknown) => void;
}) {
  const [sourceFilter, setSourceFilter] = useState("*");
  const [selectedSnapshot, setSelectedSnapshot] = useState(
    preferredSnapshot || latestSnapshot(snapshots)?.snapshot_id,
  );
  const sources = useResource(
    async (signal) => (projectID ? readSources(api, projectID, signal) : []),
    [api, projectID],
  );
  const available = snapshots.filter(
    (snapshot) =>
      sourceFilter === "*" || (snapshot.source_id || "legacy") === sourceFilter,
  );
  const current =
    available.find((snapshot) => snapshot.snapshot_id === selectedSnapshot) ||
    latestSnapshot(available);
  const [planCursors, setPlanCursors] = useState([""]);
  const [selectedPlan, setSelectedPlan] = useState<Plan>();
  const planDirectory = useResource(
    async (signal) =>
      current && projectID
        ? api.get<{ plans: Plan[]; next_cursor: string }>(
            `/v1/projects/${encodeURIComponent(projectID)}/workflow-plans?snapshot_id=${encodeURIComponent(current.snapshot_id)}&limit=50&cursor=${encodeURIComponent(planCursors.at(-1) || "")}`,
            signal,
          )
        : { plans: [], next_cursor: "" },
    [api, projectID, current?.snapshot_id, planCursors.at(-1)],
  );
  useEffect(() => {
    setPlanCursors([""]);
    setSelectedPlan(undefined);
    const id =
      projectID && sessionStorage.getItem(`workflow-plan:${projectID}`);
    if (!id || !current) return;
    const controller = new AbortController();
    api
      .get<{ plan: Plan }>(
        `/v1/projects/${encodeURIComponent(projectID!)}/workflow-plans/${encodeURIComponent(id)}`,
        controller.signal,
      )
      .then((value) => {
        if (value.plan.scope.snapshot_id === current.snapshot_id)
          setSelectedPlan(value.plan);
      })
      .catch(() => {});
    return () => controller.abort();
  }, [api, projectID, current?.snapshot_id]);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const form = new FormData(e.currentTarget);
        onSubmit({
          workflow_plan_id: selectedPlan?.plan_id || "",
          analyze_candidates:
            !!selectedPlan && form.get("workflowAnalyze") === "on",
          accept_partial_nodes:
            selectedPlan && form.get("workflowPartial") === "on"
              ? [...selectedPlan.nodes.map((n) => n.id), "$publish", "$analyze"]
              : [],
          name: form.get("name"),
          objective: form.get("objective"),
          snapshot_id: form.get("snapshot"),
          source_id:
            snapshots.find(
              (snapshot) => snapshot.snapshot_id === form.get("snapshot"),
            )?.source_id || "",
          scope: String(form.get("scope"))
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean),
          budget: {
            max_tool_calls: Number(form.get("tools")),
            max_depth: Number(form.get("depth")),
          },
          limits: {
            max_paths: Number(form.get("paths")),
            max_active_leases: Number(form.get("concurrency")),
          },
        });
      }}
    >
      <label>
        任务名称
        <input
          name="name"
          required
          maxLength={120}
          placeholder="例如：鉴权与越权专项"
        />
      </label>
      <label>
        挖掘目标
        <textarea
          name="objective"
          required
          maxLength={2000}
          placeholder="描述关注的安全问题与需要验证的假设…"
          rows={3}
        />
      </label>
      <label>
        代码源范围
        <select
          value={sourceFilter}
          onChange={(event) => setSourceFilter(event.target.value)}
        >
          <option value="*">全部代码源</option>
          {snapshots.some((snapshot) => !snapshot.source_id) && (
            <option value="legacy">原项目默认代码源</option>
          )}
          {(sources.data || []).map((source) => (
            <option key={source.id} value={source.id}>
              {source.name}
            </option>
          ))}
        </select>
      </label>
      {sources.error && <Failure message={sources.error} />}
      <label>
        共享图谱版本
        <select
          name="snapshot"
          value={current?.snapshot_id || ""}
          onChange={(event) => setSelectedSnapshot(event.target.value)}
          required
        >
          {!available.length && <option value="">所选代码源尚无快照</option>}
          {[...available].reverse().map((s) => (
            <option key={s.snapshot_id} value={s.snapshot_id}>
              {sources.data?.find((source) => source.id === s.source_id)
                ?.name ||
                s.source_id ||
                "原项目代码源"}{" "}
              · {s.commit.slice(0, 12)} · {dateLabel(s.created_at)}
            </option>
          ))}
        </select>
      </label>
      <label>
        执行方式 / 固定计划
        <select
          aria-label="任务工作流计划"
          value={selectedPlan?.plan_id || ""}
          onChange={(e) =>
            setSelectedPlan(
              planDirectory.data?.plans.find(
                (p) => p.plan_id === e.target.value,
              ),
            )
          }
        >
          <option value="">原有路径任务（需先构建图谱）</option>
          {selectedPlan &&
            !planDirectory.data?.plans.some(
              (p) => p.plan_id === selectedPlan.plan_id,
            ) && (
              <option value={selectedPlan.plan_id}>
                {selectedPlan.workflow.spec.name}@
                {selectedPlan.workflow.spec.version} · {selectedPlan.plan_id}
              </option>
            )}
          {planDirectory.data?.plans.map((p) => (
            <option key={p.plan_id} value={p.plan_id}>
              {p.workflow.spec.name}@{p.workflow.spec.version} · {p.plan_id}
            </option>
          ))}
        </select>
      </label>
      {planDirectory.error && <Failure message={planDirectory.error} />}
      <div className="workflow-pagination">
        <button
          type="button"
          className="text-button"
          disabled={planCursors.length === 1}
          onClick={() => setPlanCursors((c) => c.slice(0, -1))}
        >
          上一页计划
        </button>
        <span>第 {planCursors.length} 页</span>
        <button
          type="button"
          className="text-button"
          disabled={!planDirectory.data?.next_cursor}
          onClick={() =>
            setPlanCursors((c) => [...c, planDirectory.data!.next_cursor])
          }
        >
          下一页计划
        </button>
      </div>
      {selectedPlan && (
        <>
          <Hint>
            已固定 {selectedPlan.workflow.spec.id}@
            {selectedPlan.workflow.spec.version} · {selectedPlan.nodes.length}{" "}
            个分析节点。创建后自动执行，复用已校验输入与知识版本。
          </Hint>
          <p className="workflow-task-digest">
            计划 SHA-256 {selectedPlan.digest}
          </p>
          <label className="workflow-task-option">
            <input
              type="checkbox"
              name="workflowAnalyze"
              disabled={!canAnalyze}
            />
            在静态分析和知识发布后调用已配置模型分析候选
          </label>
          {!canAnalyze && (
            <small>
              模型分析不可用，请先在程序的模型设置中配置
              LLM；静态工作流可以独立运行。
            </small>
          )}
          <label className="workflow-task-option">
            <input type="checkbox" name="workflowPartial" />
            明确接受所有已选节点的部分覆盖结果与候选分析预算截断
          </label>
          <small>
            默认遇到部分覆盖即停止下游；接受后保留 PARTIAL 标记和覆盖说明。
          </small>
        </>
      )}
      <label>
        入口 / 敏感操作目录（可选）
        <textarea
          name="scope"
          placeholder="每行一个仓库相对路径，例如 internal/api"
          rows={2}
        />
      </label>
      <small>
        留空选择全仓库；调用链可以跨目录，范围用于选择探索起点和敏感操作。
      </small>
      <div className="form-grid">
        <label>
          候选路径上限
          <input
            type="number"
            name="paths"
            defaultValue={200}
            min={1}
            max={2000}
            required
          />
        </label>
        <label>
          并发路径上限
          <input
            type="number"
            name="concurrency"
            defaultValue={2}
            min={1}
            max={16}
            required
          />
        </label>
        <label>
          每路径工具调用上限
          <input
            type="number"
            name="tools"
            defaultValue={30}
            min={1}
            max={200}
            required
          />
        </label>
        <label>
          调用分析深度
          <input
            type="number"
            name="depth"
            defaultValue={2}
            min={1}
            max={10}
            required
          />
        </label>
      </div>
      <FormFooter busy={busy} label="创建挖掘任务" />
    </form>
  );
}
