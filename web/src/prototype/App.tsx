import {
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  Activity,
  Archive,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  Bell,
  Blocks,
  Box,
  Braces,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Circle,
  Code2,
  Database,
  Eye,
  FileCode2,
  FileJson2,
  FileText,
  Folder,
  FolderGit2,
  GitBranch,
  GitFork,
  HardDrive,
  Info,
  LayoutDashboard,
  ListFilter,
  Loader2,
  Menu,
  Moon,
  Network,
  Pause,
  Pin,
  Play,
  Plug,
  Plus,
  Search,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  Tag,
  TerminalSquare,
  Workflow,
  X,
} from "lucide-react";
import {
  API_VERSION,
  canStart,
  downloadJSON,
  gradeCounts,
  gradeNames,
  initialFindings,
  initialPlugins,
  initialProjects,
  initialSources,
  initialStorage,
  initialTasks,
  initialWorkflow,
  kindNames,
  statusNames,
  validateManifest,
  validateSource,
  validateStorage,
  validateWorkflow,
  workflowOrder,
  type ArtifactKind,
  type Execution,
  type Finding,
  type Page,
  type PluginManifest,
  type Project,
  type Source,
  type StorageProfile,
  type Task,
  type WorkflowSpec,
} from "./model";
import { interfaceCatalog, schemaCatalog } from "./interfaces";
import "./styles.css";

const navigation: {
  label: string;
  items: { id: Page; name: string; icon: typeof Activity }[];
}[] = [
  {
    label: "工作区",
    items: [
      { id: "dashboard", name: "仪表盘", icon: LayoutDashboard },
      { id: "projects", name: "项目", icon: FolderGit2 },
      { id: "tasks", name: "任务", icon: Circle },
      { id: "findings", name: "发现", icon: ShieldCheck },
    ],
  },
  {
    label: "代码与知识",
    items: [
      { id: "sources", name: "代码源", icon: Folder },
      { id: "knowledge", name: "知识图谱", icon: Network },
      { id: "artifacts", name: "产物与证据", icon: FileText },
    ],
  },
  {
    label: "执行与扩展",
    items: [
      { id: "workflows", name: "工作流", icon: Workflow },
      { id: "plugins", name: "插件中心", icon: Plug },
      { id: "executions", name: "工具执行", icon: TerminalSquare },
    ],
  },
  {
    label: "系统",
    items: [
      { id: "models", name: "LLM 配置", icon: Blocks },
      { id: "storage", name: "数据存储", icon: Database },
      { id: "interfaces", name: "接口规范", icon: Braces },
    ],
  },
];
const pages = navigation.flatMap((g) => g.items);
const readPage = (): Page =>
  pages.find((p) => p.id === location.hash.replace(/^#\/?/, "").split("/")[0])
    ?.id || "tasks";
const readTaskID = () => {
  try {
    const [page, id] = location.hash.replace(/^#\/?/, "").split("/");
    return page === "tasks" && id ? decodeURIComponent(id) : undefined;
  } catch {
    return undefined;
  }
};
const findingStates: Record<Finding["status"], string> = {
  candidate: "候选",
  confirmed: "已确认",
  inconclusive: "证据不足",
  refuted: "已排除",
};
const nowLabel = () =>
  new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "Asia/Shanghai",
  }).format(new Date());
function Button({
  children,
  primary,
  small,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  primary?: boolean;
  small?: boolean;
}) {
  return (
    <button
      {...props}
      className={`p-button ${primary ? "p-primary" : ""} ${small ? "p-small" : ""} ${props.className || ""}`}
    >
      {children}
    </button>
  );
}
function IconButton({
  label,
  children,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button
      {...props}
      title={label}
      aria-label={label}
      className={`p-icon-button ${props.className || ""}`}
    >
      {children}
    </button>
  );
}
function Status({ status }: { status: Task["status"] }) {
  return (
    <span className={`p-status p-${status.toLowerCase()}`}>
      <span />
      {statusNames[status]}
    </span>
  );
}
function Grade({ grade }: { grade?: Finding["severity"] }) {
  return (
    <span className={`p-grade p-${grade || "ungraded"}`}>
      {grade ? gradeNames[grade] : "待分级"}
    </span>
  );
}
function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="p-empty">
      <Box size={28} strokeWidth={1.3} />
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
function ErrorList({ errors }: { errors: string[] }) {
  return errors.length ? (
    <div className="p-errors" role="alert">
      {errors.map((e) => (
        <p key={e}>{e}</p>
      ))}
    </div>
  ) : null;
}
function Heading({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="p-heading">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="p-actions">{children}</div>
    </div>
  );
}
function Modal({
  title,
  children,
  close,
  wide,
}: {
  title: string;
  children: ReactNode;
  close: () => void;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null),
    id = useId();
  useEffect(() => {
    ref.current?.showModal();
  }, []);
  return (
    <dialog
      ref={ref}
      className={`p-modal ${wide ? "p-modal-wide" : ""}`}
      aria-labelledby={id}
      onCancel={close}
      onClick={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <header>
        <h2 id={id}>{title}</h2>
        <IconButton label="关闭" onClick={close}>
          <X size={18} />
        </IconButton>
      </header>
      <div className="p-modal-body">{children}</div>
    </dialog>
  );
}

export default function Prototype() {
  const [page, setPage] = useState<Page>(readPage),
    [collapsed, setCollapsed] = useState(false),
    [dark, setDark] = useState(false);
  const [projects, setProjects] = useState<Project[]>(() =>
    structuredClone(initialProjects),
  );
  const [sources, setSources] = useState<Source[]>(() =>
    structuredClone(initialSources),
  );
  const [tasks, setTasks] = useState<Task[]>(() =>
    structuredClone(initialTasks),
  );
  const [findings, setFindings] = useState<Finding[]>(() =>
    structuredClone(initialFindings),
  );
  const [plugins, setPlugins] = useState<PluginManifest[]>(() =>
    structuredClone(initialPlugins),
  );
  const [workflow, setWorkflow] = useState<WorkflowSpec>(() =>
    structuredClone(initialWorkflow),
  );
  const [storage, setStorage] = useState<StorageProfile>(() =>
    structuredClone(initialStorage),
  );
  const [projectID, setProjectID] = useState("all"),
    [detailID, setDetailID] = useState<string>();
  const [notice, setNotice] = useState(""),
    [dialog, setDialog] = useState(""),
    [limit, setLimit] = useState(4),
    [categories, setCategories] = useState([
      "权限边界",
      "输入处理",
      "依赖分析",
    ]);
  const [executions, setExecutions] = useState<Execution[]>([]),
    [globalSearch, setGlobalSearch] = useState("");
  const [findingID, setFindingID] = useState<string>();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [page, detailID]);
  useEffect(() => {
    document.title = "Codexploit · 工作台设计原型";
    const update = () => {
      setPage(readPage());
      setDetailID(readTaskID());
    };
    window.addEventListener("hashchange", update);
    const keydown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setGlobalSearch("");
        setDialog("search");
      }
    };
    window.addEventListener("keydown", keydown);
    update();
    return () => {
      window.removeEventListener("hashchange", update);
      window.removeEventListener("keydown", keydown);
    };
  }, []);
  const navigate = (next: Page) => {
    setPage(next);
    setDetailID(undefined);
    location.hash = next;
  };
  const projectName = (id: string) =>
    projects.find((p) => p.id === id)?.name || id;
  const visibleTasks = tasks.filter(
    (t) => projectID === "all" || t.project_id === projectID,
  );
  const visibleFindings = findings.filter(
    (f) => projectID === "all" || f.project_id === projectID,
  );
  const selectedTask = tasks.find((t) => t.id === detailID);
  const selectedFinding = findings.find((f) => f.id === findingID);
  const changeTask = (id: string, change: Partial<Task>) =>
    setTasks((all) => all.map((t) => (t.id === id ? { ...t, ...change } : t)));
  const toggleRun = (task: Task) => {
    if (task.status === "RUNNING") {
      changeTask(task.id, { status: "PAUSED" });
      setNotice("已暂停演示任务，新节点等待继续。");
    } else if (canStart(task, tasks, limit)) {
      changeTask(task.id, { status: "RUNNING" });
      setNotice("已启动流程演示，可在任务详情中单步推进。");
    } else setNotice("已达到并发上限，请先暂停其他演示任务。");
  };
  const advance = (task: Task) => {
    const errors = validateWorkflow(task.workflow, plugins);
    if (errors.length) {
      setNotice(errors[0]);
      return;
    }
    const order = workflowOrder(task.workflow),
      node = order[task.completed];
    if (!node || task.status !== "RUNNING") return;
    const plugin = plugins.find(
      (p) => p.id === node.plugin_id && p.version === node.plugin_version,
    )!;
    setExecutions((all) => [
      ...all,
      {
        id: `exec-${crypto.randomUUID().slice(0, 8)}`,
        task_id: task.id,
        project_id: task.project_id,
        node_id: node.id,
        plugin: plugin.id,
        plugin_version: plugin.version,
        status: "SUCCEEDED",
        inputs: plugin.consumes,
        outputs: plugin.produces,
        timestamp: nowLabel(),
      },
    ]);
    changeTask(task.id, {
      completed: task.completed + 1,
      status: task.completed + 1 === order.length ? "SUCCEEDED" : "RUNNING",
    });
    setNotice(`${plugin.name} 演示完成，已生成模拟产物记录。`);
  };
  return (
    <div
      id="prototype-root"
      className={`p-root ${collapsed ? "p-collapsed" : ""}`}
      data-theme={dark ? "dark" : "light"}
    >
      <a
        href="#prototype-main"
        className="p-skip"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById("prototype-main")?.focus();
        }}
      >
        跳转到主要内容
      </a>
      <aside className="p-sidebar">
        <a href="/prototype/#tasks" className="p-brand">
          <span>
            <GitFork size={24} strokeWidth={2.5} />
          </span>
          <strong>
            codexploit<small>RESEARCH WORKSPACE</small>
          </strong>
        </a>
        <nav aria-label="主要功能">
          {navigation.map((group) => (
            <div className="p-nav-group" key={group.label}>
              <p>{group.label}</p>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  title={item.name}
                  aria-label={item.name}
                  aria-current={page === item.id ? "page" : undefined}
                  className={page === item.id ? "p-nav-active" : ""}
                  onClick={() => navigate(item.id)}
                >
                  <item.icon size={18} strokeWidth={1.7} />
                  <span>{item.name}</span>
                  {item.id === "tasks" && (
                    <small>
                      {
                        tasks.filter(
                          (t) => t.status === "RUNNING" && !t.archived,
                        ).length
                      }
                    </small>
                  )}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="p-sidebar-bottom">
          <span className="p-avatar">研</span>
          <span>
            设计工作区<small>交互原型 · 内存数据</small>
          </span>
          <a href="/" title="返回正式工作区" aria-label="返回正式工作区">
            <ArrowRight size={17} />
          </a>
        </div>
      </aside>
      <div className="p-main-shell">
        <header className="p-topbar">
          <div>
            <IconButton
              label={collapsed ? "展开导航" : "收起导航"}
              onClick={() => setCollapsed(!collapsed)}
            >
              <Menu size={18} />
            </IconButton>
            <span className="p-topbar-divider" />
            <button
              className="p-global-search"
              onClick={() => {
                setGlobalSearch("");
                setDialog("search");
              }}
            >
              <Search size={16} />
              <span>搜索项目、任务或插件</span>
              <kbd>⌘ K</kbd>
            </button>
          </div>
          <div>
            <select
              aria-label="项目范围"
              value={projectID}
              onChange={(e) => {
                setProjectID(e.target.value);
                setDetailID(undefined);
              }}
            >
              <option value="all">全部项目</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <IconButton label="原型说明" onClick={() => setDialog("about")}>
              <Info size={17} />
            </IconButton>
            <IconButton
              label={dark ? "切换浅色" : "切换深色"}
              onClick={() => setDark(!dark)}
            >
              {dark ? <Sun size={17} /> : <Moon size={17} />}
            </IconButton>
            <span className="p-avatar">研</span>
          </div>
        </header>
        <div className="p-prototype-banner">
          <span>
            <span className="p-demo-dot" />
            设计原型
          </span>
          <p>
            本页面使用示例数据，可体验配置与流程；扫描、模型调用和数据库连接均为模拟。
          </p>
          <a href="/">
            正式工作区
            <ArrowRight size={13} />
          </a>
        </div>
        <main id="prototype-main" tabIndex={-1}>
          {notice && (
            <div className="p-notice" role="status">
              <CheckCircle2 size={16} />
              <span>{notice}</span>
              <IconButton label="关闭提示" onClick={() => setNotice("")}>
                <X size={14} />
              </IconButton>
            </div>
          )}
          {page === "dashboard" && (
            <>
              <Heading
                title="工作区概览"
                description="以项目积累知识，以任务推进漏洞挖掘。"
              />
              <div className="p-metrics">
                {[
                  { name: "项目", value: projects.length, icon: FolderGit2 },
                  {
                    name: "运行中任务",
                    value: tasks.filter(
                      (t) => t.status === "RUNNING" && !t.archived,
                    ).length,
                    icon: Activity,
                  },
                  {
                    name: "候选发现",
                    value: findings.filter((f) => f.status === "candidate")
                      .length,
                    icon: ShieldCheck,
                  },
                  { name: "已注册插件", value: plugins.length, icon: Plug },
                ].map((m) => (
                  <section key={m.name}>
                    <div>
                      <span>{m.name}</span>
                      <m.icon size={18} />
                    </div>
                    <strong>{m.value}</strong>
                  </section>
                ))}
              </div>
              <div className="p-dashboard-grid">
                <section className="p-panel">
                  <PanelTitle
                    title="当前任务"
                    action={
                      <Button small onClick={() => navigate("tasks")}>
                        全部任务
                        <ArrowRight size={14} />
                      </Button>
                    }
                  />
                  <TaskList
                    tasks={visibleTasks.filter((t) => !t.archived)}
                    findings={findings}
                    projectName={projectName}
                    onOpen={setDetailIDAndTasks}
                    onToggle={toggleRun}
                    onChange={changeTask}
                  />
                </section>
                <section className="p-panel">
                  <PanelTitle title="平台能力" />
                  <div className="p-capabilities">
                    {[
                      {
                        icon: Folder,
                        title: "两类代码源",
                        text: "本地文件夹 / Git 项目仓库",
                        page: "sources",
                      },
                      {
                        icon: Network,
                        title: "项目共享知识",
                        text: "语法、语义、路径和证据分层",
                        page: "knowledge",
                      },
                      {
                        icon: Workflow,
                        title: "可组合分析流程",
                        text: "插件按产物类型连接成 DAG",
                        page: "workflows",
                      },
                      {
                        icon: Database,
                        title: "独立持久化服务",
                        text: "PostgreSQL 与产物存储解耦",
                        page: "storage",
                      },
                    ].map((c) => (
                      <button
                        key={c.title}
                        onClick={() => navigate(c.page as Page)}
                      >
                        <c.icon size={20} />
                        <span>
                          <strong>{c.title}</strong>
                          <small>{c.text}</small>
                        </span>
                        <ChevronRight size={15} />
                      </button>
                    ))}
                  </div>
                </section>
              </div>
            </>
          )}
          {page === "projects" && (
            <>
              <Heading
                title="项目"
                description="每个项目拥有独立的代码源、知识空间和挖掘任务。"
              >
                <Button primary onClick={() => setDialog("project")}>
                  <Plus size={16} />
                  新建项目
                </Button>
              </Heading>
              <div className="p-project-list">
                {projects.map((p) => {
                  const projectSources = sources.filter(
                    (s) => s.project_id === p.id,
                  );
                  return (
                    <article key={p.id} className="p-panel">
                      <div className="p-project-top">
                        <span className="p-project-icon">
                          <FolderGit2 size={23} />
                        </span>
                        <div>
                          <button
                            className="p-title-link"
                            onClick={() => {
                              setProjectID(p.id);
                              navigate("tasks");
                            }}
                          >
                            {p.name}
                          </button>
                          <p>{p.description}</p>
                        </div>
                        <span className="p-tag">{p.language}</span>
                      </div>
                      <div className="p-project-stats">
                        <span>
                          <strong>{projectSources.length}</strong> 代码源
                        </span>
                        <span>
                          <strong>
                            {
                              tasks.filter(
                                (t) => t.project_id === p.id && !t.archived,
                              ).length
                            }
                          </strong>{" "}
                          任务
                        </span>
                        <span>
                          <strong>
                            {
                              findings.filter((f) => f.project_id === p.id)
                                .length
                            }
                          </strong>{" "}
                          发现
                        </span>
                      </div>
                      <div className="p-project-bottom">
                        <span>
                          <Network size={14} />
                          项目共享知识空间
                        </span>
                        <Button
                          small
                          onClick={() => {
                            setProjectID(p.id);
                            navigate("knowledge");
                          }}
                        >
                          查看图谱
                          <ArrowRight size={13} />
                        </Button>
                      </div>
                    </article>
                  );
                })}
              </div>
            </>
          )}
          {page === "tasks" &&
            (selectedTask ? (
              <TaskDetail
                task={selectedTask}
                project={projectName(selectedTask.project_id)}
                sources={sources}
                tasks={tasks}
                plugins={plugins}
                findings={findings}
                executions={executions}
                onBack={() => navigate("tasks")}
                onToggle={() => toggleRun(selectedTask)}
                onAdvance={() => advance(selectedTask)}
                onFinding={setFindingID}
              />
            ) : (
              <>
                <Heading
                  title="挖掘任务"
                  description="任务独立执行，代码事实与发现汇入所属项目的知识空间。"
                />
                <TaskPage
                  tasks={visibleTasks}
                  findings={findings}
                  categories={categories}
                  projectName={projectName}
                  onOpen={setDetailIDAndTasks}
                  onToggle={toggleRun}
                  onChange={changeTask}
                  onCreate={() => setDialog("task")}
                  onConcurrency={() => setDialog("concurrency")}
                  onCategories={() => setDialog("categories")}
                />
              </>
            ))}
          {page === "sources" && (
            <>
              <Heading
                title="代码源"
                description="本地文件夹与项目仓库统一为不可变代码快照。"
              >
                <Button primary onClick={() => setDialog("source")}>
                  <Plus size={16} />
                  添加代码源
                </Button>
              </Heading>
              <SourcesPage
                sources={sources.filter(
                  (s) => projectID === "all" || s.project_id === projectID,
                )}
                projectName={projectName}
                onSnapshot={(source) => {
                  const revision = source.revision + 1;
                  setSources((all) =>
                    all.map((s) =>
                      s.id === source.id
                        ? {
                            ...s,
                            revision,
                            snapshot: `snap-${source.id}-r${revision}`,
                          }
                        : s,
                    ),
                  );
                  setNotice("新快照已在原型中生成；已有任务保留原快照版本。");
                }}
                onOpen={(source) => {
                  setProjectID(source.project_id);
                  navigate("knowledge");
                }}
              />
            </>
          )}
          {page === "knowledge" && (
            <>
              <Heading
                title="项目知识图谱"
                description="同一项目共享逻辑知识空间，每条事实保留快照、工具与任务来源。"
              />
              <GraphExplorer
                key={projectID}
                projects={projects}
                sources={sources}
                tasks={tasks}
                initialProject={
                  projectID === "all" ? projects[0]?.id : projectID
                }
              />
            </>
          )}
          {page === "findings" && (
            <>
              <Heading
                title="发现"
                description="漏洞分为高、中、低；确认状态与严重性独立管理。"
              >
                <Button
                  onClick={() =>
                    downloadJSON("findings-demo.json", {
                      api_version: API_VERSION,
                      simulation: true,
                      findings: visibleFindings,
                    })
                  }
                >
                  <ArrowDownToLine size={15} />
                  导出发现
                </Button>
              </Heading>
              <FindingsTable
                findings={visibleFindings}
                projectName={projectName}
                onOpen={setFindingID}
              />
            </>
          )}
          {page === "plugins" && (
            <>
              <Heading
                title="插件中心"
                description="通过统一清单声明能力、输入输出、版本和运行边界。"
              >
                <Button
                  onClick={() =>
                    downloadJSON("plugin-manifest-example.json", {
                      ...initialPlugins[2],
                      id: "team.scanner.custom",
                      name: "自定义扫描器",
                      runtime: {
                        kind: "process",
                        entrypoint: "bin/scanner-adapter",
                      },
                    })
                  }
                >
                  <ArrowDownToLine size={15} />
                  清单示例
                </Button>
                <Button primary onClick={() => setDialog("plugin")}>
                  <Plus size={16} />
                  注册插件
                </Button>
              </Heading>
              <PluginsPage
                plugins={plugins}
                onInspect={(plugin) => {
                  setGlobalSearch(JSON.stringify(plugin, null, 2));
                  setDialog("manifest");
                }}
                onWorkflow={() => navigate("workflows")}
              />
            </>
          )}
          {page === "workflows" && (
            <WorkflowEditor
              plugins={plugins}
              workflow={workflow}
              onSave={(flow) => {
                setWorkflow(flow);
                setNotice("工作流模板已保存到原型，新任务将固定此配置的副本。");
              }}
            />
          )}
          {page === "executions" && (
            <>
              <Heading
                title="工具执行"
                description="每次插件调用记录输入、输出、版本和所属任务。"
              />
              <ExecutionTable
                executions={executions.filter(
                  (e) => projectID === "all" || e.project_id === projectID,
                )}
                onTask={setDetailIDAndTasks}
              />
              <div className="p-inline-note">
                <Info size={15} />
                进入任务详情，点击“推进下一节点”可生成可追溯的演示执行记录。
              </div>
            </>
          )}
          {page === "artifacts" && (
            <>
              <Heading
                title="产物与证据"
                description="原始报告与标准化产物独立保留，通过引用连接到共享图谱。"
              />
              <ArtifactsPage
                sources={sources.filter(
                  (s) => projectID === "all" || s.project_id === projectID,
                )}
                executions={executions.filter(
                  (e) => projectID === "all" || e.project_id === projectID,
                )}
              />
            </>
          )}
          {page === "models" && <ModelsPage onNotice={setNotice} />}
          {page === "storage" && (
            <StoragePage
              storage={storage}
              onSave={(value) => {
                setStorage(value);
                setNotice(
                  "存储方案已保存到原型。正式服务的 SQLite 数据与部署配置保持独立。",
                );
              }}
            />
          )}
          {page === "interfaces" && <InterfacesPage />}
        </main>
        <footer className="p-footer">
          <span>
            CODEXPLOIT <span>·</span> 项目 → 任务 → 发现
          </span>
          <span>接口契约 {API_VERSION} · 设计原型</span>
        </footer>
      </div>
      {dialog === "about" && (
        <Modal title="关于这个原型" close={() => setDialog("")}>
          <div className="p-prose">
            <p>
              这是用于验证功能分区和扩展接口的交互原型。示例内容保留在当前页面内存中，刷新后重置。
            </p>
            <p>
              可体验：项目与代码源管理、任务筛选和暂停、单步工作流、图谱节点查看、发现分级、插件清单导入、DAG
              校验与存储方案导出。
            </p>
            <p>
              本页不执行目标代码、不调用真实模型，也不连接数据库。正式工作区继续使用账号密码登录。
            </p>
            <a className="p-text-link" href="/">
              进入正式工作区
              <ArrowRight size={14} />
            </a>
          </div>
        </Modal>
      )}
      {dialog === "source" && (
        <Modal title="添加代码源" close={() => setDialog("")}>
          <SourceForm
            projects={projects}
            initialProject={projectID}
            onSubmit={(value) => {
              setSources((all) => [
                ...all,
                {
                  ...value,
                  id: `src-${crypto.randomUUID().slice(0, 8)}`,
                  snapshot: "",
                  files: 0,
                  revision: 0,
                },
              ]);
              setDialog("");
              setNotice("代码源已添加到原型，生成快照后即可用于任务。");
            }}
          />
        </Modal>
      )}
      {dialog === "project" && (
        <Modal title="新建项目" close={() => setDialog("")}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const form = new FormData(e.currentTarget);
              const id = `proj-${crypto.randomUUID().slice(0, 8)}`;
              setProjects((all) => [
                ...all,
                {
                  id,
                  name: String(form.get("name")).trim(),
                  description: String(form.get("description")).trim(),
                  language: "待分析",
                  updated: nowLabel(),
                },
              ]);
              setProjectID(id);
              setDialog("");
              navigate("sources");
              setNotice("项目已创建，下一步添加代码源。");
            }}
          >
            <label>
              项目名称
              <input
                name="name"
                required
                maxLength={80}
                placeholder="例如：订单服务"
              />
            </label>
            <label>
              项目说明
              <textarea
                name="description"
                required
                maxLength={300}
                placeholder="描述代码范围和挖掘目标"
              />
            </label>
            <div className="p-form-footer">
              <Button primary>
                <Plus size={15} />
                创建并添加代码源
              </Button>
            </div>
          </form>
        </Modal>
      )}
      {dialog === "task" && (
        <Modal title="新建挖掘任务" close={() => setDialog("")}>
          <TaskForm
            projects={projects}
            sources={sources}
            categories={categories}
            initialProject={projectID}
            workflow={workflow}
            onSubmit={(value) => {
              const task: Task = {
                ...value,
                id: `task-${crypto.randomUUID().slice(0, 8)}`,
                status: "QUEUED",
                completed: 0,
                pinned: false,
                archived: false,
                created: nowLabel(),
                workflow: structuredClone(workflow),
              };
              setTasks((all) => [...all, task]);
              setDialog("");
              navigate("tasks");
              setNotice("演示任务已创建，快照和工作流版本已固定。");
            }}
          />
        </Modal>
      )}
      {dialog === "concurrency" && (
        <Modal title="任务并发设置" close={() => setDialog("")}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const next = Number(new FormData(e.currentTarget).get("limit"));
              if (
                tasks.filter((t) => t.status === "RUNNING" && !t.archived)
                  .length > next
              ) {
                setNotice("请先暂停任务，再降低并发上限。");
                return;
              }
              setLimit(next);
              setDialog("");
              setNotice("并发设置已更新，新启动的演示任务会检查此上限。");
            }}
          >
            <p className="p-muted">
              并发限制用于控制同时运行的任务数量，节点另有独立超时与工具预算。
            </p>
            <label>
              最大并发任务
              <input
                name="limit"
                type="number"
                min={1}
                max={8}
                defaultValue={limit}
                required
              />
            </label>
            <div className="p-form-footer">
              <Button primary>保存设置</Button>
            </div>
          </form>
        </Modal>
      )}
      {dialog === "categories" && (
        <Modal title="任务分类管理" close={() => setDialog("")}>
          <div className="p-category-list">
            {categories.map((name) => (
              <span key={name}>
                <Tag size={14} />
                {name}
              </span>
            ))}
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const name = String(
                new FormData(e.currentTarget).get("category"),
              ).trim();
              if (name && !categories.includes(name))
                setCategories((all) => [...all, name]);
              e.currentTarget.reset();
            }}
          >
            <label>
              新增分类
              <input
                name="category"
                maxLength={30}
                required
                placeholder="例如：数据访问"
              />
            </label>
            <Button>
              <Plus size={14} />
              添加分类
            </Button>
          </form>
        </Modal>
      )}
      {dialog === "plugin" && (
        <Modal title="注册自定义插件" close={() => setDialog("")} wide>
          <PluginImport
            onSubmit={(value) => {
              if (
                plugins.some(
                  (p) => p.id === value.id && p.version === value.version,
                )
              )
                return ["相同 ID 与版本的插件已注册，请修改版本号。"];
              setPlugins((all) => [...all, value]);
              setDialog("");
              setNotice(
                "插件清单已注册到原型，可在工作流中选择；外部程序尚未执行。",
              );
              return [];
            }}
          />
        </Modal>
      )}
      {dialog === "manifest" && (
        <Modal title="插件标准清单" close={() => setDialog("")} wide>
          <pre className="p-json">{globalSearch}</pre>
          <Button
            onClick={() =>
              downloadJSON("plugin-manifest.json", JSON.parse(globalSearch))
            }
          >
            <ArrowDownToLine size={15} />
            导出清单
          </Button>
        </Modal>
      )}
      {dialog === "search" && (
        <Modal
          title="搜索工作区"
          close={() => {
            setDialog("");
            setGlobalSearch("");
          }}
        >
          <label>
            名称、目标或 ID
            <input
              autoFocus
              value={globalSearch}
              onChange={(e) => setGlobalSearch(e.target.value)}
              placeholder="输入关键词"
            />
          </label>
          <div className="p-search-results">
            {[
              ...projects.map((p) => ({
                id: p.id,
                name: p.name,
                type: "项目",
                open: () => {
                  setProjectID(p.id);
                  navigate("tasks");
                },
              })),
              ...tasks.map((t) => ({
                id: t.id,
                name: t.name,
                type: "任务",
                open: () => {
                  setProjectID("all");
                  setDetailIDAndTasks(t.id);
                },
              })),
              ...plugins.map((p) => ({
                id: p.id,
                name: p.name,
                type: "插件",
                open: () => navigate("plugins"),
              })),
            ]
              .filter((r) =>
                `${r.id} ${r.name}`
                  .toLowerCase()
                  .includes(globalSearch.toLowerCase()),
              )
              .map((r) => (
                <button
                  key={r.id}
                  onClick={() => {
                    r.open();
                    setDialog("");
                    setGlobalSearch("");
                  }}
                >
                  <span className="p-tag">{r.type}</span>
                  <strong>{r.name}</strong>
                  <ChevronRight size={15} />
                </button>
              ))}
          </div>
        </Modal>
      )}
      {selectedFinding && (
        <Modal title="发现详情" close={() => setFindingID(undefined)} wide>
          <FindingDetail
            finding={selectedFinding}
            onGrade={(severity) => {
              setFindings((all) =>
                all.map((f) =>
                  f.id === selectedFinding.id ? { ...f, severity } : f,
                ),
              );
              setNotice("发现分级已更新，确认状态与证据保持独立。");
            }}
          />
        </Modal>
      )}
    </div>
  );
  function setDetailIDAndTasks(id: string) {
    setPage("tasks");
    location.hash = `tasks/${encodeURIComponent(id)}`;
    setDetailID(id);
  }
}

function PanelTitle({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <div className="p-panel-title">
      <h2>{title}</h2>
      {action}
    </div>
  );
}
function TaskList({
  tasks,
  findings,
  projectName,
  onOpen,
  onToggle,
  onChange,
}: {
  tasks: Task[];
  findings: Finding[];
  projectName: (id: string) => string;
  onOpen: (id: string) => void;
  onToggle: (task: Task) => void;
  onChange: (id: string, value: Partial<Task>) => void;
}) {
  return (
    <div className="p-table-scroll">
      <table className="p-table p-task-table">
        <thead>
          <tr>
            <th>ID / 项目</th>
            <th>名称与目标</th>
            <th>状态</th>
            <th>目标进度</th>
            <th>
              已确认 <span className="p-muted">高 / 中 / 低</span>
            </th>
            <th>活动节点</th>
            <th>创建时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {tasks.map((task) => {
            const counts = gradeCounts(findings, task.id);
            const candidates = findings.filter(
              (f) => f.task_id === task.id && f.status === "candidate",
            ).length;
            return (
              <tr key={task.id}>
                <td>
                  <code className="p-id">{task.id}</code>
                  <small>{projectName(task.project_id)}</small>
                </td>
                <td>
                  <button
                    className="p-title-link"
                    onClick={() => onOpen(task.id)}
                  >
                    {task.name}
                    {task.pinned && <Pin size={12} fill="currentColor" />}
                  </button>
                  <small className="p-ellipsis" title={task.objective}>
                    {task.objective}
                  </small>
                </td>
                <td>
                  <Status status={task.status} />
                </td>
                <td className="p-tabular">
                  {task.completed}
                  <span className="p-muted">
                    {" "}
                    / {task.workflow.nodes.length}
                  </span>
                </td>
                <td>
                  <div className="p-grade-counts">
                    <span>{counts.high}</span>
                    <span>/</span>
                    <span>{counts.medium}</span>
                    <span>/</span>
                    <span>{counts.low}</span>
                  </div>
                  {candidates > 0 && <small>候选 {candidates}</small>}
                </td>
                <td className="p-tabular">
                  {task.status === "RUNNING" ? 1 : 0}
                </td>
                <td className="p-muted p-nowrap">{task.created}</td>
                <td>
                  <div className="p-row-actions">
                    <IconButton
                      label={`查看 ${task.name}`}
                      onClick={() => onOpen(task.id)}
                    >
                      <Eye size={16} />
                    </IconButton>
                    <IconButton
                      label={
                        task.status === "RUNNING"
                          ? `暂停 ${task.name}`
                          : `继续 ${task.name}`
                      }
                      disabled={task.status === "SUCCEEDED" || task.archived}
                      onClick={() => onToggle(task)}
                    >
                      {task.status === "RUNNING" ? (
                        <Pause size={16} />
                      ) : (
                        <Play size={16} />
                      )}
                    </IconButton>
                    <IconButton
                      label={task.pinned ? "取消置顶" : "置顶任务"}
                      onClick={() =>
                        onChange(task.id, { pinned: !task.pinned })
                      }
                      className={task.pinned ? "p-is-pinned" : ""}
                    >
                      <Pin size={15} />
                    </IconButton>
                    <IconButton
                      label={task.archived ? "恢复任务" : "归档任务"}
                      onClick={() =>
                        onChange(task.id, {
                          archived: !task.archived,
                          status:
                            task.status === "RUNNING" ? "PAUSED" : task.status,
                        })
                      }
                    >
                      <Archive size={16} />
                    </IconButton>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {!tasks.length && (
        <Empty title="没有匹配的任务">
          调整筛选条件，或创建一个新的挖掘任务。
        </Empty>
      )}
    </div>
  );
}
function TaskPage(
  props: Parameters<typeof TaskList>[0] & {
    categories: string[];
    onCreate: () => void;
    onConcurrency: () => void;
    onCategories: () => void;
  },
) {
  const [archived, setArchived] = useState(false),
    [search, setSearch] = useState(""),
    [status, setStatus] = useState("all"),
    [category, setCategory] = useState("all"),
    [page, setPage] = useState(0),
    [size, setSize] = useState(10);
  const filtered = props.tasks
    .filter(
      (t) =>
        t.archived === archived &&
        (status === "all" || t.status === status) &&
        (category === "all" || t.category === category) &&
        `${t.id} ${t.name} ${t.objective}`
          .toLowerCase()
          .includes(search.toLowerCase()),
    )
    .sort((a, b) => Number(b.pinned) - Number(a.pinned));
  const currentPage = Math.min(
    page,
    Math.max(0, Math.ceil(filtered.length / size) - 1),
  );
  return (
    <>
      <div className="p-tabs p-segment-tabs">
        <button
          className={!archived ? "p-tab-active" : ""}
          onClick={() => {
            setArchived(false);
            setPage(0);
          }}
        >
          当前任务
        </button>
        <button
          className={archived ? "p-tab-active" : ""}
          onClick={() => {
            setArchived(true);
            setPage(0);
          }}
        >
          已归档
        </button>
      </div>
      <section className="p-panel p-task-panel">
        <div className="p-table-toolbar">
          <div className="p-filter-group">
            <label className="p-search-input">
              <Search size={16} />
              <input
                aria-label="搜索任务"
                placeholder="搜索名称 / 目标 / ID"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(0);
                }}
              />
            </label>
            <select
              aria-label="任务状态"
              value={status}
              onChange={(e) => {
                setStatus(e.target.value);
                setPage(0);
              }}
            >
              <option value="all">全部状态</option>
              {Object.entries(statusNames).map(([key, value]) => (
                <option key={key} value={key}>
                  {value}
                </option>
              ))}
            </select>
            <select
              aria-label="任务分类"
              value={category}
              onChange={(e) => {
                setCategory(e.target.value);
                setPage(0);
              }}
            >
              <option value="all">全部分类</option>
              {props.categories.map((name) => (
                <option key={name}>{name}</option>
              ))}
            </select>
            <span className="p-count">
              {filtered.length}/
              {props.tasks.filter((t) => t.archived === archived).length} 条
            </span>
          </div>
          <div className="p-actions">
            <Button small onClick={props.onConcurrency}>
              <SlidersHorizontal size={15} />
              并发设置
            </Button>
            <Button small onClick={props.onCategories}>
              <Tag size={15} />
              分类管理
            </Button>
            <Button small primary onClick={props.onCreate}>
              <Plus size={15} />
              新建任务
            </Button>
          </div>
        </div>
        <TaskList
          {...props}
          tasks={filtered.slice(currentPage * size, (currentPage + 1) * size)}
        />
        <div className="p-pagination">
          <select
            aria-label="每页条数"
            value={size}
            onChange={(e) => {
              setSize(Number(e.target.value));
              setPage(0);
            }}
          >
            <option value={10}>10</option>
            <option value={20}>20</option>
            <option value={50}>50</option>
          </select>
          <span>条 / 页</span>
          <span>
            {filtered.length ? currentPage * size + 1 : 0}–
            {Math.min((currentPage + 1) * size, filtered.length)} / 共{" "}
            {filtered.length} 条
          </span>
          <div>
            <IconButton
              label="上一页"
              disabled={!currentPage}
              onClick={() => setPage(currentPage - 1)}
            >
              <ChevronRight className="p-reverse" size={15} />
            </IconButton>
            <IconButton
              label="下一页"
              disabled={(currentPage + 1) * size >= filtered.length}
              onClick={() => setPage(currentPage + 1)}
            >
              <ChevronRight size={15} />
            </IconButton>
          </div>
        </div>
      </section>
    </>
  );
}

function SourceForm({
  projects,
  initialProject,
  onSubmit,
}: {
  projects: Project[];
  initialProject: string;
  onSubmit: (
    value: Omit<Source, "id" | "snapshot" | "files" | "revision">,
  ) => void;
}) {
  const [kind, setKind] = useState<Source["kind"]>("git_repository"),
    [errors, setErrors] = useState<string[]>([]);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const form = new FormData(e.currentTarget);
        const location = String(form.get("location")).trim(),
          ref = kind === "local_folder" ? "" : String(form.get("ref")).trim();
        const errors = validateSource(kind, location, ref);
        setErrors(errors);
        if (!errors.length)
          onSubmit({
            project_id: String(form.get("project")),
            name: String(form.get("name")).trim(),
            kind,
            location,
            ref,
          });
      }}
    >
      <div className="p-source-types">
        <button
          type="button"
          className={kind === "local_folder" ? "p-selected" : ""}
          onClick={() => {
            setKind("local_folder");
            setErrors([]);
          }}
        >
          <Folder size={22} />
          <strong>本地文件夹</strong>
          <small>读取已挂载的源码目录</small>
        </button>
        <button
          type="button"
          className={kind === "git_repository" ? "p-selected" : ""}
          onClick={() => {
            setKind("git_repository");
            setErrors([]);
          }}
        >
          <FolderGit2 size={22} />
          <strong>项目仓库</strong>
          <small>按 Git 分支或提交获取代码</small>
        </button>
      </div>
      <label>
        所属项目
        <select
          required
          name="project"
          defaultValue={
            initialProject === "all" ? projects[0]?.id : initialProject
          }
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        代码源名称
        <input
          required
          name="name"
          maxLength={80}
          placeholder="为代码源设置可辨识的名称"
        />
      </label>
      <label>
        {kind === "local_folder" ? "容器内目录" : "Git 仓库地址"}
        <input
          key={kind}
          required
          name="location"
          placeholder={
            kind === "local_folder"
              ? "/repos/service"
              : "https://forge.example.invalid/team/service.git"
          }
        />
      </label>
      {kind === "git_repository" ? (
        <>
          <label>
            分支 / 标签 / 提交
            <input required name="ref" defaultValue="main" />
          </label>
          <div className="p-inline-note">
            <GitBranch size={15} />
            凭据通过服务端引用管理，不嵌入仓库 URL。
          </div>
        </>
      ) : (
        <div className="p-inline-note">
          <HardDrive size={15} />
          目录需先挂载到容器的 /repos/ 下。文件夹模式按文件内容生成快照。
        </div>
      )}
      <ErrorList errors={errors} />
      <div className="p-form-footer">
        <Button primary>
          <Plus size={15} />
          添加代码源
        </Button>
      </div>
    </form>
  );
}
function SourcesPage({
  sources,
  projectName,
  onSnapshot,
  onOpen,
}: {
  sources: Source[];
  projectName: (id: string) => string;
  onSnapshot: (source: Source) => void;
  onOpen: (source: Source) => void;
}) {
  const [filter, setFilter] = useState("all"),
    [search, setSearch] = useState("");
  const filtered = sources.filter(
    (s) =>
      (filter === "all" || s.kind === filter) &&
      `${s.name} ${s.location}`.toLowerCase().includes(search.toLowerCase()),
  );
  return (
    <section className="p-panel">
      <div className="p-table-toolbar">
        <label className="p-search-input">
          <Search size={15} />
          <input
            aria-label="搜索代码源"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索代码源名称或地址"
          />
        </label>
        <select
          aria-label="代码源类型"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        >
          <option value="all">全部类型</option>
          <option value="local_folder">本地文件夹</option>
          <option value="git_repository">项目仓库</option>
        </select>
      </div>
      <div className="p-table-scroll">
        <table className="p-table">
          <thead>
            <tr>
              <th>代码源</th>
              <th>类型</th>
              <th>位置 / 版本</th>
              <th>所属项目</th>
              <th>最新快照</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => (
              <tr key={s.id}>
                <td>
                  <strong>{s.name}</strong>
                  <small>{s.id}</small>
                </td>
                <td>
                  <span className="p-type-label">
                    {s.kind === "git_repository" ? (
                      <FolderGit2 size={15} />
                    ) : (
                      <Folder size={15} />
                    )}
                    {s.kind === "git_repository" ? "项目仓库" : "本地文件夹"}
                  </span>
                </td>
                <td>
                  <code className="p-source-location">{s.location}</code>
                  <small>
                    {s.ref ? `分支：${s.ref}` : "内容寻址 · 文件夹模式"}
                  </small>
                </td>
                <td>{projectName(s.project_id)}</td>
                <td>
                  {s.snapshot ? (
                    <>
                      <code>{s.snapshot}</code>
                      <small>
                        版本 {s.revision} · {s.files || "待索引"}{" "}
                        {s.files ? "个文件" : ""}
                      </small>
                    </>
                  ) : (
                    <span className="p-muted">尚未生成</span>
                  )}
                </td>
                <td>
                  <div className="p-actions">
                    <Button small onClick={() => onSnapshot(s)}>
                      <GitBranch size={14} />
                      {s.snapshot ? "更新快照" : "生成快照"}
                    </Button>
                    <IconButton
                      label={`查看 ${s.name} 图谱`}
                      disabled={!s.snapshot}
                      onClick={() => onOpen(s)}
                    >
                      <Network size={16} />
                    </IconButton>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!filtered.length && (
        <Empty title="还没有代码源">
          选择本地文件夹或项目仓库，建立第一个代码快照。
        </Empty>
      )}
    </section>
  );
}

function TaskForm({
  projects,
  sources,
  categories,
  initialProject,
  workflow,
  onSubmit,
}: {
  projects: Project[];
  sources: Source[];
  categories: string[];
  initialProject: string;
  workflow: WorkflowSpec;
  onSubmit: (
    value: Pick<
      Task,
      | "project_id"
      | "source_id"
      | "snapshot_id"
      | "name"
      | "objective"
      | "category"
    >,
  ) => void;
}) {
  const [project, setProject] = useState(
    initialProject === "all" ? projects[0]?.id : initialProject,
  );
  const available = sources.filter(
    (s) => s.project_id === project && s.snapshot,
  );
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const form = new FormData(e.currentTarget),
          source = sources.find((s) => s.id === form.get("source"));
        if (!source || source.project_id !== project || !source.snapshot)
          return;
        onSubmit({
          project_id: project,
          source_id: source.id,
          snapshot_id: source.snapshot,
          name: String(form.get("name")).trim(),
          objective: String(form.get("objective")).trim(),
          category: String(form.get("category")),
        });
      }}
    >
      <label>
        所属项目
        <select value={project} onChange={(e) => setProject(e.target.value)}>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        任务名称
        <input
          required
          name="name"
          maxLength={100}
          placeholder="例如：导出接口输入处理"
        />
      </label>
      <label>
        挖掘目标
        <textarea
          required
          name="objective"
          maxLength={1000}
          placeholder="描述要审查的安全边界或代码行为"
        />
      </label>
      <div className="p-form-grid">
        <label>
          代码快照
          <select required name="source" key={project}>
            {available.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} · {s.snapshot}
              </option>
            ))}
          </select>
        </label>
        <label>
          分类
          <select name="category">
            {categories.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </label>
      </div>
      <div className="p-workflow-summary">
        <Workflow size={20} />
        <span>
          <strong>{workflow.name}</strong>
          <small>
            v{workflow.version} · {workflow.nodes.length} 个节点 ·
            创建任务时固定配置
          </small>
        </span>
      </div>
      {!available.length && (
        <div className="p-inline-note">
          此项目没有可用快照，请先在代码源页面生成快照。
        </div>
      )}
      <div className="p-form-footer">
        <Button primary disabled={!available.length}>
          <Plus size={15} />
          创建演示任务
        </Button>
      </div>
    </form>
  );
}

function TaskDetail({
  task,
  project,
  sources,
  tasks,
  plugins,
  findings,
  executions,
  onBack,
  onToggle,
  onAdvance,
  onFinding,
}: {
  task: Task;
  project: string;
  sources: Source[];
  tasks: Task[];
  plugins: PluginManifest[];
  findings: Finding[];
  executions: Execution[];
  onBack: () => void;
  onToggle: () => void;
  onAdvance: () => void;
  onFinding: (id: string) => void;
}) {
  const [tab, setTab] = useState("execution");
  const order = workflowOrder(task.workflow);
  return (
    <>
      <button className="p-back" onClick={onBack}>
        <ArrowLeft size={15} />
        返回任务列表
      </button>
      <Heading title={task.name} description={`${project} / ${task.id}`}>
        <Status status={task.status} />
        <Button disabled={task.status === "SUCCEEDED"} onClick={onToggle}>
          {task.status === "RUNNING" ? <Pause size={15} /> : <Play size={15} />}
          {task.status === "RUNNING" ? "暂停任务" : "继续演示"}
        </Button>
      </Heading>
      <div className="p-task-context">
        <span>
          <FolderGit2 size={15} />
          {project}
        </span>
        <span>
          <GitBranch size={15} />
          <code>{task.snapshot_id}</code>
        </span>
        <span>
          <Workflow size={15} />
          {task.workflow.name} v{task.workflow.version}
        </span>
        <span>
          {task.completed} / {order.length} 节点完成
        </span>
      </div>
      <p className="p-task-objective">{task.objective}</p>
      <div className="p-tabs">
        {[
          { id: "execution", name: "执行过程" },
          { id: "knowledge", name: "探索与图谱" },
          { id: "findings", name: "发现" },
          { id: "report", name: "报告" },
        ].map((t) => (
          <button
            key={t.id}
            className={tab === t.id ? "p-tab-active" : ""}
            onClick={() => setTab(t.id)}
          >
            {t.name}
          </button>
        ))}
      </div>
      {tab === "execution" && (
        <div className="p-task-detail-grid">
          <section className="p-panel">
            <PanelTitle
              title="工作流执行"
              action={
                <Button
                  small
                  primary
                  disabled={task.status !== "RUNNING"}
                  onClick={onAdvance}
                >
                  <Play size={14} />
                  推进下一节点
                </Button>
              }
            />
            <ol className="p-step-list">
              {order.map((node, i) => {
                const plugin = plugins.find(
                  (p) =>
                    p.id === node.plugin_id &&
                    p.version === node.plugin_version,
                );
                return (
                  <li
                    key={node.id}
                    className={
                      i < task.completed
                        ? "p-step-complete"
                        : i === task.completed && task.status === "RUNNING"
                          ? "p-step-current"
                          : ""
                    }
                  >
                    <span className="p-step-marker">
                      {i < task.completed ? <Check size={15} /> : i + 1}
                    </span>
                    <div>
                      <strong>{plugin?.name || node.plugin_id}</strong>
                      <small>
                        <code>{node.id}</code> ·{" "}
                        {plugin?.kind && kindNames[plugin.kind]} · 超时{" "}
                        {node.timeout_seconds}s
                      </small>
                      <div className="p-step-types">
                        {plugin?.produces.map((k) => <code key={k}>{k}</code>)}
                      </div>
                    </div>
                    <span className="p-muted">
                      {i < task.completed
                        ? "已完成"
                        : i === task.completed && task.status === "RUNNING"
                          ? "等待推进"
                          : "待运行"}
                    </span>
                  </li>
                );
              })}
            </ol>
          </section>
          <div>
            <section className="p-panel">
              <PanelTitle title="固定的任务上下文" />
              <dl className="p-definition">
                <dt>项目</dt>
                <dd>{project}</dd>
                <dt>源码版本</dt>
                <dd>
                  <code>{task.snapshot_id}</code>
                </dd>
                <dt>代码源</dt>
                <dd>{sources.find((s) => s.id === task.source_id)?.name}</dd>
                <dt>知识范围</dt>
                <dd>所属项目 / 当前快照</dd>
                <dt>事实来源</dt>
                <dd>插件 ID + 版本 + 节点 + 证据</dd>
              </dl>
            </section>
            <section className="p-panel p-side-note">
              <Info size={17} />
              <p>
                “推进下一节点”只演示节点状态和产物传递。任务之间共享项目知识，执行记录独立保留。
              </p>
            </section>
          </div>
          <section className="p-panel p-full-width">
            <PanelTitle title="本次工具调用" />
            <ExecutionTable
              executions={executions.filter((e) => e.task_id === task.id)}
            />
          </section>
        </div>
      )}
      {tab === "knowledge" && (
        <GraphExplorer
          projects={[
            {
              id: task.project_id,
              name: project,
              description: "",
              language: "",
              updated: "",
            },
          ]}
          sources={sources}
          tasks={tasks}
          initialProject={task.project_id}
          pinnedSnapshot={task.snapshot_id}
        />
      )}
      {tab === "findings" && (
        <FindingsTable
          findings={findings.filter((f) => f.task_id === task.id)}
          projectName={() => project}
          onOpen={onFinding}
        />
      )}
      {tab === "report" && (
        <section className="p-panel">
          <PanelTitle
            title="任务报告"
            action={
              <Button
                small
                onClick={() =>
                  downloadJSON(`${task.id}-report.json`, {
                    api_version: API_VERSION,
                    simulation: true,
                    project_id: task.project_id,
                    task,
                    findings: findings.filter((f) => f.task_id === task.id),
                    executions: executions.filter((e) => e.task_id === task.id),
                  })
                }
              >
                <ArrowDownToLine size={14} />
                导出 JSON
              </Button>
            }
          />
          <div className="p-report">
            <h2>{task.name}</h2>
            <p>{task.objective}</p>
            <dl className="p-definition">
              <dt>范围</dt>
              <dd>
                {project} / {task.snapshot_id}
              </dd>
              <dt>流程</dt>
              <dd>
                {task.workflow.name} v{task.workflow.version}
              </dd>
              <dt>执行进度</dt>
              <dd>
                {task.completed} / {task.workflow.nodes.length} 节点
              </dd>
              <dt>发现</dt>
              <dd>
                {findings.filter((f) => f.task_id === task.id).length}{" "}
                条演示发现，确认状态独立展示
              </dd>
            </dl>
            <h3>分析边界</h3>
            <p>
              报告为原型示例。规则告警、静态路径与已确认漏洞分别记录；缺少传播路径的告警保留代码位置与分析局限。
            </p>
          </div>
        </section>
      )}
    </>
  );
}

function GraphExplorer({
  projects,
  sources,
  tasks,
  initialProject,
  pinnedSnapshot,
}: {
  projects: Project[];
  sources: Source[];
  tasks: Task[];
  initialProject?: string;
  pinnedSnapshot?: string;
}) {
  const [project, setProject] = useState(
      initialProject || projects[0]?.id || "",
    ),
    [layer, setLayer] = useState("paths"),
    [selected, setSelected] = useState(2),
    [query, setQuery] = useState("");
  const available = [
    ...new Set([
      ...sources
        .filter((s) => s.project_id === project && s.snapshot)
        .map((s) => s.snapshot),
      ...tasks
        .filter((t) => t.project_id === project)
        .map((t) => t.snapshot_id),
    ]),
  ];
  const [snapshot, setSnapshot] = useState(
    pinnedSnapshot || available[0] || "",
  );
  const scopeSnapshot =
    pinnedSnapshot || (available.includes(snapshot) ? snapshot : available[0]);
  const linkedTasks = tasks.filter(
    (t) => t.project_id === project && t.snapshot_id === scopeSnapshot,
  );
  const marker = useId().replace(/:/g, "");
  const nodes =
    layer === "syntax"
      ? [
          {
            title: "routes.go",
            kind: "code.file",
            sub: "HTTP 路由注册",
            x: 28,
            y: 130,
          },
          {
            title: "InvoiceHandler",
            kind: "code.symbol",
            sub: "GetInvoice · 第 42 行",
            x: 260,
            y: 46,
          },
          {
            title: "InvoiceStore",
            kind: "code.symbol",
            sub: "FindByID · 第 78 行",
            x: 492,
            y: 130,
          },
          {
            title: "RequestContext",
            kind: "code.symbol",
            sub: "MerchantID · 第 21 行",
            x: 260,
            y: 235,
          },
        ]
      : layer === "semantics"
        ? [
            {
              title: "HTTP 请求输入",
              kind: "security.source",
              sub: "invoice_id",
              x: 28,
              y: 130,
            },
            {
              title: "商户身份边界",
              kind: "security.boundary",
              sub: "context.merchant_id",
              x: 260,
              y: 46,
            },
            {
              title: "账单查询",
              kind: "security.sink",
              sub: "InvoiceStore.FindByID",
              x: 492,
              y: 130,
            },
            {
              title: "归属校验",
              kind: "security.control",
              sub: "覆盖范围未解析",
              x: 260,
              y: 235,
            },
          ]
        : [
            {
              title: "GET /invoices/:id",
              kind: "path.entry",
              sub: "用户可控参数",
              x: 28,
              y: 130,
            },
            {
              title: "参数读取与传递",
              kind: "path.step",
              sub: "静态代码事实",
              x: 260,
              y: 46,
            },
            {
              title: "FindByID(id)",
              kind: "path.target",
              sub: "敏感资源读取",
              x: 492,
              y: 130,
            },
            {
              title: "权限检查待确认",
              kind: "path.question",
              sub: "候选路径 · 证据不足",
              x: 260,
              y: 235,
            },
          ];
  const active = nodes[Math.min(selected, nodes.length - 1)];
  const edges = [
    [0, 1, layer === "syntax" ? "CALLS" : "INPUT_TO"],
    [1, 2, layer === "syntax" ? "CALLS" : "REACHES"],
    [0, 3, layer === "syntax" ? "REFERENCES" : "SCOPED_BY"],
    [3, 2, layer === "syntax" ? "REFERENCES" : "CONTROL_SCOPE_UNKNOWN"],
  ] as const;
  return (
    <>
      <div className="p-graph-toolbar">
        <div>
          <label>
            项目
            <select
              aria-label="图谱项目"
              value={project}
              disabled={!!pinnedSnapshot}
              onChange={(e) => setProject(e.target.value)}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            代码快照
            <select
              aria-label="图谱快照"
              value={scopeSnapshot || ""}
              disabled={!!pinnedSnapshot}
              onChange={(e) => setSnapshot(e.target.value)}
            >
              {available.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
        </div>
        <span>
          <Network size={15} />
          {linkedTasks.length} 个任务共享此版本
        </span>
      </div>
      {!scopeSnapshot ? (
        <Empty title="尚未建立快照">
          先添加代码源并生成快照，图谱按版本保存。
        </Empty>
      ) : (
        <div className="p-graph-layout">
          <section className="p-panel p-graph-panel">
            <div className="p-graph-controls">
              <div className="p-tabs">
                {[
                  { id: "syntax", name: "代码结构" },
                  { id: "semantics", name: "安全语义" },
                  { id: "paths", name: "分析路径" },
                ].map((l) => (
                  <button
                    key={l.id}
                    className={layer === l.id ? "p-tab-active" : ""}
                    onClick={() => {
                      setLayer(l.id);
                      setSelected(0);
                    }}
                  >
                    {l.name}
                  </button>
                ))}
              </div>
              <label className="p-search-input">
                <Search size={14} />
                <input
                  aria-label="定位图谱节点"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="定位节点"
                />
              </label>
            </div>
            <div className="p-graph-canvas">
              <div className="p-graph-view-label">
                {layer === "syntax"
                  ? "SCG"
                  : layer === "semantics"
                    ? "ASG"
                    : "PATH GRAPH"}
                <span>演示结构</span>
              </div>
              <svg
                viewBox="0 0 700 370"
                role="group"
                aria-label="项目知识图谱，选择节点可查看来源与证据"
              >
                <defs>
                  <marker
                    id={marker}
                    markerWidth="8"
                    markerHeight="8"
                    refX="7"
                    refY="4"
                    orient="auto"
                  >
                    <path d="M 0 0 L 8 4 L 0 8 z" fill="currentColor" />
                  </marker>
                </defs>
                {edges.map(([from, to, label], i) => {
                  const a = nodes[from],
                    b = nodes[to];
                  return (
                    <g key={i} className="p-graph-edge">
                      <path
                        d={`M ${a.x + 170} ${a.y + 34} C ${a.x + 220} ${a.y + 34}, ${b.x - 45} ${b.y + 34}, ${b.x} ${b.y + 34}`}
                        markerEnd={`url(#${marker})`}
                      />
                      <text x={(a.x + 170 + b.x) / 2} y={(a.y + b.y) / 2 + 16}>
                        {label}
                      </text>
                    </g>
                  );
                })}
                {nodes.map((node, i) => (
                  <g
                    key={node.title}
                    className={`p-graph-node ${selected === i ? "p-node-selected" : ""} ${query && !`${node.title} ${node.kind}`.toLowerCase().includes(query.toLowerCase()) ? "p-node-dim" : ""}`}
                    transform={`translate(${node.x},${node.y})`}
                    role="button"
                    tabIndex={0}
                    aria-label={`查看节点 ${node.title}`}
                    onClick={() => setSelected(i)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setSelected(i);
                      }
                    }}
                  >
                    <rect width="178" height="78" rx="9" />
                    <circle cx="16" cy="19" r="3" />
                    <text className="p-node-kind" x="27" y="23">
                      {node.kind}
                    </text>
                    <text className="p-node-title" x="14" y="46">
                      {node.title}
                    </text>
                    <text className="p-node-sub" x="14" y="65">
                      {node.sub}
                    </text>
                  </g>
                ))}
              </svg>
              <div className="p-graph-legend">
                <span>
                  <i />
                  观察事实
                </span>
                <span>
                  <i />
                  推断关系
                </span>
                <span>调用可达与可利用性分别记录</span>
              </div>
            </div>
            <div className="p-graph-caption">
              <Info size={14} />
              语法树原始产物独立保存，通用事实索引到图谱。上方节点为界面演示。
            </div>
          </section>
          <aside className="p-panel p-node-inspector">
            <PanelTitle title="节点详情" />
            <div className="p-inspector-body">
              <span className="p-tag">{active.kind}</span>
              <h3>{active.title}</h3>
              <p>{active.sub}</p>
              <dl className="p-definition">
                <dt>快照</dt>
                <dd>
                  <code>{scopeSnapshot}</code>
                </dd>
                <dt>生成插件</dt>
                <dd>
                  <code>
                    {layer === "syntax"
                      ? "core.parser.go"
                      : layer === "semantics"
                        ? "core.security.rules"
                        : "core.normalize.results"}
                  </code>
                </dd>
                <dt>证据等级</dt>
                <dd>{layer === "syntax" ? "observed" : "inferred"}</dd>
                <dt>来源任务</dt>
                <dd>
                  {linkedTasks.map((t) => (
                    <code className="p-block-code" key={t.id}>
                      {t.id}
                    </code>
                  ))}
                </dd>
                <dt>局限</dt>
                <dd>示例路径尚未建立完整数据流证明。</dd>
              </dl>
              <h4>代码位置示例</h4>
              <pre className="p-code-slice">
                <span>40 id := request.Param("id")</span>
                <span>41 merchant := context.MerchantID</span>
                <span className="p-code-line-highlight">
                  42 invoice := store.FindByID(id)
                </span>
                <span>43 return respond(invoice)</span>
              </pre>
              <Button
                small
                onClick={() =>
                  downloadJSON("graph-node-demo.json", {
                    api_version: API_VERSION,
                    simulation: true,
                    project_id: project,
                    snapshot_id: scopeSnapshot,
                    node: active,
                    task_refs: linkedTasks.map((t) => t.id),
                  })
                }
              >
                <ArrowDownToLine size={14} />
                导出节点
              </Button>
            </div>
          </aside>
        </div>
      )}
    </>
  );
}

function FindingsTable({
  findings,
  projectName,
  onOpen,
}: {
  findings: Finding[];
  projectName: (id: string) => string;
  onOpen: (id: string) => void;
}) {
  const [grade, setGrade] = useState("all"),
    [state, setState] = useState("all"),
    [search, setSearch] = useState("");
  const filtered = findings.filter(
    (f) =>
      (grade === "all" || f.severity === grade) &&
      (state === "all" || f.status === state) &&
      `${f.title} ${f.file} ${f.id}`
        .toLowerCase()
        .includes(search.toLowerCase()),
  );
  return (
    <section className="p-panel">
      <div className="p-table-toolbar">
        <label className="p-search-input">
          <Search size={15} />
          <input
            aria-label="搜索发现"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索标题 / 文件 / ID"
          />
        </label>
        <div className="p-filter-group">
          <select
            aria-label="漏洞级别"
            value={grade}
            onChange={(e) => setGrade(e.target.value)}
          >
            <option value="all">全部级别</option>
            {Object.entries(gradeNames).map(([key, name]) => (
              <option key={key} value={key}>
                {name}
              </option>
            ))}
          </select>
          <select
            aria-label="确认状态"
            value={state}
            onChange={(e) => setState(e.target.value)}
          >
            <option value="all">全部确认状态</option>
            {Object.entries(findingStates).map(([key, name]) => (
              <option key={key} value={key}>
                {name}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div className="p-table-scroll">
        <table className="p-table">
          <thead>
            <tr>
              <th>发现 / 代码位置</th>
              <th>级别</th>
              <th>确认状态</th>
              <th>项目 / 任务</th>
              <th>来源插件</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <tr key={f.id}>
                <td>
                  <button className="p-title-link" onClick={() => onOpen(f.id)}>
                    {f.title}
                  </button>
                  <small>
                    <code>
                      {f.file}:{f.line}
                    </code>{" "}
                    · {f.cwe}
                  </small>
                </td>
                <td>
                  <Grade grade={f.severity} />
                </td>
                <td>
                  <span className={`p-verdict p-verdict-${f.status}`}>
                    {findingStates[f.status]}
                  </span>
                </td>
                <td>
                  {projectName(f.project_id)}
                  <small>{f.task_id}</small>
                </td>
                <td>
                  <code>{f.plugin}</code>
                </td>
                <td>
                  <IconButton
                    label={`查看 ${f.title}`}
                    onClick={() => onOpen(f.id)}
                  >
                    <Eye size={16} />
                  </IconButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!filtered.length && (
        <Empty title="没有匹配的发现">
          调整级别或确认状态筛选。无发现不代表不存在漏洞。
        </Empty>
      )}
    </section>
  );
}
function FindingDetail({
  finding,
  onGrade,
}: {
  finding: Finding;
  onGrade: (grade: NonNullable<Finding["severity"]>) => void;
}) {
  return (
    <div className="p-finding-detail">
      <div className="p-finding-detail-heading">
        <h3>{finding.title}</h3>
        <span className={`p-verdict p-verdict-${finding.status}`}>
          {findingStates[finding.status]}
        </span>
      </div>
      <dl className="p-definition">
        <dt>严重性分级</dt>
        <dd>
          <select
            aria-label="修改漏洞分级"
            value={finding.severity || ""}
            onChange={(e) =>
              onGrade(e.target.value as NonNullable<Finding["severity"]>)
            }
          >
            <option value="" disabled>
              待分级
            </option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>
        </dd>
        <dt>代码位置</dt>
        <dd>
          <code>
            {finding.file}:{finding.line}
          </code>
        </dd>
        <dt>代码快照</dt>
        <dd>
          <code>{finding.snapshot_id}</code>
        </dd>
        <dt>来源任务</dt>
        <dd>
          <code>{finding.task_id}</code>
        </dd>
        <dt>来源插件</dt>
        <dd>
          <code>{finding.plugin}@1.0.0</code>
        </dd>
      </dl>
      <h4>分析路径</h4>
      <div className="p-finding-path">
        <code>{finding.source}</code>
        <ArrowRight size={16} />
        <span>参数传递 / 代码关系</span>
        <ArrowRight size={16} />
        <code>{finding.sink}</code>
      </div>
      <h4>证据与局限</h4>
      <p>{finding.evidence}</p>
      <div className="p-inline-note">
        <Info size={15} />
        分级调整仅影响严重性。候选、已确认、证据不足和已排除分别保存。
      </div>
    </div>
  );
}

function PluginsPage({
  plugins,
  onInspect,
  onWorkflow,
}: {
  plugins: PluginManifest[];
  onInspect: (plugin: PluginManifest) => void;
  onWorkflow: () => void;
}) {
  const [kind, setKind] = useState("all"),
    [search, setSearch] = useState("");
  const filtered = plugins.filter(
    (p) =>
      (kind === "all" || p.kind === kind) &&
      `${p.name} ${p.id}`.toLowerCase().includes(search.toLowerCase()),
  );
  return (
    <>
      <div className="p-plugin-summary">
        <span>
          <Plug size={16} />
          <strong>{plugins.length}</strong> 个已注册清单
        </span>
        <span>
          <Braces size={16} />
          统一协议 <code>{API_VERSION}</code>
        </span>
        <span>
          <ShieldCheck size={16} />
          源码只读 · 明确输入输出
        </span>
      </div>
      <section className="p-panel">
        <div className="p-table-toolbar">
          <label className="p-search-input">
            <Search size={15} />
            <input
              aria-label="搜索插件"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="搜索插件名称或 ID"
            />
          </label>
          <select
            aria-label="插件能力"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
          >
            <option value="all">全部能力</option>
            {Object.entries(kindNames).map(([key, name]) => (
              <option key={key} value={key}>
                {name}
              </option>
            ))}
          </select>
        </div>
        <div className="p-plugin-grid">
          {filtered.map((p) => (
            <article key={`${p.id}@${p.version}`}>
              <div className="p-plugin-header">
                <span className="p-plugin-icon">
                  <Plug size={20} />
                </span>
                <span className="p-tag">{kindNames[p.kind]}</span>
                <span className="p-muted">v{p.version}</span>
              </div>
              <h3>{p.name}</h3>
              <code className="p-plugin-id">{p.id}</code>
              <p>{p.description}</p>
              <dl>
                <dt>输入</dt>
                <dd>
                  {p.consumes.map((k) => (
                    <code key={k}>{k}</code>
                  ))}
                </dd>
                <dt>输出</dt>
                <dd>
                  {p.produces.map((k) => (
                    <code key={k}>{k}</code>
                  ))}
                </dd>
              </dl>
              <div className="p-plugin-footer">
                <span>
                  {p.runtime.kind === "builtin"
                    ? "内置契约示例"
                    : `${p.runtime.kind} · 待接执行器`}
                </span>
                <div>
                  <IconButton
                    label={`查看 ${p.name} 清单`}
                    onClick={() => onInspect(p)}
                  >
                    <FileJson2 size={16} />
                  </IconButton>
                  <IconButton
                    label={`在工作流中使用 ${p.name}`}
                    onClick={onWorkflow}
                  >
                    <ArrowRight size={16} />
                  </IconButton>
                </div>
              </div>
            </article>
          ))}
        </div>
        {!filtered.length && (
          <Empty title="没有匹配的插件">
            调整能力筛选，或导入自定义插件清单。
          </Empty>
        )}
      </section>
    </>
  );
}
function PluginImport({
  onSubmit,
}: {
  onSubmit: (value: PluginManifest) => string[];
}) {
  const [text, setText] = useState(
      JSON.stringify(
        {
          ...initialPlugins[2],
          id: "team.scanner.custom",
          name: "自定义扫描器",
          runtime: { kind: "process", entrypoint: "bin/scanner-adapter" },
        },
        null,
        2,
      ),
    ),
    [errors, setErrors] = useState<string[]>([]);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        try {
          const value: unknown = JSON.parse(text);
          const errors = validateManifest(value);
          setErrors(errors.length ? errors : onSubmit(value as PluginManifest));
        } catch {
          setErrors(["清单不是有效的 JSON，请检查格式。"]);
        }
      }}
    >
      <p className="p-muted">
        注册步骤验证清单和能力声明。原型不会下载或执行外部程序。
      </p>
      <label>
        插件清单 JSON
        <textarea
          className="p-json-editor"
          required
          spellCheck={false}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </label>
      <ErrorList errors={errors} />
      <div className="p-form-footer">
        <Button primary>
          <Check size={15} />
          校验并注册清单
        </Button>
      </div>
    </form>
  );
}

function WorkflowEditor({
  plugins,
  workflow,
  onSave,
}: {
  plugins: PluginManifest[];
  workflow: WorkflowSpec;
  onSave: (flow: WorkflowSpec) => void;
}) {
  const [draft, setDraft] = useState<WorkflowSpec>(() =>
      structuredClone(workflow),
    ),
    [tab, setTab] = useState("visual"),
    [selected, setSelected] = useState("normalize"),
    [text, setText] = useState(JSON.stringify(workflow, null, 2)),
    [errors, setErrors] = useState<string[]>([]),
    [saved, setSaved] = useState(false);
  const node = draft.nodes.find((n) => n.id === selected),
    plugin = plugins.find(
      (p) => p.id === node?.plugin_id && p.version === node?.plugin_version,
    );
  const update = (value: WorkflowSpec) => {
    setDraft(value);
    setText(JSON.stringify(value, null, 2));
    setSaved(false);
    setErrors([]);
  };
  const save = () => {
    let value: unknown = draft;
    if (tab === "json") {
      try {
        value = JSON.parse(text);
      } catch {
        setErrors(["工作流 JSON 格式无效。"]);
        return;
      }
    }
    const errors = validateWorkflow(value, plugins);
    setErrors(errors);
    if (!errors.length) {
      const valid = value as WorkflowSpec;
      setDraft(valid);
      setText(JSON.stringify(valid, null, 2));
      onSave(structuredClone(valid));
      setSaved(true);
    }
  };
  const stages = (function () {
    const result: Record<string, number> = {};
    const order = workflowOrder(draft);
    for (const n of order)
      result[n.id] = n.needs.length
        ? Math.max(...n.needs.map((id) => result[id] || 0)) + 1
        : 0;
    return result;
  })();
  const maxStage = Math.max(0, ...Object.values(stages));
  return (
    <>
      <Heading
        title="工作流"
        description="按输入输出组合分析工具，任务创建时固定插件版本与节点配置。"
      >
        <Button onClick={() => downloadJSON("workflow.json", draft)}>
          <ArrowDownToLine size={15} />
          导出流程
        </Button>
        <Button primary onClick={save}>
          <Check size={15} />
          保存工作流
        </Button>
      </Heading>
      <div className="p-workflow-meta">
        <label>
          模板名称
          <input
            value={draft.name}
            maxLength={100}
            onChange={(e) => update({ ...draft, name: e.target.value })}
          />
        </label>
        <label>
          版本
          <input
            value={draft.version}
            onChange={(e) => update({ ...draft, version: e.target.value })}
          />
        </label>
        <span>
          <Workflow size={16} />
          {draft.nodes.length} 个节点
        </span>
        <div className="p-tabs p-segment-tabs">
          <button
            className={tab === "visual" ? "p-tab-active" : ""}
            onClick={() => setTab("visual")}
          >
            可视化
          </button>
          <button
            className={tab === "json" ? "p-tab-active" : ""}
            onClick={() => {
              setText(JSON.stringify(draft, null, 2));
              setTab("json");
            }}
          >
            JSON 配置
          </button>
        </div>
      </div>
      <ErrorList errors={errors} />
      {saved && (
        <div className="p-inline-note p-success">
          <CheckCircle2 size={15} />
          工作流已通过引用、依赖环路和产物类型校验。
        </div>
      )}
      {tab === "json" ? (
        <section className="p-panel p-json-panel">
          <label>
            工作流标准定义
            <textarea
              className="p-json-editor p-workflow-json"
              value={text}
              onChange={(e) => {
                setText(e.target.value);
                setSaved(false);
              }}
              spellCheck={false}
            />
          </label>
        </section>
      ) : (
        <div className="p-workflow-layout">
          <section className="p-panel p-workflow-canvas">
            <div className="p-workflow-canvas-heading">
              <span>
                <span className="p-demo-dot" />
                DAG 编排
              </span>
              <small>从左到右执行 · 同列节点可并行</small>
            </div>
            <div className="p-workflow-stages">
              {Array.from({ length: maxStage + 1 }, (_, stage) => (
                <div className="p-workflow-stage" key={stage}>
                  <small>阶段 {stage + 1}</small>
                  {draft.nodes
                    .filter((n) => (stages[n.id] ?? 0) === stage)
                    .map((n) => {
                      const p = plugins.find(
                        (p) =>
                          p.id === n.plugin_id &&
                          p.version === n.plugin_version,
                      );
                      return (
                        <button
                          key={n.id}
                          className={`p-flow-node ${selected === n.id ? "p-flow-selected" : ""}`}
                          onClick={() => setSelected(n.id)}
                        >
                          <span>
                            <Plug size={15} />
                            {p ? kindNames[p.kind] : "未知插件"}
                            <ChevronRight size={14} />
                          </span>
                          <strong>{p?.name || n.plugin_id}</strong>
                          <code>{n.id}</code>
                          <small>
                            {n.needs.length
                              ? `依赖 ${n.needs.join(" · ")}`
                              : "输入：source.snapshot"}
                          </small>
                          <div>
                            {p?.produces.map((k) => <code key={k}>{k}</code>)}
                          </div>
                        </button>
                      );
                    })}
                </div>
              ))}
            </div>
            <div className="p-workflow-add">
              <select
                aria-label="选择新增节点的插件"
                value=""
                onChange={(e) => {
                  const plugin = plugins.find(
                    (p) => `${p.id}@${p.version}` === e.target.value,
                  );
                  if (!plugin) return;
                  const id = `node_${draft.nodes.length + 1}_${crypto.randomUUID().slice(0, 4)}`;
                  update({
                    ...draft,
                    nodes: [
                      ...draft.nodes,
                      {
                        id,
                        plugin_id: plugin.id,
                        plugin_version: plugin.version,
                        needs: [],
                        config: {},
                        timeout_seconds: 120,
                      },
                    ],
                  });
                  setSelected(id);
                }}
              >
                <option value="">＋ 添加插件节点</option>
                {plugins.map((p) => (
                  <option
                    key={`${p.id}@${p.version}`}
                    value={`${p.id}@${p.version}`}
                  >
                    {p.name} · {p.version}
                  </option>
                ))}
              </select>
              <small>配置右侧依赖后，保存时检查输入类型与循环。</small>
            </div>
          </section>
          <aside className="p-panel p-workflow-inspector">
            <PanelTitle title="节点配置" />
            {node && plugin ? (
              <div className="p-inspector-body">
                <span className="p-tag">{kindNames[plugin.kind]}</span>
                <h3>{plugin.name}</h3>
                <code>
                  {plugin.id}@{plugin.version}
                </code>
                <label>
                  节点 ID
                  <input value={node.id} disabled />
                </label>
                <label>
                  超时（秒）
                  <input
                    type="number"
                    min={5}
                    max={600}
                    value={node.timeout_seconds}
                    onChange={(e) =>
                      update({
                        ...draft,
                        nodes: draft.nodes.map((n) =>
                          n.id === node.id
                            ? { ...n, timeout_seconds: Number(e.target.value) }
                            : n,
                        ),
                      })
                    }
                  />
                </label>
                <fieldset>
                  <legend>上游依赖</legend>
                  {draft.nodes
                    .filter((n) => n.id !== node.id)
                    .map((n) => (
                      <label className="p-check-label" key={n.id}>
                        <input
                          type="checkbox"
                          checked={node.needs.includes(n.id)}
                          onChange={(e) =>
                            update({
                              ...draft,
                              nodes: draft.nodes.map((item) =>
                                item.id === node.id
                                  ? {
                                      ...item,
                                      needs: e.target.checked
                                        ? [...item.needs, n.id]
                                        : item.needs.filter(
                                            (id) => id !== n.id,
                                          ),
                                    }
                                  : item,
                              ),
                            })
                          }
                        />
                        {n.id}
                      </label>
                    ))}
                </fieldset>
                <div className="p-port-list">
                  <h4>需要的输入</h4>
                  {plugin.consumes.map((k) => (
                    <code key={k}>{k}</code>
                  ))}
                  <h4>产生的输出</h4>
                  {plugin.produces.map((k) => (
                    <code key={k}>{k}</code>
                  ))}
                </div>
                <Button
                  small
                  className="p-danger"
                  onClick={() => {
                    update({
                      ...draft,
                      nodes: draft.nodes
                        .filter((n) => n.id !== node.id)
                        .map((n) => ({
                          ...n,
                          needs: n.needs.filter((id) => id !== node.id),
                        })),
                    });
                    setSelected(
                      draft.nodes.find((n) => n.id !== node.id)?.id || "",
                    );
                  }}
                >
                  <X size={14} />
                  移除节点
                </Button>
              </div>
            ) : (
              <Empty title="选择一个节点">查看能力、输入输出和依赖配置。</Empty>
            )}
          </aside>
        </div>
      )}
      <div className="p-inline-note">
        <Info size={15} />
        工具只读快照并输出产物；归一化和发布步骤负责写入项目知识图谱。工作流中保存凭据引用。
      </div>
    </>
  );
}

function ExecutionTable({
  executions,
  onTask,
}: {
  executions: Execution[];
  onTask?: (id: string) => void;
}) {
  return (
    <section className="p-panel">
      <div className="p-table-scroll">
        <table className="p-table">
          <thead>
            <tr>
              <th>调用 / 节点</th>
              <th>所属任务</th>
              <th>插件版本</th>
              <th>输入 → 输出</th>
              <th>结果</th>
              <th>时间</th>
            </tr>
          </thead>
          <tbody>
            {executions.map((e) => (
              <tr key={e.id}>
                <td>
                  <code>{e.id}</code>
                  <small>{e.node_id}</small>
                </td>
                <td>
                  {onTask ? (
                    <button
                      className="p-title-link"
                      onClick={() => onTask(e.task_id)}
                    >
                      {e.task_id}
                    </button>
                  ) : (
                    <code>{e.task_id}</code>
                  )}
                </td>
                <td>
                  <code>
                    {e.plugin}@{e.plugin_version}
                  </code>
                </td>
                <td>
                  <small>{e.inputs.join(" / ")}</small>
                  <strong className="p-artifact-output">
                    {e.outputs.join(" / ")}
                  </strong>
                </td>
                <td>
                  <span className="p-status p-succeeded">
                    <span />
                    演示完成
                  </span>
                </td>
                <td className="p-nowrap">{e.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!executions.length && (
        <Empty title="尚无演示执行记录">
          在任务详情中单步推进工作流，查看节点间的产物流转。
        </Empty>
      )}
    </section>
  );
}
function ArtifactsPage({
  sources,
  executions,
}: {
  sources: Source[];
  executions: Execution[];
}) {
  const artifacts = [
    ...sources
      .filter((s) => s.snapshot)
      .map((s) => ({
        id: `artifact-${s.snapshot}`,
        kind: "source.snapshot",
        owner: s.name,
        snapshot: s.snapshot,
        producer: "core.source",
        data: {
          api_version: API_VERSION,
          simulation: true,
          source_id: s.id,
          snapshot_id: s.snapshot,
          kind: s.kind,
          revision: s.revision,
        },
      })),
    ...executions.flatMap((e) =>
      e.outputs.map((kind) => ({
        id: `${e.id}-${kind}`,
        kind,
        owner: e.task_id,
        snapshot: "由任务上下文固定",
        producer: e.plugin,
        data: {
          api_version: API_VERSION,
          simulation: true,
          execution_id: e.id,
          task_id: e.task_id,
          producer: e.plugin,
          producer_version: e.plugin_version,
          kind,
        },
      })),
    ),
  ];
  return (
    <section className="p-panel">
      <PanelTitle
        title="标准产物目录"
        action={<span className="p-count">{artifacts.length} 项</span>}
      />
      <div className="p-table-scroll">
        <table className="p-table">
          <thead>
            <tr>
              <th>产物类型 / ID</th>
              <th>项目代码源 / 任务</th>
              <th>版本范围</th>
              <th>生成者</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {artifacts.map((a) => (
              <tr key={a.id}>
                <td>
                  <span className="p-type-label">
                    <FileJson2 size={16} />
                    <strong>{a.kind}</strong>
                  </span>
                  <small>{a.id}</small>
                </td>
                <td>{a.owner}</td>
                <td>
                  <code>{a.snapshot}</code>
                </td>
                <td>
                  <code>{a.producer}</code>
                </td>
                <td>
                  <Button
                    small
                    onClick={() => downloadJSON(`${a.id}.json`, a.data)}
                  >
                    <ArrowDownToLine size={14} />
                    导出演示产物
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ModelsPage({ onNotice }: { onNotice: (notice: string) => void }) {
  return (
    <>
      <Heading
        title="LLM 配置"
        description="模型连接由程序管理，任务使用固定的配置版本与工具预算。"
      />
      <div className="p-settings-grid">
        <section className="p-panel">
          <PanelTitle title="模型服务配置示意" />
          <form
            className="p-settings-form"
            onSubmit={(e) => {
              e.preventDefault();
              const data = new FormData(e.currentTarget);
              onNotice(
                `原型已记录模型选择：${data.get("model")}。真实连接与密钥在正式工作区配置。`,
              );
            }}
          >
            <label>
              接口协议
              <select name="protocol">
                <option>OpenAI 兼容 · Chat Completions</option>
                <option>OpenAI · Responses</option>
              </select>
            </label>
            <label>
              API 根地址
              <input
                required
                type="url"
                name="endpoint"
                defaultValue="https://api.example.invalid/v1"
              />
            </label>
            <label>
              模型名称
              <input required name="model" defaultValue="research-model" />
            </label>
            <label>
              凭据引用
              <input value="secret-llm-main" readOnly />
            </label>
            <div className="p-inline-note">
              <Info size={15} />
              此处展示配置结构。正式工作区提供 API Key
              输入、加密保存与真实连接测试。
            </div>
            <div className="p-form-footer">
              <Button primary>保存原型配置</Button>
            </div>
          </form>
        </section>
        <section className="p-panel">
          <PanelTitle title="执行边界" />
          <div className="p-prose">
            <p>
              Agent 通过统一工具层读取代码与项目知识，输出结构化假设与证据引用。
            </p>
            <ul>
              <li>工具白名单、超时和预算由调度器控制。</li>
              <li>模型配置不进入工作流导出文件。</li>
              <li>候选结论不能自动成为已确认漏洞。</li>
              <li>密钥配置属于系统级权限。</li>
            </ul>
            <a href="/#/settings" className="p-text-link">
              在正式工作区配置模型
              <ArrowRight size={14} />
            </a>
          </div>
        </section>
      </div>
    </>
  );
}
function StoragePage({
  storage,
  onSave,
}: {
  storage: StorageProfile;
  onSave: (value: StorageProfile) => void;
}) {
  const [draft, setDraft] = useState<StorageProfile>(() =>
      structuredClone(storage),
    ),
    [errors, setErrors] = useState<string[]>([]),
    [checked, setChecked] = useState(false);
  const update = (value: StorageProfile) => {
    setDraft(value);
    setChecked(false);
    setErrors([]);
  };
  return (
    <>
      <Heading
        title="数据存储"
        description="业务通过持久化接口访问独立数据服务，应用镜像与用户数据分别升级。"
      >
        <Button onClick={() => downloadJSON("storage-profile.json", draft)}>
          <ArrowDownToLine size={15} />
          导出存储方案
        </Button>
      </Heading>
      <div className="p-storage-topology">
        <section>
          <Blocks size={25} />
          <strong>codexploit</strong>
          <small>应用容器 · WebUI / API / 编排</small>
        </section>
        <ArrowRight size={20} />
        <section>
          <Database size={25} />
          <strong>
            {draft.metadata.driver === "postgresql"
              ? "PostgreSQL"
              : draft.metadata.driver === "sqlite"
                ? "SQLite"
                : "自定义适配器"}
          </strong>
          <small>
            {draft.metadata.driver === "sqlite"
              ? "本地开发与轻量部署"
              : "独立数据库容器 · 元数据与图谱索引"}
          </small>
        </section>
        <span className="p-topology-plus">＋</span>
        <section>
          <HardDrive size={25} />
          <strong>
            {draft.artifacts.driver === "volume"
              ? "产物存储服务"
              : "S3 兼容对象存储"}
          </strong>
          <small>快照 / 原生 AST / 报告 / 证据</small>
        </section>
      </div>
      <div className="p-settings-grid">
        <section className="p-panel">
          <PanelTitle title="元数据存储适配器" />
          <form
            className="p-settings-form"
            onSubmit={(e) => {
              e.preventDefault();
              const errors = validateStorage(draft);
              setErrors(errors);
              if (!errors.length) {
                onSave(structuredClone(draft));
                setChecked(true);
              }
            }}
          >
            <label>
              数据库类型
              <select
                value={draft.metadata.driver}
                onChange={(e) =>
                  update({
                    ...draft,
                    metadata: {
                      ...draft.metadata,
                      driver: e.target
                        .value as StorageProfile["metadata"]["driver"],
                    },
                  })
                }
              >
                <option value="postgresql">PostgreSQL · 独立容器</option>
                <option value="sqlite">SQLite · 本地开发</option>
                <option value="custom">其他数据库 · 自定义适配器</option>
              </select>
            </label>
            {draft.metadata.driver !== "sqlite" && (
              <>
                <div className="p-form-grid">
                  <label>
                    服务名 / 主机
                    <input
                      required
                      value={draft.metadata.host}
                      onChange={(e) =>
                        update({
                          ...draft,
                          metadata: { ...draft.metadata, host: e.target.value },
                        })
                      }
                    />
                  </label>
                  <label>
                    端口
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      required
                      value={draft.metadata.port}
                      onChange={(e) =>
                        update({
                          ...draft,
                          metadata: {
                            ...draft.metadata,
                            port: Number(e.target.value),
                          },
                        })
                      }
                    />
                  </label>
                </div>
                <label>
                  数据库
                  <input
                    required
                    value={draft.metadata.database}
                    onChange={(e) =>
                      update({
                        ...draft,
                        metadata: {
                          ...draft.metadata,
                          database: e.target.value,
                        },
                      })
                    }
                  />
                </label>
                <label>
                  凭据引用
                  <input
                    required
                    value={draft.metadata.credential_ref}
                    onChange={(e) =>
                      update({
                        ...draft,
                        metadata: {
                          ...draft.metadata,
                          credential_ref: e.target.value,
                        },
                      })
                    }
                  />
                </label>
              </>
            )}
            <ErrorList errors={errors} />
            {checked && (
              <div className="p-inline-note p-success">
                <Check size={15} />
                结构校验通过。原型未建立真实数据库连接。
              </div>
            )}
            <div className="p-form-footer">
              <Button
                type="button"
                onClick={() => {
                  const errors = validateStorage(draft);
                  setErrors(errors);
                  setChecked(!errors.length);
                }}
              >
                <Check size={15} />
                校验配置
              </Button>
              <Button primary>保存方案</Button>
            </div>
          </form>
        </section>
        <div>
          <section className="p-panel">
            <PanelTitle title="源码与分析产物" />
            <div className="p-settings-form">
              <label>
                产物后端
                <select
                  value={draft.artifacts.driver}
                  onChange={(e) =>
                    update({
                      ...draft,
                      artifacts: {
                        ...draft.artifacts,
                        driver: e.target.value as "volume" | "s3",
                        endpoint:
                          e.target.value === "s3"
                            ? "http://object-store:9000"
                            : "artifact-service",
                      },
                    })
                  }
                >
                  <option value="volume">独立文件服务与数据卷</option>
                  <option value="s3">S3 兼容对象存储</option>
                </select>
              </label>
              <label>
                {draft.artifacts.driver === "volume"
                  ? "产物服务名"
                  : "服务地址"}
                <input
                  value={draft.artifacts.endpoint}
                  onChange={(e) =>
                    update({
                      ...draft,
                      artifacts: {
                        ...draft.artifacts,
                        endpoint: e.target.value,
                      },
                    })
                  }
                />
              </label>
              {draft.artifacts.driver === "s3" && (
                <label>
                  桶名称
                  <input
                    value={draft.artifacts.bucket}
                    onChange={(e) =>
                      update({
                        ...draft,
                        artifacts: {
                          ...draft.artifacts,
                          bucket: e.target.value,
                        },
                      })
                    }
                  />
                </label>
              )}
              <div className="p-inline-note">
                <HardDrive size={15} />
                数据库保存索引、摘要和引用；源码及大型产物由产物接口读取。
              </div>
            </div>
          </section>
          <section className="p-panel p-storage-responsibilities">
            <PanelTitle title="数据归属" />
            {[
              {
                name: "PostgreSQL",
                text: "项目、任务、工作流、节点与边、发现、执行事件、产物索引",
              },
              {
                name: "产物后端",
                text: "不可变源码快照、原始 AST、扫描报告、证据内容",
              },
              {
                name: "密钥服务",
                text: "数据库与 LLM 凭据；配置文件中只传递引用",
              },
            ].map((item) => (
              <div key={item.name}>
                <strong>{item.name}</strong>
                <p>{item.text}</p>
              </div>
            ))}
          </section>
        </div>
      </div>
      <div className="p-inline-note">
        <Info size={15} />
        这是目标部署方案。当前正式服务仍使用 SQLite；PostgreSQL
        驱动接线、迁移与兼容性验收见分层接口文档。
      </div>
    </>
  );
}

function InterfacesPage() {
  const [selected, setSelected] = useState(interfaceCatalog[0].id),
    [tab, setTab] = useState("methods");
  const current = interfaceCatalog.find((layer) => layer.id === selected)!;
  const schema = schemaCatalog[current.schema as keyof typeof schemaCatalog];
  return (
    <>
      <Heading
        title="接口规范"
        description="每层具有独立输入输出、错误语义、版本和适配边界。"
      >
        <Button
          onClick={() =>
            downloadJSON("codexploit-interface-contracts-v1.json", {
              api_version: API_VERSION,
              maturity: "design-prototype",
              layers: interfaceCatalog,
              schemas: schemaCatalog,
            })
          }
        >
          <ArrowDownToLine size={15} />
          导出接口包
        </Button>
      </Heading>
      <div className="p-interface-layout">
        <aside className="p-panel p-interface-nav">
          {interfaceCatalog.map((layer) => (
            <button
              key={layer.id}
              className={selected === layer.id ? "p-selected" : ""}
              onClick={() => setSelected(layer.id)}
            >
              <span>{layer.id}</span>
              <strong>{layer.name}</strong>
              <ChevronRight size={14} />
            </button>
          ))}
        </aside>
        <section className="p-panel">
          <div className="p-contract-heading">
            <span className="p-tag">{API_VERSION}</span>
            <h2>{current.name}</h2>
            <p>{current.description}</p>
            <code>{current.port}</code>
          </div>
          <div className="p-tabs">
            <button
              className={tab === "methods" ? "p-tab-active" : ""}
              onClick={() => setTab("methods")}
            >
              标准方法
            </button>
            <button
              className={tab === "schema" ? "p-tab-active" : ""}
              onClick={() => setTab("schema")}
            >
              数据 Schema
            </button>
            <button
              className={tab === "rules" ? "p-tab-active" : ""}
              onClick={() => setTab("rules")}
            >
              契约规则
            </button>
          </div>
          {tab === "methods" && (
            <div className="p-table-scroll">
              <table className="p-table">
                <thead>
                  <tr>
                    <th>方法</th>
                    <th>输入</th>
                    <th>输出</th>
                  </tr>
                </thead>
                <tbody>
                  {current.methods.map((m) => (
                    <tr key={m[0]}>
                      <td>
                        <code>{m[0]}</code>
                      </td>
                      <td>{m[1]}</td>
                      <td>{m[2]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="p-inline-note">
                <Info size={15} />
                目录为扩展目标接口。现有实现映射、兼容边界与验收标准记录于
                docs/design/interfaces/v1/。
              </div>
            </div>
          )}
          {tab === "schema" && (
            <div className="p-schema-body">
              <pre className="p-json">{JSON.stringify(schema, null, 2)}</pre>
              <Button
                small
                onClick={() =>
                  downloadJSON(`${current.schema}.schema.json`, schema)
                }
              >
                <ArrowDownToLine size={14} />
                下载 Schema
              </Button>
            </div>
          )}
          {tab === "rules" && (
            <div className="p-prose">
              <ul>
                {current.rules.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
              <h3>统一约定</h3>
              <p>
                项目与快照隔离、不可变产物、来源追踪、超时与取消、幂等写入、显式覆盖范围。
              </p>
              <p>
                接口名称是目标契约；原型与现有正式 API
                分开标识，未接线的能力不显示为真实执行成功。
              </p>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
