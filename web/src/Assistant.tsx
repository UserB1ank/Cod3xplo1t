import { useCallback, useEffect, useRef, useState } from "react";
import {
  Loader2,
  MessageSquare,
  RefreshCw,
  Send,
  ShieldCheck,
  Square,
  Wrench,
  Bot,
  GitBranch,
  Network,
  ArrowDown,
  ArrowRight,
  ChevronRight,
  Pause,
} from "lucide-react";
import type { ApiClient } from "./api";
import { Badge, EmptyState, Failure, Hint, Panel } from "./components";
import type {
  SupervisorMessage,
  SupervisorRun,
  SupervisorSession,
  PathSubtask,
  AuditPath,
  AuditEvent,
  Run,
} from "./types";
import { shortId, clock, eventNames } from "./domain";
import { taskState, type Task } from "./workbench";
import { composerAction, insertComposerNewline } from "./assistant-composer";
import { Markdown } from "./Markdown";

const toolLabels: Record<string, string> = {
  inspect_project: "查看项目记录",
  list_source_files: "列出源码文件",
  read_source_file: "读取源码窗口",
  graph_summary: "读取图谱摘要",
  list_modules: "列出模块",
  list_symbols: "检索符号",
  get_symbol: "读取符号",
  get_callers: "查询调用方",
  get_callees: "查询被调用方",
  find_call_paths: "查找调用路径",
  get_code_slice: "读取源码片段",
  list_unresolved_calls: "查看未解析调用",
};

function toolLabel(name?: string) {
  return (name && toolLabels[name]) || name || "工具调用";
}

function objectSummary(args?: string) {
  if (!args) return "";
  try {
    const value = JSON.parse(args) as Record<string, unknown>;
    const preferred = [
      "file",
      "path_id",
      "audit_id",
      "report_id",
      "symbol_id",
      "id",
      "section",
      "query",
      "name_contains",
      "module_id",
    ];
    for (const key of preferred) {
      const raw = value[key];
      if (typeof raw === "string" && raw.trim()) return raw;
    }
    if (typeof value.snapshot_id === "string") return "当前固定源码";
    return "";
  } catch {
    return "";
  }
}

function truncatedResult(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  if (record.truncated === true || record.result_too_large === true) return true;
  if (typeof record.truncation_reason === "string" && record.truncation_reason)
    return true;
  if (typeof record.error === "string" && /truncat|too large/i.test(record.error))
    return true;
  return false;
}

function toolOutcome(
  content: string,
  eventStatus?: string,
): { ok: boolean; truncated: boolean; value?: unknown; text: string } {
  let value: unknown;
  try {
    value = JSON.parse(content);
  } catch {
    value = undefined;
  }
  const record =
    value && typeof value === "object"
      ? (value as Record<string, unknown>)
      : undefined;
  const failed =
    eventStatus === "error" ||
    record?.ok === false ||
    (!!record?.error && record.ok !== true);
  const text =
    record && typeof record.result === "string"
      ? record.result
      : record && record.result !== undefined
        ? JSON.stringify(record.result, null, 2)
        : content;
  return {
    ok: !failed,
    truncated: truncatedResult(value),
    value,
    text: text || "（空结果）",
  };
}

function messageID() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `client-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function stateLabel(status: string) {
  switch (status) {
    case "RUNNING":
      return "正在思考";
    case "SUCCEEDED":
      return "已完成";
    case "FAILED":
      return "失败";
    case "CANCELLED":
      return "已停止";
    default:
      return status;
  }
}

export function Assistant({
  api,
  projectID,
  canWrite,
  projectName,
  tasks,
  revision,
  onTask,
  onNavigate,
}: {
  api: ApiClient;
  projectID: string;
  canWrite: boolean;
  projectName: string;
  tasks: Task[];
  revision: number;
  onTask: (taskID: string) => void;
  onNavigate: (view: string) => void;
}) {
  const [activeChild, setActiveChild] = useState<PathSubtask>();
  const childStorageKey = `codexploit:active-subtask:${projectID}`;
  const [selections, setSelections] = useState<PathSubtask[]>([]);
  const [taskFilter, setTaskFilter] = useState("all");
  const [selectionError, setSelectionError] = useState("");
  const [sessions, setSessions] = useState<SupervisorSession[]>([]);
  const [session, setSession] = useState<SupervisorSession>();
  const [available, setAvailable] = useState(true);
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const sessionID = session?.session_id || "";
  const activeRun = session?.runs.find((run) => run.status === "RUNNING");
  const timer = useRef<number>();
  const selectedSession = useRef("");
  const pendingMessage = useRef<{ content: string; id: string }>();
  const sending = useRef(false);
  const feed = useRef<HTMLDivElement>(null);
  const composer = useRef<HTMLTextAreaElement>(null);
  const following = useRef(true);
  const [showJump, setShowJump] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    const read = () =>
      api
        .pathSelections(projectID, undefined, controller.signal)
        .then((page) => {
          if (!controller.signal.aborted) {
            setSelections(page.selections);
            setSelectionError("");
          }
        })
        .catch((value) => {
          if (!controller.signal.aborted)
            setSelectionError(
              value instanceof Error ? value.message : "读取子任务失败",
            );
        });
    void read();
    const interval = window.setInterval(read, 3000);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [api, projectID, revision]);
  useEffect(() => {
    const saved = window.sessionStorage.getItem(childStorageKey);
    if (!saved) return;
    const fresh = selections.find((item) => item.selection_id === saved);
    if (!fresh) return;
    if (
      !activeChild ||
      activeChild.selection_id !== fresh.selection_id ||
      activeChild.state !== fresh.state ||
      activeChild.run_id !== fresh.run_id
    ) {
      setActiveChild(fresh);
    }
  }, [selections, childStorageKey, activeChild]);
  useEffect(() => {
    if (activeChild)
      window.sessionStorage.setItem(childStorageKey, activeChild.selection_id);
  }, [activeChild, childStorageKey]);
  const backToMain = () => {
    setActiveChild(undefined);
    window.sessionStorage.removeItem(childStorageKey);
  };
  const load = useCallback(
    async (signal?: AbortSignal) => {
      const page = await api.supervisorSessions(projectID, signal);
      if (signal?.aborted) return;
      setAvailable(page.available);
      setReason(page.reason || "");
      setSessions(page.sessions);
      let current =
        page.sessions.find(
          (item) => item.session_id === selectedSession.current,
        ) || page.sessions[0];
      if (!current && page.available && canWrite) {
        current = (await api.createSupervisorSession(projectID)).session;
        setSessions([current]);
      }
      if (current) {
        const fresh = await api.supervisorSession(
          projectID,
          current.session_id,
          signal,
        );
        if (signal?.aborted) return;
        selectedSession.current = fresh.session.session_id;
        setSession(fresh.session);
      } else {
        setSession(undefined);
      }
    },
    [api, projectID, canWrite],
  );

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    load(controller.signal)
      .catch((value) => {
        if (!controller.signal.aborted)
          setError(value instanceof Error ? value.message : "读取会话失败");
      })
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, [load]);

  useEffect(() => {
    if (!activeRun || !sessionID) return;
    const controller = new AbortController();
    timer.current = window.setInterval(() => {
      api
        .supervisorSession(projectID, sessionID, controller.signal)
        .then((value) => {
          if (!controller.signal.aborted) setSession(value.session);
        })
        .catch((value) => {
          if (!controller.signal.aborted)
            setError(value instanceof Error ? value.message : "更新会话失败");
        });
    }, 1200);
    return () => {
      controller.abort();
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [activeRun?.run_id, api, projectID, sessionID]);

  const send = async () => {
    const content = draft.trim();
    if (!content || !sessionID || sending.current || busy || activeRun || !canWrite || !available)
      return;
    sending.current = true;
    setBusy(true);
    setError("");
    try {
      if (pendingMessage.current?.content !== content)
        pendingMessage.current = { content, id: messageID() };
      await api.sendSupervisorMessage(
        projectID,
        sessionID,
        content,
        pendingMessage.current.id,
      );
      pendingMessage.current = undefined;
      setDraft("");
      composer.current?.focus();
      const fresh = await api.supervisorSession(projectID, sessionID);
      setSession(fresh.session);
    } catch (value) {
      setError(value instanceof Error ? value.message : "发送失败");
    } finally {
      sending.current = false;
      setBusy(false);
    }
  };

  useEffect(() => {
    if (following.current && feed.current)
      feed.current.scrollTop = feed.current.scrollHeight;
  }, [session?.messages.length, activeRun?.run_id]);
  const latestRun = session?.runs[session.runs.length - 1];
  const callInfo = new Map<
    string,
    { name: string; arguments: string; messageID: string }
  >();
  for (const message of session?.messages || []) {
    for (const call of message.calls || []) {
      callInfo.set(call.call_id, {
        name: call.name,
        arguments: call.arguments,
        messageID: message.message_id,
      });
    }
  }
  const toolEvents = new Map<
    string,
    { status: string; label: string; created_at: string }
  >();
  for (const event of session?.events || []) {
    if (event.type !== "tool_result") continue;
    const callID = event.detail?.call_id;
    if (!callID) continue;
    toolEvents.set(callID, {
      status: event.detail?.status || "",
      label: event.summary || "",
      created_at: event.created_at,
    });
  }
  const shownTasks = selections.filter(
    (item) =>
      taskFilter === "all" ||
      (taskFilter === "active"
        ? ["RUNNING", "ANALYZING", "QUEUED"].includes(item.state)
        : !["RUNNING", "ANALYZING", "QUEUED"].includes(item.state)),
  );
  return (
    <>
      <div className="agent-workspace-summary">
        <span>
          <Bot size={15} />主 Agent ·{" "}
          {activeRun ? "正在执行" : available ? "等待对话" : "模型不可用"}
        </span>
        <span>{selections.length} 个路径审查任务</span>
        <button className="text-button" onClick={() => onNavigate("paths")}>
          选择审查路径 <ArrowRight size={13} />
        </button>
        <details>
          <summary>执行能力</summary>
          <p>
            主 Agent 可查看当前项目的源码、导入、分析阶段、工作流、插件、任务、发现、报告和脱敏诊断。
            图谱未就绪时仍可读取源码并排查构建状态。
          </p>
        </details>
      </div>
      <div className="supervisor-layout command-workspace">
        <aside className="supervisor-tasks">
          <div className="workbench-section-heading">
            <h2>指挥与任务</h2>
            <span>{selections.length}</span>
          </div>
          <button
            className={`master-agent-tab ${!activeChild ? "selected" : ""}`}
            onClick={backToMain}
          >
            <span className="agent-avatar">
              <Bot size={19} />
            </span>
            <span>
              <strong>主 Agent</strong>
              <small>项目对话与图谱查询</small>
            </span>
            <ChevronRight size={13} />
          </button>
          <div className="workbench-section-heading">
            <h3>路径审查子任务</h3>
            <button className="text-button" onClick={() => onNavigate("paths")}>
              选择 +
            </button>
          </div>
          <select
            aria-label="筛选子任务"
            value={taskFilter}
            onChange={(event) => setTaskFilter(event.target.value)}
          >
            <option value="all">全部状态</option>
            <option value="active">进行中</option>
            <option value="completed">已结束或待关注</option>
          </select>
          {selectionError && <Failure message={selectionError} />}
          <div className="workbench-task-list">
            {shownTasks.map((item) => (
              <button
                key={item.selection_id}
                className={
                  activeChild?.selection_id === item.selection_id
                    ? "selected"
                    : ""
                }
                onClick={() => setActiveChild(item)}
              >
                <span
                  className={`task-state-dot ${item.state.toLowerCase()}`}
                />
                <span>
                  <small className="mono">{shortId(item.path_id)}</small>
                  <strong title={`${item.entry_subject || "入口未记录"} → ${item.target_subject || "敏感操作未记录"}`}>
                    {childTaskTitle(item)}
                  </strong>
                  <small>
                    {childStateLabel(item.state)}
                    {item.target_kind ? ` · ${item.target_kind}` : ""}
                  </small>
                </span>
              </button>
            ))}
            {!shownTasks.length && (
              <p className="workbench-task-empty">
                {selections.length
                  ? "没有匹配的任务。"
                  : "从审查路径中选择目标，开始独立的 Agent 审查。"}
              </p>
            )}
          </div>
          {tasks.filter(
            (task) =>
              !selections.some((item) => item.audit_id === task.audit_id),
          ).length > 0 && (
            <details className="workbench-other-tasks">
              <summary>分析与其他任务</summary>
              {tasks
                .filter(
                  (task) =>
                    !selections.some((item) => item.audit_id === task.audit_id),
                )
                .map((task) => (
                  <button
                    key={task.audit_id}
                    onClick={() => onTask(task.audit_id)}
                  >
                    <strong>{task.name || shortId(task.audit_id)}</strong>
                    <Badge status={taskState(task)} />
                  </button>
                ))}
            </details>
          )}
          <button
            className="workbench-manage-tasks"
            onClick={() => onNavigate("tasks")}
          >
            任务管理 <ArrowRight size={13} />
          </button>
        </aside>
        {activeChild ? (
          <ChildReview
            key={activeChild.selection_id}
            api={api}
            selection={activeChild}
            canWrite={canWrite}
            onDetails={() => onTask(activeChild.audit_id)}
            onBack={backToMain}
          />
        ) : (
          <section className="supervisor-main">
            <div className="supervisor-heading">
              <span className="agent-avatar">
                <Bot size={21} />
              </span>
              <div>
                <h2>主 Agent</h2>
                <p>对话、查询代码与解释审查依据</p>
              </div>
              {session && (
                <select
                  aria-label="选择主 Agent 会话"
                  value={sessionID}
                  onChange={(event) => {
                    selectedSession.current = event.target.value;
                    setError("");
                    setLoading(true);
                    void load()
                      .catch((value) => setError(String(value)))
                      .finally(() => setLoading(false));
                  }}
                >
                  {sessions.map((item) => (
                    <option key={item.session_id} value={item.session_id}>
                      {item.title || `会话 ${shortId(item.session_id)}`}
                    </option>
                  ))}
                </select>
              )}
              <button
                className="icon-button"
                aria-label="刷新主 Agent 会话"
                onClick={() =>
                  void load().catch((value) => setError(String(value)))
                }
              >
                <RefreshCw size={14} />
              </button>
            </div>

            <div
              className="supervisor-messages"
              ref={feed}
              onScroll={() => {
                const el = feed.current;
                if (!el) return;
                const near = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
                following.current = near;
                setShowJump(!near);
              }}
              aria-live="polite"
            >
              {loading ? (
                <div className="supervisor-loading">
                  <Loader2 size={18} className="spin" />
                  读取会话…
                </div>
              ) : !available && !session ? (
                <EmptyState title="主 Agent 暂不可用">
                  {reason || "请先配置可用的模型。"}
                  <button
                    className="button secondary"
                    onClick={() => onNavigate("configuration")}
                  >
                    配置模型 <ArrowRight size={13} />
                  </button>
                </EmptyState>
              ) : !session ? (
                <EmptyState title="等待项目会话">
                  输入就绪后，可在此与主 Agent 对话。
                </EmptyState>
              ) : (
                <>
                  {!session.messages.length ? (
                    <div className="supervisor-empty">
                      <MessageSquare size={22} />
                      <strong>从一个问题开始</strong>
                      <p>
                        例如：“这个项目有哪些入口？”、“这个路径为什么被保留？”或“解释一下
                        sql_execution 的调用链”。
                      </p>
                    </div>
                  ) : (
                    session.messages.map((message) => (
                      <MessageRow
                        key={message.message_id}
                        message={message}
                        latestRunID={latestRun?.run_id || ""}
                        callInfo={callInfo}
                        toolEvents={toolEvents}
                      />
                    ))
                  )}
                  {activeRun && (
                    <div className="supervisor-thinking">
                      <Loader2 className="spin" size={15} />{" "}
                      {stateLabel(activeRun.status)}
                      <span className="muted">
                        {activeRun.tool_digest
                          ? `工具契约 ${activeRun.tool_digest.slice(0, 12)}`
                          : ""}
                      </span>
                    </div>
                  )}
                </>
              )}
            </div>

            {error && <Failure message={error} />}
            <div className="supervisor-composer">
              <textarea
                ref={composer}
                aria-label="与主 Agent 对话"
                aria-busy={busy}
                disabled={!canWrite || !available || !session || loading}
                rows={3}
                value={draft}
                placeholder="提问或排查项目问题…（回车发送，Ctrl+回车换行）"
                onChange={(event) => setDraft(event.target.value)}
                onKeyDown={(event) => {
                  const action = composerAction({key: event.key, ctrlKey: event.ctrlKey, repeat: event.repeat, keyCode: event.keyCode, isComposing: event.nativeEvent.isComposing});
                  if (action === "ignore") return;
                  event.preventDefault();
                  if (action === "newline") {
                    const input = event.currentTarget;
                    const start = input.selectionStart;
                    const end = input.selectionEnd;
                    const next = insertComposerNewline(input.value, start, end);
                    setDraft(next.value);
                    window.requestAnimationFrame(() => input.setSelectionRange(next.cursor, next.cursor));
                  } else {
                    void send();
                  }
                }}
              />
              <div className="supervisor-composer-actions">
                <small className="muted">
                  回车发送 · Ctrl+回车换行
                </small>
                {showJump && (
                  <button
                    className="button secondary"
                    onClick={() => {
                      const el = feed.current;
                      if (el) el.scrollTop = el.scrollHeight;
                      following.current = true;
                      setShowJump(false);
                    }}
                  >
                    回到最新 <ArrowDown size={13} />
                  </button>
                )}
                {error && draft.trim() && !activeRun && !busy && (
                  <button
                    className="button secondary"
                    onClick={() => void send()}
                    disabled={!canWrite || !available || !session}
                  >
                    重试发送 <RefreshCw size={13} />
                  </button>
                )}
                {activeRun && (
                  <button
                    className="button secondary"
                    disabled={!canWrite}
                    onClick={() =>
                      void api
                        .cancelSupervisorRun(
                          projectID,
                          sessionID,
                          activeRun.run_id,
                        )
                        .then(async () => {
                          const fresh = await api.supervisorSession(
                            projectID,
                            sessionID,
                          );
                          setSession(fresh.session);
                        })
                        .catch((value) =>
                          setError(
                            value instanceof Error ? value.message : "停止失败",
                          ),
                        )
                    }
                  >
                    <Square size={13} /> 停止本轮
                  </button>
                )}
                <button
                  className="button primary"
                  disabled={
                    !canWrite ||
                    !available ||
                    !session ||
                    loading ||
                    busy ||
                    !draft.trim() ||
                    !!activeRun
                  }
                  onClick={() => void send()}
                >
                  {busy ? (
                    <Loader2 size={14} className="spin" />
                  ) : (
                    <Send size={14} />
                  )}
                  发送
                </button>
              </div>
            </div>
          </section>
        )}

        <aside className="supervisor-side">
          <Panel title="项目上下文">
            <strong>{projectName}</strong>
            <p className="muted">
              {session
                ? `源码输入 ${shortId(session.snapshot_id)}`
                : "当前项目"}
            </p>
            <button
              className="text-button"
              onClick={() => onNavigate("knowledge")}
            >
              查看代码图谱 <ArrowRight size={13} />
            </button>
            <button
              className="text-button"
              onClick={() => onNavigate("findings")}
            >
              发现与证据 <ArrowRight size={13} />
            </button>
          </Panel>
          {activeChild && (
            <Panel title="当前子任务">
              <code className="muted">{shortId(activeChild.path_id)}</code>
              <p>所属任务 {shortId(activeChild.audit_id)}</p>
              <button
                className="text-button"
                onClick={() => onTask(activeChild.audit_id)}
              >
                查看任务详情 <ArrowRight size={12} />
              </button>
            </Panel>
          )}
          <Panel
            title={
              activeChild ? "主 Agent 运行（与此子任务独立）" : "主 Agent 本轮信息"
            }
          >
            {latestRun ? (
              <dl className="supervisor-pin">
                <div>
                  <dt>运行</dt>
                  <dd className="mono">{latestRun.run_id}</dd>
                </div>
                <div>
                  <dt>状态</dt>
                  <dd>{stateLabel(latestRun.status)}</dd>
                </div>
                <div>
                  <dt>运行时</dt>
                  <dd>
                    {latestRun.runtime} · {latestRun.model}
                  </dd>
                </div>
                <div>
                  <dt>配置版本</dt>
                  <dd className="mono">{latestRun.config_version || "—"}</dd>
                </div>
                <div>
                  <dt>模型用量</dt>
                  <dd>
                    {latestRun.input_tokens} / {latestRun.output_tokens} tokens
                  </dd>
                </div>
                <div>
                  <dt>工具契约</dt>
                  <dd className="mono">
                    {latestRun.tool_digest
                      ? latestRun.tool_digest.slice(0, 16)
                      : "—"}
                  </dd>
                </div>
                {latestRun.error && (
                  <div>
                    <dt>
                      {latestRun.status === "CANCELLED"
                        ? "停止原因"
                        : "失败原因"}
                    </dt>
                    <dd>{latestRun.error}</dd>
                  </div>
                )}
              </dl>
            ) : (
              <Hint>
                发送第一轮问题后，这里会固定模型、配置、工具契约和真实用量。
              </Hint>
            )}
          </Panel>
          <Panel title="事件">
            <div className="supervisor-events">
              {(session?.events || []).slice(-12).map((event) => (
                <div key={event.event_id}>
                  <span className="mono">{event.seq}</span>
                  <span>{event.type}</span>
                  <small className="muted">{event.summary}</small>
                </div>
              ))}
              {!session?.events.length && <Hint>还没有事件。</Hint>}
            </div>
          </Panel>
          <div className="supervisor-boundary">
            <ShieldCheck size={14} />
            项目与会话由宿主绑定；工具只读，模型不能通过参数更换项目。聊天文字不会被当作路径审查结论。
          </div>
        </aside>
      </div>
    </>
  );
}

function MessageRow({
  message,
  latestRunID,
  callInfo,
  toolEvents,
}: {
  message: SupervisorMessage;
  latestRunID: string;
  callInfo: Map<string, { name: string; arguments: string; messageID: string }>;
  toolEvents: Map<
    string,
    { status: string; label: string; created_at: string }
  >;
}) {
  if (message.role === "tool") {
    const call = message.tool_call_id
      ? callInfo.get(message.tool_call_id)
      : undefined;
    const event = message.tool_call_id
      ? toolEvents.get(message.tool_call_id)
      : undefined;
    const outcome = toolOutcome(message.content, event?.status);
    const current = !!message.run_id && message.run_id === latestRunID;
    return (
      <details className="supervisor-tool-message">
        <summary>
          <Wrench size={14} />
          <strong>{toolLabel(call?.name)}</strong>
          {objectSummary(call?.arguments) && (
            <span className="tool-object">
              {objectSummary(call?.arguments)}
            </span>
          )}
          <span className={`tool-state ${outcome.ok ? "ok" : "failed"}`}>
            {outcome.ok ? (outcome.truncated ? "成功 · 已截断" : "成功") : "失败"}
          </span>
          <span className="tool-run-label">
            {current ? "本轮" : "历史"}
            {message.created_at ? ` · ${clock(message.created_at)}` : ""}
          </span>
        </summary>
        <div className="tool-detail">
          <dl>
            <div>
              <dt>调用 ID</dt>
              <dd className="mono">{message.tool_call_id || "未记录"}</dd>
            </div>
            <div>
              <dt>来源轮次</dt>
              <dd className="mono">{message.run_id || "历史记录未记录运行 ID"}</dd>
            </div>
            {call?.arguments && (
              <div>
                <dt>参数</dt>
                <dd>
                  <pre>{call.arguments}</pre>
                </dd>
              </div>
            )}
          </dl>
          {outcome.truncated && (
            <p className="tool-truncated">
              工具结果声明了截断；未显示的部分不能当作不存在。可缩小范围后重新查询。
            </p>
          )}
          <pre className="tool-raw">{outcome.text}</pre>
        </div>
      </details>
    );
  }
  return (
    <article className={`supervisor-message ${message.role}`}>
      <span className="supervisor-role">
        {message.role === "user" ? "你" : "主 Agent"}
        {message.run_id === latestRunID && latestRunID ? " · 本轮" : ""}
      </span>
      {message.role === "assistant" ? (
        <Markdown source={message.content || "（模型请求了工具）"} />
      ) : (
        <p>{message.content || "（模型请求了工具）"}</p>
      )}
      {!!message.calls?.length && (
        <div className="supervisor-calls">
          {message.calls.map((call) => (
            <span key={call.call_id}>
              <Wrench size={11} /> {toolLabel(call.name)}
            </span>
          ))}
        </div>
      )}
    </article>
  );
}

function stopReasonLabel(reason?: string) {
  return (
    (
      {
        completed: "正常完成",
        "no_new_evidence": "无新证据收敛",
        round_limit: "模型轮次上限",
        tool_call_limit: "工具预算耗尽",
        budget_exhausted: "审计预算耗尽",
        budget_paused: "预算暂停，已保存检查点",
        invalid_output: "输出校验失败",
        timed_out: "执行超时",
        timeout: "执行超时",
        retry_exhausted: "重试耗尽",
        empty_answer: "模型未返回答案",
        cancelled: "已取消",
      } as Record<string, string>
    )[reason || ""] || reason || "未记录"
  );
}

function hypothesisLabel(status?: string) {
  return (
    (
      {
        candidate: "候选假设",
        refuted: "已排除",
        inconclusive: "证据不足",
      } as Record<string, string>
    )[status || ""] || status || "未记录"
  );
}

function severityLabel(value?: string) {
  return (
    (
      { high: "高", medium: "中", low: "低" } as Record<string, string>
    )[value || ""] || value || "未记录"
  );
}

function obligationLabel(kind: string) {
  return (
    (
      {
        source_is_attacker_controlled: "源受攻击者控制",
        flow_reaches_sink: "数据到达敏感操作",
        control_ineffective_or_absent: "安全控制缺失或无效",
        sink_is_sensitive: "敏感操作可造成影响",
      } as Record<string, string>
    )[kind] || kind
  );
}

function childStateLabel(state: string) {
  return (
    (
      {
        RUNNING: "运行中",
        ANALYZING: "审查中",
        QUEUED: "等待调度",
        PAUSED: "已暂停",
        SUCCEEDED: "已完成",
        CONCLUDED: "已完成",
        FAILED: "失败",
        CANCELLED: "已停止",
        BLOCKED: "受阻",
        INTERRUPTED: "已中断",
        INVALID_OUTPUT: "输出校验失败",
        BUDGET_EXHAUSTED: "预算已耗尽",
        TIMED_OUT: "已超时",
      } as Record<string, string>
    )[state] || state
  );
}

function childLeaf(subject?: string) {
  const symbol = (subject || "").split(" · ")[0].replace(/^sink:/, "");
  return symbol.split("/").pop()?.split(".").pop() || symbol;
}

function childTaskTitle(item: PathSubtask) {
  const entry = childLeaf(item.entry_subject) || "入口";
  const target = childLeaf(item.target_subject) || item.target_kind || "敏感操作";
  return `${entry} → ${target}`;
}

function childLocation(subject?: string) {
  return (subject || "").split(" · ")[1] || "";
}

function answerVerdict(
  run: Run | undefined,
  answer: import("./types").AgentAnswer | undefined,
) {
  if (!answer) return "未记录结构化答案";
  if (run?.status === "PAUSED") return "预算暂停 · 已保存检查点";
  if (answer.finding_candidate) return "形成候选，尚未确认漏洞";
  if (answer.hypothesis.status === "refuted") return "已排除该假设";
  if (answer.hypothesis.status === "inconclusive") return "证据不足，未下结论";
  return "审查结束，未形成候选";
}

function EvidenceList({
  title,
  items,
}: {
  title: string;
  items: import("./types").AnswerEvidence[];
}) {
  return (
    <div className="child-evidence-group">
      <h4>
        {title} <span>{items.length}</span>
      </h4>
      {items.length ? (
        <ul>
          {items.map((item, index) => (
            <li key={`${item.ref || item.kind}-${index}`}>
              <span className="child-evidence-kind">{item.kind}</span>
              {item.file ? (
                <code className="mono">
                  {item.file}
                  {item.line ? `:${item.line}` : ""}
                </code>
              ) : (
                <span className="muted">位置未记录</span>
              )}
              {item.ref && <small className="mono">引用 {item.ref}</small>}
              {(item.summary || item.quote) && (
                <p>{item.summary || item.quote}</p>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p className="child-empty-evidence">未记录此类证据。</p>
      )}
    </div>
  );
}

function ChildAnswer({ run }: { run?: Run }) {
  const answer = run?.answer;
  if (!answer) {
    return (
      <div className="child-answer child-answer-empty">
        <h3>审查结果</h3>
        <p>
          {run?.status === "PAUSED"
            ? "预算暂停，未产生结构化答案；检查点已保存，可从任务详情继续。"
            : "未记录宿主已接受的结构化答案。"}
        </p>
        <p className="muted">
          执行日志不能代替答案；不要从事件文本推断审查结论。
        </p>
      </div>
    );
  }
  const obligations = answer.obligations || [];
  const met = obligations.filter((item) => item.verdict === "met").length;
  const unknown = obligations.filter((item) => item.verdict === "unknown");
  return (
    <div className="child-answer">
      <div className="child-answer-heading">
        <div>
          <span className="eyebrow">ACCEPTED ANSWER</span>
          <h3>{answerVerdict(run, answer)}</h3>
        </div>
        <span
          className={`child-candidate ${answer.finding_candidate ? "candidate" : "empty"}`}
        >
          {answer.finding_candidate ? "形成候选" : "未形成候选"}
        </span>
      </div>
      <p className="child-answer-statement">
        {answer.hypothesis.statement || "答案未记录假设陈述。"}
      </p>
      <dl className="child-answer-meta">
        <div>
          <dt>假设状态</dt>
          <dd>{hypothesisLabel(answer.hypothesis.status)}</dd>
        </div>
        <div>
          <dt>置信</dt>
          <dd>{answer.hypothesis.confidence || "未记录"}</dd>
        </div>
        <div>
          <dt>义务</dt>
          <dd>
            {obligations.length
              ? `${met}/${obligations.length} 满足 · ${unknown.length} 未知`
              : "未记录"}
          </dd>
        </div>
        <div>
          <dt>严重性提示</dt>
          <dd>{severityLabel(answer.severity_hint)}</dd>
        </div>
      </dl>
      {!!obligations.length && (
        <div className="child-obligations">
          <h4>审查义务</h4>
          <ul>
            {obligations.map((item) => (
              <li className={`verdict-${item.verdict}`} key={item.kind}>
                <span>{obligationLabel(item.kind)}</span>
                <strong>
                  {item.verdict === "met"
                    ? "满足"
                    : item.verdict === "not_met"
                      ? "不满足"
                      : "未知"}
                </strong>
                {item.blocker && <small>阻碍：{item.blocker}</small>}
                {item.reason && <p>{item.reason}</p>}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="child-evidence-grid">
        <EvidenceList
          title="支持证据"
          items={answer.supporting_evidence || []}
        />
        <EvidenceList
          title="反对证据"
          items={answer.contradicting_evidence || []}
        />
      </div>
      {answer.falsifier && (
        <div className="child-falsifier">
          <h4>反证检查</h4>
          <p>{answer.falsifier.claim || "未记录反证声明。"}</p>
          <small>
            {answer.falsifier.checked ? "已检查" : "未检查"}
            {answer.falsifier.how?.length
              ? ` · 依据 ${answer.falsifier.how.join("、")}`
              : ""}
          </small>
        </div>
      )}
      {answer.notes && (
        <div className="child-answer-note">
          <h4>审查说明</h4>
          <p>{answer.notes}</p>
        </div>
      )}
      {answer.next_action && (
        <div className="child-answer-note">
          <h4>下一步</h4>
          <p>{answer.next_action}</p>
        </div>
      )}
      <p className="child-answer-source">
        来源：宿主已接受的运行答案；显示层不重新审判，也不把候选提升为已确认。
      </p>
    </div>
  );
}

function ChildReview({
  api,
  selection,
  canWrite,
  onDetails,
  onBack,
}: {
  api: ApiClient;
  selection: PathSubtask;
  canWrite: boolean;
  onDetails: () => void;
  onBack: () => void;
}) {
  const [path, setPath] = useState<AuditPath>();
  const [runs, setRuns] = useState<Run[]>([]);
  const [runID, setRunID] = useState(selection.run_id || "");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    const read = async () => {
      try {
        const [page, runPage] = await Promise.all([
          api.path(selection.path_id, controller.signal),
          api.get<{ runs: Run[]; total: number }>(
            `/runs?audit_id=${encodeURIComponent(selection.audit_id)}&limit=100`,
            controller.signal,
          ),
        ]);
        const candidates = runPage.runs.filter(
          (item) => item.path_id === selection.path_id,
        );
        const current =
          candidates.find((item) => item.run_id === runID) ||
          candidates.find((item) => item.run_id === selection.run_id) ||
          candidates[0];
        const eventPage = current
          ? await api.runEvents(current.run_id, controller.signal)
          : { events: page.events };
        if (!controller.signal.aborted) {
          setPath(page.path);
          setRuns(candidates);
          if (!runID && current) setRunID(current.run_id);
          setEvents(eventPage.events);
          setError("");
        }
      } catch (value) {
        if (!controller.signal.aborted)
          setError(value instanceof Error ? value.message : "读取任务失败");
      }
    };
    void read();
    const timer = window.setInterval(read, 2500);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [api, selection, tick, runID]);
  const run =
    runs.find((item) => item.run_id === runID) ||
    runs.find((item) => item.run_id === selection.run_id) ||
    runs[0];
  const failedEvents = events.filter(
    (event) =>
      /error|failed|rejected/i.test(event.type) ||
      /失败|error/i.test(event.reason || ""),
  ).length;
  return (
    <section className="child-review-main">
      <div className="supervisor-heading">
        <span className="agent-avatar">
          <GitBranch size={20} />
        </span>
        <div>
          <h2>{childTaskTitle(selection)}</h2>
          <p className="child-heading-location">
            {childLocation(selection.entry_subject) || "入口位置未记录"} →{" "}
            {childLocation(selection.target_subject) || "目标位置未记录"} ·{" "}
            <span className="mono">{shortId(selection.path_id)}</span>
          </p>
        </div>
        <button className="text-button" onClick={onBack}>
          返回主 Agent
        </button>
      </div>
      <div className="child-review-controls">
        <Badge
          status={
            run?.status === "INVALID_OUTPUT"
              ? "FAILED"
              : run?.status || path?.status || selection.state
          }
          label={childStateLabel(
            run?.status || path?.status || selection.state,
          )}
        />
        {runs.length > 1 && (
          <label className="child-run-picker">
            历史运行
            <select
              aria-label="选择该路径的历史运行"
              value={run?.run_id || ""}
              onChange={(event) => setRunID(event.target.value)}
            >
              {runs.map((item) => (
                <option key={item.run_id} value={item.run_id}>
                  {childStateLabel(item.status)} ·{" "}
                  {item.started_at?.slice(0, 19).replace("T", " ") ||
                    item.run_id}
                </option>
              ))}
            </select>
          </label>
        )}
        <button className="button secondary" onClick={onDetails}>
          任务详情与控制 <ArrowRight size={13} />
        </button>
        {path?.status === "PAUSED" && (
          <button
            className="button primary"
            disabled={!canWrite || busy}
            onClick={async () => {
              setBusy(true);
              try {
                await api.changePath(selection.path_id, "resume");
                setTick((n) => n + 1);
              } catch (e) {
                setError(String(e));
              } finally {
                setBusy(false);
              }
            }}
          >
            继续路径调度
          </button>
        )}
        {path &&
          ["QUEUED", "ANALYZING", "LOCAL_EXPLORING"].includes(path.status) && (
            <button
              className="button secondary"
              disabled={!canWrite || busy}
              title="暂停后续调度；活动运行可能继续到执行边界"
              onClick={async () => {
                setBusy(true);
                try {
                  await api.changePath(selection.path_id, "pause");
                  setTick((n) => n + 1);
                } catch (e) {
                  setError(String(e));
                } finally {
                  setBusy(false);
                }
              }}
            >
              <Pause size={13} />
              暂停路径调度
            </button>
          )}
      </div>
      {error && <Failure message={error} />}
      <div className="child-review-feed">
        <div className="child-review-objective">
          <span className="eyebrow">REVIEW SCOPE</span>
          <h3 title={childTaskTitle(selection)}>{childTaskTitle(selection)}</h3>
          <p className="child-scope-location mono">
            {childLocation(path?.entry_subject || selection.entry_subject) ||
              "入口位置未记录"}{" "}
            →{" "}
            {childLocation(path?.target_subject || selection.target_subject) ||
              "目标位置未记录"}
          </p>
          <p className="child-scope-goal">
            {run?.task?.security_goal || path?.objectives.join(" · ")}
          </p>
          {path?.selection?.reason && (
            <p className="child-scope-reason">
              筛选依据：{path.selection.reason}
            </p>
          )}
        </div>
        <ChildAnswer run={run} />
        <div className="child-run-context">
          <div>
            <span>当前运行</span>
            <code className="mono">{run?.run_id || "未记录"}</code>
          </div>
          <div>
            <span>运行时与模型</span>
            <strong>
              {run?.runtime || "—"} · {run?.pin?.model || "模型未记录"}
            </strong>
          </div>
          <div>
            <span>用量</span>
            <strong>
              {run?.tool_calls ?? "—"} 次工具 ·{" "}
              {run ? run.input_tokens + run.output_tokens : "—"} tokens
            </strong>
          </div>
          <div>
            <span>停止原因</span>
            <strong>{stopReasonLabel(run?.stop_reason)}</strong>
          </div>
        </div>
        {run?.error && <Failure message={run.error} />}
        <details className="child-execution-log">
          <summary>
            执行记录（{events.length} 条
            {failedEvents ? ` · ${failedEvents} 条错误或拒绝` : ""}）
            <span>默认折叠协议日志；展开可逐项追溯</span>
          </summary>
          {events.length ? (
            <ol className="child-event-list">
              {[...events]
                .sort((a, b) => a.seq - b.seq)
                .map((event) => (
                  <li
                    key={event.event_id}
                    className={
                      /error|failed|rejected/i.test(event.type)
                        ? "failed"
                        : ""
                    }
                  >
                    <span className="event-timeline-dot" />
                    <div>
                      <strong>{eventNames[event.type] || event.type}</strong>
                      <small>{clock(event.created_at)}</small>
                      <p>
                        {event.summary ||
                          event.reason ||
                          "已记录执行事件"}
                      </p>
                    </div>
                  </li>
                ))}
            </ol>
          ) : (
            <EmptyState title="等待执行记录">
              实际工具调用和状态变化将在这里显示；日志不能代替结构化答案。
            </EmptyState>
          )}
        </details>
        <details className="child-direction-note">
          <summary>
            <MessageSquare size={16} /> 子任务消息能力尚未接入
          </summary>
          <p>
            当前可查看结构化答案、执行记录并进入任务控制。向子 Agent
            补充方向需要服务端提供消息与应用回执接口。
          </p>
        </details>
      </div>
    </section>
  );
}
