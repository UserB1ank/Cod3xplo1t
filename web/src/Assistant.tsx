import { useCallback, useEffect, useRef, useState } from "react";
import {
  Loader2,
  MessageSquare,
  RefreshCw,
  Send,
  ShieldCheck,
  Square,
  Wrench,
} from "lucide-react";
import type { ApiClient } from "./api";
import { EmptyState, Hint, Panel } from "./components";
import type {
  SupervisorMessage,
  SupervisorRun,
  SupervisorSession,
} from "./types";

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
}: {
  api: ApiClient;
  projectID: string;
  canWrite: boolean;
}) {
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

  const load = useCallback(
    async (signal?: AbortSignal) => {
      const page = await api.supervisorSessions(projectID, signal);
      setAvailable(page.available);
      setReason(page.reason || "");
      setSessions(page.sessions);
      let current = page.sessions[0];
      if (!current && page.available && canWrite) {
        current = (await api.createSupervisorSession(projectID)).session;
        setSessions([current]);
      }
      if (current) {
        const fresh = await api.supervisorSession(projectID, current.session_id, signal);
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
        if (!controller.signal.aborted) setError(value instanceof Error ? value.message : "读取会话失败");
      })
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, [load]);

  useEffect(() => {
    if (!activeRun || !sessionID) return;
    timer.current = window.setInterval(() => {
      api
        .supervisorSession(projectID, sessionID)
        .then((value) => setSession(value.session))
        .catch(() => undefined);
    }, 1200);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [activeRun, api, projectID, sessionID]);

  const send = async () => {
    const content = draft.trim();
    if (!content || !sessionID || busy) return;
    setBusy(true);
    setError("");
    try {
      await api.sendSupervisorMessage(projectID, sessionID, content, messageID());
      setDraft("");
      const fresh = await api.supervisorSession(projectID, sessionID);
      setSession(fresh.session);
    } catch (value) {
      setError(value instanceof Error ? value.message : "发送失败");
    } finally {
      setBusy(false);
    }
  };

  if (loading) {
    return (
      <div className="supervisor-loading">
        <Loader2 className="spin" size={18} /> 读取项目会话…
      </div>
    );
  }
  if (!available) {
    return (
      <EmptyState title="项目助手暂不可用">
        {reason || "当前部署没有可用的模型设置。"} 请先在“配置 → 模型”中启用并测试模型，或由管理员检查运行时。
      </EmptyState>
    );
  }
  if (!session) {
    return (
      <EmptyState title="尚无可用的项目会话">
        项目输入就绪后，项目助手会在这里创建一个默认会话。
      </EmptyState>
    );
  }
  const latestRun = session.runs[session.runs.length - 1];
  return (
    <div className="supervisor-layout">
      <section className="supervisor-main">
        <div className="supervisor-heading">
          <div className="supervisor-session-meta">
            <span className="mono">{session.session_id}</span>
            <small>{sessions.length} 个会话 · 默认会话</small>
          </div>
        </div>

        <div className="supervisor-messages" aria-live="polite">
          {!session.messages.length ? (
            <div className="supervisor-empty">
              <MessageSquare size={22} />
              <strong>从一个问题开始</strong>
              <p>例如：“这个项目有哪些入口？”、“这个路径为什么被保留？”或“解释一下 sql_execution 的调用链”。</p>
            </div>
          ) : (
            session.messages.map((message) => (
              <MessageRow key={message.message_id} message={message} />
            ))
          )}
          {activeRun && (
            <div className="supervisor-thinking">
              <Loader2 className="spin" size={15} /> {stateLabel(activeRun.status)}
              <span className="muted">
                {activeRun.tool_digest ? `工具契约 ${activeRun.tool_digest.slice(0, 12)}` : ""}
              </span>
            </div>
          )}
        </div>

        {error && <Hint>{error}</Hint>}
        <div className="supervisor-composer">
          <textarea
            aria-label="向项目助手提问"
            rows={3}
            value={draft}
            placeholder="输入问题，或要求它查询某个入口、符号、路径…"
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
                event.preventDefault();
                void send();
              }
            }}
          />
          <div className="supervisor-composer-actions">
            <small className="muted">⌘/Ctrl + Enter 发送 · 不选择指令类型</small>
            {activeRun && (
              <button
                className="button secondary"
                disabled={!canWrite}
                onClick={() =>
                  void api
                    .cancelSupervisorRun(projectID, session.session_id, activeRun.run_id)
                    .then((value) => {
                      setSession((current) =>
                        current
                          ? {
                              ...current,
                              runs: current.runs.map((run) =>
                                run.run_id === value.run.run_id ? value.run : run,
                              ),
                            }
                          : current,
                      );
                    })
                    .catch((value) => setError(value instanceof Error ? value.message : "停止失败"))
                }
              >
                <Square size={13} /> 停止本轮
              </button>
            )}
            <button
              className="button primary"
              disabled={!canWrite || busy || !draft.trim() || !!activeRun}
              onClick={() => void send()}
            >
              {busy ? <Loader2 size={14} className="spin" /> : <Send size={14} />}
              发送
            </button>
          </div>
        </div>
      </section>

      <aside className="supervisor-side">
        <Panel title="本轮固定信息">
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
                <dd>{latestRun.runtime} · {latestRun.model}</dd>
              </div>
              <div>
                <dt>配置版本</dt>
                <dd className="mono">{latestRun.config_version || "—"}</dd>
              </div>
              <div>
                <dt>模型用量</dt>
                <dd>{latestRun.input_tokens} / {latestRun.output_tokens} tokens</dd>
              </div>
              <div>
                <dt>工具契约</dt>
                <dd className="mono">{latestRun.tool_digest ? latestRun.tool_digest.slice(0, 16) : "—"}</dd>
              </div>
              {latestRun.error && (
                <div>
                  <dt>失败原因</dt>
                  <dd>{latestRun.error}</dd>
                </div>
              )}
            </dl>
          ) : (
            <Hint>发送第一轮问题后，这里会固定模型、配置、工具契约和真实用量。</Hint>
          )}
        </Panel>
        <Panel title="事件">
          <div className="supervisor-events">
            {session.events.slice(-12).map((event) => (
              <div key={event.event_id}>
                <span className="mono">{event.seq}</span>
                <span>{event.type}</span>
                <small className="muted">{event.summary}</small>
              </div>
            ))}
            {!session.events.length && <Hint>还没有事件。</Hint>}
          </div>
        </Panel>
        <div className="supervisor-boundary">
          <ShieldCheck size={14} />
          项目与会话由宿主绑定；工具只读，模型不能通过参数更换项目。聊天文字不会被当作路径审查结论。
        </div>
      </aside>
    </div>
  );
}

function MessageRow({ message }: { message: SupervisorMessage }) {
  if (message.role === "tool") {
    return (
      <details className="supervisor-tool-message">
        <summary>
          <Wrench size={13} /> 工具结果
          {message.tool_call_id ? <span className="mono">{message.tool_call_id}</span> : null}
        </summary>
        <pre>{message.content}</pre>
      </details>
    );
  }
  return (
    <article className={`supervisor-message ${message.role}`}>
      <span className="supervisor-role">{message.role === "user" ? "你" : "项目助手"}</span>
      <p>{message.content || "（模型请求了工具）"}</p>
      {!!message.calls?.length && (
        <div className="supervisor-calls">
          {message.calls.map((call) => (
            <span key={call.call_id}>
              <Wrench size={11} /> {call.name}
            </span>
          ))}
        </div>
      )}
    </article>
  );
}
