import {
  Bot,
  ExternalLink,
  Loader2,
  Plus,
  RefreshCw,
  Send,
  Square,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import type { ApiClient } from "./api";
import { projectAgentConversation } from "./agent-conversation";
import { AgentConversationFeed } from "./AgentConversationFeed";
import { AgentToolActivity } from "./AgentToolActivity";
import { composerAction, insertComposerNewline } from "./assistant-composer";
import { Markdown } from "./Markdown";
import type { SupervisorRun, SupervisorSession } from "./types";

const quickPrompts = [
  "总结当前图谱覆盖和主要限制",
  "指出最值得先审查的路径",
  "解释当前图谱中的高风险攻击面",
];

function clientMessageID() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `graph-chat-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function runLabel(run?: SupervisorRun) {
  if (!run) return "等待对话";
  if (run.status === "RUNNING") return "正在查询";
  if (run.status === "FAILED") return "本轮失败";
  if (run.status === "CANCELLED") return "本轮已停止";
  return "已完成";
}

export function GraphAgentChat({
  api,
  projectID,
  canWrite,
  agentAvailable,
  onOpenWorkbench,
}: {
  api: ApiClient;
  projectID: string;
  canWrite: boolean;
  agentAvailable: boolean;
  onOpenWorkbench?: () => void;
}) {
  const [sessions, setSessions] = useState<SupervisorSession[]>([]);
  const [session, setSession] = useState<SupervisorSession>();
  const [available, setAvailable] = useState(agentAvailable);
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [draft, setDraft] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const selectedSession = useRef("");
  const composer = useRef<HTMLTextAreaElement>(null);
  const feed = useRef<HTMLDivElement>(null);
  const sessionID = session?.session_id || "";
  const activeRun = session?.runs.find((run) => run.status === "RUNNING");
  const latestRun = session?.runs.at(-1);

  const load = useCallback(
    async (preferredID = selectedSession.current, signal?: AbortSignal) => {
      const page = await api.supervisorSessions(projectID, signal);
      if (signal?.aborted) return;
      setAvailable(page.available);
      setReason(page.reason || "");
      let current =
        page.sessions.find((item) => item.session_id === preferredID) ||
        page.sessions[0];
      let nextSessions = page.sessions;
      if (!current && page.available && canWrite) {
        current = (
          await api.createSupervisorSession(projectID, "图谱对话", true)
        ).session;
        nextSessions = [current, ...page.sessions];
      }
      if (signal?.aborted) return;
      setSessions(nextSessions);
      if (!current) {
        selectedSession.current = "";
        setSession(undefined);
        return;
      }
      const fresh = await api.supervisorSession(
        projectID,
        current.session_id,
        signal,
      );
      if (signal?.aborted) return;
      selectedSession.current = fresh.session.session_id;
      setSession(fresh.session);
    },
    [api, canWrite, projectID],
  );

  useEffect(() => {
    const controller = new AbortController();
    selectedSession.current = "";
    setSessions([]);
    setSession(undefined);
    setDraft("");
    setError("");
    setLoading(true);
    load("", controller.signal)
      .catch((value) => {
        if (!controller.signal.aborted)
          setError(value instanceof Error ? value.message : "读取会话失败");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [load]);

  useEffect(() => {
    if (!activeRun || !sessionID) return;
    const controller = new AbortController();
    const timer = window.setInterval(() => {
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
      window.clearInterval(timer);
    };
  }, [activeRun?.run_id, api, projectID, sessionID]);

  useEffect(() => {
    if (feed.current) feed.current.scrollTop = feed.current.scrollHeight;
  }, [session?.messages.length, activeRun?.run_id]);

  const createSession = async () => {
    if (!canWrite || !available || busy) return;
    setBusy(true);
    setError("");
    try {
      const created = (
        await api.createSupervisorSession(
          projectID,
          `图谱会话 ${sessions.length + 1}`,
        )
      ).session;
      selectedSession.current = created.session_id;
      setSessions((current) => [
        created,
        ...current.filter((item) => item.session_id !== created.session_id),
      ]);
      setSession(created);
      setDraft("");
      composer.current?.focus();
    } catch (value) {
      setError(value instanceof Error ? value.message : "新建会话失败");
    } finally {
      setBusy(false);
    }
  };

  const switchSession = async (id: string) => {
    selectedSession.current = id;
    setLoading(true);
    setError("");
    try {
      await load(id);
    } catch (value) {
      setError(value instanceof Error ? value.message : "切换会话失败");
    } finally {
      setLoading(false);
    }
  };

  const send = async (content = draft) => {
    const text = content.trim();
    if (
      !text ||
      !sessionID ||
      busy ||
      activeRun ||
      !canWrite ||
      !available
    )
      return;
    setBusy(true);
    setError("");
    try {
      await api.sendSupervisorMessage(
        projectID,
        sessionID,
        text,
        clientMessageID(),
      );
      if (content === draft) setDraft("");
      const fresh = await api.supervisorSession(projectID, sessionID);
      setSession(fresh.session);
      composer.current?.focus();
    } catch (value) {
      setError(value instanceof Error ? value.message : "发送失败");
    } finally {
      setBusy(false);
    }
  };

  const conversation = session ? projectAgentConversation(session) : [];
  const visibleConversation = conversation.filter(
    (entry) => entry.kind !== "tool-result",
  );

  return (
    <aside className="graph-agent-panel" aria-label="图谱 Agent 对话">
      <header className="graph-agent-heading">
        <div>
          <span className="agent-avatar">
            <Bot size={18} />
          </span>
          <span>
            <strong>图谱 Agent</strong>
            <small>{runLabel(activeRun || latestRun)}</small>
          </span>
        </div>
        <div className="graph-agent-controls">
          {sessions.length > 0 && (
            <select
              aria-label="选择图谱 Agent 会话"
              value={sessionID}
              disabled={loading || busy}
              onChange={(event) => void switchSession(event.target.value)}
            >
              {sessions.map((item) => (
                <option key={item.session_id} value={item.session_id}>
                  {item.title || `会话 ${item.session_id.slice(-6)}`}
                </option>
              ))}
            </select>
          )}
          <button
            type="button"
            className="icon-button"
            aria-label="新建图谱 Agent 会话"
            title="新建会话"
            disabled={!canWrite || !available || busy || loading}
            onClick={() => void createSession()}
          >
            <Plus size={15} />
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label="刷新图谱 Agent 会话"
            title="刷新"
            disabled={loading || busy}
            onClick={() => {
              setLoading(true);
              void load()
                .catch((value) =>
                  setError(
                    value instanceof Error ? value.message : "刷新会话失败",
                  ),
                )
                .finally(() => setLoading(false));
            }}
          >
            <RefreshCw size={14} className={loading ? "spin" : ""} />
          </button>
        </div>
      </header>

      <div className="graph-agent-context">
        <span>当前项目独立会话</span>
        {onOpenWorkbench && (
          <button type="button" className="text-button" onClick={onOpenWorkbench}>
            完整工作台 <ExternalLink size={12} />
          </button>
        )}
      </div>

      <AgentConversationFeed
        className="graph-agent-feed"
        label="图谱 Agent 对话历史"
        busy={loading || busy || !!activeRun}
        ref={feed}
      >
        {loading ? (
          <div className="graph-agent-loading">
            <Loader2 size={16} className="spin" /> 读取会话…
          </div>
        ) : !available ? (
          <div className="graph-agent-empty">
            <Bot size={20} />
            <strong>Agent 暂不可用</strong>
            <p>{reason || "请先在配置中启用可用的模型。"}</p>
          </div>
        ) : !session ? (
          <div className="graph-agent-empty">
            <Bot size={20} />
            <strong>等待源码输入</strong>
            <p>源码就绪后即可开始图谱对话。</p>
          </div>
        ) : !visibleConversation.length ? (
          <div className="graph-agent-empty">
            <Bot size={20} />
            <strong>直接从图谱开始提问</strong>
            <p>Agent 会使用当前项目、固定源码和可用图谱工具回答。</p>
            <div className="graph-agent-prompts">
              {quickPrompts.map((prompt) => (
                <button
                  type="button"
                  key={prompt}
                  disabled={!canWrite || busy || !!activeRun}
                  onClick={() => void send(prompt)}
                >
                  {prompt}
                </button>
              ))}
            </div>
          </div>
        ) : (
          visibleConversation.map((entry) => {
            if (entry.kind === "tool-activity") {
              return (
                <AgentToolActivity
                  key={entry.messageID}
                  calls={entry.calls}
                  current={!!entry.runID && entry.runID === latestRun?.run_id}
                  compact
                />
              );
            }
            if (entry.kind === "empty-message") {
              return (
                <article
                  className="graph-agent-message assistant"
                  key={entry.message.message_id}
                >
                  <span>Agent</span>
                  <p>本轮未返回可显示文本。</p>
                </article>
              );
            }
            const message = entry.message;
            return (
              <article
                className={`graph-agent-message ${message.role}`}
                key={message.message_id}
              >
                <span>{message.role === "user" ? "你" : "Agent"}</span>
                {message.role === "assistant" ? (
                  <Markdown source={message.content} />
                ) : (
                  <p>{message.content}</p>
                )}
              </article>
            );
          })
        )}
        {activeRun && (
          <div className="graph-agent-thinking">
            <Loader2 size={14} className="spin" /> 正在查询当前项目…
          </div>
        )}
      </AgentConversationFeed>

      {error && (
        <p className="graph-agent-error" role="alert">
          {error}
        </p>
      )}

      <div className="graph-agent-composer">
        <textarea
          ref={composer}
          rows={3}
          aria-label="与图谱 Agent 快速对话"
          aria-describedby="graph-agent-composer-help"
          placeholder="询问入口、路径、覆盖或源码事实…"
          value={draft}
          disabled={!canWrite || !available || !session || loading}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            const action = composerAction({
              key: event.key,
              ctrlKey: event.ctrlKey,
              repeat: event.repeat,
              keyCode: event.keyCode,
              isComposing: event.nativeEvent.isComposing,
            });
            if (action === "ignore") return;
            event.preventDefault();
            if (action === "newline") {
              const input = event.currentTarget;
              const next = insertComposerNewline(
                input.value,
                input.selectionStart,
                input.selectionEnd,
              );
              setDraft(next.value);
              window.requestAnimationFrame(() =>
                input.setSelectionRange(next.cursor, next.cursor),
              );
            } else {
              void send();
            }
          }}
        />
        <div>
          <small id="graph-agent-composer-help">
            回车发送 · Ctrl+回车换行
          </small>
          {activeRun ? (
            <button
              type="button"
              className="button secondary"
              disabled={!canWrite}
              onClick={() =>
                void api
                  .cancelSupervisorRun(projectID, sessionID, activeRun.run_id)
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
              <Square size={12} /> 停止
            </button>
          ) : (
            <button
              type="button"
              className="button primary"
              aria-label="发送图谱 Agent 消息"
              disabled={
                !canWrite ||
                !available ||
                !session ||
                loading ||
                busy ||
                !draft.trim()
              }
              onClick={() => void send()}
            >
              {busy ? (
                <Loader2 size={13} className="spin" />
              ) : (
                <Send size={13} />
              )}
              发送
            </button>
          )}
        </div>
      </div>
    </aside>
  );
}
