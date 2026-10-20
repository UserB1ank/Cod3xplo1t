import { useEffect, useRef, useState } from "react";
import { ApiClient } from "./api";
import { AuditEvent } from "./types";
import { EmptyState, Failure } from "./components";
import { dateLabel, eventNames, shortId } from "./domain";

// EventFeed is the agent log: it follows one run (or the whole task) by cursor,
// keeps the last 500 entries and lets a reviewer expand the raw payload. It is
// shared by the task page and the project activity panel.
export function EventFeed({ api, endpoint }: { api: ApiClient; endpoint: string }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState("");
  const cursor = useRef(0);
  const feed = useRef<HTMLDivElement>(null);
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
  useEffect(() => {
    const element = feed.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [events]);
  return (
    <>
      {error && <Failure message={error} />}
      {events.length ? (
        <div className="event-feed" ref={feed}>
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

function errorText(error: unknown) {
  return error instanceof Error ? error.message : "事件读取失败";
}
