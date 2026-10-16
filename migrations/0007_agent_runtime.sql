-- Codexploit P5: agent runs, their event streams and the hypotheses they produce.
--
-- The orchestrator owns the process, the lease and the budget; the agent owns only
-- its bounded reasoning. That split is why a run is a row here rather than a
-- session inside an agent: a run survives a crashed adapter, and its events are the
-- audit trail of what the agent was given and what it asked for.
--
-- No hidden chain of thought is stored: `agent_events` holds the explicit,
-- auditable exchanges (task, tool requests and their results, expansion decisions,
-- structured output) and nothing else.

CREATE TABLE IF NOT EXISTS agent_runs (
    run_id             TEXT PRIMARY KEY,
    path_id            TEXT NOT NULL,
    audit_id           TEXT NOT NULL,
    snapshot_id        TEXT NOT NULL,
    runtime            TEXT NOT NULL,
    runtime_version    TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL,
    -- The task is stored verbatim: reproducing what an agent was asked is the only
    -- way to judge what it answered.
    task_json          TEXT NOT NULL,
    exploration_json   TEXT NOT NULL,
    budget_json        TEXT NOT NULL,
    -- Budget actually consumed, updated as events arrive.
    tool_calls         INTEGER NOT NULL DEFAULT 0,
    expansions         INTEGER NOT NULL DEFAULT 0,
    input_tokens       INTEGER NOT NULL DEFAULT 0,
    output_tokens      INTEGER NOT NULL DEFAULT 0,
    elapsed_ms         BIGINT NOT NULL DEFAULT 0,
    -- Lease/heartbeat of the run itself, independent of the path lease.
    owner              TEXT NOT NULL DEFAULT '',
    started_at         TEXT NOT NULL DEFAULT '',
    deadline_at        TEXT NOT NULL DEFAULT '',
    heartbeat_at       TEXT NOT NULL DEFAULT '',
    finished_at        TEXT NOT NULL DEFAULT '',
    exit_code          INTEGER,
    stop_reason        TEXT NOT NULL DEFAULT '',
    error              TEXT NOT NULL DEFAULT '',
    output_json        TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    version            INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS agent_runs_path_idx ON agent_runs(path_id, created_at);
CREATE INDEX IF NOT EXISTS agent_runs_status_idx ON agent_runs(snapshot_id, status);
CREATE INDEX IF NOT EXISTS agent_runs_audit_idx ON agent_runs(audit_id, status);

-- Append-only, numbered per run. A tool request and its result are two events with
-- the same call id, so a replay can put the exchange back together.
CREATE TABLE IF NOT EXISTS agent_events (
    event_id   TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL,
    path_id    TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    type       TEXT NOT NULL,
    call_id    TEXT NOT NULL DEFAULT '',
    tool       TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT 'agent',
    summary    TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_events_seq_idx ON agent_events(run_id, seq);
CREATE INDEX IF NOT EXISTS agent_events_type_idx ON agent_events(run_id, type, seq);

CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id     TEXT PRIMARY KEY,
    run_id            TEXT NOT NULL,
    path_id           TEXT NOT NULL,
    audit_id          TEXT NOT NULL,
    snapshot_id       TEXT NOT NULL,
    -- The security goal the hypothesis answers, copied from the task.
    security_goal     TEXT NOT NULL,
    statement         TEXT NOT NULL,
    status            TEXT NOT NULL,
    confidence        TEXT NOT NULL,
    -- Evidence is referenced, never inlined: supporting and contradicting evidence
    -- are separate lists because the contradiction is the interesting part.
    supporting_json   TEXT NOT NULL,
    contradicting_json TEXT NOT NULL,
    next_action       TEXT NOT NULL DEFAULT '',
    finding_candidate INTEGER NOT NULL DEFAULT 0,
    severity_hint     TEXT NOT NULL DEFAULT '',
    digest            TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS hypotheses_digest_idx ON hypotheses(path_id, digest);
CREATE INDEX IF NOT EXISTS hypotheses_run_idx ON hypotheses(run_id);
CREATE INDEX IF NOT EXISTS hypotheses_audit_idx ON hypotheses(audit_id, status);
