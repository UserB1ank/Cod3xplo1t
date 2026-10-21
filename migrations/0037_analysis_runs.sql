-- Project-level one-click analysis aggregate (#64).
--
-- The workflow runner remains the executor. This table preserves the fixed
-- plan/invocation lineage, stage projection, coverage and history so a page
-- reload or process restart never guesses a stage from the latest run.

CREATE TABLE IF NOT EXISTS analysis_runs (
    analysis_run_id  TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    snapshot_id      TEXT NOT NULL,
    task_id          TEXT NOT NULL,
    workflow_run_id  TEXT NOT NULL,
    plan_id          TEXT NOT NULL,
    plan_digest      TEXT NOT NULL,
    workflow_id      TEXT NOT NULL,
    workflow_version TEXT NOT NULL,
    state            TEXT NOT NULL,
    agent_assisted   INTEGER NOT NULL DEFAULT 0,
    idempotency_key  TEXT NOT NULL DEFAULT '',
    stages_json      TEXT NOT NULL DEFAULT '[]',
    coverage_json    TEXT NOT NULL DEFAULT '{}',
    limitations_json TEXT NOT NULL DEFAULT '[]',
    path_count       INTEGER NOT NULL DEFAULT 0,
    knowledge_json   TEXT NOT NULL DEFAULT '[]',
    failure_code     TEXT NOT NULL DEFAULT '',
    failure_message  TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    version          BIGINT NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS analysis_runs_idempotency_idx
    ON analysis_runs(project_id, idempotency_key) WHERE idempotency_key <> '';
CREATE UNIQUE INDEX IF NOT EXISTS analysis_runs_active_idx
    ON analysis_runs(project_id) WHERE state IN ('QUEUED', 'CREATED', 'RUNNING', 'PAUSED', 'CANCELLING');
CREATE INDEX IF NOT EXISTS analysis_runs_project_created_idx
    ON analysis_runs(project_id, created_at DESC);
