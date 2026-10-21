-- Project supervisor conversation (#66). Messages, runs and ordered events are
-- kept in one bounded document so a turn cannot be observed half-written.

CREATE TABLE IF NOT EXISTS supervisor_sessions (
    session_id    TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    snapshot_id   TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    state         TEXT NOT NULL,
    document_json TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    version       BIGINT NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS supervisor_sessions_project_idx
    ON supervisor_sessions(project_id, created_at DESC);
