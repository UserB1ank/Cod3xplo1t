-- Project management for single-source audits (#63).
--
-- A new project owns exactly one implicit audit input. The input is written in
-- the same transaction as the project row and moves importing -> ready only
-- after its immutable snapshot exists. Older projects have no row here and are
-- reported as legacy, which preserves their multi-source history unchanged.
--
-- project_deletions is the durable intent of a DELETE. It is written before any
-- row is removed and only becomes completed after the last project-scoped row
-- is gone, so a retried request resumes cleanup instead of guessing.

ALTER TABLE projects ADD COLUMN description TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS project_inputs (
    project_id      TEXT PRIMARY KEY REFERENCES projects(id),
    state           TEXT NOT NULL,
    source_id       TEXT NOT NULL DEFAULT '',
    source_kind     TEXT NOT NULL DEFAULT '',
    source_name     TEXT NOT NULL DEFAULT '',
    snapshot_id     TEXT NOT NULL DEFAULT '',
    files           INTEGER NOT NULL DEFAULT 0,
    bytes           BIGINT NOT NULL DEFAULT 0,
    failure_code    TEXT NOT NULL DEFAULT '',
    failure_message TEXT NOT NULL DEFAULT '',
    version         BIGINT NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS project_inputs_state_idx ON project_inputs(state, updated_at);

CREATE TABLE IF NOT EXISTS project_deletions (
    project_id TEXT PRIMARY KEY,
    state      TEXT NOT NULL,
    failure    TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS project_deletions_state_idx ON project_deletions(state, updated_at);
