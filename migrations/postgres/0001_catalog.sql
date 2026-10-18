-- PostgreSQL catalog profile. Only these domains are wired; execution, graphs
-- and task state require later migrations. Documents and UTC times use TEXT.

CREATE TABLE IF NOT EXISTS projects (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    source        TEXT NOT NULL,
    identity_kind TEXT NOT NULL,
    identity      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id   TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES projects(id),
    commit_sha    TEXT NOT NULL,
    vcs           TEXT NOT NULL,
    worktree_dirty INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    manifest_json TEXT
);

CREATE INDEX IF NOT EXISTS snapshots_project_idx ON snapshots(project_id, created_at);

CREATE TABLE IF NOT EXISTS analyses (
    analysis_id   TEXT PRIMARY KEY,
    snapshot_id   TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    engine        TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    ruleset_hash  TEXT NOT NULL,
    config_hash   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    document_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS analyses_snapshot_idx ON analyses(snapshot_id);

-- Codexploit P1 schema: durable write idempotency.
--
-- One row per claimed (scope, key). status = 0 means "claimed, still running":
-- the request that owns the row is executing and a retry must be told to wait
-- rather than run the work again. CompleteIdempotent() moves the row to the
-- stored response, after which retries replay it. The primary key is what makes
-- the claim atomic: a second concurrent INSERT loses to a unique violation and
-- has to report the winner's state instead of claiming the key twice.
--
-- expires_at is written in a fixed-width UTC timestamp form so that an ordinary
-- string comparison (expires_at <= ?) is also a chronological comparison; the
-- DDL itself stays dialect-neutral (TEXT/INTEGER/BIGINT) and runs unchanged on
-- SQLite and PostgreSQL.

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope         TEXT NOT NULL,
    key           TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    principal     TEXT NOT NULL,
    status        INTEGER NOT NULL,
    body          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);

-- Expiry sweeps and the per-claim expiry check both filter on this column.
CREATE INDEX IF NOT EXISTS idempotency_expiry_idx ON idempotency_keys(expires_at);

-- Conditional project updates and recoverable snapshot deletion.
ALTER TABLE projects ADD COLUMN version BIGINT NOT NULL DEFAULT 1;

-- Completed tombstones reject late writers until explicit re-registration.
CREATE TABLE IF NOT EXISTS snapshot_deletions (
    snapshot_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0
);

-- Versioned explicit inputs coexist with each project's legacy default source.
CREATE TABLE IF NOT EXISTS project_sources (
    source_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    version BIGINT NOT NULL,
    definition_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS project_sources_page_idx ON project_sources(project_id, source_id);

CREATE TABLE IF NOT EXISTS source_snapshots (
    snapshot_id TEXT PRIMARY KEY REFERENCES snapshots(snapshot_id),
    source_id TEXT NOT NULL REFERENCES project_sources(source_id),
    source_version BIGINT NOT NULL
);

CREATE TABLE artifact_refs (
    artifact_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    ref_json TEXT NOT NULL
);
CREATE INDEX artifact_refs_scope ON artifact_refs(project_id, source_id, snapshot_id, artifact_id);
