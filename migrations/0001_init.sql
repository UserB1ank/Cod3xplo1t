-- Codexploit P1 schema: projects, snapshots and analyses.
--
-- Later phases add their own tables in their own migrations (modules, symbols,
-- graph_edges, asg_nodes, asg_edges, audit_paths, path_features, path_events,
-- agent_runs, agent_events, hypotheses, findings, evidence, verification_runs).
-- They are intentionally not created here: an unused table is a promise the
-- code does not keep yet.
--
-- The DDL avoids dialect-specific types so the same file runs on SQLite and
-- PostgreSQL. Timestamps are stored as RFC3339 UTC strings; documents are stored
-- as JSON text.

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
