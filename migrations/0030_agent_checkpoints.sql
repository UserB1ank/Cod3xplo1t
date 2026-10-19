ALTER TABLE agent_runs ADD COLUMN checkpoint_id TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_runs ADD COLUMN resume_of TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS agent_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL,
    audit_id      TEXT NOT NULL,
    path_id       TEXT NOT NULL,
    snapshot_id   TEXT NOT NULL,
    version       INTEGER NOT NULL,
    digest        TEXT NOT NULL,
    document_json TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_checkpoints_run ON agent_checkpoints(run_id, created_at);
