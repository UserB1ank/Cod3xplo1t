CREATE TABLE IF NOT EXISTS review_batches (
    batch_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    audit_id TEXT NOT NULL,
    state TEXT NOT NULL,
    path_ids_json TEXT NOT NULL,
    max_concurrent INTEGER NOT NULL CHECK (max_concurrent > 0),
    created_by TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    execution_owner TEXT NOT NULL DEFAULT '',
    lease_epoch BIGINT NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    heartbeat_at TEXT NOT NULL DEFAULT '',
    lease_until TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS review_batches_one_active_audit
    ON review_batches (audit_id)
    WHERE state IN ('RUNNING', 'PAUSED', 'CANCELLING');

CREATE INDEX IF NOT EXISTS review_batches_project_created
    ON review_batches (project_id, created_at DESC);

CREATE INDEX IF NOT EXISTS review_batches_recoverable
    ON review_batches (lease_until, created_at)
    WHERE state IN ('RUNNING', 'CANCELLING');
