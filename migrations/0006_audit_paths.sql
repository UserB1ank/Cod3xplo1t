-- Codexploit P4: AuditPath generation, dedup and scheduling.
--
-- audit_paths is the scheduling unit of the design (§3.3). It stores the resolved
-- chain as steps, the exact dedup signature, the approximate cluster, the feature
-- snapshot and the score, so a ranking can be replayed instead of trusted.
--
-- Attention: `audit_paths.status` is the lifecycle state machine (guide §11) and
-- `path_status` is the evidence class of the candidate (guide §8.1). They answer
-- different questions and must not be conflated.

CREATE TABLE IF NOT EXISTS audits (
    audit_id                   TEXT PRIMARY KEY,
    snapshot_id                TEXT NOT NULL,
    scg_version                TEXT NOT NULL DEFAULT '',
    asg_version                TEXT NOT NULL DEFAULT '',
    status                     TEXT NOT NULL,
    budget_json                TEXT NOT NULL,
    limits_json                TEXT NOT NULL,
    score_version              INTEGER NOT NULL,
    config_hash                TEXT NOT NULL,
    path_count                 INTEGER NOT NULL DEFAULT 0,
    counts_by_status_json      TEXT NOT NULL,
    counts_by_path_status_json TEXT NOT NULL,
    coverage_json              TEXT NOT NULL,
    limitations_json           TEXT NOT NULL,
    created_at                 TEXT NOT NULL,
    updated_at                 TEXT NOT NULL,
    version                    INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS audits_snapshot_idx ON audits(snapshot_id, status);

CREATE TABLE IF NOT EXISTS audit_paths (
    path_id            TEXT PRIMARY KEY,
    audit_id           TEXT NOT NULL,
    snapshot_id        TEXT NOT NULL,
    scg_version        TEXT NOT NULL DEFAULT '',
    asg_version        TEXT NOT NULL DEFAULT '',
    entry_node_id      TEXT NOT NULL,
    target_node_id     TEXT NOT NULL,
    path_kind          TEXT NOT NULL,
    path_status        TEXT NOT NULL,
    status             TEXT NOT NULL,
    steps_json         TEXT NOT NULL,
    signature          TEXT NOT NULL,
    cluster_json       TEXT NOT NULL,
    scg_refs_json      TEXT NOT NULL,
    asg_refs_json      TEXT NOT NULL,
    objectives_json    TEXT NOT NULL,
    boundaries_json    TEXT NOT NULL,
    controls_json      TEXT NOT NULL,
    inputs_json        TEXT NOT NULL,
    assets_json        TEXT NOT NULL,
    open_questions_json TEXT NOT NULL,
    limitations_json   TEXT NOT NULL,
    depth              INTEGER NOT NULL DEFAULT 0,
    branch_count       INTEGER NOT NULL DEFAULT 0,
    budget_json        TEXT NOT NULL,
    features_json      TEXT NOT NULL,
    risk               REAL NOT NULL DEFAULT 0,
    support            REAL NOT NULL DEFAULT 0,
    utility            REAL NOT NULL DEFAULT 0,
    priority           REAL NOT NULL DEFAULT 0,
    score_version      INTEGER NOT NULL DEFAULT 1,
    weights_json       TEXT NOT NULL,
    score_seq          INTEGER NOT NULL DEFAULT 0,
    lease_owner        TEXT NOT NULL DEFAULT '',
    lease_until        TEXT NOT NULL DEFAULT '',
    heartbeat_at       TEXT NOT NULL DEFAULT '',
    attempts           INTEGER NOT NULL DEFAULT 0,
    max_attempts       INTEGER NOT NULL DEFAULT 0,
    last_error         TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    version            INTEGER NOT NULL DEFAULT 1
);

-- Queue order: the scheduler reads queued paths of one audit by priority.
CREATE INDEX IF NOT EXISTS audit_paths_queue_idx ON audit_paths(audit_id, status, priority DESC, path_id);
CREATE INDEX IF NOT EXISTS audit_paths_snapshot_idx ON audit_paths(snapshot_id, status);
CREATE INDEX IF NOT EXISTS audit_paths_targets_idx ON audit_paths(audit_id, entry_node_id, target_node_id);
-- Exact dedup inside one audit is a database invariant, not a convention.
CREATE UNIQUE INDEX IF NOT EXISTS audit_paths_signature_idx ON audit_paths(audit_id, signature);

CREATE TABLE IF NOT EXISTS path_features (
    path_id       TEXT NOT NULL,
    seq           INTEGER NOT NULL,
    audit_id      TEXT NOT NULL,
    score_version INTEGER NOT NULL,
    risk          REAL NOT NULL,
    support       REAL NOT NULL,
    utility       REAL NOT NULL,
    priority      REAL NOT NULL,
    features_json TEXT NOT NULL,
    weights_json  TEXT NOT NULL,
    reasons_json  TEXT NOT NULL,
    computed_at   TEXT NOT NULL,
    PRIMARY KEY (path_id, seq)
);

CREATE INDEX IF NOT EXISTS path_features_audit_idx ON path_features(audit_id);

-- The event log is append-only: corrections are new events, never overwrites.
-- `seq` is audit-scoped, which is what makes appending after a rerun collision-free.
CREATE TABLE IF NOT EXISTS path_events (
    event_id    TEXT PRIMARY KEY,
    audit_id    TEXT NOT NULL,
    path_id     TEXT NOT NULL DEFAULT '',
    seq         INTEGER NOT NULL,
    type        TEXT NOT NULL,
    from_status TEXT NOT NULL DEFAULT '',
    to_status   TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS path_events_seq_idx ON path_events(audit_id, seq);
CREATE INDEX IF NOT EXISTS path_events_path_idx ON path_events(audit_id, path_id, seq);
