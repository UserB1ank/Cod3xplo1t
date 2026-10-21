CREATE TABLE environment_leases (
    lease_id       TEXT PRIMARY KEY,
    plan_id        TEXT NOT NULL,
    project_id     TEXT NOT NULL,
    snapshot_id    TEXT NOT NULL,
    owner          TEXT NOT NULL,
    provider       TEXT NOT NULL,
    environment_id TEXT NOT NULL DEFAULT '',
    image_digest   TEXT NOT NULL DEFAULT '',
    source_digest  TEXT NOT NULL DEFAULT '',
    receipt_digest TEXT NOT NULL DEFAULT '',
    epoch          INTEGER NOT NULL,
    state          TEXT NOT NULL,
    cleanup        TEXT NOT NULL,
    failure        TEXT NOT NULL DEFAULT '',
    expires_at     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX environment_leases_owner_state ON environment_leases (owner, state);
CREATE INDEX environment_leases_expiry ON environment_leases (expires_at);
