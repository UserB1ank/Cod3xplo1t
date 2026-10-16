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
