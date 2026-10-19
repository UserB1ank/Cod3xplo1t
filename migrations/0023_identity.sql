-- Shared administrator identity, revocable sessions and login rate-limit
-- windows. Timestamps are Unix milliseconds so comparisons are dialect-neutral.
CREATE TABLE IF NOT EXISTS identity_account (
    singleton     INTEGER PRIMARY KEY CHECK (singleton = 1),
    username      TEXT NOT NULL,
    salt          BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    iterations    INTEGER NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_sessions (
    token_hash BLOB PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_sessions_expiry ON identity_sessions(expires_at);

CREATE TABLE IF NOT EXISTS identity_login_attempts (
    peer_hash         TEXT PRIMARY KEY,
    count             INTEGER NOT NULL,
    window_started_at INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_login_attempts_expiry ON identity_login_attempts(expires_at);
