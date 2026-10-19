-- PostgreSQL shared identity, revocable sessions and login rate-limit windows.
-- Timestamps are Unix milliseconds so the SQL implementation stays identical.
CREATE TABLE IF NOT EXISTS identity_account (
    singleton     INTEGER PRIMARY KEY CHECK (singleton = 1),
    username      TEXT NOT NULL,
    salt          BYTEA NOT NULL,
    password_hash BYTEA NOT NULL,
    iterations    INTEGER NOT NULL,
    created_at    BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_sessions (
    token_hash BYTEA PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_sessions_expiry ON identity_sessions(expires_at);

CREATE TABLE IF NOT EXISTS identity_login_attempts (
    peer_hash         TEXT PRIMARY KEY,
    count             BIGINT NOT NULL,
    window_started_at BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_login_attempts_expiry ON identity_login_attempts(expires_at);
