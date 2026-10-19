CREATE TABLE IF NOT EXISTS agent_audit_budgets (
    audit_id        TEXT PRIMARY KEY,
    limit_tokens    INTEGER NOT NULL,
    reserved_tokens INTEGER NOT NULL DEFAULT 0,
    used_tokens     INTEGER NOT NULL DEFAULT 0,
    version         INTEGER NOT NULL DEFAULT 1,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_budget_grants (
    grant_id     TEXT PRIMARY KEY,
    audit_id     TEXT NOT NULL,
    run_id       TEXT NOT NULL DEFAULT '',
    tokens       INTEGER NOT NULL,
    reason       TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    decision     TEXT NOT NULL,
    decided_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    decided_at   TEXT NOT NULL DEFAULT '',
    version      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_budget_grants_audit ON agent_budget_grants(audit_id, created_at);
