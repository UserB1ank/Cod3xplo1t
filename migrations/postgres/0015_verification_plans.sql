CREATE TABLE verification_plans (
    plan_id       TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL,
    state         TEXT NOT NULL,
    plan_json     TEXT NOT NULL,
    approval_json TEXT NOT NULL DEFAULT '',
    version       BIGINT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX verification_plans_project_state ON verification_plans (project_id, state, created_at);
