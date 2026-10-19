-- PostgreSQL task, execution, finding and workflow state.

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
    risk               DOUBLE PRECISION NOT NULL DEFAULT 0,
    support            DOUBLE PRECISION NOT NULL DEFAULT 0,
    utility            DOUBLE PRECISION NOT NULL DEFAULT 0,
    priority           DOUBLE PRECISION NOT NULL DEFAULT 0,
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
    risk          DOUBLE PRECISION NOT NULL,
    support       DOUBLE PRECISION NOT NULL,
    utility       DOUBLE PRECISION NOT NULL,
    priority      DOUBLE PRECISION NOT NULL,
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


-- Codexploit P5: agent runs, their event streams and the hypotheses they produce.
--
-- The orchestrator owns the process, the lease and the budget; the agent owns only
-- its bounded reasoning. That split is why a run is a row here rather than a
-- session inside an agent: a run survives a crashed adapter, and its events are the
-- audit trail of what the agent was given and what it asked for.
--
-- No hidden chain of thought is stored: `agent_events` holds the explicit,
-- auditable exchanges (task, tool requests and their results, expansion decisions,
-- structured output) and nothing else.

CREATE TABLE IF NOT EXISTS agent_runs (
    run_id             TEXT PRIMARY KEY,
    path_id            TEXT NOT NULL,
    audit_id           TEXT NOT NULL,
    snapshot_id        TEXT NOT NULL,
    runtime            TEXT NOT NULL,
    runtime_version    TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL,
    -- The task is stored verbatim: reproducing what an agent was asked is the only
    -- way to judge what it answered.
    task_json          TEXT NOT NULL,
    exploration_json   TEXT NOT NULL,
    budget_json        TEXT NOT NULL,
    -- Budget actually consumed, updated as events arrive.
    tool_calls         INTEGER NOT NULL DEFAULT 0,
    expansions         INTEGER NOT NULL DEFAULT 0,
    input_tokens       INTEGER NOT NULL DEFAULT 0,
    output_tokens      INTEGER NOT NULL DEFAULT 0,
    elapsed_ms         BIGINT NOT NULL DEFAULT 0,
    -- Lease/heartbeat of the run itself, independent of the path lease.
    owner              TEXT NOT NULL DEFAULT '',
    started_at         TEXT NOT NULL DEFAULT '',
    deadline_at        TEXT NOT NULL DEFAULT '',
    heartbeat_at       TEXT NOT NULL DEFAULT '',
    finished_at        TEXT NOT NULL DEFAULT '',
    exit_code          INTEGER,
    stop_reason        TEXT NOT NULL DEFAULT '',
    error              TEXT NOT NULL DEFAULT '',
    output_json        TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    version            INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS agent_runs_path_idx ON agent_runs(path_id, created_at);
CREATE INDEX IF NOT EXISTS agent_runs_status_idx ON agent_runs(snapshot_id, status);
CREATE INDEX IF NOT EXISTS agent_runs_audit_idx ON agent_runs(audit_id, status);

-- Append-only, numbered per run. A tool request and its result are two events with
-- the same call id, so a replay can put the exchange back together.
CREATE TABLE IF NOT EXISTS agent_events (
    event_id   TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL,
    path_id    TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    type       TEXT NOT NULL,
    call_id    TEXT NOT NULL DEFAULT '',
    tool       TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT 'agent',
    summary    TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_events_seq_idx ON agent_events(run_id, seq);
CREATE INDEX IF NOT EXISTS agent_events_type_idx ON agent_events(run_id, type, seq);

CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id     TEXT PRIMARY KEY,
    run_id            TEXT NOT NULL,
    path_id           TEXT NOT NULL,
    audit_id          TEXT NOT NULL,
    snapshot_id       TEXT NOT NULL,
    -- The security goal the hypothesis answers, copied from the task.
    security_goal     TEXT NOT NULL,
    statement         TEXT NOT NULL,
    status            TEXT NOT NULL,
    confidence        TEXT NOT NULL,
    -- Evidence is referenced, never inlined: supporting and contradicting evidence
    -- are separate lists because the contradiction is the interesting part.
    supporting_json   TEXT NOT NULL,
    contradicting_json TEXT NOT NULL,
    next_action       TEXT NOT NULL DEFAULT '',
    finding_candidate INTEGER NOT NULL DEFAULT 0,
    severity_hint     TEXT NOT NULL DEFAULT '',
    digest            TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS hypotheses_digest_idx ON hypotheses(path_id, digest);
CREATE INDEX IF NOT EXISTS hypotheses_run_idx ON hypotheses(run_id);
CREATE INDEX IF NOT EXISTS hypotheses_audit_idx ON hypotheses(audit_id, status);


-- Codexploit P6: isolated verification runs, immutable evidence and findings.
--
-- Three tables, three rules:
--   verification_runs  one attempt to verify one hypothesis against one plan; the
--                      plan hash makes a rerun a replay instead of a new attempt;
--   evidence           append-only, content-addressed objects. A correction is a
--                      new object that supersedes the old one; nothing is updated;
--   findings           one row per hypothesis, whose status only verification may
--                      move past `candidate`. `refuted` means contradicting
--                      evidence exists, which is not the same as "not reproduced".

CREATE TABLE IF NOT EXISTS verification_runs (
    run_id            TEXT PRIMARY KEY,
    hypothesis_id     TEXT NOT NULL,
    finding_id        TEXT NOT NULL,
    path_id           TEXT NOT NULL,
    audit_id          TEXT NOT NULL,
    snapshot_id       TEXT NOT NULL,
    -- plan_hash is the exact plan that was executed; the same plan for the same
    -- hypothesis is the same verification.
    plan_hash         TEXT NOT NULL,
    plan_json         TEXT NOT NULL,
    environment_json  TEXT NOT NULL,
    environment_digest TEXT NOT NULL DEFAULT '',
    outcome           TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL,
    executor          TEXT NOT NULL,
    executor_version  TEXT NOT NULL DEFAULT '',
    -- Border controls: whether the scope allowed network access and whether a human
    -- approved the plan. Both are recorded, because a verification without them is
    -- not reproducible evidence.
    network_allowed   INTEGER NOT NULL DEFAULT 0,
    approved          INTEGER NOT NULL DEFAULT 0,
    approved_by       TEXT NOT NULL DEFAULT '',
    approved_at       TEXT NOT NULL DEFAULT '',
    owner             TEXT NOT NULL DEFAULT '',
    exit_code         INTEGER,
    stop_reason       TEXT NOT NULL DEFAULT '',
    error             TEXT NOT NULL DEFAULT '',
    reproduction      TEXT NOT NULL DEFAULT '',
    started_at        TEXT NOT NULL DEFAULT '',
    finished_at       TEXT NOT NULL DEFAULT '',
    elapsed_ms        BIGINT NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    version           INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS verification_runs_plan_idx ON verification_runs(hypothesis_id, plan_hash);
CREATE INDEX IF NOT EXISTS verification_runs_finding_idx ON verification_runs(finding_id, created_at);
CREATE INDEX IF NOT EXISTS verification_runs_snapshot_idx ON verification_runs(snapshot_id, status);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id       TEXT PRIMARY KEY,
    kind              TEXT NOT NULL,
    -- Provenance: which tool produced this, at which version, from which snapshot and
    -- about which hypothesis, path and finding.
    tool              TEXT NOT NULL,
    tool_version      TEXT NOT NULL DEFAULT '',
    snapshot_id       TEXT NOT NULL,
    hypothesis_id     TEXT NOT NULL DEFAULT '',
    finding_id        TEXT NOT NULL DEFAULT '',
    path_id           TEXT NOT NULL DEFAULT '',
    verification_run_id TEXT NOT NULL DEFAULT '',
    -- Source location when the evidence points at code.
    file              TEXT NOT NULL DEFAULT '',
    line              INTEGER NOT NULL DEFAULT 0,
    -- content_hash is the digest of the *redacted* content, so the hash and the stored
    -- bytes always agree. redacted records that a transformation happened.
    content_hash      TEXT NOT NULL,
    content           TEXT NOT NULL,
    redacted          INTEGER NOT NULL DEFAULT 0,
    redaction_notes   TEXT NOT NULL DEFAULT '',
    -- supersedes points at the evidence this one corrects; the old object stays.
    supersedes        TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS evidence_finding_idx ON evidence(finding_id, created_at);
CREATE INDEX IF NOT EXISTS evidence_hypothesis_idx ON evidence(hypothesis_id, created_at);
CREATE INDEX IF NOT EXISTS evidence_run_idx ON evidence(verification_run_id, created_at);
CREATE INDEX IF NOT EXISTS evidence_snapshot_idx ON evidence(snapshot_id, kind);

CREATE TABLE IF NOT EXISTS findings (
    finding_id        TEXT PRIMARY KEY,
    hypothesis_id     TEXT NOT NULL,
    path_id           TEXT NOT NULL,
    audit_id          TEXT NOT NULL,
    snapshot_id       TEXT NOT NULL,
    title             TEXT NOT NULL,
    severity          TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL,
    confidence        TEXT NOT NULL DEFAULT '',
    -- Evidence is referenced, never inlined, and the three lists stay separate
    -- because a contradiction is the interesting part.
    supporting_json   TEXT NOT NULL,
    contradicting_json TEXT NOT NULL,
    inconclusive_json TEXT NOT NULL,
    verification_run_ids_json TEXT NOT NULL,
    environments_json TEXT NOT NULL,
    reproduce_steps   TEXT NOT NULL DEFAULT '',
    limitations_json  TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    version           INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS findings_hypothesis_idx ON findings(hypothesis_id);
CREATE INDEX IF NOT EXISTS findings_audit_idx ON findings(audit_id, status);
CREATE INDEX IF NOT EXISTS findings_snapshot_idx ON findings(snapshot_id, status);


-- Codexploit P7: retry scheduling for AuditPaths.
--
-- A failed attempt must not be retried immediately and forever. The path carries
-- when it is next allowed to run, so the scheduler can skip work that is in backoff
-- without holding a lease on it, and so a crash loses nothing: the due time is
-- durable state, not a timer in a process.
--
-- `attempts` already exists and is incremented when a run settles; this column is
-- the other half of that policy.

ALTER TABLE audit_paths ADD COLUMN next_attempt_at TEXT NOT NULL DEFAULT '';

-- The scheduler's query is "queued paths of this audit whose backoff has elapsed",
-- which is why the index leads with the two columns it filters on.
CREATE INDEX IF NOT EXISTS audit_paths_due_idx ON audit_paths(audit_id, status, next_attempt_at, priority DESC, path_id);


ALTER TABLE audits ADD COLUMN task_name TEXT NOT NULL DEFAULT '';
ALTER TABLE audits ADD COLUMN objective TEXT NOT NULL DEFAULT '';
ALTER TABLE audits ADD COLUMN scope_json TEXT NOT NULL DEFAULT 'null';
ALTER TABLE audits ADD COLUMN paused INTEGER NOT NULL DEFAULT 0;


ALTER TABLE audit_paths ADD COLUMN entry_kind TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_paths ADD COLUMN entry_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_paths ADD COLUMN target_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_paths ADD COLUMN target_kind TEXT NOT NULL DEFAULT '';

UPDATE audit_paths SET entry_subject = COALESCE((SELECT subject FROM asg_nodes WHERE node_id = audit_paths.entry_node_id AND snapshot_id = audit_paths.snapshot_id), '');
UPDATE audit_paths SET target_subject = COALESCE((SELECT subject FROM asg_nodes WHERE node_id = audit_paths.target_node_id AND snapshot_id = audit_paths.snapshot_id), '');
UPDATE audit_paths SET target_kind = COALESCE((SELECT kind FROM asg_nodes WHERE node_id = audit_paths.target_node_id AND snapshot_id = audit_paths.snapshot_id), '');


ALTER TABLE audits ADD COLUMN task_pinned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audits ADD COLUMN task_archived INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audits ADD COLUMN task_category TEXT NOT NULL DEFAULT '';
ALTER TABLE projects ADD COLUMN task_categories_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE projects ADD COLUMN task_categories_version INTEGER NOT NULL DEFAULT 1;


CREATE TABLE workflow_versions (
 project_id TEXT NOT NULL,
 workflow_id TEXT NOT NULL,
 version TEXT NOT NULL,
 digest TEXT NOT NULL,
 record_json TEXT NOT NULL,
 PRIMARY KEY(project_id,workflow_id,version)
);
CREATE TABLE workflow_heads (
 project_id TEXT NOT NULL,
 workflow_id TEXT NOT NULL,
 digest TEXT NOT NULL,
 version TEXT NOT NULL,
 PRIMARY KEY(project_id,workflow_id)
);
CREATE TABLE workflow_plans (
 plan_id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 document_json TEXT NOT NULL
);
CREATE INDEX workflow_plans_scope ON workflow_plans(project_id,snapshot_id);


CREATE TABLE workflow_runs (
 run_id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 task_id TEXT NOT NULL UNIQUE,
 plan_id TEXT NOT NULL,
 status TEXT NOT NULL,
 version INTEGER NOT NULL,
 document_json TEXT NOT NULL
);
CREATE INDEX workflow_runs_scope ON workflow_runs(project_id,snapshot_id);


-- Plugin observations grouped by a versioned fingerprint, plus append-only
-- severity assessments. The findings table still owns the verdict and its
-- optimistic version; these tables add provenance and review history without
-- letting a plugin write `confirmed`.

CREATE TABLE IF NOT EXISTS finding_observations (
    observation_id      TEXT PRIMARY KEY,
    finding_id          TEXT NOT NULL,
    project_id          TEXT NOT NULL,
    snapshot_id         TEXT NOT NULL,
    task_id             TEXT NOT NULL DEFAULT '',
    fingerprint         TEXT NOT NULL,
    fingerprint_version TEXT NOT NULL,
    -- content_hash makes a replay with a fresh timestamp a no-op, while the same
    -- observation id with different content is a conflict.
    content_hash        TEXT NOT NULL,
    observation_json    TEXT NOT NULL,
    created_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS finding_observations_finding_idx ON finding_observations(finding_id, created_at);
CREATE INDEX IF NOT EXISTS finding_observations_project_idx ON finding_observations(project_id, created_at);
CREATE INDEX IF NOT EXISTS finding_observations_task_idx ON finding_observations(task_id, created_at);
CREATE INDEX IF NOT EXISTS finding_observations_snapshot_idx ON finding_observations(snapshot_id, created_at);
CREATE INDEX IF NOT EXISTS finding_observations_fingerprint_idx ON finding_observations(fingerprint_version, fingerprint);

CREATE TABLE IF NOT EXISTS finding_severity_audits (
    audit_id          TEXT PRIMARY KEY,
    finding_id        TEXT NOT NULL,
    version           INTEGER NOT NULL,
    previous_severity TEXT NOT NULL DEFAULT '',
    severity          TEXT NOT NULL,
    reason            TEXT NOT NULL,
    actor             TEXT NOT NULL,
    created_at        TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS finding_severity_audits_version_idx ON finding_severity_audits(finding_id, version);
CREATE INDEX IF NOT EXISTS finding_severity_audits_finding_idx ON finding_severity_audits(finding_id, version);
ALTER TABLE audit_paths ADD COLUMN lease_epoch BIGINT NOT NULL DEFAULT 0;

CREATE TABLE workflow_leases (
    run_id TEXT PRIMARY KEY REFERENCES workflow_runs(run_id),
    owner TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL
);

CREATE TABLE runtime_hosts (
    host_id TEXT PRIMARY KEY,
    epoch BIGINT NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL
);
ALTER TABLE plugin_invocations ADD COLUMN host_id TEXT NOT NULL DEFAULT '';
ALTER TABLE plugin_invocations ADD COLUMN host_epoch BIGINT NOT NULL DEFAULT 0;

CREATE TABLE workflow_node_claims (
    invocation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES workflow_runs(run_id),
    epoch BIGINT NOT NULL
);
ALTER TABLE agent_runs ADD COLUMN lease_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE agent_runs ADD COLUMN host_id TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_runs ADD COLUMN host_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE verification_runs ADD COLUMN host_id TEXT NOT NULL DEFAULT '';
ALTER TABLE verification_runs ADD COLUMN host_epoch BIGINT NOT NULL DEFAULT 0;

ALTER TABLE agent_runs ADD COLUMN workflow_run_id TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_runs ADD COLUMN workflow_epoch BIGINT NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX agent_runs_path_allocation_idx ON agent_runs(path_id, lease_epoch) WHERE lease_epoch > 0;
