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
