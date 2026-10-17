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
