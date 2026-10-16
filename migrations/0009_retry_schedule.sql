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
