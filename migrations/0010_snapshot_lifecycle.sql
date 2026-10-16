-- Conditional project updates and recoverable snapshot deletion.
ALTER TABLE projects ADD COLUMN version BIGINT NOT NULL DEFAULT 1;

-- Completed tombstones reject late writers until explicit re-registration.
CREATE TABLE IF NOT EXISTS snapshot_deletions (
    snapshot_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0
);
