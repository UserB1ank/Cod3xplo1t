CREATE TABLE IF NOT EXISTS agent_checkpoint_resumes (
    checkpoint_id TEXT PRIMARY KEY,
    claimed_at    TEXT NOT NULL
);
