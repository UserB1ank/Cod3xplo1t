-- Encrypted model settings in the shared PostgreSQL store. The installation
-- key is supplied by an independent deployment secret, never this table.
CREATE TABLE IF NOT EXISTS llm_settings (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    ciphertext BYTEA NOT NULL,
    version    BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
