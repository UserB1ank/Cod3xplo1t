-- Encrypted model settings. Ciphertext and its effective configuration version
-- live in the shared database; the installation key stays outside it.
CREATE TABLE IF NOT EXISTS llm_settings (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    ciphertext BLOB NOT NULL,
    version    INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
