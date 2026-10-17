-- Versioned explicit inputs coexist with each project's legacy default source.
CREATE TABLE IF NOT EXISTS project_sources (
    source_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    version BIGINT NOT NULL,
    definition_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS project_sources_page_idx ON project_sources(project_id, source_id);

CREATE TABLE IF NOT EXISTS source_snapshots (
    snapshot_id TEXT PRIMARY KEY REFERENCES snapshots(snapshot_id),
    source_id TEXT NOT NULL REFERENCES project_sources(source_id),
    source_version BIGINT NOT NULL
);
