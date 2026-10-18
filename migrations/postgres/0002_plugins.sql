CREATE TABLE plugin_versions (
    plugin_id TEXT NOT NULL,
    version TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (plugin_id, version)
);
CREATE TABLE plugin_invocations (
    invocation_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,
    document_json TEXT NOT NULL
);
CREATE INDEX plugin_invocations_scope ON plugin_invocations(project_id, snapshot_id, invocation_id);
