CREATE TABLE artifact_refs (
    artifact_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    ref_json TEXT NOT NULL
);
CREATE INDEX artifact_refs_scope ON artifact_refs(project_id, source_id, snapshot_id, artifact_id);
