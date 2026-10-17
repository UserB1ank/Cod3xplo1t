CREATE TABLE knowledge_revisions (
    project_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    revision TEXT NOT NULL,
    revision_no INTEGER NOT NULL,
    batch_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    base_revision TEXT NOT NULL,
    document_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, snapshot_id, revision)
);
CREATE UNIQUE INDEX knowledge_revisions_batch ON knowledge_revisions(project_id, snapshot_id, batch_id);
CREATE INDEX knowledge_revisions_head ON knowledge_revisions(project_id, snapshot_id, revision_no);
CREATE TABLE knowledge_outbox (
    event_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    revision TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX knowledge_outbox_scope ON knowledge_outbox(project_id, snapshot_id, revision);
