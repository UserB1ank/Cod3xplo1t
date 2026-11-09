-- Investigation knowledge is append-only and separate from verification verdicts.
CREATE TABLE knowledge_claim_heads (
    snapshot_id TEXT PRIMARY KEY REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0)
);

CREATE TABLE knowledge_claim_records (
    record_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES knowledge_claim_heads(snapshot_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    claim_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('claim', 'observation', 'question', 'evidence')),
    request_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    document_json TEXT NOT NULL,
    UNIQUE(snapshot_id, revision),
    UNIQUE(snapshot_id, request_key)
);
CREATE UNIQUE INDEX knowledge_claim_identity_idx ON knowledge_claim_records(snapshot_id, claim_id) WHERE kind='claim';
CREATE INDEX knowledge_claim_detail_idx ON knowledge_claim_records(snapshot_id, claim_id, revision);

CREATE TABLE knowledge_claim_outbox (
    record_id TEXT PRIMARY KEY REFERENCES knowledge_claim_records(record_id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL REFERENCES knowledge_claim_heads(snapshot_id) ON DELETE CASCADE,
    revision BIGINT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type='knowledge_appended')
);
