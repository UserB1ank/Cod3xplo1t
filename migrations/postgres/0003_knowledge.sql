-- Fixed graph indexes and atomic shared knowledge publications.


CREATE TABLE IF NOT EXISTS graph_builds (
    snapshot_id         TEXT PRIMARY KEY,
    graph_version       TEXT NOT NULL,
    engine              TEXT NOT NULL,
    engine_version      TEXT NOT NULL,
    frontends_json      TEXT NOT NULL,
    coverage_json       TEXT NOT NULL,
    limitations_json    TEXT NOT NULL,
    resolution_json     TEXT NOT NULL,
    edges_by_kind_json  TEXT NOT NULL,
    modules             INTEGER NOT NULL,
    files               INTEGER NOT NULL,
    symbols             INTEGER NOT NULL,
    call_sites          INTEGER NOT NULL,
    edges               INTEGER NOT NULL,
    built_at            TEXT NOT NULL,
    build_duration_ms   BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS scg_modules (
    module_id       TEXT PRIMARY KEY,
    snapshot_id     TEXT NOT NULL,
    path            TEXT NOT NULL,
    name            TEXT NOT NULL,
    language        TEXT NOT NULL,
    manifest_file   TEXT NOT NULL,
    files           INTEGER NOT NULL,
    symbols         INTEGER NOT NULL,
    lines           INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS scg_modules_snapshot_idx ON scg_modules(snapshot_id, path);

CREATE TABLE IF NOT EXISTS scg_files (
    file_id       TEXT PRIMARY KEY,
    snapshot_id   TEXT NOT NULL,
    module_id     TEXT NOT NULL,
    path          TEXT NOT NULL,
    language      TEXT NOT NULL,
    bytes         BIGINT NOT NULL,
    lines         INTEGER NOT NULL,
    parse_status  TEXT NOT NULL,
    parse_error   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS scg_files_snapshot_idx ON scg_files(snapshot_id, module_id, path);

CREATE TABLE IF NOT EXISTS scg_symbols (
    symbol_id       TEXT PRIMARY KEY,
    snapshot_id     TEXT NOT NULL,
    module_id       TEXT NOT NULL,
    file_id         TEXT NOT NULL,
    file            TEXT NOT NULL,
    language        TEXT NOT NULL,
    kind            TEXT NOT NULL,
    name            TEXT NOT NULL,
    qualified_name  TEXT NOT NULL,
    signature       TEXT NOT NULL,
    receiver        TEXT NOT NULL,
    result_type     TEXT NOT NULL,
    exported        INTEGER NOT NULL,
    start_line      INTEGER NOT NULL,
    end_line        INTEGER NOT NULL,
    start_col       INTEGER NOT NULL,
    end_col         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS scg_symbols_snapshot_idx ON scg_symbols(snapshot_id, module_id, qualified_name);
CREATE INDEX IF NOT EXISTS scg_symbols_name_idx ON scg_symbols(snapshot_id, name);
CREATE INDEX IF NOT EXISTS scg_symbols_file_idx ON scg_symbols(snapshot_id, file_id);

CREATE TABLE IF NOT EXISTS scg_call_sites (
    call_site_id        TEXT PRIMARY KEY,
    snapshot_id         TEXT NOT NULL,
    caller_symbol_id    TEXT NOT NULL,
    file_id             TEXT NOT NULL,
    file                TEXT NOT NULL,
    line                INTEGER NOT NULL,
    col                 INTEGER NOT NULL,
    callee_text         TEXT NOT NULL,
    callee_symbol_id    TEXT NOT NULL,
    callee_qualified    TEXT NOT NULL,
    resolution          TEXT NOT NULL,
    confidence          TEXT NOT NULL,
    detail              TEXT NOT NULL,
    analyzer            TEXT NOT NULL,
    analyzer_version    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS scg_call_sites_caller_idx ON scg_call_sites(snapshot_id, caller_symbol_id);
CREATE INDEX IF NOT EXISTS scg_call_sites_file_idx ON scg_call_sites(snapshot_id, file_id, line);

CREATE TABLE IF NOT EXISTS scg_edges (
    edge_id           TEXT PRIMARY KEY,
    snapshot_id       TEXT NOT NULL,
    from_id           TEXT NOT NULL,
    to_id             TEXT NOT NULL,
    kind              TEXT NOT NULL,
    resolution        TEXT NOT NULL,
    confidence        TEXT NOT NULL,
    file              TEXT NOT NULL,
    line              INTEGER NOT NULL,
    col               INTEGER NOT NULL,
    analyzer          TEXT NOT NULL,
    analyzer_version  TEXT NOT NULL,
    call_site_id      TEXT NOT NULL,
    detail_json       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS scg_edges_from_idx ON scg_edges(snapshot_id, from_id, kind);
CREATE INDEX IF NOT EXISTS scg_edges_to_idx ON scg_edges(snapshot_id, to_id, kind);

ALTER TABLE scg_call_sites ADD COLUMN args_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE scg_call_sites ADD COLUMN receiver_from TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS asg_builds (
    snapshot_id         TEXT PRIMARY KEY,
    asg_version         TEXT NOT NULL,
    scg_version         TEXT NOT NULL,
    engine              TEXT NOT NULL,
    engine_version      TEXT NOT NULL,
    ruleset_hash        TEXT NOT NULL,
    nodes               INTEGER NOT NULL,
    edges               INTEGER NOT NULL,
    nodes_by_kind_json  TEXT NOT NULL,
    edges_by_kind_json  TEXT NOT NULL,
    evidence_json       TEXT NOT NULL,
    coverage_json       TEXT NOT NULL,
    limitations_json    TEXT NOT NULL,
    built_at            TEXT NOT NULL,
    build_duration_ms   BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS asg_nodes (
    node_id         TEXT PRIMARY KEY,
    snapshot_id     TEXT NOT NULL,
    kind            TEXT NOT NULL,
    subject         TEXT NOT NULL,
    label           TEXT NOT NULL,
    detail_json     TEXT NOT NULL,
    evidence_status TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    generator       TEXT NOT NULL,
    module_id       TEXT NOT NULL,
    file            TEXT NOT NULL,
    line            INTEGER NOT NULL,
    scg_refs_json   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS asg_nodes_snapshot_idx ON asg_nodes(snapshot_id, kind, label);
CREATE INDEX IF NOT EXISTS asg_nodes_subject_idx ON asg_nodes(snapshot_id, subject);

CREATE TABLE IF NOT EXISTS asg_edges (
    edge_id         TEXT PRIMARY KEY,
    snapshot_id     TEXT NOT NULL,
    from_id         TEXT NOT NULL,
    to_id           TEXT NOT NULL,
    kind            TEXT NOT NULL,
    evidence_status TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    generator       TEXT NOT NULL,
    detail_json     TEXT NOT NULL,
    scg_refs_json   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS asg_edges_from_idx ON asg_edges(snapshot_id, from_id, kind);
CREATE INDEX IF NOT EXISTS asg_edges_to_idx ON asg_edges(snapshot_id, to_id, kind);
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
CREATE TABLE knowledge_analyses (
    analysis_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    scg_version TEXT NOT NULL,
    asg_version TEXT NOT NULL,
    document_json TEXT NOT NULL
);
CREATE INDEX knowledge_analyses_scope ON knowledge_analyses(project_id, snapshot_id, analysis_id);

CREATE TABLE knowledge_analysis_paths (
    analysis_id TEXT NOT NULL REFERENCES knowledge_analyses(analysis_id),
    project_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    scg_version TEXT NOT NULL,
    asg_version TEXT NOT NULL,
    path_id TEXT NOT NULL,
    entry_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    document_json TEXT NOT NULL,
    PRIMARY KEY (analysis_id, path_id)
);
CREATE INDEX knowledge_analysis_paths_scope ON knowledge_analysis_paths(project_id,snapshot_id,scg_version,asg_version,path_id,analysis_id);
