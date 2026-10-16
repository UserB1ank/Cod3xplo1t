-- Codexploit P2 schema: the Source Code Graph (SCG).
--
-- The graph is stored relationally (design doc §9: SQL for structure, native
-- analysis artifacts for the rest). One snapshot has at most one graph; a
-- rebuild replaces it inside a single transaction, so a reader never sees a
-- half-written graph.
--
-- Column names follow the SCG model in internal/scg. The DDL stays
-- dialect-neutral (TEXT/INTEGER/BIGINT) so the same file runs on SQLite and
-- PostgreSQL.

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
