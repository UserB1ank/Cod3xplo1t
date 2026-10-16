-- Codexploit P3 (part 2): the Attack Surface Graph (ASG) candidate.
--
-- The ASG is stored separately from the SCG on purpose: the SCG is the fact
-- layer produced by static analysis, the ASG is the security-semantics layer
-- derived from it, and the design doc forbids the ASG from overwriting SCG facts
-- (§3.2). Every ASG row carries the SCG node ids it was derived from, so nothing
-- is asserted without evidence, and the whole document of a snapshot is replaced
-- in one transaction on rebuild.

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
