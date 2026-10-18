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
