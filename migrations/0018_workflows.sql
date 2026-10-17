CREATE TABLE workflow_versions (
 project_id TEXT NOT NULL,
 workflow_id TEXT NOT NULL,
 version TEXT NOT NULL,
 digest TEXT NOT NULL,
 record_json TEXT NOT NULL,
 PRIMARY KEY(project_id,workflow_id,version)
);
CREATE TABLE workflow_heads (
 project_id TEXT NOT NULL,
 workflow_id TEXT NOT NULL,
 digest TEXT NOT NULL,
 version TEXT NOT NULL,
 PRIMARY KEY(project_id,workflow_id)
);
CREATE TABLE workflow_plans (
 plan_id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 document_json TEXT NOT NULL
);
CREATE INDEX workflow_plans_scope ON workflow_plans(project_id,snapshot_id);
