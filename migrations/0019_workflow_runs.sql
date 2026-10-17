CREATE TABLE workflow_runs (
 run_id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL,
 snapshot_id TEXT NOT NULL,
 task_id TEXT NOT NULL UNIQUE,
 plan_id TEXT NOT NULL,
 status TEXT NOT NULL,
 version INTEGER NOT NULL,
 document_json TEXT NOT NULL
);
CREATE INDEX workflow_runs_scope ON workflow_runs(project_id,snapshot_id);
