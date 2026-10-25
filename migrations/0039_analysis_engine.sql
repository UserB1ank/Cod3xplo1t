-- Compatibility for existing standalone catalogs; the formal deployment uses PG.
ALTER TABLE analysis_runs ADD COLUMN engine_json TEXT NOT NULL DEFAULT 'null';
