-- Historical runs retain a null engine; their immutable plans remain readable.
ALTER TABLE analysis_runs ADD COLUMN engine_json TEXT NOT NULL DEFAULT 'null';
