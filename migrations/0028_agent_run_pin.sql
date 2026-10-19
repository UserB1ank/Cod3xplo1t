-- The run pin records the runtime, model and configuration versions a run used.
-- It is additive: a run stored before it existed has no pin, and that reads as
-- "not recorded", not as the current configuration.
ALTER TABLE agent_runs ADD COLUMN pin_json TEXT NOT NULL DEFAULT '';
