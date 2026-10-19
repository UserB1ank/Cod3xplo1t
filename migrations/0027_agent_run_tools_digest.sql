-- The tool schema digest pins the native contracts a run used. The column is
-- additive: a run stored before it existed has an empty digest, which reads as
-- "not recorded" rather than as a different contract.
ALTER TABLE agent_runs ADD COLUMN tools_digest TEXT NOT NULL DEFAULT '';
