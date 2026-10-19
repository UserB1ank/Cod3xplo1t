-- The alias table is the run's model-facing vocabulary: canonical ids stay in the
-- ledger, the model sees short names, and the host resolves them. The column is
-- additive, so a run stored before it existed has no table and its ids remain
-- canonical rather than being reinterpreted.
ALTER TABLE agent_runs ADD COLUMN aliases_json TEXT NOT NULL DEFAULT '';
