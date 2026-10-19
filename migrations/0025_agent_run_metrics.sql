-- Run metrics are observations the orchestrator made about a run, not claims the
-- adapter made about itself: exchanges, evidence novelty, invalid calls and
-- truncated results. The column is additive, so a run stored before it existed
-- decodes with no metrics instead of failing.
ALTER TABLE agent_runs ADD COLUMN metrics_json TEXT NOT NULL DEFAULT '';
