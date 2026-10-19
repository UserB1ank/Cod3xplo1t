-- A task may choose its agent runtime; the choice is part of the task, not of a
-- process-wide flag. Empty means the deployment default.
ALTER TABLE audits ADD COLUMN runtime TEXT NOT NULL DEFAULT '';
