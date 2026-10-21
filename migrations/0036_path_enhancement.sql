-- Deterministic path enhancement (#29): the audit keeps the selected/filtered
-- ledger, and each retained path keeps its selection provenance. Both fields
-- are nullable JSON so old audits and paths remain readable unchanged.

ALTER TABLE audits ADD COLUMN enhancement_json TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_paths ADD COLUMN selection_json TEXT NOT NULL DEFAULT '';
