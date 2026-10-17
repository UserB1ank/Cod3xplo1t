ALTER TABLE audit_paths ADD COLUMN entry_kind TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_paths ADD COLUMN entry_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_paths ADD COLUMN target_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_paths ADD COLUMN target_kind TEXT NOT NULL DEFAULT '';

UPDATE audit_paths SET entry_subject = COALESCE((SELECT subject FROM asg_nodes WHERE node_id = audit_paths.entry_node_id AND snapshot_id = audit_paths.snapshot_id), '');
UPDATE audit_paths SET target_subject = COALESCE((SELECT subject FROM asg_nodes WHERE node_id = audit_paths.target_node_id AND snapshot_id = audit_paths.snapshot_id), '');
UPDATE audit_paths SET target_kind = COALESCE((SELECT kind FROM asg_nodes WHERE node_id = audit_paths.target_node_id AND snapshot_id = audit_paths.snapshot_id), '');
