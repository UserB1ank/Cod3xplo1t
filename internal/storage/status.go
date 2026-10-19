package storage

import (
	"context"
	"time"
)

// Status contains no connection strings, file paths, database names or errors
// supplied by a driver. Readiness concerns the declared profile only.
type Status struct {
	APIVersion    string            `json:"api_version"`
	Driver        string            `json:"driver"`
	Profile       string            `json:"profile"`
	Readiness     string            `json:"readiness"`
	Durable       bool              `json:"durable"`
	SchemaVersion string            `json:"schema_version"`
	Capabilities  map[string]bool   `json:"capabilities"`
	Locations     map[string]string `json:"locations"`
}

func IsPostgres(store Store) bool {
	s, ok := store.(*SQL)
	return ok && s.postgres
}

func StorageCapabilities(_ Store) map[string]bool {
	return map[string]bool{
		"projects": true, "sources": true, "snapshots": true, "artifacts": true, "inventory": true,
		"knowledge": true, "plugins": true, "tasks": true, "findings": true, "workflows": true, "reports": true,
	}
}

// ProbeStatus checks connectivity and the business columns actually used by
// supported operations. A live connection alone does not prove schema readiness.
func ProbeStatus(ctx context.Context, store Store) Status {
	result := Status{APIVersion: "codexploit/v1", Driver: "memory", Profile: "complete", Readiness: "ready", SchemaVersion: "memory", Capabilities: StorageCapabilities(store), Locations: map[string]string{"catalog": "memory", "artifact_content": "workspace", "accounts": "workspace", "model_settings": "workspace"}}
	if store == nil {
		result.Readiness = "unavailable"
		return result
	}
	s, ok := store.(*SQL)
	if !ok {
		return result
	}
	result.Driver, result.Durable = "sqlite", true
	result.Locations["catalog"] = "sqlite"
	if s.postgres {
		result.Driver, result.Profile = "postgres", "execution"
		result.Locations["catalog"] = "postgres"
	}
	result.SchemaVersion = "unknown"
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		result.Readiness = "unavailable"
		return result
	}
	if s.postgres {
		for _, query := range []string{`SELECT run_id,owner,epoch,lease_until FROM workflow_leases LIMIT 0`, `SELECT host_id,epoch,lease_until FROM runtime_hosts LIMIT 0`, `SELECT invocation_id,run_id,epoch FROM workflow_node_claims LIMIT 0`, `SELECT host_id,host_epoch FROM agent_runs LIMIT 0`, `SELECT host_id,host_epoch FROM verification_runs LIMIT 0`} {
			rows, err := s.db.QueryContext(ctx, query)
			if err != nil {
				result.Readiness = "unavailable"
				return result
			}
			rows.Close()
		}
	}
	for _, query := range []string{
		`SELECT id, version FROM projects LIMIT 0`,
		`SELECT source_id, project_id, version, definition_json FROM project_sources LIMIT 0`,
		`SELECT snapshot_id, project_id, metadata_json, manifest_json FROM snapshots LIMIT 0`,
		`SELECT snapshot_id, source_id, source_version FROM source_snapshots LIMIT 0`,
		`SELECT artifact_id, project_id, source_id, snapshot_id, ref_json FROM artifact_refs LIMIT 0`,
		`SELECT snapshot_id, completed FROM snapshot_deletions LIMIT 0`,
		`SELECT scope, key, status, body FROM idempotency_keys LIMIT 0`,
		`SELECT analysis_id, snapshot_id, document_json FROM analyses LIMIT 0`,
		`SELECT snapshot_id, graph_version FROM graph_builds LIMIT 0`,
		`SELECT symbol_id, snapshot_id FROM scg_symbols LIMIT 0`,
		`SELECT snapshot_id, asg_version FROM asg_builds LIMIT 0`,
		`SELECT plugin_id, version, record_json FROM plugin_versions LIMIT 0`,
		`SELECT invocation_id, status, document_json FROM plugin_invocations LIMIT 0`,
		`SELECT project_id, snapshot_id, revision_no FROM knowledge_revisions LIMIT 0`,
		`SELECT event_id, revision FROM knowledge_outbox LIMIT 0`,
		`SELECT analysis_id, scg_version FROM knowledge_analyses LIMIT 0`,
		`SELECT analysis_id, path_id FROM knowledge_analysis_paths LIMIT 0`,
		`SELECT audit_id,task_pinned,task_archived FROM audits LIMIT 0`,
		`SELECT path_id,lease_epoch FROM audit_paths LIMIT 0`,
		`SELECT run_id,lease_epoch FROM agent_runs LIMIT 0`,
		`SELECT run_id,seq FROM agent_events LIMIT 0`,
		`SELECT run_id,version FROM verification_runs LIMIT 0`,
		`SELECT finding_id,version FROM findings LIMIT 0`,
		`SELECT evidence_id,snapshot_id FROM evidence LIMIT 0`,
		`SELECT observation_id,content_hash FROM finding_observations LIMIT 0`,
		`SELECT audit_id,version FROM finding_severity_audits LIMIT 0`,
		`SELECT run_id,version FROM workflow_runs LIMIT 0`,
	} {
		rows, err := s.db.QueryContext(ctx, query)
		if err != nil {
			result.Readiness = "unavailable"
			return result
		}
		rows.Close()
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), '') FROM schema_migrations`).Scan(&result.SchemaVersion); err != nil || result.SchemaVersion == "" {
		result.SchemaVersion, result.Readiness = "unknown", "unavailable"
	}
	return result
}
