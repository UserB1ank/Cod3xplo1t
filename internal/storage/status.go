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

func CatalogOnly(store Store) bool {
	s, ok := store.(*SQL)
	return ok && s.postgres
}

func StorageCapabilities(store Store) map[string]bool {
	full := !CatalogOnly(store)
	return map[string]bool{
		"projects": true, "sources": true, "snapshots": true, "artifacts": true, "inventory": true,
		"knowledge": full, "plugins": full, "tasks": full, "findings": full, "workflows": full, "reports": full,
	}
}

// ProbeStatus checks connectivity and the catalog columns actually used by
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
		result.Driver, result.Profile = "postgres", "catalog"
		result.Locations["catalog"] = "postgres"
	}
	result.SchemaVersion = "unknown"
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		result.Readiness = "unavailable"
		return result
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
