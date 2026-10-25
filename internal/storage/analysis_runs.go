package storage

import (
	"context"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// AnalysisKnowledge is the immutable knowledge revision published by the
// default four-stage analysis. It is a pointer, not a copy of the facts.
type AnalysisKnowledge struct {
	Revision string `json:"revision"`
	Digest   string `json:"digest"`
}

// AnalysisRunStage is the project-facing projection of one fixed workflow node.
// It carries the tool identity, the invocation, the artifacts it consumed and
// produced, and the real failure or skip reason. It never carries a fabricated
// completion percentage.
type AnalysisRunStage struct {
	OperationID   string              `json:"operation_id,omitempty"`
	Key           string              `json:"key"`
	Label         string              `json:"label"`
	Status        string              `json:"status"`
	NodeID        string              `json:"node_id,omitempty"`
	PluginID      string              `json:"plugin_id,omitempty"`
	PluginVersion string              `json:"plugin_version,omitempty"`
	InvocationID  string              `json:"invocation_id,omitempty"`
	Inputs        []artifact.Ref      `json:"inputs,omitempty"`
	Outputs       []artifact.Ref      `json:"outputs,omitempty"`
	Knowledge     []AnalysisKnowledge `json:"knowledge,omitempty"`
	AgentRunIDs   []string            `json:"agent_run_ids,omitempty"`
	ErrorCode     string              `json:"error_code,omitempty"`
	Note          string              `json:"note,omitempty"`
	StartedAt     string              `json:"started_at,omitempty"`
	FinishedAt    string              `json:"finished_at,omitempty"`
}

// AnalysisRun aggregates the fixed workflow run for a project's one-click
// analysis. The workflow runner remains the only executor; this row keeps the
// project-level identity, history and stage projection stable across restarts.
type AnalysisRun struct {
	Engine          *AnalysisEnginePin  `json:"engine,omitempty"`
	ID              string              `json:"analysis_run_id"`
	ProjectID       string              `json:"project_id"`
	SnapshotID      string              `json:"snapshot_id"`
	TaskID          string              `json:"task_id"`
	WorkflowRunID   string              `json:"workflow_run_id"`
	PlanID          string              `json:"plan_id"`
	PlanDigest      string              `json:"plan_digest"`
	WorkflowID      string              `json:"workflow_id"`
	WorkflowVersion string              `json:"workflow_version"`
	State           string              `json:"state"`
	AgentAssisted   bool                `json:"agent_assisted"`
	IdempotencyKey  string              `json:"idempotency_key,omitempty"`
	Stages          []AnalysisRunStage  `json:"stages"`
	Coverage        path.Coverage       `json:"coverage"`
	Limitations     []string            `json:"limitations"`
	PathCount       int                 `json:"path_count"`
	Knowledge       []AnalysisKnowledge `json:"knowledge"`
	FailureCode     string              `json:"failure_code,omitempty"`
	FailureMessage  string              `json:"failure_message,omitempty"`
	CreatedAt       string              `json:"created_at"`
	UpdatedAt       string              `json:"updated_at"`
	Version         int64               `json:"version"`
}

// AnalysisEnginePin identifies the whole provider. Stage configurations and
// rules are additionally fixed by the immutable plan and its digest.
type AnalysisEnginePin struct {
	ID             string `json:"id"`
	ProfileVersion string `json:"profile_version"`
	PluginID       string `json:"plugin_id"`
	PluginVersion  string `json:"plugin_version"`
	PackageDigest  string `json:"package_digest"`
	ManifestDigest string `json:"manifest_digest"`
}

// AnalysisRunStore is implemented by Memory and SQL. It is deliberately small
// because the workflow runner owns leases, retries and node execution.
type AnalysisRunStore interface {
	CreateAnalysisRun(ctx context.Context, run AnalysisRun, idempotencyKey string) (AnalysisRun, error)
	GetAnalysisRun(ctx context.Context, projectID, analysisRunID string) (AnalysisRun, error)
	GetAnalysisRunByIdempotency(ctx context.Context, projectID, idempotencyKey string) (AnalysisRun, error)
	ListAnalysisRuns(ctx context.Context, projectID string, limit int) ([]AnalysisRun, error)
	UpdateAnalysisRun(ctx context.Context, run AnalysisRun) (AnalysisRun, error)
	ActiveAnalysisRun(ctx context.Context, projectID string) (AnalysisRun, bool, error)
}

var _ AnalysisRunStore = (*Memory)(nil)
