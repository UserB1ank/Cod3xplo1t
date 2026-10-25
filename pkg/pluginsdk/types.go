// Package pluginsdk provides the public file-job and stage boundary types.
// Implementations need not link host internal packages.
package pluginsdk

import (
	"context"
	"encoding/json"
)

type Stage string

const (
	Source       Stage = "source"
	Parse        Stage = "parse"
	Semantic     Stage = "semantic"
	Scan         Stage = "scan"
	PathGenerate Stage = "path.generate"
	PathEnhance  Stage = "path.enhance"
	Agent        Stage = "agent"
	Environment  Stage = "environment"
	Verification Stage = "verification"
	Report       Stage = "report"
)

type Scope struct {
	ProjectID  string `json:"project_id"`
	SourceID   string `json:"source_id"`
	SnapshotID string `json:"snapshot_id"`
}

type Port struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	SchemaID    string `json:"schema_id"`
	Cardinality string `json:"cardinality"`
	Required    bool   `json:"required"`
}

// Paths are relative to an exclusive job root. The host materializes inputs.
// A package entrypoint or any source-derived shell command is never an input port.
type LocalInput struct {
	ArtifactID string `json:"artifact_id,omitempty"`
	Port       string `json:"port"`
	Kind       string `json:"kind"`
	SchemaID   string `json:"schema_id"`
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}

type Budget struct {
	TimeoutSeconds int   `json:"timeout_seconds"`
	MaxInputBytes  int64 `json:"max_input_bytes"`
	MaxOutputBytes int64 `json:"max_output_bytes"`
	MaxOutputFiles int   `json:"max_output_files"`
}

type JobRequest struct {
	APIVersion      string          `json:"api_version"`
	InvocationID    string          `json:"invocation_id"`
	PluginID        string          `json:"plugin_id"`
	PluginVersion   string          `json:"plugin_version"`
	OperationID     string          `json:"operation_id"`
	Stage           Stage           `json:"stage"`
	Scope           Scope           `json:"scope"`
	Inputs          []LocalInput    `json:"inputs"`
	OutputDirectory string          `json:"output_directory"`
	Config          json.RawMessage `json:"config"`
	Budget          Budget          `json:"budget"`
}

// The host assigns authoritative ArtifactRef IDs and producer metadata only
// after validating every declared output and the invocation's current lease.
type LocalOutput struct {
	Port      string `json:"port"`
	Kind      string `json:"kind"`
	SchemaID  string `json:"schema_id"`
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
}

// Nil counts mean unknown, not zero. The four counts use the same Unit.
type Coverage struct {
	Unit      string   `json:"unit"`
	Seen      *int64   `json:"seen"`
	Analyzed  *int64   `json:"analyzed"`
	Skipped   *int64   `json:"skipped"`
	Failed    *int64   `json:"failed"`
	Truncated bool     `json:"truncated"`
	Reasons   []string `json:"reasons"`
}

type JobResult struct {
	APIVersion   string        `json:"api_version"`
	InvocationID string        `json:"invocation_id"`
	Status       string        `json:"status"`
	ErrorCode    string        `json:"error_code,omitempty"`
	Outputs      []LocalOutput `json:"outputs"`
	Coverage     Coverage      `json:"coverage"`
	Limitations  []string      `json:"limitations"`
}

type CheckRequest struct {
	PluginID      string `json:"plugin_id"`
	PluginVersion string `json:"plugin_version"`
	OperationID   string `json:"operation_id"`
}

type CheckResult struct {
	ProtocolVersion string   `json:"protocol_version"`
	ToolVersion     string   `json:"tool_version"`
	Operations      []string `json:"operations"`
	Ready           bool     `json:"ready"`
	Reason          string   `json:"reason,omitempty"`
}

// Implement in any language. A handler owns no installation, database, graph
// publication or verdict privileges. A cancelled context must stop subprocesses;
// the host also terminates the process tree and fences any late result.
type StageHandler interface {
	Check(context.Context, CheckRequest) (CheckResult, error)
	Execute(context.Context, JobRequest) (JobResult, error)
}

// Host-owned package lifecycle. These methods are not RPCs granted to plugins.
type Release struct {
	PluginID       string `json:"plugin_id"`
	PluginVersion  string `json:"plugin_version"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	ManifestDigest string `json:"manifest_digest"`
	PackageDigest  string `json:"package_digest"`
}

type Installation struct {
	ID        string  `json:"id"`
	Release   Release `json:"release"`
	WorkerID  string  `json:"worker_id"`
	Installed bool    `json:"installed"`
	Integrity string  `json:"integrity"`
	Probe     string  `json:"probe"`
	Enabled   bool    `json:"enabled"`
	Version   int64   `json:"version"`
}

type PackageManager interface {
	Register(context.Context, json.RawMessage) error
	Install(context.Context, Release, string) (Installation, error)
	Check(context.Context, string) (Installation, error)
	Uninstall(context.Context, string, int64) error
}

// These domain ports share package metadata but retain their own authorization,
// budget and lifecycle semantics. RawMessage must pass the existing domain
// schema before invocation and after return; it does not permit arbitrary JSON.
type AgentRuntime interface {
	Run(context.Context, json.RawMessage) (json.RawMessage, error)
}

type EnvironmentProvider interface {
	Provision(context.Context, json.RawMessage) (json.RawMessage, error)
	Destroy(context.Context, string) error
}

type VerificationExecutor interface {
	Verify(context.Context, json.RawMessage, json.RawMessage) (json.RawMessage, error)
}
