// Package wire defines the versioned NDJSON JSON-RPC vocabulary exchanged
// between the plugin host and a process plugin. It is intentionally separate
// from the plugin package so a tool binary can link it without the host.
package wire

import (
	"encoding/json"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

// Protocol is the only handshake version accepted by this host.
const Protocol = "codexploit/process-plugin/v1"

// ScannerReportFormat identifies the native alert document produced by the
// first process scanner. Unknown formats are unsupported, never guessed.
const ScannerReportFormat = "codexploit/scanner-alerts/v1"

// JSON-RPC methods.
const (
	PluginInitialize = "plugin.initialize"
	PluginExecute    = "plugin.execute"
	PluginStatus     = "plugin.status"
	PluginCancel     = "plugin.cancel"
	PluginEvent      = "plugin.event"
	PluginOutput     = "plugin.output"
	HostReadArtifact = "host.artifacts.read"
)

// MaxMessageBytes bounds one NDJSON control message. Reports and source trees
// use the artifact channel instead of an oversized control line.
const MaxMessageBytes = 1 << 20

// MaxReportBytes bounds the raw native report one invocation may return.
const MaxReportBytes = 16 << 20

// MaxReadChunkBytes bounds one host artifact read response.
const MaxReadChunkBytes = 256 << 10

type HostCapabilities struct {
	ArtifactRead bool `json:"artifact_read"`
	GraphQuery   bool `json:"graph_query"`
}

// InitializeParams is sent host -> plugin before any execution.
type InitializeParams struct {
	Protocol        string           `json:"protocol"`
	ManifestDigest  string           `json:"manifest_digest"`
	PackageDigest   string           `json:"package_digest"`
	Host            HostCapabilities `json:"host"`
	MaxMessageBytes int              `json:"max_message_bytes"`
	MaxReportBytes  int64            `json:"max_report_bytes"`
}

type PluginCapabilities struct {
	Alerts           bool   `json:"alerts"`
	DataFlow         bool   `json:"data_flow"`
	CallReachability bool   `json:"call_reachability"`
	Network          string `json:"network"`
}

// InitializeResult is the plugin's advertised, fixed capability set.
type InitializeResult struct {
	Protocol       string             `json:"protocol"`
	PluginID       string             `json:"plugin_id"`
	PluginVersion  string             `json:"plugin_version"`
	ManifestDigest string             `json:"manifest_digest"`
	Capabilities   PluginCapabilities `json:"capabilities"`
	MaxReportBytes int64              `json:"max_report_bytes"`
}

// ExecuteParams starts one bound invocation.
type ExecuteParams struct {
	InvocationID  string          `json:"invocation_id"`
	PluginID      string          `json:"plugin_id"`
	PluginVersion string          `json:"plugin_version"`
	PackageDigest string          `json:"package_digest"`
	Scope         artifact.Scope  `json:"scope"`
	Inputs        []artifact.Ref  `json:"inputs"`
	Config        json.RawMessage `json:"config"`
	Budget        plugin.Budget   `json:"budget"`
}

type ExecuteResult struct {
	Accepted     bool   `json:"accepted"`
	InvocationID string `json:"invocation_id"`
}

type StatusParams struct {
	InvocationID string `json:"invocation_id"`
}

// StatusResult is the bounded terminal or in-progress state of an invocation.
type StatusResult struct {
	InvocationID string          `json:"invocation_id"`
	Status       string          `json:"status"`
	ErrorCode    string          `json:"error_code,omitempty"`
	Coverage     plugin.Coverage `json:"coverage"`
	Limitations  []string        `json:"limitations"`
	ReportBytes  int64           `json:"report_bytes,omitempty"`
	ReportSHA256 string          `json:"report_sha256,omitempty"`
}

type CancelParams struct {
	InvocationID string `json:"invocation_id"`
}

type CancelResult struct {
	Cancelled bool `json:"cancelled"`
}

// Event is a short progress notification. Seq starts at 1 and must be dense.
type Event struct {
	InvocationID string `json:"invocation_id"`
	Seq          int    `json:"seq"`
	Type         string `json:"type"`
	Message      string `json:"message,omitempty"`
}

// OutputChunk carries a bounded slice of the raw report. Index starts at 0 and
// must be dense; Final marks the end of the report.
type OutputChunk struct {
	InvocationID string `json:"invocation_id"`
	Index        int    `json:"index"`
	Data         string `json:"data"`
	Final        bool   `json:"final"`
}

// ReadArtifactParams is a plugin -> host read. The host serves only inputs bound
// to the same invocation.
type ReadArtifactParams struct {
	InvocationID string `json:"invocation_id"`
	ArtifactID   string `json:"artifact_id"`
	Offset       int64  `json:"offset"`
	Length       int64  `json:"length"`
}

type ReadArtifactResult struct {
	Data  string `json:"data"`
	EOF   bool   `json:"eof"`
	Total int64  `json:"total"`
}

// ScannerReport is the native evidence produced by the first process scanner.
type ScannerReport struct {
	Format       string             `json:"format"`
	Scope        artifact.Scope     `json:"scope"`
	Tool         ToolInfo           `json:"tool"`
	Capabilities PluginCapabilities `json:"capabilities"`
	Coverage     plugin.Coverage    `json:"coverage"`
	Limitations  []string           `json:"limitations"`
	Alerts       []ScannerAlert     `json:"alerts"`
}

type ToolInfo struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Ruleset string `json:"ruleset"`
}

type ScannerAlert struct {
	ID           string   `json:"id"`
	RuleID       string   `json:"rule_id"`
	RuleVersion  string   `json:"rule_version"`
	Title        string   `json:"title"`
	SeverityHint string   `json:"severity_hint"`
	File         string   `json:"file"`
	Line         int      `json:"line"`
	EndLine      int      `json:"end_line"`
	Column       int      `json:"column"`
	Message      string   `json:"message"`
	Evidence     []string `json:"evidence"`
	Limitations  []string `json:"limitations"`
}
