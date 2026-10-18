package publication

import (
	"context"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// AnalysisIndex materializes a host-verified native report with its publication.
// It is transient input to the atomic store call, not part of revision JSON.
type AnalysisIndex struct {
	Summary AnalysisSummary
	Graph   *scg.Graph
	Surface *asg.Document
	Paths   []path.Path
}

// AnalysisSummary identifies a direct analysis, independently of execution tasks.
type AnalysisSummary struct {
	ID             string            `json:"analysis_id"`
	Producer       artifact.Producer `json:"producer"`
	NativeArtifact artifact.Ref      `json:"native_artifact"`
	SCGVersion     string            `json:"scg_version"`
	ASGVersion     string            `json:"asg_version"`
	PathCount      int               `json:"path_count"`
	HasPaths       bool              `json:"has_paths"`
	Coverage       path.Coverage     `json:"coverage"`
	Limitations    []string          `json:"limitations"`
}

type AnalysisPathQuery struct {
	AnalysisID   string
	EntryNodeID  string
	TargetNodeID string
	Offset       int
	Limit        int
}

// AnalysisReader exposes only published analysis metadata and candidate paths.
type AnalysisReader interface {
	ListKnowledgeAnalyses(context.Context, Scope, int) ([]AnalysisSummary, error)
	ListKnowledgeAnalysisPaths(context.Context, Scope, string, string, AnalysisPathQuery) ([]path.Path, int, error)
}
