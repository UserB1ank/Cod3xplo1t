package plugin

import "github.com/open-mcp-ai/Codexploit/internal/artifact"

type AnalysisResult struct {
	APIVersion  string            `json:"api_version"`
	Scope       artifact.Scope    `json:"scope"`
	Producer    artifact.Producer `json:"producer"`
	Status      string            `json:"status"`
	Outputs     []artifact.Ref    `json:"outputs"`
	Coverage    AnalysisCoverage  `json:"coverage"`
	Diagnostics []Diagnostic      `json:"diagnostics"`
}
type AnalysisCoverage struct {
	FilesSeen     int      `json:"files_seen"`
	FilesAnalyzed int      `json:"files_analyzed"`
	FilesSkipped  int      `json:"files_skipped"`
	Limitations   []string `json:"limitations"`
}
type Diagnostic struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func analysisResult(inv Invocation) *AnalysisResult {
	status := "failed"
	switch inv.Status {
	case "SUCCEEDED":
		status = "succeeded"
	case "PARTIAL":
		status = "partial"
	case "UNSUPPORTED":
		status = "unsupported"
	}
	analyzed := inv.Coverage.ParsedFiles + inv.Coverage.PartialFiles
	result := &AnalysisResult{APIVersion: "codexploit/v1", Scope: inv.Request.Scope, Producer: artifact.Producer{PluginID: inv.Request.PluginID, PluginVersion: inv.Request.PluginVersion, InvocationID: inv.ID, ConfigDigest: inv.ConfigDigest}, Status: status, Outputs: inv.Outputs, Coverage: AnalysisCoverage{FilesSeen: inv.Coverage.InputFiles, FilesAnalyzed: analyzed, FilesSkipped: inv.Coverage.InputFiles - analyzed, Limitations: inv.Limitations}, Diagnostics: []Diagnostic{}}
	if inv.ErrorCode != "" {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Level: "error", Code: inv.ErrorCode, Message: "Analysis did not produce a consumable normalized result"})
	} else if inv.Status == "PARTIAL" {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Level: "warning", Code: "partial_coverage", Message: "Some inputs or bounded analysis regions were not fully analyzed"})
	}
	return result
}
