package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/analysisengine"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

type engineStatus struct {
	Pin       storage.AnalysisEnginePin `json:"engine"`
	Ready     bool                      `json:"ready"`
	Reason    string                    `json:"reason,omitempty"`
	Languages []string                  `json:"languages"`
}

func (s *Server) analysisProvider() analysisengine.Provider {
	if s.AnalysisEngine != nil {
		return s.AnalysisEngine
	}
	return analysisengine.Default()
}
func (s *Server) analysisEngineStatus(ctx context.Context) (engineStatus, error) {
	spec := s.analysisProvider().Workflow()
	status := engineStatus{Pin: storage.AnalysisEnginePin{ID: workflow.DefaultEngineID, ProfileVersion: spec.Version}, Languages: []string{}}
	if len(spec.Nodes) == 0 {
		return status, workflow.ErrInvalid
	}
	first := spec.Nodes[0]
	status.Pin.PluginID, status.Pin.PluginVersion = first.PluginID, first.PluginVersion
	if first.PluginID != workflow.DefaultEnginePluginID {
		status.Pin.ID = first.PluginID
	}
	if s.PluginCatalog == nil {
		status.Reason = "主图谱引擎未安装"
		return status, nil
	}
	record, err := s.PluginCatalog.Get(ctx, first.PluginID, first.PluginVersion)
	if errors.Is(err, plugin.ErrNotFound) {
		status.Reason = "主图谱引擎尚未安装；请部署固定版本的 Joern 包"
		return status, nil
	}
	if err != nil {
		return status, err
	}
	status.Pin.PackageDigest, status.Pin.ManifestDigest = record.PackageDigest, record.ManifestDigest
	status.Languages = record.Manifest.Languages
	if !record.Executable {
		status.Reason = "主图谱引擎未就绪：" + record.Reason
		return status, nil
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return status, err
	}
	validation, err := s.WorkflowCompiler.Validate(ctx, raw)
	if err != nil {
		return status, err
	}
	if !validation.Valid {
		status.Reason = "主图谱引擎的阶段接口或配置不兼容"
		return status, nil
	}
	status.Ready = true
	return status, nil
}
func (s *Server) handleAnalysisEngine(w http.ResponseWriter, r *http.Request) {
	if _, err := s.Store.GetProject(r.Context(), r.PathValue("projectID")); err != nil {
		writeStorageError(w, err)
		return
	}
	if s.WorkflowCompiler == nil {
		writeError(w, 503, "analysis_unavailable", errors.New("workflow compiler unavailable"))
		return
	}
	status, err := s.analysisEngineStatus(r.Context())
	if err != nil {
		writeAnalysisError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"api_version": "codexploit/v1", "analysis_engine": status})
}

func analysisLanguage(spec workflow.Spec) string {
	if len(spec.Nodes) > 0 && spec.Nodes[0].PluginID == "codexploit.joern" {
		return "Mixed"
	}
	return "Go"
}

func normalizeAnalysisFrontend(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if raw == "JAVA" {
		return "JAVA", nil
	}
	value := strings.ToUpper(strings.Join(strings.Fields(raw), " "))
	switch value {
	case "AUTO", "MIXED":
		return "AUTO", nil
	case "C", "C++", "CPP", "C / C++", "C/C++":
		return "C", nil
	case "C#", "CSHARP", "C SHARP", "CSHARPSRC":
		return "CSHARPSRC", nil
	case "GO", "GOLANG":
		return "GOLANG", nil
	case "JAVA", "JAVA SOURCE", "JAVASRC":
		return "JAVASRC", nil
	case "JAVA BYTECODE", "BYTECODE", "JAVACLASS":
		return "JAVA", nil
	case "JS", "JAVASCRIPT", "TYPESCRIPT", "TS":
		return "JAVASCRIPT", nil
	case "KOTLIN":
		return "KOTLIN", nil
	case "PHP":
		return "PHP", nil
	case "PYTHON", "PYTHONSRC":
		return "PYTHONSRC", nil
	case "RUBY", "RUBYSRC":
		return "RUBYSRC", nil
	case "RUST":
		return "RUST", nil
	case "SWIFT", "SWIFTSRC":
		return "SWIFTSRC", nil
	case "ABAP":
		return "ABAP", nil
	case "BINARY", "GHIDRA":
		return "GHIDRA", nil
	default:
		return "", fmt.Errorf("unsupported analysis frontend %q", raw)
	}
}

func analysisWorkflowForFrontend(spec workflow.Spec, raw string) (workflow.Spec, error) {
	frontend, err := normalizeAnalysisFrontend(raw)
	if err != nil {
		return spec, err
	}
	if frontend == "" {
		return spec, nil
	}
	if len(spec.Nodes) == 0 || spec.Nodes[0].PluginID != workflow.DefaultEnginePluginID {
		return spec, fmt.Errorf("the selected analysis engine does not accept a frontend")
	}
	var config map[string]any
	if err := json.Unmarshal(spec.Nodes[0].Config, &config); err != nil {
		return spec, err
	}
	config["frontend"] = frontend
	encoded, err := json.Marshal(config)
	if err != nil {
		return spec, err
	}
	spec.Nodes = append([]workflow.Node(nil), spec.Nodes...)
	spec.Nodes[0].Config = encoded
	return spec, nil
}

func analysisLanguageForFrontend(spec workflow.Spec, frontend string) string {
	switch frontend {
	case "C":
		return "C"
	case "CSHARPSRC":
		return "C#"
	case "GOLANG":
		return "Go"
	case "JAVASRC":
		return "Java"
	case "JAVA":
		return "Java bytecode"
	case "JAVASCRIPT":
		return "JavaScript"
	case "KOTLIN":
		return "Kotlin"
	case "PHP":
		return "PHP"
	case "PYTHONSRC":
		return "Python"
	case "RUBYSRC":
		return "Ruby"
	case "RUST":
		return "Rust"
	case "SWIFTSRC":
		return "Swift"
	case "ABAP":
		return "ABAP"
	case "GHIDRA":
		return "Binary"
	default:
		return analysisLanguage(spec)
	}
}
