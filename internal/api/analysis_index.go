package api

import (
	"context"
	"encoding/json"
	"io"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
)

func (s *Server) publicationAnalysis(ctx context.Context, document plugin.DiscoveryDocument) (*publication.AnalysisIndex, error) {
	ref := document.NativeArtifact
	if ref.SchemaID != "codexploit/builtin-native/v1" {
		return nil, nil
	}
	reader, _, err := s.Artifacts.Open(ctx, document.Scope, ref.ID, 64<<20)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, (64<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<20 {
		return nil, artifact.ErrBudget
	}
	var native plugin.NativeReport
	if json.Unmarshal(raw, &native) != nil || native.Scope != document.Scope || native.Graph == nil || native.Surface == nil {
		return nil, plugin.ErrInvalid
	}
	index := &publication.AnalysisIndex{Graph: native.Graph, Surface: native.Surface, Summary: publication.AnalysisSummary{ID: ref.Producer.InvocationID, Producer: ref.Producer, NativeArtifact: ref, SCGVersion: native.Graph.GraphVersion, ASGVersion: native.Surface.ASGVersion, Limitations: append([]string{}, native.Limitations...)}}
	if native.Paths != nil {
		index.Paths = native.Paths.Paths
		index.Summary.PathCount = len(index.Paths)
		index.Summary.HasPaths = true
		index.Summary.Coverage = native.Paths.Coverage
		index.Summary.Limitations = append(index.Summary.Limitations, native.Paths.Limitations...)
	}
	return index, nil
}
