package publication

import (
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

// BatchFromDiscovery projects a normalized discovery document onto one
// publication batch. Attack-surface nodes and scanner candidates both become
// facts; an edge whose endpoint is outside the batch is omitted and counted
// rather than given a fabricated endpoint.
func BatchFromDiscovery(batchID string, scope Scope, producer artifact.Producer, document plugin.DiscoveryDocument, baseRevision, layer string) (Batch, int) {
	batch := Batch{
		ID:           batchID,
		Scope:        scope,
		BaseRevision: baseRevision,
		Producer:     producer,
		Layer:        layer,
		Facts:        make([]BatchFact, 0, len(document.Nodes)+len(document.Candidates)),
		Edges:        make([]BatchEdge, 0, len(document.Edges)),
		Coverage:     BatchCoverage{FilesSeen: document.Coverage.InputFiles, FilesAnalyzed: document.Coverage.ParsedFiles, FilesSkipped: document.Coverage.UnparsedFiles, Limitations: document.Limitations},
		Limitations:  append([]string(nil), document.Limitations...),
	}
	seen := map[string]bool{}
	for _, node := range document.Nodes {
		attributes := map[string]string{
			"subject":         node.Subject,
			"generator":       node.Generator,
			"evidence_status": string(node.Evidence),
		}
		for key, value := range node.Detail {
			attributes[key] = value
		}
		var location *Location
		if node.File != "" {
			location = &Location{File: node.File, StartLine: node.Line, EndLine: node.Line}
		}
		batch.Facts = append(batch.Facts, BatchFact{
			ID:         node.ID,
			Kind:       string(node.Kind),
			Label:      node.Label,
			Location:   location,
			Confidence: string(node.Confidence),
			Attributes: attributes,
			Evidence:   node.SCGRefs,
		})
		seen[node.ID] = true
	}
	for _, candidate := range document.Candidates {
		if seen[candidate.ID] {
			continue
		}
		attributes := map[string]string{
			"status":         candidate.Status,
			"title":          candidate.Title,
			"severity_hint":  candidate.SeverityHint,
			"evidence_class": "candidate",
		}
		var location *Location
		if candidate.File != "" {
			attributes["file"] = candidate.File
			location = &Location{File: candidate.File, StartLine: candidate.Line, EndLine: candidate.Line}
		}
		batch.Facts = append(batch.Facts, BatchFact{
			ID:         candidate.ID,
			Kind:       "scanner.alert",
			Label:      candidate.Title,
			Location:   location,
			Confidence: "observed",
			Attributes: attributes,
			Evidence:   candidate.EvidenceRefs,
		})
		seen[candidate.ID] = true
	}
	omitted := 0
	for _, edge := range document.Edges {
		if !seen[edge.From] || !seen[edge.To] {
			omitted++
			continue
		}
		batch.Edges = append(batch.Edges, BatchEdge{From: edge.From, To: edge.To, Kind: string(edge.Kind)})
	}
	return batch, omitted
}
