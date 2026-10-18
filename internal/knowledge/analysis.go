package knowledge

import (
	"context"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
)

func (r *Reader) pinnedAnalyses(ctx context.Context, scope Scope, scgVersion, asgVersion string) ([]publication.AnalysisSummary, error) {
	if r.Analyses == nil {
		return nil, nil
	}
	rows, err := r.Analyses.ListKnowledgeAnalyses(ctx, publication.Scope{ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID}, 1001)
	if err != nil {
		return nil, err
	}
	kept := []publication.AnalysisSummary{}
	for _, row := range rows {
		if row.SCGVersion == scgVersion && (asgVersion == "" || row.ASGVersion == asgVersion) {
			kept = append(kept, row)
		}
	}
	return kept, nil
}

func (r *Reader) analysisPaths(ctx context.Context, scope Scope, view *View, d descriptor, q PathQuery, offset, limit int) (*PathPage, bool, error) {
	analyses, err := r.pinnedAnalyses(ctx, scope, d.SCG, d.ASG)
	if err != nil {
		return nil, true, err
	}
	if len(analyses) == 0 || q.AuditID != "" {
		if r.Queue == nil {
			return &PathPage{Paths: []path.Path{}, Audits: []AuditRef{}, Meta: metaFor(view, LayerPaths, 0)}, true, nil
		}
		return nil, false, nil
	}
	meta := metaFor(view, LayerPaths, 0)
	for _, a := range analyses {
		if a.HasPaths && a.Coverage.Truncated {
			meta.Truncated = true
			meta.TruncationReason = "analysis_coverage"
		}
	}
	if len(analyses) > 1000 {
		meta.Truncated = true
		meta.TruncationReason = "analysis_metadata_budget"
		analyses = analyses[:1000]
	}
	query := publication.AnalysisPathQuery{AnalysisID: q.AnalysisID, EntryNodeID: q.EntryNodeID, TargetNodeID: q.TargetNodeID, Offset: offset, Limit: limit}
	refs := []AuditRef{}
	if r.Queue == nil || q.AnalysisID != "" {
		rows, total, err := r.Analyses.ListKnowledgeAnalysisPaths(ctx, publication.Scope{ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID}, d.SCG, d.ASG, query)
		if err != nil {
			return nil, true, err
		}
		meta.Total = total
		next := ""
		if offset+len(rows) < total {
			next = encodeCursor(offset + len(rows))
		}
		return &PathPage{Paths: rows, Audits: refs, Analyses: analyses, NextCursor: next, Meta: meta}, true, nil
	}
	// Complete modes may share a view between execution tasks and direct calls.
	// Bound the merged query explicitly and retain canonical identities.
	const budget = 10000
	query.Offset, query.Limit = 0, budget+1
	rows, total, err := r.Analyses.ListKnowledgeAnalysisPaths(ctx, publication.Scope{ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID}, d.SCG, d.ASG, query)
	if err != nil {
		return nil, true, err
	}
	tasks, err := r.pinnedAudits(ctx, scope.SnapshotID, d)
	if err != nil {
		return nil, true, err
	}
	for _, a := range tasks {
		refs = append(refs, AuditRef{ID: a.ID, Name: a.Name, Status: a.Status, Paths: a.PathCount})
	}
	work, workTotal, err := r.Queue.Paths(path.PathQuery{SnapshotID: scope.SnapshotID, EntryNodeID: q.EntryNodeID, TargetNodeID: q.TargetNodeID, Limit: budget + 1})
	if err != nil {
		return nil, true, err
	}
	byID := map[string]path.Path{}
	for _, p := range append(rows, work...) {
		if p.SCGVersion == d.SCG && (d.ASG == "" || p.ASGVersion == d.ASG) {
			byID[p.ID] = p
		} else {
			meta.Omitted++
		}
	}
	keys := make([]string, 0, len(byID))
	for id := range byID {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	if total > budget || workTotal > budget || len(keys) > budget {
		meta.Truncated = true
		meta.TruncationReason = "paths_budget"
		if len(keys) > budget {
			keys = keys[:budget]
		}
	}
	meta.Total = len(keys)
	kept := []path.Path{}
	for i := offset; i < len(keys) && len(kept) < limit; i++ {
		kept = append(kept, byID[keys[i]])
	}
	next := ""
	if offset+len(kept) < len(keys) {
		next = encodeCursor(offset + len(kept))
	}
	return &PathPage{Paths: kept, Audits: refs, Analyses: analyses, NextCursor: next, Meta: meta}, true, nil
}
