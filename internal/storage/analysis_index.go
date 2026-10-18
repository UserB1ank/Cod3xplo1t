package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
)

func validateAnalysis(scope publication.Scope, index *publication.AnalysisIndex) error {
	if index == nil {
		return nil
	}
	s := index.Summary
	if s.ID == "" || s.Producer.InvocationID != s.ID || s.NativeArtifact.Scope.ProjectID != scope.ProjectID || s.NativeArtifact.Scope.SnapshotID != scope.SnapshotID || s.NativeArtifact.Producer != s.Producer || s.NativeArtifact.Validate() != nil || validateGraph(scope.SnapshotID, index.Graph) != nil || validateASG(scope.SnapshotID, index.Surface) != nil || s.SCGVersion != index.Graph.GraphVersion || s.ASGVersion != index.Surface.ASGVersion || index.Surface.SCGVersion != s.SCGVersion {
		return publication.ErrInvalidBatch
	}
	seen := map[string]bool{}
	for _, p := range index.Paths {
		if p.ID == "" || seen[p.ID] || p.SnapshotID != scope.SnapshotID || p.SCGVersion != s.SCGVersion || p.ASGVersion != s.ASGVersion {
			return publication.ErrInvalidBatch
		}
		seen[p.ID] = true
	}
	return nil
}

func (s *SQL) indexAnalysisTx(ctx context.Context, tx *sql.Tx, scope publication.Scope, index *publication.AnalysisIndex) error {
	if err := validateAnalysis(scope, index); err != nil || index == nil {
		return err
	}
	var version string
	err := tx.QueryRowContext(ctx, s.rebind(`SELECT graph_version FROM graph_builds WHERE snapshot_id=?`), scope.SnapshotID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		if err := s.replaceGraphTx(ctx, tx, scope.SnapshotID, index.Graph); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if version != index.Summary.SCGVersion {
		return publication.ErrVersionConflict
	}
	err = tx.QueryRowContext(ctx, s.rebind(`SELECT asg_version FROM asg_builds WHERE snapshot_id=?`), scope.SnapshotID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		if err := s.replaceASGTx(ctx, tx, scope.SnapshotID, index.Surface); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if version != index.Summary.ASGVersion {
		return publication.ErrVersionConflict
	}
	raw, err := json.Marshal(index.Summary)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO knowledge_analyses (analysis_id,project_id,snapshot_id,scg_version,asg_version,document_json) VALUES (?,?,?,?,?,?) ON CONFLICT(analysis_id) DO NOTHING`), index.Summary.ID, scope.ProjectID, scope.SnapshotID, index.Summary.SCGVersion, index.Summary.ASGVersion, string(raw))
	if err != nil {
		return err
	}
	var old string
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM knowledge_analyses WHERE analysis_id=?`), index.Summary.ID).Scan(&old); err != nil {
		return err
	}
	if !sameDocument([]byte(old), raw) {
		return publication.ErrBatchConflict
	}
	count, err := result.RowsAffected()
	if err != nil || count == 0 {
		return err
	}
	for _, p := range index.Paths {
		// Native candidate identities remain unchanged; these are discovered
		// paths, never queued task work or verified findings.
		p.AuditID = ""
		p.Status = path.StatusDiscovered
		doc, err := json.Marshal(p)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO knowledge_analysis_paths (analysis_id,project_id,snapshot_id,scg_version,asg_version,path_id,entry_node_id,target_node_id,document_json) VALUES (?,?,?,?,?,?,?,?,?)`), index.Summary.ID, scope.ProjectID, scope.SnapshotID, p.SCGVersion, p.ASGVersion, p.ID, p.EntryNodeID, p.TargetNodeID, string(doc))
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SQL) ListKnowledgeAnalyses(ctx context.Context, scope publication.Scope, limit int) ([]publication.AnalysisSummary, error) {
	if !knowledgeScopeExists(ctx, s.db, s.rebind, scope) {
		return nil, publication.ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT document_json FROM knowledge_analyses WHERE project_id=? AND snapshot_id=? ORDER BY analysis_id LIMIT ?`), scope.ProjectID, scope.SnapshotID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []publication.AnalysisSummary{}
	for rows.Next() {
		var raw string
		var summary publication.AnalysisSummary
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &summary); err != nil {
			return nil, err
		}
		result = append(result, summary)
	}
	return result, rows.Err()
}

func (s *SQL) ListKnowledgeAnalysisPaths(ctx context.Context, scope publication.Scope, scgVersion, asgVersion string, q publication.AnalysisPathQuery) ([]path.Path, int, error) {
	if !knowledgeScopeExists(ctx, s.db, s.rebind, scope) {
		return nil, 0, publication.ErrNotFound
	}
	conditions := []string{"p.project_id=?", "p.snapshot_id=?", "p.scg_version=?"}
	args := []any{scope.ProjectID, scope.SnapshotID, scgVersion}
	if asgVersion != "" {
		conditions = append(conditions, "p.asg_version=?")
		args = append(args, asgVersion)
	}
	for _, filter := range []struct{ column, value string }{{"analysis_id", q.AnalysisID}, {"entry_node_id", q.EntryNodeID}, {"target_node_id", q.TargetNodeID}} {
		if filter.value != "" {
			conditions = append(conditions, "p."+filter.column+"=?")
			args = append(args, filter.value)
		}
	}
	if q.AnalysisID == "" {
		conditions = append(conditions, `p.analysis_id=(SELECT MIN(other.analysis_id) FROM knowledge_analysis_paths other WHERE other.project_id=p.project_id AND other.snapshot_id=p.snapshot_id AND other.scg_version=p.scg_version AND other.asg_version=p.asg_version AND other.path_id=p.path_id)`)
	}
	where := " WHERE " + strings.Join(conditions, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM knowledge_analysis_paths p`+where), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT p.document_json FROM knowledge_analysis_paths p`+where+` ORDER BY p.path_id LIMIT ? OFFSET ?`), append(args, q.Limit, q.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []path.Path{}
	for rows.Next() {
		var raw string
		var p path.Path
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

type indexedMemoryAnalysis struct {
	Scope   publication.Scope
	Summary publication.AnalysisSummary
	Paths   []path.Path
}

func (m *Memory) indexAnalysisLocked(scope publication.Scope, index *publication.AnalysisIndex) error {
	if err := validateAnalysis(scope, index); err != nil || index == nil {
		return err
	}
	if prior := m.graphs[scope.SnapshotID]; prior != nil && prior.graph.GraphVersion != index.Summary.SCGVersion {
		return publication.ErrVersionConflict
	}
	if prior := m.asgDocuments[scope.SnapshotID]; prior != nil && prior.ASGVersion != index.Summary.ASGVersion {
		return publication.ErrVersionConflict
	}
	raw, err := json.Marshal(index)
	if err != nil {
		return err
	}
	var copy publication.AnalysisIndex
	if err := json.Unmarshal(raw, &copy); err != nil {
		return err
	}
	if old, ok := m.knowledgeAnalyses[copy.Summary.ID]; ok {
		a, _ := json.Marshal(old.Summary)
		b, _ := json.Marshal(copy.Summary)
		if old.Scope != scope || !sameDocument(a, b) {
			return publication.ErrBatchConflict
		}
		return nil
	}
	if m.graphs[scope.SnapshotID] == nil {
		m.graphs[scope.SnapshotID] = &memoryGraph{graph: copy.Graph}
	}
	if m.asgDocuments[scope.SnapshotID] == nil {
		m.asgDocuments[scope.SnapshotID] = copy.Surface
	}
	for i := range copy.Paths {
		copy.Paths[i].AuditID = ""
		copy.Paths[i].Status = path.StatusDiscovered
	}
	if m.knowledgeAnalyses == nil {
		m.knowledgeAnalyses = map[string]indexedMemoryAnalysis{}
	}
	m.knowledgeAnalyses[copy.Summary.ID] = indexedMemoryAnalysis{scope, copy.Summary, copy.Paths}
	return nil
}

func (m *Memory) ListKnowledgeAnalyses(ctx context.Context, scope publication.Scope, limit int) ([]publication.AnalysisSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.knowledgeScopeWritable(scope) {
		return nil, publication.ErrNotFound
	}
	result := []publication.AnalysisSummary{}
	for _, a := range m.knowledgeAnalyses {
		if a.Scope == scope {
			raw, _ := json.Marshal(a.Summary)
			var copy publication.AnalysisSummary
			_ = json.Unmarshal(raw, &copy)
			result = append(result, copy)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (m *Memory) ListKnowledgeAnalysisPaths(ctx context.Context, scope publication.Scope, scgVersion, asgVersion string, q publication.AnalysisPathQuery) ([]path.Path, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.knowledgeScopeWritable(scope) {
		return nil, 0, publication.ErrNotFound
	}
	byID := map[string]path.Path{}
	ids := make([]string, 0, len(m.knowledgeAnalyses))
	for id := range m.knowledgeAnalyses {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := m.knowledgeAnalyses[id]
		if a.Scope != scope || a.Summary.SCGVersion != scgVersion || (asgVersion != "" && a.Summary.ASGVersion != asgVersion) || (q.AnalysisID != "" && q.AnalysisID != id) {
			continue
		}
		for _, p := range a.Paths {
			if (q.EntryNodeID != "" && q.EntryNodeID != p.EntryNodeID) || (q.TargetNodeID != "" && q.TargetNodeID != p.TargetNodeID) {
				continue
			}
			if _, ok := byID[p.ID]; !ok {
				byID[p.ID] = p
			}
		}
	}
	keys := make([]string, 0, len(byID))
	for id := range byID {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	total := len(keys)
	result := []path.Path{}
	for i := q.Offset; i < total && len(result) < q.Limit; i++ {
		raw, _ := json.Marshal(byID[keys[i]])
		var p path.Path
		_ = json.Unmarshal(raw, &p)
		result = append(result, p)
	}
	return result, total, nil
}
