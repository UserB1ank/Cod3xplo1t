package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// ReplaceASG implements ASGStore. The whole ASG of a snapshot is replaced inside
// one transaction, so a rebuild is idempotent and a reader sees either the old
// attack surface or the new one, never a mixture.
func (s *SQL) ReplaceASG(ctx context.Context, snapshotID string, doc *asg.Document) error {
	if err := validateASG(snapshotID, doc); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	if err := s.snapshotWritableTx(ctx, tx, snapshotID); err != nil {
		return err
	}

	for _, table := range []string{"asg_nodes", "asg_edges", "asg_builds"} {
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM `+table+` WHERE snapshot_id = ?`), snapshotID); err != nil {
			return mapSQLError(err)
		}
	}

	nodeStmt, err := tx.PrepareContext(ctx, s.rebind(`
INSERT INTO asg_nodes (node_id, snapshot_id, kind, subject, label, detail_json, evidence_status, confidence,
    generator, module_id, file, line, scg_refs_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return mapSQLError(err)
	}
	defer nodeStmt.Close()
	for _, n := range doc.Nodes {
		detail := "{}"
		if len(n.Detail) > 0 {
			data, merr := json.Marshal(n.Detail)
			if merr != nil {
				return merr
			}
			detail = string(data)
		}
		refs, merr := json.Marshal(n.SCGRefs)
		if merr != nil {
			return merr
		}
		if _, err := nodeStmt.ExecContext(ctx, n.ID, snapshotID, string(n.Kind), n.Subject, n.Label, detail,
			string(n.Evidence), string(n.Confidence), n.Generator, n.ModuleID, n.File, n.Line, string(refs)); err != nil {
			return mapSQLError(err)
		}
	}

	edgeStmt, err := tx.PrepareContext(ctx, s.rebind(`
INSERT INTO asg_edges (edge_id, snapshot_id, from_id, to_id, kind, evidence_status, confidence, generator,
    detail_json, scg_refs_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return mapSQLError(err)
	}
	defer edgeStmt.Close()
	for _, e := range doc.Edges {
		detail := "{}"
		if len(e.Detail) > 0 {
			data, merr := json.Marshal(e.Detail)
			if merr != nil {
				return merr
			}
			detail = string(data)
		}
		refs, merr := json.Marshal(e.SCGRefs)
		if merr != nil {
			return merr
		}
		if _, err := edgeStmt.ExecContext(ctx, e.ID, snapshotID, e.From, e.To, string(e.Kind), string(e.Evidence),
			string(e.Confidence), e.Generator, detail, string(refs)); err != nil {
			return mapSQLError(err)
		}
	}

	// The summary is derived from the rows just written rather than trusted from
	// the caller: asgSummaryOf works on a value copy, so the caller's histogram
	// fields are neither used nor rewritten.
	summary := asgSummaryOf(doc)
	nodesByKind, err := json.Marshal(summary.NodesByKind)
	if err != nil {
		return err
	}
	edgesByKind, err := json.Marshal(summary.EdgesByKind)
	if err != nil {
		return err
	}
	evidence, err := json.Marshal(summary.EvidenceCounts)
	if err != nil {
		return err
	}
	coverage, err := json.Marshal(summary.Coverage)
	if err != nil {
		return err
	}
	limitations, err := json.Marshal(summary.Limitations)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`
INSERT INTO asg_builds (snapshot_id, asg_version, scg_version, engine, engine_version, ruleset_hash, nodes, edges,
    nodes_by_kind_json, edges_by_kind_json, evidence_json, coverage_json, limitations_json, built_at, build_duration_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		snapshotID, summary.ASGVersion, summary.SCGVersion, summary.Engine.Name, summary.Engine.Version,
		summary.RulesetHash, summary.Nodes, summary.Edges, string(nodesByKind), string(edgesByKind),
		string(evidence), string(coverage), string(limitations), summary.BuiltAt, summary.BuildDurationMS); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

// DeleteASG implements ASGStore. Deleting an absent ASG is a no-op: the derived
// layer the caller asked to remove is already gone.
func (s *SQL) DeleteASG(ctx context.Context, snapshotID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	for _, table := range []string{"asg_nodes", "asg_edges", "asg_builds"} {
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM `+table+` WHERE snapshot_id = ?`), snapshotID); err != nil {
			return mapSQLError(err)
		}
	}
	return tx.Commit()
}

// ASGSummary implements ASGStore.
func (s *SQL) ASGSummary(ctx context.Context, snapshotID string) (*asg.Summary, error) {
	row := s.db.QueryRowContext(ctx, s.rebind(`
SELECT asg_version, scg_version, engine, engine_version, ruleset_hash, nodes, edges, nodes_by_kind_json,
       edges_by_kind_json, evidence_json, coverage_json, limitations_json, built_at, build_duration_ms
FROM asg_builds WHERE snapshot_id = ?`), snapshotID)
	var (
		out                                          asg.Summary
		nodesByKind, edgesByKind, evidence, coverage string
		limitations                                  string
	)
	if err := row.Scan(&out.ASGVersion, &out.SCGVersion, &out.Engine.Name, &out.Engine.Version, &out.RulesetHash,
		&out.Nodes, &out.Edges, &nodesByKind, &edgesByKind, &evidence, &coverage, &limitations,
		&out.BuiltAt, &out.BuildDurationMS); err != nil {
		return nil, mapSQLError(err)
	}
	out.SnapshotID = snapshotID
	if err := json.Unmarshal([]byte(nodesByKind), &out.NodesByKind); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(edgesByKind), &out.EdgesByKind); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(evidence), &out.EvidenceCounts); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(coverage), &out.Coverage); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(limitations), &out.Limitations); err != nil {
		return nil, err
	}
	if out.Limitations == nil {
		out.Limitations = []string{}
	}
	if out.NodesByKind == nil {
		out.NodesByKind = map[string]int{}
	}
	if out.EdgesByKind == nil {
		out.EdgesByKind = map[string]int{}
	}
	if out.EvidenceCounts == nil {
		out.EvidenceCounts = map[string]int{}
	}
	return &out, nil
}

// requireASG fails with ErrNotFound when a snapshot has no ASG, so a query
// against an unindexed snapshot is never answered with an empty list. "No
// matching node" and "no attack surface" must not look the same to a caller.
func (s *SQL) requireASG(ctx context.Context, snapshotID string) error {
	var count int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(1) FROM asg_builds WHERE snapshot_id = ?`), snapshotID).Scan(&count); err != nil {
		return mapSQLError(err)
	}
	if count == 0 {
		return fmt.Errorf("%w: ASG for snapshot %s", ErrNotFound, snapshotID)
	}
	return nil
}

const asgNodeColumns = `node_id, snapshot_id, kind, subject, label, detail_json, evidence_status, confidence,
	generator, module_id, file, line, scg_refs_json`

func scanASGNode(scan func(...any) error) (asg.Node, error) {
	var (
		n                          asg.Node
		kind, evidence, confidence string
		detail, refs               string
	)
	if err := scan(&n.ID, &n.SnapshotID, &kind, &n.Subject, &n.Label, &detail, &evidence, &confidence,
		&n.Generator, &n.ModuleID, &n.File, &n.Line, &refs); err != nil {
		return asg.Node{}, err
	}
	n.Kind = asg.NodeKind(kind)
	n.Evidence = asg.EvidenceStatus(evidence)
	n.Confidence = scg.Confidence(confidence)
	if detail != "" && detail != "{}" {
		if err := json.Unmarshal([]byte(detail), &n.Detail); err != nil {
			return asg.Node{}, fmt.Errorf("storage: decode ASG node detail for %s: %w", n.ID, err)
		}
	}
	if refs != "" && refs != "null" {
		if err := json.Unmarshal([]byte(refs), &n.SCGRefs); err != nil {
			return asg.Node{}, fmt.Errorf("storage: decode ASG node SCG references for %s: %w", n.ID, err)
		}
	}
	return n, nil
}

// asgNodeFilter builds the shared WHERE clause of ASG node reads.
func asgNodeFilter(q ASGNodeQuery) (string, []any) {
	where := []string{"snapshot_id = ?"}
	args := []any{q.SnapshotID}
	if len(q.Kinds) > 0 {
		placeholders := make([]string, 0, len(q.Kinds))
		for _, k := range q.Kinds {
			placeholders = append(placeholders, "?")
			args = append(args, string(k))
		}
		where = append(where, "kind IN ("+strings.Join(placeholders, ", ")+")")
	}
	if q.Subject != "" {
		where = append(where, "subject = ?")
		args = append(args, q.Subject)
	}
	if q.Generator != "" {
		where = append(where, "generator = ?")
		args = append(args, q.Generator)
	}
	if q.File != "" {
		where = append(where, "file = ?")
		args = append(args, q.File)
	}
	return strings.Join(where, " AND "), args
}

// ListASGNodes implements ASGStore.
func (s *SQL) ListASGNodes(ctx context.Context, q ASGNodeQuery) ([]asg.Node, int, error) {
	if err := s.requireASG(ctx, q.SnapshotID); err != nil {
		return nil, 0, err
	}
	where, args := asgNodeFilter(q)
	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(1) FROM asg_nodes WHERE `+where), args...).Scan(&total); err != nil {
		return nil, 0, mapSQLError(err)
	}
	query := `SELECT ` + asgNodeColumns + ` FROM asg_nodes WHERE ` + where + ` ORDER BY kind, label, node_id LIMIT ? OFFSET ?`
	args = append(args, normaliseLimit(q.Limit, 200, 2000), max(q.Offset, 0))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, 0, mapSQLError(err)
	}
	defer rows.Close()
	var out []asg.Node
	for rows.Next() {
		n, err := scanASGNode(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, n)
	}
	return out, total, rows.Err()
}

// GetASGNode implements ASGStore.
func (s *SQL) GetASGNode(ctx context.Context, snapshotID, nodeID string) (asg.Node, error) {
	if err := s.requireASG(ctx, snapshotID); err != nil {
		return asg.Node{}, err
	}
	row := s.db.QueryRowContext(ctx, s.rebind(`SELECT `+asgNodeColumns+` FROM asg_nodes
WHERE snapshot_id = ? AND node_id = ?`), snapshotID, nodeID)
	n, err := scanASGNode(row.Scan)
	if err != nil {
		return asg.Node{}, mapSQLError(err)
	}
	return n, nil
}

// ListASGEdges implements ASGStore. The result is bounded rather than paged:
// callers ask for the edges of a small set of endpoints, not for a listing.
func (s *SQL) ListASGEdges(ctx context.Context, q ASGEdgeQuery) ([]asg.Edge, error) {
	if err := s.requireASG(ctx, q.SnapshotID); err != nil {
		return nil, err
	}
	where := []string{"snapshot_id = ?"}
	args := []any{q.SnapshotID}
	if len(q.From) > 0 {
		placeholders := make([]string, 0, len(q.From))
		for _, id := range q.From {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		where = append(where, "from_id IN ("+strings.Join(placeholders, ", ")+")")
	}
	if len(q.To) > 0 {
		placeholders := make([]string, 0, len(q.To))
		for _, id := range q.To {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		where = append(where, "to_id IN ("+strings.Join(placeholders, ", ")+")")
	}
	if len(q.Kinds) > 0 {
		placeholders := make([]string, 0, len(q.Kinds))
		for _, k := range q.Kinds {
			placeholders = append(placeholders, "?")
			args = append(args, string(k))
		}
		where = append(where, "kind IN ("+strings.Join(placeholders, ", ")+")")
	}
	query := `SELECT edge_id, snapshot_id, from_id, to_id, kind, evidence_status, confidence, generator,
		detail_json, scg_refs_json FROM asg_edges WHERE ` + strings.Join(where, " AND ") +
		` ORDER BY edge_id LIMIT ?`
	args = append(args, normaliseLimit(q.Limit, 500, 5000))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var out []asg.Edge
	for rows.Next() {
		var (
			e                    asg.Edge
			kind, evidence, conf string
			detail, refs         string
		)
		if err := rows.Scan(&e.ID, &e.SnapshotID, &e.From, &e.To, &kind, &evidence, &conf, &e.Generator,
			&detail, &refs); err != nil {
			return nil, err
		}
		e.Kind = asg.EdgeKind(kind)
		e.Evidence = asg.EvidenceStatus(evidence)
		e.Confidence = scg.Confidence(conf)
		if detail != "" && detail != "{}" {
			if err := json.Unmarshal([]byte(detail), &e.Detail); err != nil {
				return nil, fmt.Errorf("storage: decode ASG edge detail for %s: %w", e.ID, err)
			}
		}
		if refs != "" && refs != "null" {
			if err := json.Unmarshal([]byte(refs), &e.SCGRefs); err != nil {
				return nil, fmt.Errorf("storage: decode ASG edge SCG references for %s: %w", e.ID, err)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
