package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// auditColumnNames is the column list of `audits` in the order every statement
// here reads and writes it. The write and the scan must stay aligned, so both are
// derived from this one list.
var auditColumnNames = []string{
	"audit_id", "snapshot_id", "scg_version", "asg_version", "status", "budget_json", "limits_json",
	"score_version", "config_hash", "path_count", "counts_by_status_json", "counts_by_path_status_json",
	"coverage_json", "limitations_json", "created_at", "updated_at", "version",
}

var pathColumnNames = []string{
	"path_id", "audit_id", "snapshot_id", "scg_version", "asg_version", "entry_node_id", "target_node_id",
	"path_kind", "path_status", "status", "steps_json", "signature", "cluster_json", "scg_refs_json",
	"asg_refs_json", "objectives_json", "boundaries_json", "controls_json", "inputs_json", "assets_json",
	"open_questions_json", "limitations_json", "depth", "branch_count", "budget_json", "features_json",
	"risk", "support", "utility", "priority", "score_version", "weights_json", "score_seq", "lease_owner",
	"lease_until", "heartbeat_at", "attempts", "max_attempts", "last_error", "next_attempt_at",
	"created_at", "updated_at", "version",
}

var featureColumnNames = []string{
	"path_id", "seq", "audit_id", "score_version", "risk", "support", "utility", "priority",
	"features_json", "weights_json", "reasons_json", "computed_at",
}

var eventColumnNames = []string{
	"event_id", "audit_id", "path_id", "seq", "type", "from_status", "to_status", "actor", "reason",
	"detail_json", "created_at",
}

var (
	auditSelectColumns    = strings.Join(auditColumnNames, ", ")
	pathSelectColumns     = strings.Join(pathColumnNames, ", ")
	pathSelectByIDSQL     = "SELECT " + pathSelectColumns + " FROM audit_paths WHERE path_id = ?"
	pathUpdateSetClauses  = setClauses(pathColumnNames[1:])
	auditUpdateSetClauses = setClauses(auditColumnNames[1:])
)

// pathScoreJSON is the payload of `audit_paths.weights_json`.
//
// The schema has no column for Score.ComputedAt, so the weights and the score
// timestamp travel together in the one TEXT column the audit_paths table gives
// them: storing the bare map would silently drop the timestamp of every score the
// engine writes, and GetPath would return a document that is not the one written.
type pathScoreJSON struct {
	Weights    map[string]float64 `json:"weights"`
	ComputedAt string             `json:"computed_at,omitempty"`
}

// sqlExecer is what deleteAuditRowsForSnapshot needs: both *sql.DB and *sql.Tx
// satisfy it, so the same cascade serves DeleteAuditsForSnapshot and
// DeleteSnapshot.
type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// setClauses renders "name = ?" for every column but the primary key.
func setClauses(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, name+" = ?")
	}
	return out
}

// placeholders renders a question-mark list; rebind translates it per dialect.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

// whereClause joins filter predicates, or returns nothing when there are none.
func whereClause(clauses []string) string {
	if len(clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(clauses, " AND ")
}

// mapAuditSQLError translates driver errors into the path engine's vocabulary:
// the API answers with distinct HTTP codes for "gone" and "lost the race", and
// the engine matches on these sentinels.
func mapAuditSQLError(err error) error {
	mapped := mapSQLError(err)
	switch {
	case mapped == nil:
		return nil
	case errors.Is(mapped, ErrNotFound):
		return fmt.Errorf("%w: %v", path.ErrNotFound, err)
	case errors.Is(mapped, ErrConflict):
		return fmt.Errorf("%w: %v", path.ErrConflict, err)
	}
	return mapped
}

// forUpdate locks the row a write transaction is about to change on PostgreSQL.
// SQLite serialises writers itself and rejects the clause, so it is only added
// for the PostgreSQL dialect.
func (s *SQL) forUpdate() string {
	if s.postgres {
		return " FOR UPDATE"
	}
	return ""
}

// auditWriteValues renders one audit in auditColumnNames order.
func auditWriteValues(audit path.Audit) ([]any, error) {
	budget, err := jsonString(audit.Budget)
	if err != nil {
		return nil, err
	}
	limits, err := jsonString(audit.Limits)
	if err != nil {
		return nil, err
	}
	counts, err := jsonString(audit.CountsByStatus)
	if err != nil {
		return nil, err
	}
	countsByPath, err := jsonString(audit.CountsByPathStatus)
	if err != nil {
		return nil, err
	}
	coverage, err := jsonString(audit.Coverage)
	if err != nil {
		return nil, err
	}
	limitations, err := jsonString(audit.Limitations)
	if err != nil {
		return nil, err
	}
	return []any{
		audit.ID, audit.SnapshotID, audit.SCGVersion, audit.ASGVersion, audit.Status, budget, limits,
		audit.ScoreVersion, audit.ConfigHash, audit.PathCount, counts, countsByPath, coverage, limitations,
		audit.CreatedAt, audit.UpdatedAt, audit.Version,
	}, nil
}

// scanAuditRow reads the columns of auditColumnNames in order.
func scanAuditRow(scan func(...any) error) (path.Audit, error) {
	var (
		audit                                                       path.Audit
		budget, limits, counts, countsByPath, coverage, limitations string
	)
	if err := scan(&audit.ID, &audit.SnapshotID, &audit.SCGVersion, &audit.ASGVersion, &audit.Status, &budget,
		&limits, &audit.ScoreVersion, &audit.ConfigHash, &audit.PathCount, &counts, &countsByPath, &coverage,
		&limitations, &audit.CreatedAt, &audit.UpdatedAt, &audit.Version); err != nil {
		return path.Audit{}, err
	}
	for _, column := range []struct {
		raw    string
		target any
	}{
		{budget, &audit.Budget},
		{limits, &audit.Limits},
		{counts, &audit.CountsByStatus},
		{countsByPath, &audit.CountsByPathStatus},
		{coverage, &audit.Coverage},
		{limitations, &audit.Limitations},
	} {
		if err := decodeJSON(column.raw, column.target); err != nil {
			return path.Audit{}, fmt.Errorf("storage: audit %s: %w", audit.ID, err)
		}
	}
	return audit, nil
}

// pathWriteValues renders one path in pathColumnNames order.
func pathWriteValues(p path.Path) ([]any, error) {
	steps, err := jsonString(p.Steps)
	if err != nil {
		return nil, err
	}
	cluster, err := jsonString(p.Cluster)
	if err != nil {
		return nil, err
	}
	scgRefs, err := jsonString(p.SCGRefs)
	if err != nil {
		return nil, err
	}
	asgRefs, err := jsonString(p.ASGRefs)
	if err != nil {
		return nil, err
	}
	objectives, err := jsonString(p.Objectives)
	if err != nil {
		return nil, err
	}
	boundaries, err := jsonString(p.Boundaries)
	if err != nil {
		return nil, err
	}
	controls, err := jsonString(p.Controls)
	if err != nil {
		return nil, err
	}
	inputs, err := jsonString(p.Inputs)
	if err != nil {
		return nil, err
	}
	assets, err := jsonString(p.Assets)
	if err != nil {
		return nil, err
	}
	openQuestions, err := jsonString(p.OpenQuestions)
	if err != nil {
		return nil, err
	}
	limitations, err := jsonString(p.Limitations)
	if err != nil {
		return nil, err
	}
	budget, err := jsonString(p.Budget)
	if err != nil {
		return nil, err
	}
	features, err := jsonString(p.Features)
	if err != nil {
		return nil, err
	}
	weights, err := jsonString(pathScoreJSON{Weights: p.Score.Weights, ComputedAt: p.Score.ComputedAt})
	if err != nil {
		return nil, err
	}
	return []any{
		p.ID, p.AuditID, p.SnapshotID, p.SCGVersion, p.ASGVersion, p.EntryNodeID, p.TargetNodeID, p.PathKind,
		string(p.PathStatus), string(p.Status), steps, p.Signature, cluster, scgRefs, asgRefs, objectives,
		boundaries, controls, inputs, assets, openQuestions, limitations, p.Depth, p.BranchCount, budget,
		features, p.Score.Risk, p.Score.Support, p.Score.Utility, p.Score.Priority, p.Score.ScoreVersion,
		weights, p.ScoreSeq, p.LeaseOwner, p.LeaseUntil, p.HeartbeatAt, p.Attempts, p.MaxAttempts, p.LastError,
		p.NextAttemptAt, p.CreatedAt, p.UpdatedAt, p.Version,
	}, nil
}

// scanPathRow reads the columns of pathColumnNames in order.
func scanPathRow(scan func(...any) error) (path.Path, error) {
	var (
		p                                                                                  path.Path
		pathStatus, status                                                                 string
		steps, cluster, scgRefs, asgRefs, objectives, boundaries, controls, inputs, assets string
		openQuestions, limitations, budget, features, weights                              string
	)
	if err := scan(&p.ID, &p.AuditID, &p.SnapshotID, &p.SCGVersion, &p.ASGVersion, &p.EntryNodeID,
		&p.TargetNodeID, &p.PathKind, &pathStatus, &status, &steps, &p.Signature, &cluster, &scgRefs,
		&asgRefs, &objectives, &boundaries, &controls, &inputs, &assets, &openQuestions, &limitations,
		&p.Depth, &p.BranchCount, &budget, &features, &p.Score.Risk, &p.Score.Support, &p.Score.Utility,
		&p.Score.Priority, &p.Score.ScoreVersion, &weights, &p.ScoreSeq, &p.LeaseOwner, &p.LeaseUntil,
		&p.HeartbeatAt, &p.Attempts, &p.MaxAttempts, &p.LastError, &p.NextAttemptAt, &p.CreatedAt, &p.UpdatedAt,
		&p.Version); err != nil {
		return path.Path{}, err
	}
	p.PathStatus = path.PathStatus(pathStatus)
	p.Status = path.Status(status)
	var score pathScoreJSON
	for _, column := range []struct {
		raw    string
		target any
	}{
		{steps, &p.Steps},
		{cluster, &p.Cluster},
		{scgRefs, &p.SCGRefs},
		{asgRefs, &p.ASGRefs},
		{objectives, &p.Objectives},
		{boundaries, &p.Boundaries},
		{controls, &p.Controls},
		{inputs, &p.Inputs},
		{assets, &p.Assets},
		{openQuestions, &p.OpenQuestions},
		{limitations, &p.Limitations},
		{budget, &p.Budget},
		{features, &p.Features},
		{weights, &score},
	} {
		if err := decodeJSON(column.raw, column.target); err != nil {
			return path.Path{}, fmt.Errorf("storage: path %s: %w", p.ID, err)
		}
	}
	p.Score.Weights = score.Weights
	p.Score.ComputedAt = score.ComputedAt
	return p, nil
}

// featureWriteValues renders one score snapshot in featureColumnNames order.
func featureWriteValues(record path.FeatureRecord) ([]any, error) {
	features, err := jsonString(record.Features)
	if err != nil {
		return nil, err
	}
	weights, err := jsonString(record.Weights)
	if err != nil {
		return nil, err
	}
	reasons, err := jsonString(record.Reasons)
	if err != nil {
		return nil, err
	}
	return []any{
		record.PathID, record.Seq, record.AuditID, record.ScoreVersion, record.Risk, record.Support,
		record.Utility, record.Priority, features, weights, reasons, record.ComputedAt,
	}, nil
}

// scanFeatureRow reads the columns of featureColumnNames in order.
func scanFeatureRow(scan func(...any) error) (path.FeatureRecord, error) {
	var (
		record                     path.FeatureRecord
		features, weights, reasons string
	)
	if err := scan(&record.PathID, &record.Seq, &record.AuditID, &record.ScoreVersion, &record.Risk,
		&record.Support, &record.Utility, &record.Priority, &features, &weights, &reasons,
		&record.ComputedAt); err != nil {
		return path.FeatureRecord{}, err
	}
	for _, column := range []struct {
		raw    string
		target any
	}{
		{features, &record.Features},
		{weights, &record.Weights},
		{reasons, &record.Reasons},
	} {
		if err := decodeJSON(column.raw, column.target); err != nil {
			return path.FeatureRecord{}, fmt.Errorf("storage: features of path %s: %w", record.PathID, err)
		}
	}
	return record, nil
}

// eventWriteValues renders one event in eventColumnNames order.
func eventWriteValues(event path.Event) ([]any, error) {
	detail, err := jsonString(event.Detail)
	if err != nil {
		return nil, err
	}
	return []any{
		event.ID, event.AuditID, event.PathID, event.Seq, event.Type, string(event.From), string(event.To),
		event.Actor, event.Reason, detail, event.CreatedAt,
	}, nil
}

// scanEventRow reads the columns of eventColumnNames in order.
func scanEventRow(scan func(...any) error) (path.Event, error) {
	var (
		event            path.Event
		from, to, detail string
	)
	if err := scan(&event.ID, &event.AuditID, &event.PathID, &event.Seq, &event.Type, &from, &to, &event.Actor,
		&event.Reason, &detail, &event.CreatedAt); err != nil {
		return path.Event{}, err
	}
	event.From = path.Status(from)
	event.To = path.Status(to)
	if err := decodeJSON(detail, &event.Detail); err != nil {
		return path.Event{}, fmt.Errorf("storage: event %s: %w", event.ID, err)
	}
	return event, nil
}

// CreateAudit implements path.Store.
func (s *SQL) CreateAudit(audit path.Audit) error {
	if audit.ID == "" {
		return fmt.Errorf("%w: an audit needs an id", path.ErrInvalidArgument)
	}
	values, err := auditWriteValues(audit)
	if err != nil {
		return err
	}
	query := "INSERT INTO audits (" + strings.Join(auditColumnNames, ", ") + ") VALUES (" + placeholders(len(values)) + ")"
	return s.snapshotWrite(context.Background(), audit.SnapshotID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), s.rebind(query), values...)
		return mapAuditSQLError(err)
	})
}

// GetAudit implements path.Store.
func (s *SQL) GetAudit(auditID string) (*path.Audit, error) {
	row := s.db.QueryRowContext(context.Background(),
		s.rebind("SELECT "+auditSelectColumns+" FROM audits WHERE audit_id = ?"), auditID)
	audit, err := scanAuditRow(row.Scan)
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	return &audit, nil
}

// ListAudits implements path.Store.
func (s *SQL) ListAudits(q path.AuditQuery) ([]path.Audit, int, error) {
	ctx := context.Background()
	clauses := []string{}
	args := []any{}
	if q.SnapshotID != "" {
		clauses = append(clauses, "snapshot_id = ?")
		args = append(args, q.SnapshotID)
	}
	if q.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, q.Status)
	}
	where := whereClause(clauses)

	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM audits"+where), args...).Scan(&total); err != nil {
		return nil, 0, mapAuditSQLError(err)
	}
	query := "SELECT " + auditSelectColumns + " FROM audits" + where + " ORDER BY audit_id LIMIT ? OFFSET ?"
	args = append(args, normaliseLimit(q.Limit, 100, 1000), max(q.Offset, 0))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, 0, mapAuditSQLError(err)
	}
	defer rows.Close()
	var out []path.Audit
	for rows.Next() {
		audit, err := scanAuditRow(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, audit)
	}
	return out, total, rows.Err()
}

// UpdateAudit implements path.Store.
func (s *SQL) UpdateAudit(audit path.Audit, expectedVersion int64) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapAuditSQLError(err)
	}
	defer tx.Rollback()
	if err := s.snapshotWritableTx(ctx, tx, audit.SnapshotID); err != nil {
		return err
	}

	var current int64
	row := tx.QueryRowContext(ctx, s.rebind("SELECT version FROM audits WHERE audit_id = ?"+s.forUpdate()), audit.ID)
	if err := row.Scan(&current); err != nil {
		return mapAuditSQLError(err)
	}
	if expectedVersion > 0 && current != expectedVersion {
		return fmt.Errorf("%w: audit %s is at version %d, expected %d", path.ErrConflict, audit.ID, current, expectedVersion)
	}
	if audit.Version <= current {
		audit.Version = current + 1
	}
	values, err := auditWriteValues(audit)
	if err != nil {
		return err
	}
	args := append(append([]any{}, values[1:]...), audit.ID, current)
	query := "UPDATE audits SET " + strings.Join(auditUpdateSetClauses, ", ") + " WHERE audit_id = ? AND version = ?"
	res, err := tx.ExecContext(ctx, s.rebind(query), args...)
	if err != nil {
		return mapAuditSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return mapAuditSQLError(err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: audit %s was changed by another writer", path.ErrConflict, audit.ID)
	}
	return tx.Commit()
}

// ReplacePaths implements path.Store. The previous generation is deleted and the
// new one inserted in one transaction: a reader sees one generation or the other,
// never a mixture, and the unique (audit_id, signature) index makes exact dedup
// the database's invariant rather than a caller's convention.
func (s *SQL) ReplacePaths(auditID string, paths []path.Path) error {
	if auditID == "" {
		return fmt.Errorf("%w: an audit id is required", path.ErrInvalidArgument)
	}
	values := make([][]any, 0, len(paths))
	keep := make(map[string]bool, len(paths))
	signatures := make(map[string]bool, len(paths))
	for _, p := range paths {
		if p.AuditID != auditID {
			return fmt.Errorf("%w: path %s belongs to audit %q, not %q", path.ErrInvalidArgument, p.ID, p.AuditID, auditID)
		}
		if signatures[p.Signature] {
			return fmt.Errorf("%w: duplicate path signature %s in audit %s", path.ErrConflict, p.Signature, auditID)
		}
		signatures[p.Signature] = true
		if keep[p.ID] {
			return fmt.Errorf("%w: duplicate path id %s in audit %s", path.ErrConflict, p.ID, auditID)
		}
		keep[p.ID] = true
		rendered, err := pathWriteValues(p)
		if err != nil {
			return err
		}
		values = append(values, rendered)
	}

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapAuditSQLError(err)
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM audits WHERE audit_id = ?"), auditID).Scan(&exists); err != nil {
		return mapAuditSQLError(err)
	}
	if exists == 0 {
		return fmt.Errorf("%w: audit %s", path.ErrNotFound, auditID)
	}

	// Paths that leave the generation take their feature snapshots with them: the
	// score sequence restarts from the stored generation, so a stale row would
	// collide when the path comes back. Snapshots of surviving paths stay.
	rows, err := tx.QueryContext(ctx, s.rebind("SELECT path_id FROM audit_paths WHERE audit_id = ?"), auditID)
	if err != nil {
		return mapAuditSQLError(err)
	}
	var removed []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return mapAuditSQLError(err)
		}
		if !keep[id] {
			removed = append(removed, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return mapAuditSQLError(err)
	}
	rows.Close()
	for _, id := range removed {
		if _, err := tx.ExecContext(ctx, s.rebind("DELETE FROM path_features WHERE path_id = ?"), id); err != nil {
			return mapAuditSQLError(err)
		}
	}
	if _, err := tx.ExecContext(ctx, s.rebind("DELETE FROM audit_paths WHERE audit_id = ?"), auditID); err != nil {
		return mapAuditSQLError(err)
	}
	insert := "INSERT INTO audit_paths (" + strings.Join(pathColumnNames, ", ") + ") VALUES (" + placeholders(len(pathColumnNames)) + ")"
	stmt, err := tx.PrepareContext(ctx, s.rebind(insert))
	if err != nil {
		return mapAuditSQLError(err)
	}
	defer stmt.Close()
	for _, rendered := range values {
		if _, err := stmt.ExecContext(ctx, rendered...); err != nil {
			return mapAuditSQLError(err)
		}
	}
	return tx.Commit()
}

// GetPath implements path.Store.
func (s *SQL) GetPath(pathID string) (*path.Path, error) {
	row := s.db.QueryRowContext(context.Background(), s.rebind(pathSelectByIDSQL), pathID)
	p, err := scanPathRow(row.Scan)
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	return &p, nil
}

// ListPaths implements path.Store.
func (s *SQL) ListPaths(q path.PathQuery) ([]path.Path, int, error) {
	ctx := context.Background()
	where, args := pathQueryFilter(q)

	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM audit_paths"+where), args...).Scan(&total); err != nil {
		return nil, 0, mapAuditSQLError(err)
	}
	// Priority order is the queue order; the path id breaks ties so paging is
	// stable, which is what a scheduler that resumes from an offset needs.
	order := " ORDER BY priority DESC, path_id"
	switch q.Sort {
	case "path_id":
		order = " ORDER BY path_id"
	case "created":
		order = " ORDER BY created_at, path_id"
	}
	query := "SELECT " + pathSelectColumns + " FROM audit_paths" + where + order + " LIMIT ? OFFSET ?"
	// Paths are bounded per audit by Limits.MaxPaths and the engine pages with an
	// explicit limit, so only a default applies and nothing is silently truncated.
	args = append(args, normaliseLimit(q.Limit, 500, 0), max(q.Offset, 0))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, 0, mapAuditSQLError(err)
	}
	defer rows.Close()
	var out []path.Path
	for rows.Next() {
		p, err := scanPathRow(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

// ListDuePaths implements path.Store: the queued paths of one audit whose backoff
// has elapsed, oldest due time first.
//
// `now` and next_attempt_at are both RFC3339, so comparing them as strings
// compares times and the query stays dialect-neutral. An empty next_attempt_at
// means the path was never deferred, which counts as due and sorts first.
func (s *SQL) ListDuePaths(auditID, now string, limit int) ([]path.Path, error) {
	ctx := context.Background()
	query := "SELECT " + pathSelectColumns + " FROM audit_paths WHERE audit_id = ? AND status = ?" +
		" AND (next_attempt_at = '' OR next_attempt_at <= ?) ORDER BY next_attempt_at, path_id LIMIT ?"
	rows, err := s.db.QueryContext(ctx, s.rebind(query), auditID, string(path.StatusQueued), now,
		normaliseLimit(limit, 100, 1000))
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	defer rows.Close()
	var out []path.Path
	for rows.Next() {
		p, err := scanPathRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// pathQueryFilter renders the shared WHERE clause of a path listing.
func pathQueryFilter(q path.PathQuery) (string, []any) {
	clauses := []string{}
	args := []any{}
	if q.AuditID != "" {
		clauses = append(clauses, "audit_id = ?")
		args = append(args, q.AuditID)
	}
	if q.SnapshotID != "" {
		clauses = append(clauses, "snapshot_id = ?")
		args = append(args, q.SnapshotID)
	}
	if len(q.Status) > 0 {
		clauses = append(clauses, "status IN ("+placeholders(len(q.Status))+")")
		for _, status := range q.Status {
			args = append(args, string(status))
		}
	}
	if len(q.PathStatus) > 0 {
		clauses = append(clauses, "path_status IN ("+placeholders(len(q.PathStatus))+")")
		for _, status := range q.PathStatus {
			args = append(args, string(status))
		}
	}
	if q.EntryNodeID != "" {
		clauses = append(clauses, "entry_node_id = ?")
		args = append(args, q.EntryNodeID)
	}
	if q.TargetNodeID != "" {
		clauses = append(clauses, "target_node_id = ?")
		args = append(args, q.TargetNodeID)
	}
	// MinPriority of 0 means "no floor": a priority of 0 is a legitimate score.
	if q.MinPriority > 0 {
		clauses = append(clauses, "priority >= ?")
		args = append(args, q.MinPriority)
	}
	// DueBefore is a retry-time filter, not a status filter: an empty
	// next_attempt_at was never deferred and always counts as due. The values are
	// RFC3339, so the comparison is a string comparison by design.
	if q.DueBefore != "" {
		clauses = append(clauses, "(next_attempt_at = '' OR next_attempt_at <= ?)")
		args = append(args, q.DueBefore)
	}
	return whereClause(clauses), args
}

// UpdatePath implements path.Store.
func (s *SQL) UpdatePath(p path.Path, expectedVersion int64) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapAuditSQLError(err)
	}
	defer tx.Rollback()

	var current int64
	row := tx.QueryRowContext(ctx, s.rebind("SELECT version FROM audit_paths WHERE path_id = ?"+s.forUpdate()), p.ID)
	if err := row.Scan(&current); err != nil {
		return mapAuditSQLError(err)
	}
	if expectedVersion > 0 && current != expectedVersion {
		return fmt.Errorf("%w: path %s is at version %d, expected %d", path.ErrConflict, p.ID, current, expectedVersion)
	}
	if p.Version <= current {
		p.Version = current + 1
	}
	if err := s.updatePathTx(ctx, tx, p, current, pathUpdateSetClauses); err != nil {
		return err
	}
	return tx.Commit()
}

// updatePathTx rewrites a path row and fails with ErrConflict when the row moved
// under the writer. It is the single write statement of every path mutation.
func (s *SQL) updatePathTx(ctx context.Context, tx *sql.Tx, p path.Path, oldVersion int64, setClauses []string) error {
	if err := s.snapshotWritableTx(ctx, tx, p.SnapshotID); err != nil {
		return err
	}
	values, err := pathWriteValues(p)
	if err != nil {
		return err
	}
	args := append(append([]any{}, values[1:]...), p.ID, oldVersion)
	query := "UPDATE audit_paths SET " + strings.Join(setClauses, ", ") + " WHERE path_id = ? AND version = ?"
	res, err := tx.ExecContext(ctx, s.rebind(query), args...)
	if err != nil {
		return mapAuditSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return mapAuditSQLError(err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: path %s was changed by another writer", path.ErrConflict, p.ID)
	}
	return nil
}

// AppendFeatures implements path.Store. One transaction per call: a batch that
// names a missing path stores nothing.
func (s *SQL) AppendFeatures(records []path.FeatureRecord) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapAuditSQLError(err)
	}
	defer tx.Rollback()

	insert := "INSERT INTO path_features (" + strings.Join(featureColumnNames, ", ") +
		") VALUES (" + placeholders(len(featureColumnNames)) + ")"
	stmt, err := tx.PrepareContext(ctx, s.rebind(insert))
	if err != nil {
		return mapAuditSQLError(err)
	}
	defer stmt.Close()
	for _, record := range records {
		var auditID string
		row := tx.QueryRowContext(ctx, s.rebind("SELECT audit_id FROM audit_paths WHERE path_id = ?"), record.PathID)
		if err := row.Scan(&auditID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: path %s", path.ErrNotFound, record.PathID)
			}
			return mapAuditSQLError(err)
		}
		values, err := featureWriteValues(record)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, values...); err != nil {
			return mapAuditSQLError(err)
		}
	}
	return tx.Commit()
}

// ListFeatures implements path.Store. Snapshots come back oldest first; a limit
// selects the most recent ones, which is the history a caller compares.
func (s *SQL) ListFeatures(pathID string, limit int) ([]path.FeatureRecord, error) {
	ctx := context.Background()
	query := "SELECT " + strings.Join(featureColumnNames, ", ") +
		" FROM path_features WHERE path_id = ? ORDER BY seq DESC LIMIT ?"
	rows, err := s.db.QueryContext(ctx, s.rebind(query), pathID, normaliseLimit(limit, 50, 1000))
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	defer rows.Close()
	var out []path.FeatureRecord
	for rows.Next() {
		record, err := scanFeatureRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, mapAuditSQLError(err)
	}
	// The tail was read newest first; the contract returns it oldest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// AppendEvents implements path.Store. One transaction per call, with the audit's
// log position checked for every event: appending after a rerun continues the log
// instead of colliding with it.
func (s *SQL) AppendEvents(events []path.Event) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapAuditSQLError(err)
	}
	defer tx.Rollback()

	insert := "INSERT INTO path_events (" + strings.Join(eventColumnNames, ", ") +
		") VALUES (" + placeholders(len(eventColumnNames)) + ")"
	stmt, err := tx.PrepareContext(ctx, s.rebind(insert))
	if err != nil {
		return mapAuditSQLError(err)
	}
	defer stmt.Close()
	for _, event := range events {
		var exists int
		if err := tx.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM audits WHERE audit_id = ?"), event.AuditID).Scan(&exists); err != nil {
			return mapAuditSQLError(err)
		}
		if exists == 0 {
			return fmt.Errorf("%w: audit %s", path.ErrNotFound, event.AuditID)
		}
		var maxSeq int64
		if err := tx.QueryRowContext(ctx, s.rebind("SELECT COALESCE(MAX(seq), 0) FROM path_events WHERE audit_id = ?"), event.AuditID).Scan(&maxSeq); err != nil {
			return mapAuditSQLError(err)
		}
		if event.Seq <= maxSeq {
			return fmt.Errorf("%w: event sequence %d is already used in audit %s", path.ErrConflict, event.Seq, event.AuditID)
		}
		if event.ID == "" {
			event.ID = path.EventID(event.AuditID, event.PathID, event.Seq)
		}
		values, err := eventWriteValues(event)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, values...); err != nil {
			return mapAuditSQLError(err)
		}
	}
	return tx.Commit()
}

// ListEvents implements path.Store.
func (s *SQL) ListEvents(q path.EventQuery) ([]path.Event, error) {
	ctx := context.Background()
	clauses := []string{}
	args := []any{}
	if q.AuditID != "" {
		clauses = append(clauses, "audit_id = ?")
		args = append(args, q.AuditID)
	}
	if q.PathID != "" {
		clauses = append(clauses, "path_id = ?")
		args = append(args, q.PathID)
	}
	clauses = append(clauses, "seq > ?")
	args = append(args, q.AfterSeq)
	query := "SELECT " + strings.Join(eventColumnNames, ", ") + " FROM path_events" + whereClause(clauses) +
		" ORDER BY audit_id, seq LIMIT ?"
	args = append(args, normaliseLimit(q.Limit, 500, 5000))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	defer rows.Close()
	var out []path.Event
	for rows.Next() {
		event, err := scanEventRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

// NextEventSeq implements path.Store.
func (s *SQL) NextEventSeq(auditID string) (int64, error) {
	ctx := context.Background()
	var exists int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM audits WHERE audit_id = ?"), auditID).Scan(&exists); err != nil {
		return 0, mapAuditSQLError(err)
	}
	if exists == 0 {
		return 0, fmt.Errorf("%w: audit %s", path.ErrNotFound, auditID)
	}
	var maxSeq int64
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COALESCE(MAX(seq), 0) FROM path_events WHERE audit_id = ?"), auditID).Scan(&maxSeq); err != nil {
		return 0, mapAuditSQLError(err)
	}
	return maxSeq + 1, nil
}

// loadPathTx reads one path inside a write transaction.
func (s *SQL) loadPathTx(ctx context.Context, tx *sql.Tx, pathID string) (path.Path, error) {
	row := tx.QueryRowContext(ctx, s.rebind(pathSelectByIDSQL+s.forUpdate()), pathID)
	p, err := scanPathRow(row.Scan)
	if err != nil {
		return path.Path{}, mapAuditSQLError(err)
	}
	return p, nil
}

// nextEventSeqTx returns the audit's next sequence number inside a transaction.
func (s *SQL) nextEventSeqTx(ctx context.Context, tx *sql.Tx, auditID string) (int64, error) {
	var maxSeq int64
	if err := tx.QueryRowContext(ctx, s.rebind("SELECT COALESCE(MAX(seq), 0) FROM path_events WHERE audit_id = ?"), auditID).Scan(&maxSeq); err != nil {
		return 0, mapAuditSQLError(err)
	}
	return maxSeq + 1, nil
}

// insertEventTx appends one event with the sequence it was stamped with.
func (s *SQL) insertEventTx(ctx context.Context, tx *sql.Tx, event path.Event) error {
	values, err := eventWriteValues(event)
	if err != nil {
		return err
	}
	query := "INSERT INTO path_events (" + strings.Join(eventColumnNames, ", ") +
		") VALUES (" + placeholders(len(eventColumnNames)) + ")"
	if _, err := tx.ExecContext(ctx, s.rebind(query), values...); err != nil {
		return mapAuditSQLError(err)
	}
	return nil
}

// persistPathChangeTx writes the updated path and its event in the caller's
// transaction. The version guard is what makes two workers unable to win the same
// path, even if they read it concurrently.
func (s *SQL) persistPathChangeTx(ctx context.Context, tx *sql.Tx, updated path.Path, oldVersion int64, event path.Event) error {
	values, err := pathWriteValues(updated)
	if err != nil {
		return err
	}
	args := append(append([]any{}, values[1:]...), updated.ID, oldVersion)
	query := "UPDATE audit_paths SET " + strings.Join(pathUpdateSetClauses, ", ") + " WHERE path_id = ? AND version = ?"
	res, err := tx.ExecContext(ctx, s.rebind(query), args...)
	if err != nil {
		return mapAuditSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return mapAuditSQLError(err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: path %s was changed by another writer", path.ErrConflict, updated.ID)
	}
	seq, err := s.nextEventSeqTx(ctx, tx, updated.AuditID)
	if err != nil {
		return err
	}
	event.Seq = seq
	event.ID = path.EventID(event.AuditID, event.PathID, seq)
	return s.insertEventTx(ctx, tx, event)
}

// Transition implements path.Store: the status change and its event are written
// in one transaction, so the state and the log can never disagree.
func (s *SQL) Transition(req path.TransitionRequest) (*path.Path, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	defer tx.Rollback()

	current, err := s.loadPathTx(ctx, tx, req.PathID)
	if err != nil {
		return nil, err
	}
	updated, event, err := planPathTransition(current, req, auditNow())
	if err != nil {
		return nil, err
	}
	if err := s.persistPathChangeTx(ctx, tx, updated, current.Version, event); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, mapAuditSQLError(err)
	}
	return &updated, nil
}

// ClaimPath implements path.Store.
func (s *SQL) ClaimPath(pathID, owner, until string, from []path.Status, actor string) (*path.Path, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	defer tx.Rollback()
	// Serialize allocation at the audit, including independent SQLite handles.
	// Taking the write lock before reading also avoids a read-to-write upgrade.
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE audits SET version = version
WHERE audit_id = (SELECT audit_id FROM audit_paths WHERE path_id = ?)`), pathID); err != nil {
		return nil, mapAuditSQLError(err)
	}

	current, err := s.loadPathTx(ctx, tx, pathID)
	if err != nil {
		return nil, err
	}
	if err := s.snapshotWritableTx(ctx, tx, current.SnapshotID); err != nil {
		return nil, err
	}
	updated, event, err := planClaim(current, owner, until, from, actor, auditNow())
	if err != nil {
		return nil, err
	}
	var limitsJSON string
	if err := tx.QueryRowContext(ctx, s.rebind("SELECT limits_json FROM audits WHERE audit_id = ?"), current.AuditID).Scan(&limitsJSON); err != nil {
		return nil, mapAuditSQLError(err)
	}
	var limits path.Limits
	if err := json.Unmarshal([]byte(limitsJSON), &limits); err != nil {
		return nil, err
	}
	var active int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM audit_paths WHERE audit_id = ? AND status IN (?, ?, ?)`),
		current.AuditID, path.StatusAnalyzing, path.StatusLocalExploring, path.StatusVerifying).Scan(&active); err != nil {
		return nil, mapAuditSQLError(err)
	}
	if active >= limits.Normalize().MaxActiveLeases {
		return nil, fmt.Errorf("%w: audit %s has no free active lease", path.ErrBudgetExceeded, current.AuditID)
	}
	if err := s.persistPathChangeTx(ctx, tx, updated, current.Version, event); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, mapAuditSQLError(err)
	}
	return &updated, nil
}

// RenewLease implements path.Store.
func (s *SQL) RenewLease(pathID, owner, until, actor string) (*path.Path, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	defer tx.Rollback()

	current, err := s.loadPathTx(ctx, tx, pathID)
	if err != nil {
		return nil, err
	}
	updated, event, err := planLeaseRenewal(current, owner, until, actor, auditNow())
	if err != nil {
		return nil, err
	}
	if err := s.persistPathChangeTx(ctx, tx, updated, current.Version, event); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, mapAuditSQLError(err)
	}
	return &updated, nil
}

// ReleaseLease implements path.Store.
func (s *SQL) ReleaseLease(pathID, owner, actor, reason string) (*path.Path, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	defer tx.Rollback()

	current, err := s.loadPathTx(ctx, tx, pathID)
	if err != nil {
		return nil, err
	}
	updated, event, err := planRelease(current, owner, actor, reason, auditNow())
	if err != nil {
		return nil, err
	}
	if err := s.persistPathChangeTx(ctx, tx, updated, current.Version, event); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, mapAuditSQLError(err)
	}
	return &updated, nil
}

// ReclaimExpired implements path.Store. Every recovered path is read before any
// of them is written, so a cursor is never open while the same transaction
// writes, and the whole recovery is one transaction.
func (s *SQL) ReclaimExpired(now string, limit int, actor string) ([]path.Path, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	defer tx.Rollback()

	query := "SELECT " + pathSelectColumns + " FROM audit_paths WHERE lease_owner <> '' AND lease_until <> ''" +
		" AND lease_until < ? ORDER BY path_id LIMIT ?"
	rows, err := tx.QueryContext(ctx, s.rebind(query), now, normaliseLimit(limit, 100, 1000))
	if err != nil {
		return nil, mapAuditSQLError(err)
	}
	var expired []path.Path
	for rows.Next() {
		p, err := scanPathRow(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		expired = append(expired, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, mapAuditSQLError(err)
	}
	rows.Close()

	out := make([]path.Path, 0, len(expired))
	for _, p := range expired {
		updated, event, err := planReclaim(p, actor, now)
		if err != nil {
			return nil, err
		}
		if err := s.persistPathChangeTx(ctx, tx, updated, p.Version, event); err != nil {
			return nil, err
		}
		out = append(out, updated)
	}
	if err := tx.Commit(); err != nil {
		return nil, mapAuditSQLError(err)
	}
	return out, nil
}

// DeleteAuditsForSnapshot implements path.Store.
func (s *SQL) DeleteAuditsForSnapshot(snapshotID string) (int, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, mapAuditSQLError(err)
	}
	defer tx.Rollback()
	removed, err := s.deleteAuditRowsForSnapshot(ctx, tx, snapshotID)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, mapAuditSQLError(err)
	}
	return removed, nil
}

// deleteAuditRowsForSnapshot removes an audit and everything derived from it. It
// takes the executor rather than opening a transaction because DeleteSnapshot
// runs it inside the transaction that removes the snapshot itself.
func (s *SQL) deleteAuditRowsForSnapshot(ctx context.Context, exec sqlExecer, snapshotID string) (int, error) {
	for _, table := range []string{"path_features", "path_events", "audit_paths"} {
		query := "DELETE FROM " + table + " WHERE audit_id IN (SELECT audit_id FROM audits WHERE snapshot_id = ?)"
		if _, err := exec.ExecContext(ctx, s.rebind(query), snapshotID); err != nil {
			return 0, mapAuditSQLError(err)
		}
	}
	res, err := exec.ExecContext(ctx, s.rebind("DELETE FROM audits WHERE snapshot_id = ?"), snapshotID)
	if err != nil {
		return 0, mapAuditSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, mapAuditSQLError(err)
	}
	return int(affected), nil
}
