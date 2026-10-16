package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// verificationRunColumnNames is the column list of `verification_runs` in the
// order every statement here reads and writes it. The write and the scan must stay
// aligned, so both are derived from this one list.
//
// The list is deliberately missing `evidence_ids`: migration 0008 has no such
// column. A run's evidence is the evidence that names it, and the list is derived
// from the `evidence` table on read (see evidenceIDsForRun).
var verificationRunColumnNames = []string{
	"run_id", "hypothesis_id", "finding_id", "path_id", "audit_id", "snapshot_id", "plan_hash",
	"plan_json", "environment_json", "environment_digest", "outcome", "status", "executor",
	"executor_version", "network_allowed", "approved", "approved_by", "approved_at", "owner",
	"exit_code", "stop_reason", "error", "reproduction", "started_at", "finished_at", "elapsed_ms",
	"created_at", "updated_at", "version",
}

var evidenceColumnNames = []string{
	"evidence_id", "kind", "tool", "tool_version", "snapshot_id", "hypothesis_id", "finding_id",
	"path_id", "verification_run_id", "file", "line", "content_hash", "content", "redacted",
	"redaction_notes", "supersedes", "created_at",
}

var findingColumnNames = []string{
	"finding_id", "hypothesis_id", "path_id", "audit_id", "snapshot_id", "title", "severity",
	"status", "confidence", "supporting_json", "contradicting_json", "inconclusive_json",
	"verification_run_ids_json", "environments_json", "reproduce_steps", "limitations_json",
	"created_at", "updated_at", "version",
}

var (
	verificationRunSelectColumns    = strings.Join(verificationRunColumnNames, ", ")
	verificationRunSelectByIDSQL    = "SELECT " + verificationRunSelectColumns + " FROM verification_runs WHERE run_id = ?"
	verificationRunInsertSQL        = "INSERT INTO verification_runs (" + strings.Join(verificationRunColumnNames, ", ") + ") VALUES (" + placeholders(len(verificationRunColumnNames)) + ")"
	verificationRunUpdateSetClauses = setClauses(verificationRunColumnNames[1:])
	evidenceSelectColumns           = strings.Join(evidenceColumnNames, ", ")
	evidenceInsertSQL               = "INSERT INTO evidence (" + strings.Join(evidenceColumnNames, ", ") + ") VALUES (" + placeholders(len(evidenceColumnNames)) + ")"
	evidenceSelectByIDSQL           = "SELECT " + evidenceSelectColumns + " FROM evidence WHERE evidence_id = ?"
	findingSelectColumns            = strings.Join(findingColumnNames, ", ")
	findingInsertSQL                = "INSERT INTO findings (" + strings.Join(findingColumnNames, ", ") + ") VALUES (" + placeholders(len(findingColumnNames)) + ")"
	findingUpdateSetClauses         = setClauses(findingColumnNames[1:])
)

// verificationQuerier is what the derived evidence list needs: both *sql.DB and
// *sql.Tx can run the query, so a single run and a page of runs share the code.
type verificationQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// verificationRunWriteValues renders one run in verificationRunColumnNames order.
// `exit_code` is nullable and the zero `any` is how the schema says "the executor
// reported no process exit".
func verificationRunWriteValues(run verify.Run) ([]any, error) {
	plan, err := verificationJSON(run.Plan)
	if err != nil {
		return nil, err
	}
	environment, err := verificationJSON(run.Environment)
	if err != nil {
		return nil, err
	}
	network, approved := 0, 0
	if run.NetworkAllowed {
		network = 1
	}
	if run.Approved {
		approved = 1
	}
	var exit any
	if run.ExitCode != nil {
		exit = *run.ExitCode
	}
	return []any{
		run.ID, run.HypothesisID, run.FindingID, run.PathID, run.AuditID, run.SnapshotID, run.PlanHash,
		plan, environment, run.EnvironmentDigest, string(run.Outcome), string(run.Status), run.Executor,
		run.ExecutorVersion, network, approved, run.ApprovedBy, run.ApprovedAt, run.Owner, exit,
		run.StopReason, run.Error, run.Reproduction, run.StartedAt, run.FinishedAt, run.ElapsedMS,
		run.CreatedAt, run.UpdatedAt, run.Version,
	}, nil
}

// scanVerificationRunRow reads the columns of verificationRunColumnNames in
// order. The derived evidence list is not a column and is filled by the caller.
func scanVerificationRunRow(scan func(...any) error) (verify.Run, error) {
	var (
		run                                verify.Run
		plan, environment, outcome, status string
		network, approved                  int
		exit                               sql.NullInt64
	)
	if err := scan(&run.ID, &run.HypothesisID, &run.FindingID, &run.PathID, &run.AuditID,
		&run.SnapshotID, &run.PlanHash, &plan, &environment, &run.EnvironmentDigest, &outcome, &status,
		&run.Executor, &run.ExecutorVersion, &network, &approved, &run.ApprovedBy, &run.ApprovedAt,
		&run.Owner, &exit, &run.StopReason, &run.Error, &run.Reproduction, &run.StartedAt,
		&run.FinishedAt, &run.ElapsedMS, &run.CreatedAt, &run.UpdatedAt, &run.Version); err != nil {
		return verify.Run{}, err
	}
	run.Outcome = verify.Outcome(outcome)
	run.Status = verify.VerificationStatus(status)
	run.NetworkAllowed = network != 0
	run.Approved = approved != 0
	if exit.Valid {
		code := int(exit.Int64)
		run.ExitCode = &code
	}
	for _, column := range []struct {
		raw    string
		target any
	}{
		{plan, &run.Plan},
		{environment, &run.Environment},
	} {
		if err := decodeVerificationJSON(column.raw, column.target); err != nil {
			return verify.Run{}, fmt.Errorf("storage: verification run %s: %w", run.ID, err)
		}
	}
	return run, nil
}

// evidenceWriteValues renders one evidence object in evidenceColumnNames order.
func evidenceWriteValues(object verify.Evidence) ([]any, error) {
	redacted := 0
	if object.Redacted {
		redacted = 1
	}
	return []any{
		object.ID, string(object.Kind), object.Tool, object.ToolVersion, object.SnapshotID,
		object.HypothesisID, object.FindingID, object.PathID, object.VerificationRunID, object.File,
		object.Line, object.ContentHash, object.Content, redacted, object.RedactionNotes,
		object.Supersedes, object.CreatedAt,
	}, nil
}

// scanEvidenceRow reads the columns of evidenceColumnNames in order.
func scanEvidenceRow(scan func(...any) error) (verify.Evidence, error) {
	var (
		object   verify.Evidence
		kind     string
		redacted int
	)
	if err := scan(&object.ID, &kind, &object.Tool, &object.ToolVersion, &object.SnapshotID,
		&object.HypothesisID, &object.FindingID, &object.PathID, &object.VerificationRunID,
		&object.File, &object.Line, &object.ContentHash, &object.Content, &redacted,
		&object.RedactionNotes, &object.Supersedes, &object.CreatedAt); err != nil {
		return verify.Evidence{}, err
	}
	object.Kind = verify.EvidenceKind(kind)
	object.Redacted = redacted != 0
	return object, nil
}

// findingWriteValues renders one verdict in findingColumnNames order.
func findingWriteValues(finding verify.Finding) ([]any, error) {
	// The three evidence lists stay separate, and so do the run, environment and
	// limitation lists: a contradiction is the interesting part and must not be
	// folded into a generic "references" column.
	values := make([]string, 0, 6)
	for _, list := range []any{
		finding.Supporting, finding.Contradicting, finding.Inconclusive,
		finding.VerificationRunIDs, finding.Environments, finding.Limitations,
	} {
		encoded, err := verificationJSON(list)
		if err != nil {
			return nil, err
		}
		values = append(values, encoded)
	}
	return []any{
		finding.ID, finding.HypothesisID, finding.PathID, finding.AuditID, finding.SnapshotID,
		finding.Title, finding.Severity, string(finding.Status), finding.Confidence,
		values[0], values[1], values[2], values[3], values[4], finding.ReproduceSteps, values[5],
		finding.CreatedAt, finding.UpdatedAt, finding.Version,
	}, nil
}

// scanFindingRow reads the columns of findingColumnNames in order.
func scanFindingRow(scan func(...any) error) (verify.Finding, error) {
	var (
		finding                                 verify.Finding
		status                                  string
		supporting, contradicting, inconclusive string
		runs, environments, limitations         string
	)
	if err := scan(&finding.ID, &finding.HypothesisID, &finding.PathID, &finding.AuditID,
		&finding.SnapshotID, &finding.Title, &finding.Severity, &status, &finding.Confidence,
		&supporting, &contradicting, &inconclusive, &runs, &environments, &finding.ReproduceSteps,
		&limitations, &finding.CreatedAt, &finding.UpdatedAt, &finding.Version); err != nil {
		return verify.Finding{}, err
	}
	finding.Status = verify.FindingStatus(status)
	for _, column := range []struct {
		raw    string
		target any
	}{
		{supporting, &finding.Supporting},
		{contradicting, &finding.Contradicting},
		{inconclusive, &finding.Inconclusive},
		{runs, &finding.VerificationRunIDs},
		{environments, &finding.Environments},
		{limitations, &finding.Limitations},
	} {
		if err := decodeVerificationJSON(column.raw, column.target); err != nil {
			return verify.Finding{}, fmt.Errorf("storage: finding %s: %w", finding.ID, err)
		}
	}
	return finding, nil
}

// verificationRunQueryFilter renders the shared WHERE clause of a run listing.
func verificationRunQueryFilter(q verify.RunQuery) (string, []any) {
	clauses := []string{}
	args := []any{}
	for _, filter := range []struct {
		column string
		value  string
	}{
		{"hypothesis_id", q.HypothesisID},
		{"finding_id", q.FindingID},
		{"path_id", q.PathID},
		{"audit_id", q.AuditID},
		{"snapshot_id", q.SnapshotID},
		{"plan_hash", q.PlanHash},
	} {
		if filter.value != "" {
			clauses = append(clauses, filter.column+" = ?")
			args = append(args, filter.value)
		}
	}
	if len(q.Status) > 0 {
		clauses = append(clauses, "status IN ("+placeholders(len(q.Status))+")")
		for _, status := range q.Status {
			args = append(args, string(status))
		}
	}
	if len(q.Outcome) > 0 {
		clauses = append(clauses, "outcome IN ("+placeholders(len(q.Outcome))+")")
		for _, outcome := range q.Outcome {
			args = append(args, string(outcome))
		}
	}
	return whereClause(clauses), args
}

// evidenceQueryFilter renders the shared WHERE clause of an evidence listing.
func evidenceQueryFilter(q verify.EvidenceQuery) (string, []any) {
	clauses := []string{}
	args := []any{}
	for _, filter := range []struct {
		column string
		value  string
	}{
		{"snapshot_id", q.SnapshotID},
		{"hypothesis_id", q.HypothesisID},
		{"finding_id", q.FindingID},
		{"path_id", q.PathID},
		{"verification_run_id", q.VerificationRunID},
	} {
		if filter.value != "" {
			clauses = append(clauses, filter.column+" = ?")
			args = append(args, filter.value)
		}
	}
	if len(q.Kinds) > 0 {
		clauses = append(clauses, "kind IN ("+placeholders(len(q.Kinds))+")")
		for _, kind := range q.Kinds {
			args = append(args, string(kind))
		}
	}
	return whereClause(clauses), args
}

// findingQueryFilter renders the shared WHERE clause of a finding listing. The
// conclusive set comes from the vocabulary, so "settled" has one definition.
func findingQueryFilter(q verify.FindingQuery) (string, []any) {
	clauses := []string{}
	args := []any{}
	for _, filter := range []struct {
		column string
		value  string
	}{
		{"audit_id", q.AuditID},
		{"snapshot_id", q.SnapshotID},
		{"path_id", q.PathID},
	} {
		if filter.value != "" {
			clauses = append(clauses, filter.column+" = ?")
			args = append(args, filter.value)
		}
	}
	if len(q.Status) > 0 {
		clauses = append(clauses, "status IN ("+placeholders(len(q.Status))+")")
		for _, status := range q.Status {
			args = append(args, string(status))
		}
	}
	if q.ConclusiveOnly {
		conclusive := conclusiveFindingStatuses()
		clauses = append(clauses, "status IN ("+placeholders(len(conclusive))+")")
		for _, status := range conclusive {
			args = append(args, string(status))
		}
	}
	if q.CandidatesOnly {
		clauses = append(clauses, "status = ?")
		args = append(args, string(verify.FindingCandidate))
	}
	return whereClause(clauses), args
}

// CreateVerificationRun implements verify.Store. The primary key and the
// (hypothesis_id, plan_hash) unique index are the schema's guarantees; the driver
// reports both as ErrConflict, which is the answer the verifier retries as a
// replay.
func (s *SQL) CreateVerificationRun(run verify.Run) error {
	prepared, err := prepareVerificationRun(run, verifyNow())
	if err != nil {
		return err
	}
	values, err := verificationRunWriteValues(prepared)
	if err != nil {
		return err
	}
	return s.snapshotWrite(context.Background(), run.SnapshotID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), s.rebind(verificationRunInsertSQL), values...)
		return mapVerifySQLError(err)
	})
}

// GetVerificationRun implements verify.Store.
func (s *SQL) GetVerificationRun(runID string) (*verify.Run, error) {
	ctx := context.Background()
	row := s.db.QueryRowContext(ctx, s.rebind(verificationRunSelectByIDSQL), runID)
	run, err := scanVerificationRunRow(row.Scan)
	if err != nil {
		return nil, mapVerifySQLError(err)
	}
	ids, err := s.evidenceIDsForRun(ctx, s.db, runID)
	if err != nil {
		return nil, err
	}
	run.EvidenceIDs = ids
	return &run, nil
}

// ListVerificationRuns implements verify.Store.
func (s *SQL) ListVerificationRuns(q verify.RunQuery) ([]verify.Run, int, error) {
	ctx := context.Background()
	where, args := verificationRunQueryFilter(q)

	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM verification_runs"+where), args...).Scan(&total); err != nil {
		return nil, 0, mapVerifySQLError(err)
	}
	query := "SELECT " + verificationRunSelectColumns + " FROM verification_runs" + where +
		" ORDER BY created_at, run_id LIMIT ? OFFSET ?"
	// A snapshot's runs are bounded by its hypotheses and plans and the caller
	// pages explicitly, so only a default applies and nothing is silently truncated.
	args = append(args, normaliseLimit(q.Limit, 100, 0), max(q.Offset, 0))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, 0, mapVerifySQLError(err)
	}
	defer rows.Close()
	var out []verify.Run
	position := map[string]int{}
	for rows.Next() {
		run, err := scanVerificationRunRow(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		position[run.ID] = len(out)
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	// The evidence list of every run on the page comes from one query, so a page of
	// N runs does not cost N round trips.
	ids, err := s.evidenceIDsForRuns(ctx, s.db, out)
	if err != nil {
		return nil, 0, err
	}
	for id, index := range position {
		out[index].EvidenceIDs = ids[id]
	}
	return out, total, nil
}

// UpdateVerificationRun implements verify.Store. The version guard is what makes
// two writers unable to close the same attempt twice: the version is read and the
// row rewritten in one transaction.
func (s *SQL) UpdateVerificationRun(run verify.Run, expectedVersion int64) error {
	prepared, err := prepareVerificationRun(run, verifyNow())
	if err != nil {
		return err
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapVerifySQLError(err)
	}
	defer tx.Rollback()

	var current int64
	row := tx.QueryRowContext(ctx, s.rebind("SELECT version FROM verification_runs WHERE run_id = ?"+s.forUpdate()), prepared.ID)
	if err := row.Scan(&current); err != nil {
		return mapVerifySQLError(err)
	}
	if expectedVersion > 0 && current != expectedVersion {
		return fmt.Errorf("%w: verification run %s is at version %d, expected %d",
			verify.ErrConflict, prepared.ID, current, expectedVersion)
	}
	if prepared.Version <= current {
		prepared.Version = current + 1
	}
	values, err := verificationRunWriteValues(prepared)
	if err != nil {
		return err
	}
	args := append(append([]any{}, values[1:]...), prepared.ID, current)
	query := "UPDATE verification_runs SET " + strings.Join(verificationRunUpdateSetClauses, ", ") +
		" WHERE run_id = ? AND version = ?"
	res, err := tx.ExecContext(ctx, s.rebind(query), args...)
	if err != nil {
		return mapVerifySQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return mapVerifySQLError(err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: verification run %s was changed by another writer", verify.ErrConflict, prepared.ID)
	}
	return tx.Commit()
}

// AppendEvidence implements verify.Store. One transaction per call: a batch that
// names an already-stored object with a different identity stores nothing. The
// evidence_id primary key is the schema's guarantee; the check below turns it into
// the verify.ErrConflict the caller retries, and a re-derived object with the same
// id, content hash and content is a no-op.
func (s *SQL) AppendEvidence(evidence []verify.Evidence) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapVerifySQLError(err)
	}
	defer tx.Rollback()

	// seen holds the first occurrence of each id in the batch: a repeated object is
	// one append, and a repeat whose identity differs is a conflict rather than a
	// race the second write would win.
	seen := map[string]verify.Evidence{}
	for _, object := range evidence {
		if err := s.snapshotWritableTx(ctx, tx, object.SnapshotID); err != nil {
			return err
		}
		if strings.TrimSpace(object.ID) == "" {
			return fmt.Errorf("%w: evidence needs an id", verify.ErrInvalidArgument)
		}
		if first, duplicate := seen[object.ID]; duplicate {
			if !sameEvidenceObject(first, object) {
				return fmt.Errorf("%w: evidence %s appears twice in the batch with different content", verify.ErrConflict, object.ID)
			}
			continue
		}
		seen[object.ID] = object
		stored, err := scanEvidenceRow(tx.QueryRowContext(ctx, s.rebind(evidenceSelectByIDSQL), object.ID).Scan)
		switch {
		case err == nil:
			if !sameEvidenceObject(stored, object) {
				return fmt.Errorf("%w: evidence %s is already stored with different content", verify.ErrConflict, object.ID)
			}
			// The same evidence, re-derived: a no-op, so the stored object keeps its
			// original timestamp and the rest of its provenance.
			continue
		case errors.Is(err, sql.ErrNoRows):
		default:
			return mapVerifySQLError(err)
		}
		values, err := evidenceWriteValues(object)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.rebind(evidenceInsertSQL), values...); err != nil {
			return mapVerifySQLError(err)
		}
	}
	return tx.Commit()
}

// GetEvidence implements verify.Store.
func (s *SQL) GetEvidence(evidenceID string) (*verify.Evidence, error) {
	row := s.db.QueryRowContext(context.Background(), s.rebind(evidenceSelectByIDSQL), evidenceID)
	object, err := scanEvidenceRow(row.Scan)
	if err != nil {
		return nil, mapVerifySQLError(err)
	}
	return &object, nil
}

// ListEvidence implements verify.Store.
func (s *SQL) ListEvidence(q verify.EvidenceQuery) ([]verify.Evidence, int, error) {
	ctx := context.Background()
	where, args := evidenceQueryFilter(q)

	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM evidence"+where), args...).Scan(&total); err != nil {
		return nil, 0, mapVerifySQLError(err)
	}
	query := "SELECT " + evidenceSelectColumns + " FROM evidence" + where +
		" ORDER BY created_at, evidence_id LIMIT ? OFFSET ?"
	// Evidence grows with the runs that produced it; the listing returns the total,
	// so a caller pages explicitly and nothing is hidden.
	args = append(args, normaliseLimit(q.Limit, 200, 0), max(q.Offset, 0))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, 0, mapVerifySQLError(err)
	}
	defer rows.Close()
	var out []verify.Evidence
	for rows.Next() {
		object, err := scanEvidenceRow(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, object)
	}
	return out, total, rows.Err()
}

// UpsertFinding implements verify.Store. The verdict is upserted by
// `findings(hypothesis_id)`, the unique index the schema declares: a re-upsert
// updates the row already stored for that hypothesis instead of adding one.
func (s *SQL) UpsertFinding(finding verify.Finding) error {
	ctx := context.Background()
	now := verifyNow()
	prepared, err := prepareFinding(finding, now)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapVerifySQLError(err)
	}
	defer tx.Rollback()
	if err := s.snapshotWritableTx(ctx, tx, prepared.SnapshotID); err != nil {
		return err
	}

	var storedID, storedCreatedAt string
	var storedVersion int64
	row := tx.QueryRowContext(ctx,
		s.rebind("SELECT finding_id, created_at, version FROM findings WHERE hypothesis_id = ?"+s.forUpdate()),
		prepared.HypothesisID)
	switch err := row.Scan(&storedID, &storedCreatedAt, &storedVersion); {
	case err == nil:
		merged, err := mergeFinding(verify.Finding{ID: storedID, CreatedAt: storedCreatedAt, Version: storedVersion}, prepared, now)
		if err != nil {
			return err
		}
		values, err := findingWriteValues(merged)
		if err != nil {
			return err
		}
		args := append(append([]any{}, values[1:]...), merged.ID)
		query := "UPDATE findings SET " + strings.Join(findingUpdateSetClauses, ", ") + " WHERE finding_id = ?"
		if _, err := tx.ExecContext(ctx, s.rebind(query), args...); err != nil {
			return mapVerifySQLError(err)
		}
	case errors.Is(err, sql.ErrNoRows):
		var taken string
		err := tx.QueryRowContext(ctx, s.rebind("SELECT hypothesis_id FROM findings WHERE finding_id = ?"), prepared.ID).Scan(&taken)
		if err == nil {
			return fmt.Errorf("%w: finding id %s is already used by the finding for hypothesis %s",
				verify.ErrConflict, prepared.ID, taken)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return mapVerifySQLError(err)
		}
		values, err := findingWriteValues(prepared)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.rebind(findingInsertSQL), values...); err != nil {
			return mapVerifySQLError(err)
		}
	default:
		return mapVerifySQLError(err)
	}
	return tx.Commit()
}

// GetFinding implements verify.Store.
func (s *SQL) GetFinding(findingID string) (*verify.Finding, error) {
	row := s.db.QueryRowContext(context.Background(),
		s.rebind("SELECT "+findingSelectColumns+" FROM findings WHERE finding_id = ?"), findingID)
	finding, err := scanFindingRow(row.Scan)
	if err != nil {
		return nil, mapVerifySQLError(err)
	}
	return &finding, nil
}

// ListFindings implements verify.Store.
func (s *SQL) ListFindings(q verify.FindingQuery) ([]verify.Finding, int, error) {
	ctx := context.Background()
	where, args := findingQueryFilter(q)

	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM findings"+where), args...).Scan(&total); err != nil {
		return nil, 0, mapVerifySQLError(err)
	}
	query := "SELECT " + findingSelectColumns + " FROM findings" + where +
		" ORDER BY created_at, finding_id LIMIT ? OFFSET ?"
	// One finding per hypothesis bounds the table and the report layer pages with
	// an explicit limit, so only a default applies here.
	args = append(args, normaliseLimit(q.Limit, 100, 0), max(q.Offset, 0))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, 0, mapVerifySQLError(err)
	}
	defer rows.Close()
	var out []verify.Finding
	for rows.Next() {
		finding, err := scanFindingRow(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, finding)
	}
	return out, total, rows.Err()
}

// DeleteVerificationForSnapshot implements verify.Store.
func (s *SQL) DeleteVerificationForSnapshot(snapshotID string) (int, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, mapVerifySQLError(err)
	}
	defer tx.Rollback()
	removed, err := s.deleteVerificationRowsForSnapshot(ctx, tx, snapshotID)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, mapVerifySQLError(err)
	}
	return removed, nil
}

// deleteVerificationRowsForSnapshot removes a snapshot's runs with their evidence
// and the findings they produced. It takes the executor rather than opening a
// transaction because DeleteSnapshot runs it inside the transaction that removes
// the snapshot itself.
//
// Evidence goes first: it can name a run by id, so a mis-tagged object must not
// outlive the run that produced it, and that condition needs the runs to still be
// readable. Findings are removed by snapshot id, because a finding belongs to the
// hypothesis of one snapshot and only its run list mentions runs.
func (s *SQL) deleteVerificationRowsForSnapshot(ctx context.Context, exec sqlExecer, snapshotID string) (int, error) {
	evidence := "DELETE FROM evidence WHERE snapshot_id = ?" +
		" OR verification_run_id IN (SELECT run_id FROM verification_runs WHERE snapshot_id = ?)"
	if _, err := exec.ExecContext(ctx, s.rebind(evidence), snapshotID, snapshotID); err != nil {
		return 0, mapVerifySQLError(err)
	}
	if _, err := exec.ExecContext(ctx, s.rebind("DELETE FROM findings WHERE snapshot_id = ?"), snapshotID); err != nil {
		return 0, mapVerifySQLError(err)
	}
	res, err := exec.ExecContext(ctx, s.rebind("DELETE FROM verification_runs WHERE snapshot_id = ?"), snapshotID)
	if err != nil {
		return 0, mapVerifySQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, mapVerifySQLError(err)
	}
	return int(affected), nil
}

// evidenceIDsForRun returns the ids of the evidence that names a run, ordered by
// id — the order the verifier records when it closes a run. `verification_runs`
// has no evidence column, so this is where a run's evidence list comes from.
func (s *SQL) evidenceIDsForRun(ctx context.Context, q verificationQuerier, runID string) ([]string, error) {
	ids := []string{}
	rows, err := q.QueryContext(ctx, s.rebind("SELECT evidence_id FROM evidence WHERE verification_run_id = ? ORDER BY evidence_id"), runID)
	if err != nil {
		return nil, mapVerifySQLError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// evidenceIDsForRuns returns the derived evidence list of every run on a page in
// one query, keyed by run id.
func (s *SQL) evidenceIDsForRuns(ctx context.Context, q verificationQuerier, runs []verify.Run) (map[string][]string, error) {
	out := map[string][]string{}
	if len(runs) == 0 {
		return out, nil
	}
	args := make([]any, 0, len(runs))
	for _, run := range runs {
		args = append(args, run.ID)
	}
	query := "SELECT verification_run_id, evidence_id FROM evidence WHERE verification_run_id IN (" +
		placeholders(len(runs)) + ") ORDER BY verification_run_id, evidence_id"
	rows, err := q.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, mapVerifySQLError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var runID, evidenceID string
		if err := rows.Scan(&runID, &evidenceID); err != nil {
			return nil, err
		}
		out[runID] = append(out[runID], evidenceID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, run := range runs {
		if _, ok := out[run.ID]; !ok {
			// A run with no evidence answers with an empty list, not a nil one: the
			// verifier records an empty list for a run that produced no evidence.
			out[run.ID] = []string{}
		}
	}
	return out, nil
}
