package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

// agentRunColumnNames is the column list of `agent_runs` in the order every
// statement here reads and writes it. The write and the scan must stay aligned,
// so both are derived from this one list.
var agentRunColumnNames = []string{
	"run_id", "path_id", "audit_id", "snapshot_id", "runtime", "runtime_version", "status",
	"task_json", "exploration_json", "budget_json", "tool_calls", "expansions", "input_tokens",
	"output_tokens", "elapsed_ms", "owner", "started_at", "deadline_at", "heartbeat_at",
	"finished_at", "exit_code", "stop_reason", "error", "output_json", "created_at", "updated_at", "version",
}

var agentEventColumnNames = []string{
	"event_id", "run_id", "path_id", "seq", "type", "call_id", "tool", "actor", "summary",
	"detail_json", "created_at",
}

var hypothesisColumnNames = []string{
	"hypothesis_id", "run_id", "path_id", "audit_id", "snapshot_id", "security_goal", "statement",
	"status", "confidence", "supporting_json", "contradicting_json", "next_action",
	"finding_candidate", "severity_hint", "digest", "created_at", "updated_at",
}

var (
	agentRunSelectColumns      = strings.Join(agentRunColumnNames, ", ")
	agentRunSelectByIDSQL      = "SELECT " + agentRunSelectColumns + " FROM agent_runs WHERE run_id = ?"
	agentRunUpdateSetClauses   = setClauses(agentRunColumnNames[1:])
	hypothesisSelectColumns    = strings.Join(hypothesisColumnNames, ", ")
	hypothesisUpdateSetClauses = setClauses(hypothesisColumnNames[1:])
)

// agentRunWriteValues renders one run in agentRunColumnNames order. `output_json`
// is the structured answer, and the empty string is how the schema says "no
// answer yet": the answer is a pointer, and the column is NOT NULL.
func agentRunWriteValues(run agent.Run) ([]any, error) {
	task, err := jsonString(run.Task)
	if err != nil {
		return nil, err
	}
	exploration, err := jsonString(run.Exploration)
	if err != nil {
		return nil, err
	}
	budget, err := jsonString(run.Budget)
	if err != nil {
		return nil, err
	}
	output := ""
	if run.Answer != nil {
		output, err = jsonString(run.Answer)
		if err != nil {
			return nil, err
		}
	}
	var exit any
	if run.ExitCode != nil {
		exit = *run.ExitCode
	}
	return []any{
		run.ID, run.PathID, run.AuditID, run.SnapshotID, run.Runtime, run.RuntimeVersion, string(run.Status),
		task, exploration, budget, run.ToolCalls, run.Expansions, run.InputTokens, run.OutputTokens,
		run.ElapsedMS, run.Owner, run.StartedAt, run.DeadlineAt, run.HeartbeatAt, run.FinishedAt, exit,
		run.StopReason, run.Error, output, run.CreatedAt, run.UpdatedAt, run.Version,
	}, nil
}

// scanAgentRunRow reads the columns of agentRunColumnNames in order.
func scanAgentRunRow(scan func(...any) error) (agent.Run, error) {
	var (
		run                                       agent.Run
		status, task, exploration, budget, output string
		exit                                      sql.NullInt64
	)
	if err := scan(&run.ID, &run.PathID, &run.AuditID, &run.SnapshotID, &run.Runtime, &run.RuntimeVersion,
		&status, &task, &exploration, &budget, &run.ToolCalls, &run.Expansions, &run.InputTokens,
		&run.OutputTokens, &run.ElapsedMS, &run.Owner, &run.StartedAt, &run.DeadlineAt, &run.HeartbeatAt,
		&run.FinishedAt, &exit, &run.StopReason, &run.Error, &output, &run.CreatedAt, &run.UpdatedAt,
		&run.Version); err != nil {
		return agent.Run{}, err
	}
	run.Status = agent.RunStatus(status)
	if exit.Valid {
		code := int(exit.Int64)
		run.ExitCode = &code
	}
	for _, column := range []struct {
		raw    string
		target any
	}{
		{task, &run.Task},
		{exploration, &run.Exploration},
		{budget, &run.Budget},
	} {
		if err := decodeJSON(column.raw, column.target); err != nil {
			return agent.Run{}, fmt.Errorf("storage: run %s: %w", run.ID, err)
		}
	}
	if output != "" {
		var answer agent.Answer
		if err := decodeJSON(output, &answer); err != nil {
			return agent.Run{}, fmt.Errorf("storage: run %s: %w", run.ID, err)
		}
		run.Answer = &answer
	}
	return run, nil
}

// agentEventWriteValues renders one run event in agentEventColumnNames order.
func agentEventWriteValues(event agent.Event) ([]any, error) {
	detail, err := jsonString(event.Detail)
	if err != nil {
		return nil, err
	}
	return []any{
		event.ID, event.RunID, event.PathID, event.Seq, event.Type, event.CallID, event.Tool,
		event.Actor, event.Summary, detail, event.CreatedAt,
	}, nil
}

// scanAgentEventRow reads the columns of agentEventColumnNames in order.
func scanAgentEventRow(scan func(...any) error) (agent.Event, error) {
	var (
		event  agent.Event
		detail string
	)
	if err := scan(&event.ID, &event.RunID, &event.PathID, &event.Seq, &event.Type, &event.CallID,
		&event.Tool, &event.Actor, &event.Summary, &detail, &event.CreatedAt); err != nil {
		return agent.Event{}, err
	}
	if err := decodeJSON(detail, &event.Detail); err != nil {
		return agent.Event{}, fmt.Errorf("storage: event %s: %w", event.ID, err)
	}
	return event, nil
}

// hypothesisWriteValues renders one claim in hypothesisColumnNames order.
func hypothesisWriteValues(h agent.Hypothesis) ([]any, error) {
	supporting, err := jsonString(h.Supporting)
	if err != nil {
		return nil, err
	}
	contradicting, err := jsonString(h.Contradicting)
	if err != nil {
		return nil, err
	}
	candidate := 0
	if h.FindingCandidate {
		candidate = 1
	}
	return []any{
		h.ID, h.RunID, h.PathID, h.AuditID, h.SnapshotID, h.SecurityGoal, h.Statement, h.Status,
		h.Confidence, supporting, contradicting, h.NextAction, candidate, h.SeverityHint, h.Digest,
		h.CreatedAt, h.UpdatedAt,
	}, nil
}

// scanHypothesisRow reads the columns of hypothesisColumnNames in order.
func scanHypothesisRow(scan func(...any) error) (agent.Hypothesis, error) {
	var (
		h                         agent.Hypothesis
		supporting, contradicting string
		candidate                 int
	)
	if err := scan(&h.ID, &h.RunID, &h.PathID, &h.AuditID, &h.SnapshotID, &h.SecurityGoal, &h.Statement,
		&h.Status, &h.Confidence, &supporting, &contradicting, &h.NextAction, &candidate, &h.SeverityHint,
		&h.Digest, &h.CreatedAt, &h.UpdatedAt); err != nil {
		return agent.Hypothesis{}, err
	}
	h.FindingCandidate = candidate != 0
	for _, column := range []struct {
		raw    string
		target any
	}{
		{supporting, &h.Supporting},
		{contradicting, &h.Contradicting},
	} {
		if err := decodeJSON(column.raw, column.target); err != nil {
			return agent.Hypothesis{}, fmt.Errorf("storage: hypothesis %s: %w", h.ID, err)
		}
	}
	return h, nil
}

// agentRunQueryFilter renders the shared WHERE clause of a run listing.
func agentRunQueryFilter(q agent.RunQuery) (string, []any) {
	clauses := []string{}
	args := []any{}
	if q.PathID != "" {
		clauses = append(clauses, "path_id = ?")
		args = append(args, q.PathID)
	}
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
	return whereClause(clauses), args
}

// agentEventQueryFilter renders the shared WHERE clause of an event listing.
func agentEventQueryFilter(q agent.EventQuery) (string, []any) {
	clauses := []string{}
	args := []any{}
	if q.RunID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, q.RunID)
	}
	if q.PathID != "" {
		clauses = append(clauses, "path_id = ?")
		args = append(args, q.PathID)
	}
	if len(q.Types) > 0 {
		clauses = append(clauses, "type IN ("+placeholders(len(q.Types))+")")
		for _, eventType := range q.Types {
			args = append(args, eventType)
		}
	}
	// AfterSeq is exclusive, and 0 matches the whole log.
	clauses = append(clauses, "seq > ?")
	args = append(args, q.AfterSeq)
	return whereClause(clauses), args
}

// hypothesisQueryFilter renders the shared WHERE clause of a claim listing.
func hypothesisQueryFilter(q agent.HypothesisQuery) (string, []any) {
	clauses := []string{}
	args := []any{}
	if q.PathID != "" {
		clauses = append(clauses, "path_id = ?")
		args = append(args, q.PathID)
	}
	if q.AuditID != "" {
		clauses = append(clauses, "audit_id = ?")
		args = append(args, q.AuditID)
	}
	if q.SnapshotID != "" {
		clauses = append(clauses, "snapshot_id = ?")
		args = append(args, q.SnapshotID)
	}
	if q.RunID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, q.RunID)
	}
	if len(q.Status) > 0 {
		clauses = append(clauses, "status IN ("+placeholders(len(q.Status))+")")
		for _, status := range q.Status {
			args = append(args, status)
		}
	}
	if q.FindingCandidatesOnly {
		clauses = append(clauses, "finding_candidate = 1")
	}
	return whereClause(clauses), args
}

// CreateRun implements agent.Store.
func (s *SQL) CreateRun(run agent.Run) error {
	if run.ID == "" {
		// A caller that forgot the id made a programming error, not a conflict with
		// stored state, and the API maps the two to different answers.
		return fmt.Errorf("%w: a run needs an id", agent.ErrInvalidArgument)
	}
	values, err := agentRunWriteValues(run)
	if err != nil {
		return err
	}
	query := "INSERT INTO agent_runs (" + strings.Join(agentRunColumnNames, ", ") +
		") VALUES (" + placeholders(len(values)) + ")"
	return s.snapshotWrite(context.Background(), run.SnapshotID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), s.rebind(query), values...)
		return mapAgentSQLError(err)
	})
}

// GetRun implements agent.Store.
func (s *SQL) GetRun(runID string) (*agent.Run, error) {
	row := s.db.QueryRowContext(context.Background(), s.rebind(agentRunSelectByIDSQL), runID)
	run, err := scanAgentRunRow(row.Scan)
	if err != nil {
		return nil, mapAgentSQLError(err)
	}
	return &run, nil
}

// ListRuns implements agent.Store.
func (s *SQL) ListRuns(q agent.RunQuery) ([]agent.Run, int, error) {
	ctx := context.Background()
	where, args := agentRunQueryFilter(q)

	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM agent_runs"+where), args...).Scan(&total); err != nil {
		return nil, 0, mapAgentSQLError(err)
	}
	query := "SELECT " + agentRunSelectColumns + " FROM agent_runs" + where +
		" ORDER BY created_at, run_id LIMIT ? OFFSET ?"
	// The runs of a snapshot are bounded by its paths and attempts and the
	// orchestrator pages with an explicit limit, so only a default applies and a
	// caller that asks for everything gets everything.
	args = append(args, normaliseLimit(q.Limit, 100, 0), max(q.Offset, 0))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, 0, mapAgentSQLError(err)
	}
	defer rows.Close()
	var out []agent.Run
	for rows.Next() {
		run, err := scanAgentRunRow(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, run)
	}
	return out, total, rows.Err()
}

// UpdateRun implements agent.Store. The version guard is what makes two workers
// unable to win the same run: the row is read and rewritten in one transaction.
func (s *SQL) UpdateRun(run agent.Run, expectedVersion int64) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapAgentSQLError(err)
	}
	defer tx.Rollback()

	var current int64
	row := tx.QueryRowContext(ctx, s.rebind("SELECT version FROM agent_runs WHERE run_id = ?"+s.forUpdate()), run.ID)
	if err := row.Scan(&current); err != nil {
		return mapAgentSQLError(err)
	}
	if expectedVersion > 0 && current != expectedVersion {
		return fmt.Errorf("%w: run %s is at version %d, expected %d",
			agent.ErrConflict, run.ID, current, expectedVersion)
	}
	if run.Version <= current {
		run.Version = current + 1
	}
	values, err := agentRunWriteValues(run)
	if err != nil {
		return err
	}
	args := append(append([]any{}, values[1:]...), run.ID, current)
	query := "UPDATE agent_runs SET " + strings.Join(agentRunUpdateSetClauses, ", ") + " WHERE run_id = ? AND version = ?"
	res, err := tx.ExecContext(ctx, s.rebind(query), args...)
	if err != nil {
		return mapAgentSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return mapAgentSQLError(err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: run %s was changed by another writer", agent.ErrConflict, run.ID)
	}
	return tx.Commit()
}

// AppendRunEvents implements agent.Store. One transaction per call: a batch that
// names a missing run or reuses a sequence stores nothing. The (run_id, seq)
// unique index is the schema's guarantee; the check below turns it into the
// agent.ErrConflict the orchestrator retries on.
func (s *SQL) AppendRunEvents(events []agent.Event) error {
	ctx := context.Background()
	now := agentNow()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapAgentSQLError(err)
	}
	defer tx.Rollback()

	for _, event := range events {
		if err := s.insertAgentEventTx(ctx, tx, event, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// insertAgentEventTx stamps and inserts one event inside a transaction. The run
// must exist and the sequence must move forward.
func (s *SQL) insertAgentEventTx(ctx context.Context, tx *sql.Tx, event agent.Event, now string) error {
	var exists int
	if err := tx.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM agent_runs WHERE run_id = ?"), event.RunID).Scan(&exists); err != nil {
		return mapAgentSQLError(err)
	}
	if exists == 0 {
		return fmt.Errorf("%w: run %s", agent.ErrNotFound, event.RunID)
	}
	maxSeq, err := s.agentEventMaxSeqTx(ctx, tx, event.RunID)
	if err != nil {
		return err
	}
	if event.Seq <= maxSeq {
		return fmt.Errorf("%w: event sequence %d is already used in run %s", agent.ErrConflict, event.Seq, event.RunID)
	}
	if event.ID == "" {
		event.ID = agent.EventID(event.RunID, event.Seq)
	}
	if event.CreatedAt == "" {
		event.CreatedAt = now
	}
	values, err := agentEventWriteValues(event)
	if err != nil {
		return err
	}
	query := "INSERT INTO agent_events (" + strings.Join(agentEventColumnNames, ", ") +
		") VALUES (" + placeholders(len(agentEventColumnNames)) + ")"
	if _, err := tx.ExecContext(ctx, s.rebind(query), values...); err != nil {
		return mapAgentSQLError(err)
	}
	return nil
}

// agentEventMaxSeqTx returns the highest sequence stored for a run inside a
// transaction; 0 means the log is empty.
func (s *SQL) agentEventMaxSeqTx(ctx context.Context, tx *sql.Tx, runID string) (int64, error) {
	var maxSeq int64
	if err := tx.QueryRowContext(ctx, s.rebind("SELECT COALESCE(MAX(seq), 0) FROM agent_events WHERE run_id = ?"), runID).Scan(&maxSeq); err != nil {
		return 0, mapAgentSQLError(err)
	}
	return maxSeq, nil
}

// ListRunEvents implements agent.Store.
func (s *SQL) ListRunEvents(q agent.EventQuery) ([]agent.Event, error) {
	ctx := context.Background()
	where, args := agentEventQueryFilter(q)
	query := "SELECT " + strings.Join(agentEventColumnNames, ", ") + " FROM agent_events" + where +
		" ORDER BY run_id, seq LIMIT ?"
	// A run's log is append-only and unbounded (heartbeats alone make it long),
	// so the listing keeps a documented cap on top of the default.
	args = append(args, normaliseLimit(q.Limit, 500, 5000))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, mapAgentSQLError(err)
	}
	defer rows.Close()
	var out []agent.Event
	for rows.Next() {
		event, err := scanAgentEventRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

// NextRunEventSeq implements agent.Store.
func (s *SQL) NextRunEventSeq(runID string) (int64, error) {
	ctx := context.Background()
	var exists int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM agent_runs WHERE run_id = ?"), runID).Scan(&exists); err != nil {
		return 0, mapAgentSQLError(err)
	}
	if exists == 0 {
		return 0, fmt.Errorf("%w: run %s", agent.ErrNotFound, runID)
	}
	var maxSeq int64
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COALESCE(MAX(seq), 0) FROM agent_events WHERE run_id = ?"), runID).Scan(&maxSeq); err != nil {
		return 0, mapAgentSQLError(err)
	}
	return maxSeq + 1, nil
}

// SaveHypotheses implements agent.Store. Claims are upserted by
// (path_id, digest) inside one transaction, together with the event that records
// the save: a claim never exists without its place in the run log, and a batch
// that fails halfway leaves neither.
func (s *SQL) SaveHypotheses(hypotheses []agent.Hypothesis) error {
	ctx := context.Background()
	now := agentNow()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapAgentSQLError(err)
	}
	defer tx.Rollback()

	for _, incoming := range hypotheses {
		if err := s.saveHypothesisTx(ctx, tx, incoming, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// saveHypothesisTx upserts one claim and its derived event inside a transaction.
func (s *SQL) saveHypothesisTx(ctx context.Context, tx *sql.Tx, incoming agent.Hypothesis, now string) error {
	h := prepareHypothesis(incoming, now)
	if err := s.snapshotWritableTx(ctx, tx, h.SnapshotID); err != nil {
		return err
	}

	var storedID, storedCreatedAt string
	row := tx.QueryRowContext(ctx,
		s.rebind("SELECT hypothesis_id, created_at FROM hypotheses WHERE path_id = ? AND digest = ?"),
		h.PathID, h.Digest)
	switch err := row.Scan(&storedID, &storedCreatedAt); {
	case err == nil:
		merged, err := mergeHypothesis(storedID, storedCreatedAt, h, now)
		if err != nil {
			return err
		}
		h = merged
		values, err := hypothesisWriteValues(h)
		if err != nil {
			return err
		}
		args := append(append([]any{}, values[1:]...), h.ID)
		query := "UPDATE hypotheses SET " + strings.Join(hypothesisUpdateSetClauses, ", ") + " WHERE hypothesis_id = ?"
		if _, err := tx.ExecContext(ctx, s.rebind(query), args...); err != nil {
			return mapAgentSQLError(err)
		}
	case errors.Is(err, sql.ErrNoRows):
		var taken string
		err := tx.QueryRowContext(ctx, s.rebind("SELECT hypothesis_id FROM hypotheses WHERE hypothesis_id = ?"), h.ID).Scan(&taken)
		if err == nil {
			return fmt.Errorf("%w: hypothesis id %s is already used by another claim", agent.ErrConflict, h.ID)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return mapAgentSQLError(err)
		}
		values, err := hypothesisWriteValues(h)
		if err != nil {
			return err
		}
		query := "INSERT INTO hypotheses (" + strings.Join(hypothesisColumnNames, ", ") +
			") VALUES (" + placeholders(len(hypothesisColumnNames)) + ")"
		if _, err := tx.ExecContext(ctx, s.rebind(query), values...); err != nil {
			return mapAgentSQLError(err)
		}
	default:
		return mapAgentSQLError(err)
	}
	return s.insertHypothesisEventTx(ctx, tx, h, now)
}

// insertHypothesisEventTx derives and stores the run event of a saved claim. A
// claim that names no run has no log to write to and is stored on its own.
func (s *SQL) insertHypothesisEventTx(ctx context.Context, tx *sql.Tx, h agent.Hypothesis, now string) error {
	if h.RunID == "" {
		return nil
	}
	seq, err := s.agentEventMaxSeqTx(ctx, tx, h.RunID)
	if err != nil {
		return err
	}
	return s.insertAgentEventTx(ctx, tx, newHypothesisEvent(h, seq+1, now), now)
}

// ListHypotheses implements agent.Store.
func (s *SQL) ListHypotheses(q agent.HypothesisQuery) ([]agent.Hypothesis, int, error) {
	ctx := context.Background()
	where, args := hypothesisQueryFilter(q)

	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM hypotheses"+where), args...).Scan(&total); err != nil {
		return nil, 0, mapAgentSQLError(err)
	}
	query := "SELECT " + hypothesisSelectColumns + " FROM hypotheses" + where +
		" ORDER BY created_at, hypothesis_id LIMIT ? OFFSET ?"
	// A path produces a bounded number of distinct claims and the verification
	// phase pages explicitly, so only a default applies here.
	args = append(args, normaliseLimit(q.Limit, 100, 0), max(q.Offset, 0))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, 0, mapAgentSQLError(err)
	}
	defer rows.Close()
	var out []agent.Hypothesis
	for rows.Next() {
		h, err := scanHypothesisRow(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, h)
	}
	return out, total, rows.Err()
}

// GetHypothesis implements agent.Store.
func (s *SQL) GetHypothesis(hypothesisID string) (*agent.Hypothesis, error) {
	row := s.db.QueryRowContext(context.Background(),
		s.rebind("SELECT "+hypothesisSelectColumns+" FROM hypotheses WHERE hypothesis_id = ?"), hypothesisID)
	h, err := scanHypothesisRow(row.Scan)
	if err != nil {
		return nil, mapAgentSQLError(err)
	}
	return &h, nil
}

// DeleteRunsForSnapshot implements agent.Store.
func (s *SQL) DeleteRunsForSnapshot(snapshotID string) (int, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, mapAgentSQLError(err)
	}
	defer tx.Rollback()
	removed, err := s.deleteAgentRowsForSnapshot(ctx, tx, snapshotID)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, mapAgentSQLError(err)
	}
	return removed, nil
}

// deleteAgentRowsForSnapshot removes a snapshot's runs with their event log and
// the claims they produced. It takes the executor rather than opening a
// transaction because DeleteSnapshot runs it inside the transaction that removes
// the snapshot itself.
//
// The claims are deleted first: a claim is removed when it belongs to the
// snapshot or to one of the runs about to disappear, and that second condition
// needs the runs to still be readable.
func (s *SQL) deleteAgentRowsForSnapshot(ctx context.Context, exec sqlExecer, snapshotID string) (int, error) {
	hypotheses := "DELETE FROM hypotheses WHERE snapshot_id = ?" +
		" OR run_id IN (SELECT run_id FROM agent_runs WHERE snapshot_id = ?)"
	if _, err := exec.ExecContext(ctx, s.rebind(hypotheses), snapshotID, snapshotID); err != nil {
		return 0, mapAgentSQLError(err)
	}
	events := "DELETE FROM agent_events WHERE run_id IN (SELECT run_id FROM agent_runs WHERE snapshot_id = ?)"
	if _, err := exec.ExecContext(ctx, s.rebind(events), snapshotID); err != nil {
		return 0, mapAgentSQLError(err)
	}
	res, err := exec.ExecContext(ctx, s.rebind("DELETE FROM agent_runs WHERE snapshot_id = ?"), snapshotID)
	if err != nil {
		return 0, mapAgentSQLError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, mapAgentSQLError(err)
	}
	return int(affected), nil
}
