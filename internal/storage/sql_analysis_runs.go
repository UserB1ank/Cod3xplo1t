package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

const analysisRunColumns = `analysis_run_id, project_id, snapshot_id, task_id, workflow_run_id, plan_id,
plan_digest, workflow_id, workflow_version, state, agent_assisted, idempotency_key, stages_json,
coverage_json, limitations_json, path_count, knowledge_json, failure_code, failure_message,
created_at, updated_at, version`

func (s *SQL) CreateAnalysisRun(ctx context.Context, run AnalysisRun, idempotencyKey string) (AnalysisRun, error) {
	if run.ID == "" || run.ProjectID == "" || run.WorkflowRunID == "" || run.PlanID == "" {
		return AnalysisRun{}, fmt.Errorf("%w: analysis run identity is incomplete", path.ErrInvalidArgument)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AnalysisRun{}, mapSQLError(err)
	}
	defer tx.Rollback()
	if err := s.lockProjectTx(ctx, tx, run.ProjectID); err != nil {
		return AnalysisRun{}, err
	}
	if idempotencyKey != "" {
		existing, err := scanAnalysisRunRow(tx.QueryRowContext(ctx, s.rebind(`SELECT `+analysisRunColumns+` FROM analysis_runs WHERE project_id = ? AND idempotency_key = ?`), run.ProjectID, idempotencyKey))
		if err == nil {
			return existing, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return AnalysisRun{}, mapSQLError(err)
		}
	}
	var active int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM analysis_runs WHERE project_id = ? AND state IN ('QUEUED','CREATED','RUNNING','PAUSED','CANCELLING')`), run.ProjectID).Scan(&active); err != nil {
		return AnalysisRun{}, mapSQLError(err)
	}
	if active > 0 {
		return AnalysisRun{}, fmt.Errorf("%w: project already has an active analysis run", ErrConflict)
	}
	stages, err := jsonString(run.Stages)
	if err != nil {
		return AnalysisRun{}, err
	}
	coverage, err := jsonString(run.Coverage)
	if err != nil {
		return AnalysisRun{}, err
	}
	limitations, err := jsonString(run.Limitations)
	if err != nil {
		return AnalysisRun{}, err
	}
	knowledge, err := jsonString(run.Knowledge)
	if err != nil {
		return AnalysisRun{}, err
	}
	run.IdempotencyKey = idempotencyKey
	run.Version = 1
	_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO analysis_runs (`+analysisRunColumns+`) VALUES (`+placeholders(22)+`)`),
		run.ID, run.ProjectID, run.SnapshotID, run.TaskID, run.WorkflowRunID, run.PlanID, run.PlanDigest,
		run.WorkflowID, run.WorkflowVersion, run.State, run.AgentAssisted, idempotencyKey, stages, coverage,
		limitations, run.PathCount, knowledge, run.FailureCode, run.FailureMessage, run.CreatedAt, run.UpdatedAt, run.Version)
	if err != nil {
		return AnalysisRun{}, mapSQLError(err)
	}
	if err := tx.Commit(); err != nil {
		return AnalysisRun{}, mapSQLError(err)
	}
	return run, nil
}

func (s *SQL) GetAnalysisRun(ctx context.Context, projectID, analysisRunID string) (AnalysisRun, error) {
	return scanAnalysisRunRow(s.db.QueryRowContext(ctx, s.rebind(`SELECT `+analysisRunColumns+` FROM analysis_runs WHERE project_id = ? AND analysis_run_id = ?`), projectID, analysisRunID))
}

func (s *SQL) GetAnalysisRunByIdempotency(ctx context.Context, projectID, idempotencyKey string) (AnalysisRun, error) {
	if idempotencyKey == "" {
		return AnalysisRun{}, fmt.Errorf("%w: idempotency key is required", path.ErrInvalidArgument)
	}
	return scanAnalysisRunRow(s.db.QueryRowContext(ctx, s.rebind(`SELECT `+analysisRunColumns+` FROM analysis_runs WHERE project_id = ? AND idempotency_key = ?`), projectID, idempotencyKey))
}

func (s *SQL) ListAnalysisRuns(ctx context.Context, projectID string, limit int) ([]AnalysisRun, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: limit must be 1–100", path.ErrInvalidArgument)
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT `+analysisRunColumns+` FROM analysis_runs WHERE project_id = ? ORDER BY created_at DESC, analysis_run_id DESC LIMIT ?`), projectID, limit)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	out := []AnalysisRun{}
	for rows.Next() {
		run, err := scanAnalysisRunRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

func (s *SQL) UpdateAnalysisRun(ctx context.Context, run AnalysisRun) (AnalysisRun, error) {
	stages, err := jsonString(run.Stages)
	if err != nil {
		return AnalysisRun{}, err
	}
	coverage, err := jsonString(run.Coverage)
	if err != nil {
		return AnalysisRun{}, err
	}
	limitations, err := jsonString(run.Limitations)
	if err != nil {
		return AnalysisRun{}, err
	}
	knowledge, err := jsonString(run.Knowledge)
	if err != nil {
		return AnalysisRun{}, err
	}
	result, err := s.db.ExecContext(ctx, s.rebind(`UPDATE analysis_runs SET state = ?, stages_json = ?, coverage_json = ?, limitations_json = ?, path_count = ?, knowledge_json = ?, failure_code = ?, failure_message = ?, updated_at = ?, version = version + 1 WHERE analysis_run_id = ? AND project_id = ? AND version = ?`),
		run.State, stages, coverage, limitations, run.PathCount, knowledge, run.FailureCode, run.FailureMessage,
		run.UpdatedAt, run.ID, run.ProjectID, run.Version)
	if err != nil {
		return AnalysisRun{}, mapSQLError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return AnalysisRun{}, err
	}
	if affected == 0 {
		if _, getErr := s.GetAnalysisRun(ctx, run.ProjectID, run.ID); getErr != nil {
			return AnalysisRun{}, getErr
		}
		return AnalysisRun{}, fmt.Errorf("%w: analysis run version", ErrConflict)
	}
	run.Version++
	return run, nil
}

func (s *SQL) ActiveAnalysisRun(ctx context.Context, projectID string) (AnalysisRun, bool, error) {
	run, err := scanAnalysisRunRow(s.db.QueryRowContext(ctx, s.rebind(`SELECT `+analysisRunColumns+` FROM analysis_runs WHERE project_id = ? AND state IN ('QUEUED','CREATED','RUNNING','PAUSED','CANCELLING') LIMIT 1`), projectID))
	if errors.Is(err, ErrNotFound) {
		return AnalysisRun{}, false, nil
	}
	if err != nil {
		return AnalysisRun{}, false, mapSQLError(err)
	}
	return run, true, nil
}

type analysisRunScanner interface {
	Scan(dest ...any) error
}

func scanAnalysisRunRow(row analysisRunScanner) (AnalysisRun, error) {
	var (
		run                                      AnalysisRun
		stages, coverage, limitations, knowledge string
	)
	if err := row.Scan(&run.ID, &run.ProjectID, &run.SnapshotID, &run.TaskID, &run.WorkflowRunID,
		&run.PlanID, &run.PlanDigest, &run.WorkflowID, &run.WorkflowVersion, &run.State,
		&run.AgentAssisted, &run.IdempotencyKey, &stages, &coverage, &limitations, &run.PathCount,
		&knowledge, &run.FailureCode, &run.FailureMessage, &run.CreatedAt, &run.UpdatedAt, &run.Version); err != nil {
		return AnalysisRun{}, mapSQLError(err)
	}
	for _, column := range []struct {
		raw    string
		target any
	}{
		{stages, &run.Stages},
		{coverage, &run.Coverage},
		{limitations, &run.Limitations},
		{knowledge, &run.Knowledge},
	} {
		if err := decodeJSON(column.raw, column.target); err != nil {
			return AnalysisRun{}, fmt.Errorf("storage: analysis run %s: %w", run.ID, err)
		}
	}
	if run.Stages == nil {
		run.Stages = []AnalysisRunStage{}
	}
	if run.Knowledge == nil {
		run.Knowledge = []AnalysisKnowledge{}
	}
	return run, nil
}
