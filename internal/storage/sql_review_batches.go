package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/reviewbatch"
)

func (s *SQL) CreateReviewBatch(ctx context.Context, batch reviewbatch.Batch) (reviewbatch.Batch, error) {
	if !s.postgres {
		return reviewbatch.Batch{}, reviewbatch.ErrUnavailable
	}
	batch = batch.Normalize()
	paths, err := json.Marshal(batch.PathIDs)
	if err != nil {
		return reviewbatch.Batch{}, err
	}
	_, err = s.db.ExecContext(ctx, s.rebind(`
INSERT INTO review_batches (
    batch_id, project_id, snapshot_id, audit_id, state, path_ids_json,
    max_concurrent, created_by, reason, last_error, execution_owner, lease_epoch,
    heartbeat_at, lease_until, created_at, updated_at, version
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		batch.ID, batch.ProjectID, batch.SnapshotID, batch.AuditID, string(batch.State),
		string(paths), batch.MaxConcurrent, batch.CreatedBy, batch.Reason, batch.LastError,
		batch.ExecutionOwner, batch.LeaseEpoch, batch.HeartbeatAt, batch.LeaseUntil,
		batch.CreatedAt, batch.UpdatedAt, batch.Version)
	if err != nil {
		return reviewbatch.Batch{}, reviewBatchSQLError(err)
	}
	stored, err := s.GetReviewBatch(ctx, batch.ID)
	if err != nil {
		return reviewbatch.Batch{}, err
	}
	return *stored, nil
}

func (s *SQL) GetReviewBatch(ctx context.Context, id string) (*reviewbatch.Batch, error) {
	if !s.postgres {
		return nil, reviewbatch.ErrUnavailable
	}
	batch, err := scanReviewBatch(s.db.QueryRowContext(ctx, s.rebind(`
SELECT batch_id, project_id, snapshot_id, audit_id, state, path_ids_json,
       max_concurrent, created_by, reason, last_error, execution_owner, lease_epoch,
       heartbeat_at, lease_until, created_at, updated_at, version
FROM review_batches WHERE batch_id = ?`), id).Scan)
	if err != nil {
		return nil, reviewBatchSQLError(err)
	}
	return &batch, nil
}

func (s *SQL) ListReviewBatches(ctx context.Context, query reviewbatch.Query) ([]reviewbatch.Batch, int, error) {
	if !s.postgres {
		return nil, 0, reviewbatch.ErrUnavailable
	}
	where := []string{"1=1"}
	args := []any{}
	if query.ProjectID != "" {
		where = append(where, "project_id = ?")
		args = append(args, query.ProjectID)
	}
	if query.AuditID != "" {
		where = append(where, "audit_id = ?")
		args = append(args, query.AuditID)
	}
	if query.State != "" {
		where = append(where, "state = ?")
		args = append(args, string(query.State))
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM review_batches WHERE "+clause), args...).Scan(&total); err != nil {
		return nil, 0, reviewBatchSQLError(err)
	}
	limit := query.Limit
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	offset := max(0, query.Offset)
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, s.rebind(`
SELECT batch_id, project_id, snapshot_id, audit_id, state, path_ids_json,
       max_concurrent, created_by, reason, last_error, execution_owner, lease_epoch,
       heartbeat_at, lease_until, created_at, updated_at, version
FROM review_batches WHERE `+clause+`
ORDER BY created_at DESC, batch_id ASC
LIMIT ? OFFSET ?`), args...)
	if err != nil {
		return nil, 0, reviewBatchSQLError(err)
	}
	defer rows.Close()
	out := []reviewbatch.Batch{}
	for rows.Next() {
		batch, err := scanReviewBatch(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, batch)
	}
	return out, total, rows.Err()
}

func (s *SQL) ControlReviewBatch(ctx context.Context, req reviewbatch.ControlRequest) (*reviewbatch.Batch, error) {
	if !s.postgres {
		return nil, reviewbatch.ErrUnavailable
	}
	var result sql.Result
	var err error
	switch req.Target {
	case reviewbatch.StatePaused:
		result, err = s.db.ExecContext(ctx, s.rebind(`
UPDATE review_batches SET state = ?, reason = ?, execution_owner = '', heartbeat_at = '',
    lease_until = '', updated_at = ?, version = version + 1
WHERE batch_id = ? AND version = ? AND state = ?`),
			string(reviewbatch.StatePaused), req.Reason, req.Now, req.BatchID, req.ExpectedVersion,
			string(reviewbatch.StateRunning))
	case reviewbatch.StateRunning:
		if req.Owner == "" || req.LeaseUntil == "" {
			return nil, fmt.Errorf("%w: resume needs an execution owner and lease", reviewbatch.ErrInvalid)
		}
		result, err = s.db.ExecContext(ctx, s.rebind(`
UPDATE review_batches SET state = ?, reason = ?, execution_owner = ?,
    lease_epoch = GREATEST(lease_epoch + 1, 1), heartbeat_at = ?, lease_until = ?,
    updated_at = ?, version = version + 1
WHERE batch_id = ? AND version = ? AND state = ?`),
			string(reviewbatch.StateRunning), req.Reason, req.Owner, req.Now, req.LeaseUntil,
			req.Now, req.BatchID, req.ExpectedVersion, string(reviewbatch.StatePaused))
	case reviewbatch.StateCancelling:
		result, err = s.db.ExecContext(ctx, s.rebind(`
UPDATE review_batches SET state = ?, reason = ?, updated_at = ?, version = version + 1
WHERE batch_id = ? AND version = ? AND state IN (?, ?)`),
			string(reviewbatch.StateCancelling), req.Reason, req.Now, req.BatchID,
			req.ExpectedVersion, string(reviewbatch.StateRunning), string(reviewbatch.StatePaused))
	default:
		return nil, fmt.Errorf("%w: unsupported control target %s", reviewbatch.ErrInvalid, req.Target)
	}
	if err != nil {
		return nil, reviewBatchSQLError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count != 1 {
		if _, getErr := s.GetReviewBatch(ctx, req.BatchID); errors.Is(getErr, reviewbatch.ErrNotFound) {
			return nil, getErr
		}
		return nil, fmt.Errorf("%w: batch %s version or state changed", reviewbatch.ErrConflict, req.BatchID)
	}
	return s.GetReviewBatch(ctx, req.BatchID)
}

func (s *SQL) ClaimReviewBatch(ctx context.Context, req reviewbatch.ClaimRequest) (*reviewbatch.Batch, error) {
	if !s.postgres {
		return nil, reviewbatch.ErrUnavailable
	}
	result, err := s.db.ExecContext(ctx, s.rebind(`
UPDATE review_batches SET execution_owner = ?, lease_epoch = lease_epoch + 1,
    heartbeat_at = ?, lease_until = ?, updated_at = ?, version = version + 1
WHERE batch_id = ? AND state IN (?, ?)
  AND (execution_owner = '' OR lease_until = '' OR lease_until <= ?)`),
		req.Owner, req.Now, req.LeaseUntil, req.Now, req.BatchID,
		string(reviewbatch.StateRunning), string(reviewbatch.StateCancelling), req.Now)
	if err != nil {
		return nil, reviewBatchSQLError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count != 1 {
		if _, getErr := s.GetReviewBatch(ctx, req.BatchID); errors.Is(getErr, reviewbatch.ErrNotFound) {
			return nil, getErr
		}
		return nil, fmt.Errorf("%w: batch %s lease is still held", reviewbatch.ErrConflict, req.BatchID)
	}
	return s.GetReviewBatch(ctx, req.BatchID)
}

func (s *SQL) RenewReviewBatch(ctx context.Context, req reviewbatch.RenewRequest) (*reviewbatch.Batch, error) {
	if !s.postgres {
		return nil, reviewbatch.ErrUnavailable
	}
	result, err := s.db.ExecContext(ctx, s.rebind(`
UPDATE review_batches SET heartbeat_at = ?, lease_until = ?, updated_at = ?, version = version + 1
WHERE batch_id = ? AND execution_owner = ? AND lease_epoch = ? AND state IN (?, ?)`),
		req.HeartbeatAt, req.LeaseUntil, req.HeartbeatAt, req.BatchID, req.Owner, req.Epoch,
		string(reviewbatch.StateRunning), string(reviewbatch.StateCancelling))
	if err != nil {
		return nil, reviewBatchSQLError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, fmt.Errorf("%w: batch %s lease changed", reviewbatch.ErrConflict, req.BatchID)
	}
	return s.GetReviewBatch(ctx, req.BatchID)
}

func (s *SQL) FinalizeReviewBatch(ctx context.Context, req reviewbatch.FinalizeRequest) (*reviewbatch.Batch, error) {
	if !s.postgres {
		return nil, reviewbatch.ErrUnavailable
	}
	if !req.State.Terminal() {
		return nil, fmt.Errorf("%w: final state %s is not terminal", reviewbatch.ErrInvalid, req.State)
	}
	result, err := s.db.ExecContext(ctx, s.rebind(`
UPDATE review_batches SET state = ?, last_error = ?, execution_owner = '',
    heartbeat_at = '', lease_until = '', updated_at = ?, version = version + 1
WHERE batch_id = ? AND version = ? AND execution_owner = ? AND lease_epoch = ? AND state IN (?, ?)`),
		string(req.State), req.LastError, req.Now, req.BatchID, req.ExpectedVersion, req.Owner, req.Epoch,
		string(reviewbatch.StateRunning), string(reviewbatch.StateCancelling))
	if err != nil {
		return nil, reviewBatchSQLError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, fmt.Errorf("%w: batch %s lease or version changed", reviewbatch.ErrConflict, req.BatchID)
	}
	return s.GetReviewBatch(ctx, req.BatchID)
}

func (s *SQL) ListReclaimableReviewBatches(ctx context.Context, now string, limit int) ([]reviewbatch.Batch, error) {
	if !s.postgres {
		return nil, reviewbatch.ErrUnavailable
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`
SELECT batch_id, project_id, snapshot_id, audit_id, state, path_ids_json,
       max_concurrent, created_by, reason, last_error, execution_owner, lease_epoch,
       heartbeat_at, lease_until, created_at, updated_at, version
FROM review_batches
WHERE state IN (?, ?) AND (execution_owner = '' OR lease_until = '' OR lease_until <= ?)
ORDER BY created_at ASC, batch_id ASC LIMIT ?`),
		string(reviewbatch.StateRunning), string(reviewbatch.StateCancelling), now, limit)
	if err != nil {
		return nil, reviewBatchSQLError(err)
	}
	defer rows.Close()
	out := []reviewbatch.Batch{}
	for rows.Next() {
		batch, err := scanReviewBatch(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, batch)
	}
	return out, rows.Err()
}

func scanReviewBatch(scan func(...any) error) (reviewbatch.Batch, error) {
	var batch reviewbatch.Batch
	var state, paths string
	if err := scan(
		&batch.ID, &batch.ProjectID, &batch.SnapshotID, &batch.AuditID, &state, &paths,
		&batch.MaxConcurrent, &batch.CreatedBy, &batch.Reason, &batch.LastError,
		&batch.ExecutionOwner, &batch.LeaseEpoch, &batch.HeartbeatAt, &batch.LeaseUntil,
		&batch.CreatedAt, &batch.UpdatedAt, &batch.Version,
	); err != nil {
		return reviewbatch.Batch{}, err
	}
	batch.State = reviewbatch.State(state)
	if err := json.Unmarshal([]byte(paths), &batch.PathIDs); err != nil {
		return reviewbatch.Batch{}, fmt.Errorf("storage: review batch path ids: %w", err)
	}
	return batch.Normalize(), nil
}

func reviewBatchSQLError(err error) error {
	if err == nil {
		return nil
	}
	if err == sql.ErrNoRows {
		return reviewbatch.ErrNotFound
	}
	// The partial unique index is the durable guard. Do not inspect driver text to
	// decide whether a batch may run: every insertion failure is closed.
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique") || strings.Contains(message, "duplicate") {
		return fmt.Errorf("%w: %v", reviewbatch.ErrConflict, err)
	}
	return err
}
