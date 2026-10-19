package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

const leaseTimeLayout = "2006-01-02T15:04:05.000000000Z"

func (s *SQL) ServerLeaseClock() bool { return s.postgres }
func databaseTime(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var now time.Time
	err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now)
	return now.UTC(), err
}

// The snapshot and audit locks precede the path lock. This serializes event
// sequences and the audit-wide allocation budget across independent workers.
func (s *SQL) mutatePostgresPath(ctx context.Context, id string, change func(*sql.Tx, path.Path, time.Time) (path.Path, path.Event, error)) (*path.Path, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var snapshot, auditID string
	if err := s.db.QueryRowContext(ctx, `SELECT snapshot_id,audit_id FROM audit_paths WHERE path_id=$1`, id).Scan(&snapshot, &auditID); err != nil {
		return nil, mapAuditSQLError(err)
	}
	var result path.Path
	err := s.snapshotWrite(ctx, snapshot, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE audits SET version=version WHERE audit_id=$1`, auditID); err != nil {
			return err
		}
		current, err := s.loadPathTx(ctx, tx, id)
		if err != nil {
			return err
		}
		now, err := databaseTime(ctx, tx)
		if err != nil {
			return err
		}
		updated, event, err := change(tx, current, now)
		if err != nil {
			return err
		}
		if err := s.persistPathChangeTx(ctx, tx, updated, current.Version, event); err != nil {
			return err
		}
		result = updated
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *SQL) ClaimPathTTL(ctx context.Context, id, owner string, ttl time.Duration, from []path.Status, actor string) (*path.Path, error) {
	if !s.postgres {
		return s.ClaimPath(id, owner, path.NowString(time.Now().Add(ttl)), from, actor)
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return nil, path.ErrInvalidArgument
	}
	return s.mutatePostgresPath(ctx, id, func(tx *sql.Tx, current path.Path, now time.Time) (path.Path, path.Event, error) {
		if !retryDue(current.NextAttemptAt, now.Format(leaseTimeLayout)) {
			return path.Path{}, path.Event{}, path.ErrNotClaimable
		}
		var limitsJSON string
		var paused, archived bool
		if err := tx.QueryRowContext(ctx, `SELECT limits_json,paused,task_archived FROM audits WHERE audit_id=$1`, current.AuditID).Scan(&limitsJSON, &paused, &archived); err != nil {
			return path.Path{}, path.Event{}, err
		}
		if paused || archived {
			return path.Path{}, path.Event{}, path.ErrNotClaimable
		}
		var limits path.Limits
		if err := decodeJSON(limitsJSON, &limits); err != nil {
			return path.Path{}, path.Event{}, err
		}
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_paths WHERE audit_id=$1 AND status IN ('ANALYZING','LOCAL_EXPLORING','VERIFYING')`, current.AuditID).Scan(&active); err != nil {
			return path.Path{}, path.Event{}, err
		}
		if active >= limits.Normalize().MaxActiveLeases {
			return path.Path{}, path.Event{}, path.ErrBudgetExceeded
		}
		return planClaim(current, owner, now.Add(ttl).Format(leaseTimeLayout), from, actor, now.Format(leaseTimeLayout))
	})
}

func checkPostgresLease(current path.Path, owner string, epoch int64, now time.Time) error {
	if owner == "" || current.LeaseOwner != owner {
		return path.ErrLeaseHeld
	}
	expires, err := time.Parse(time.RFC3339Nano, current.LeaseUntil)
	if err != nil || !expires.After(now) || epoch != current.LeaseEpoch {
		return path.ErrLeaseExpired
	}
	return nil
}

func (s *SQL) RenewPathTTL(ctx context.Context, id, owner string, epoch int64, ttl time.Duration, actor string) (*path.Path, error) {
	if !s.postgres {
		return s.RenewLease(id, owner, path.NowString(time.Now().Add(ttl)), actor)
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return nil, path.ErrInvalidArgument
	}
	return s.mutatePostgresPath(ctx, id, func(_ *sql.Tx, current path.Path, now time.Time) (path.Path, path.Event, error) {
		if err := checkPostgresLease(current, owner, epoch, now); err != nil {
			return path.Path{}, path.Event{}, err
		}
		return planLeaseRenewal(current, owner, now.Add(ttl).Format(leaseTimeLayout), actor, now.Format(leaseTimeLayout))
	})
}

func (s *SQL) ReleasePathEpoch(ctx context.Context, id, owner string, epoch int64, actor, reason string) (*path.Path, error) {
	if !s.postgres {
		return s.ReleaseLease(id, owner, actor, reason)
	}
	return s.mutatePostgresPath(ctx, id, func(_ *sql.Tx, current path.Path, now time.Time) (path.Path, path.Event, error) {
		if err := checkPostgresLease(current, owner, epoch, now); err != nil {
			return path.Path{}, path.Event{}, err
		}
		return planRelease(current, owner, actor, reason, now.Format(leaseTimeLayout))
	})
}

func (s *SQL) postgresTransition(req path.TransitionRequest) (*path.Path, error) {
	if req.SetLeaseOwner != "" {
		return nil, path.ErrInvalidArgument
	}
	return s.mutatePostgresPath(context.Background(), req.PathID, func(_ *sql.Tx, current path.Path, now time.Time) (path.Path, path.Event, error) {
		if req.Owner != "" && req.SetLeaseOwner == "" {
			if err := checkPostgresLease(current, req.Owner, req.LeaseEpoch, now); err != nil {
				return path.Path{}, path.Event{}, err
			}
		}
		return planPathTransition(current, req, now.Format(leaseTimeLayout))
	})
}

func (s *SQL) reclaimPostgresPaths(limit int, actor string) ([]path.Path, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT path_id FROM audit_paths WHERE lease_owner<>'' AND lease_until<>'' AND lease_until::timestamptz<=clock_timestamp() ORDER BY path_id LIMIT $1`, normaliseLimit(limit, 100, 1000))
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []path.Path{}
	for _, id := range ids {
		updated, err := s.mutatePostgresPath(ctx, id, func(tx *sql.Tx, current path.Path, now time.Time) (path.Path, path.Event, error) {
			expiry, err := time.Parse(time.RFC3339Nano, current.LeaseUntil)
			if err != nil || current.LeaseOwner == "" || expiry.After(now) {
				return path.Path{}, path.Event{}, path.ErrNotClaimable
			}
			if err := s.expirePathRunsTx(ctx, tx, current.ID, now.Format(leaseTimeLayout)); err != nil {
				return path.Path{}, path.Event{}, err
			}
			result, event, err := planReclaim(current, actor, now.Format(leaseTimeLayout))
			result.Attempts++
			return result, event, err
		})
		if errors.Is(err, path.ErrNotClaimable) {
			continue
		}
		if err != nil {
			return out, err
		}
		out = append(out, *updated)
	}
	return out, nil
}

func (s *SQL) reclaimWorkflowPathsTx(ctx context.Context, tx *sql.Tx, run workflow.Run, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE audits SET version=version WHERE audit_id=$1`, run.TaskID); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT path_id FROM audit_paths WHERE audit_id=$1 AND lease_owner=$2 ORDER BY path_id FOR UPDATE`, run.TaskID, "workflow-"+run.ID)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		current, err := s.loadPathTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := s.expirePathRunsTx(ctx, tx, id, now.Format(leaseTimeLayout)); err != nil {
			return err
		}
		updated, event, err := planReclaim(current, "workflow_recovery", now.Format(leaseTimeLayout))
		if err != nil {
			return err
		}
		updated.Attempts++
		if err := s.persistPathChangeTx(ctx, tx, updated, current.Version, event); err != nil {
			return err
		}
	}
	return nil
}
