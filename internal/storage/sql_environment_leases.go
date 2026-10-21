package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// AcquireEnvironmentLease implements verify.EnvironmentLeaseStore. The select and
// the write share one transaction, so two workers cannot both take the same
// expired or free environment.
func (s *SQL) AcquireEnvironmentLease(ctx context.Context, lease verify.EnvironmentLease, now time.Time) (verify.EnvironmentLease, error) {
	if strings.TrimSpace(lease.ID) == "" || strings.TrimSpace(lease.Owner) == "" || strings.TrimSpace(lease.ExpiresAt) == "" {
		return verify.EnvironmentLease{}, fmt.Errorf("%w: a lease needs an id, an owner and an expiry", verify.ErrLeaseLost)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return verify.EnvironmentLease{}, err
	}
	defer tx.Rollback()
	existing, found, err := s.environmentLeaseTx(ctx, tx, lease.ID)
	if err != nil {
		return verify.EnvironmentLease{}, err
	}
	stamp := now.UTC().Format(time.RFC3339)
	if found {
		if activeEnvironmentState(existing.State) && environmentLeaseExpired(existing, now) {
			existing.State = verify.EnvironmentFailed
			existing.Cleanup = verify.CleanupPending
			existing.Failure = "lease expired"
			existing.UpdatedAt = stamp
			if err := s.writeEnvironmentLeaseTx(ctx, tx, existing); err != nil {
				return verify.EnvironmentLease{}, err
			}
			if err := tx.Commit(); err != nil {
				return verify.EnvironmentLease{}, err
			}
			return verify.EnvironmentLease{}, verify.ErrLeaseExpired
		}
		if existing.Owner == lease.Owner && activeEnvironmentState(existing.State) {
			return existing, tx.Commit()
		}
		if activeEnvironmentState(existing.State) {
			return verify.EnvironmentLease{}, verify.ErrLeaseHeld
		}
		if existing.Cleanup == verify.CleanupPending || existing.Cleanup == verify.CleanupFailed {
			return verify.EnvironmentLease{}, fmt.Errorf("%w: the previous environment still needs cleanup (%s)", verify.ErrLeaseHeld, existing.Cleanup)
		}
		lease.Epoch = existing.Epoch + 1
		lease.CreatedAt = existing.CreatedAt
	} else {
		lease.Epoch = 1
		lease.CreatedAt = stamp
	}
	lease.State = verify.EnvironmentProvisioning
	lease.Cleanup = verify.CleanupNotStarted
	lease.UpdatedAt = stamp
	if found {
		_, err = tx.ExecContext(ctx, s.rebind(`UPDATE environment_leases SET plan_id=?,project_id=?,snapshot_id=?,owner=?,provider=?,environment_id=?,image_digest=?,source_digest=?,receipt_digest=?,epoch=?,state=?,cleanup=?,failure=?,expires_at=?,created_at=?,updated_at=? WHERE lease_id=?`),
			lease.PlanID, lease.ProjectID, lease.SnapshotID, lease.Owner, lease.Provider,
			"", "", lease.SourceDigest, "", lease.Epoch, string(lease.State), string(lease.Cleanup), "",
			lease.ExpiresAt, lease.CreatedAt, lease.UpdatedAt, lease.ID)
	} else {
		_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO environment_leases (lease_id,plan_id,project_id,snapshot_id,owner,provider,environment_id,image_digest,source_digest,receipt_digest,epoch,state,cleanup,failure,expires_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`),
			lease.ID, lease.PlanID, lease.ProjectID, lease.SnapshotID, lease.Owner, lease.Provider,
			"", "", lease.SourceDigest, "", lease.Epoch, string(lease.State), string(lease.Cleanup), "",
			lease.ExpiresAt, lease.CreatedAt, lease.UpdatedAt)
	}
	if err != nil {
		return verify.EnvironmentLease{}, mapEnvironmentLeaseError(err)
	}
	return lease, tx.Commit()
}

func (s *SQL) RenewEnvironmentLease(ctx context.Context, id, owner string, epoch int64, until, now time.Time) (verify.EnvironmentLease, error) {
	return s.updateEnvironmentLease(ctx, id, owner, epoch, now, func(lease *verify.EnvironmentLease) error {
		if !until.After(now) {
			return fmt.Errorf("%w: the new expiry is not in the future", verify.ErrLeaseLost)
		}
		lease.ExpiresAt = until.UTC().Format(time.RFC3339)
		return nil
	})
}

func (s *SQL) BindEnvironmentLease(ctx context.Context, id, owner string, epoch int64, environmentID, receiptDigest, imageDigest string, until, now time.Time) (verify.EnvironmentLease, error) {
	return s.updateEnvironmentLease(ctx, id, owner, epoch, now, func(lease *verify.EnvironmentLease) error {
		lease.EnvironmentID = environmentID
		lease.ReceiptDigest = receiptDigest
		lease.ImageDigest = imageDigest
		lease.State = verify.EnvironmentReady
		if !until.After(now) {
			return fmt.Errorf("%w: the new expiry is not in the future", verify.ErrLeaseLost)
		}
		lease.ExpiresAt = until.UTC().Format(time.RFC3339)
		return nil
	})
}

func (s *SQL) ReleaseEnvironmentLease(ctx context.Context, id, owner string, epoch int64, cleanup verify.CleanupState, failure string, now time.Time) (verify.EnvironmentLease, error) {
	if cleanup != verify.CleanupSucceeded && cleanup != verify.CleanupFailed && cleanup != verify.CleanupPending {
		return verify.EnvironmentLease{}, fmt.Errorf("%w: unknown cleanup state %q", verify.ErrLeaseLost, cleanup)
	}
	return s.updateEnvironmentLease(ctx, id, owner, epoch, now, func(lease *verify.EnvironmentLease) error {
		lease.Cleanup = cleanup
		lease.Failure = strings.TrimSpace(failure)
		if cleanup == verify.CleanupSucceeded {
			lease.State = verify.EnvironmentDestroyed
		} else {
			lease.State = verify.EnvironmentFailed
		}
		return nil
	})
}

func (s *SQL) updateEnvironmentLease(ctx context.Context, id, owner string, epoch int64, now time.Time, change func(*verify.EnvironmentLease) error) (verify.EnvironmentLease, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return verify.EnvironmentLease{}, err
	}
	defer tx.Rollback()
	lease, found, err := s.environmentLeaseTx(ctx, tx, id)
	if err != nil {
		return verify.EnvironmentLease{}, err
	}
	if !found {
		return verify.EnvironmentLease{}, verify.ErrLeaseNotFound
	}
	if lease.Owner != owner || lease.Epoch != epoch {
		return verify.EnvironmentLease{}, verify.ErrLeaseLost
	}
	if environmentLeaseExpired(lease, now) {
		lease.State = verify.EnvironmentFailed
		lease.Cleanup = verify.CleanupPending
		lease.Failure = "lease expired"
		lease.UpdatedAt = now.UTC().Format(time.RFC3339)
		if err := s.writeEnvironmentLeaseTx(ctx, tx, lease); err != nil {
			return verify.EnvironmentLease{}, err
		}
		if err := tx.Commit(); err != nil {
			return verify.EnvironmentLease{}, err
		}
		return verify.EnvironmentLease{}, verify.ErrLeaseExpired
	}
	if err := change(&lease); err != nil {
		return verify.EnvironmentLease{}, err
	}
	lease.UpdatedAt = now.UTC().Format(time.RFC3339)
	if err := s.writeEnvironmentLeaseTx(ctx, tx, lease); err != nil {
		return verify.EnvironmentLease{}, err
	}
	if err := tx.Commit(); err != nil {
		return verify.EnvironmentLease{}, err
	}
	return lease, nil
}

func (s *SQL) GetEnvironmentLease(ctx context.Context, id string) (verify.EnvironmentLease, error) {
	row := s.db.QueryRowContext(ctx, s.rebind(`SELECT lease_id,plan_id,project_id,snapshot_id,owner,provider,environment_id,image_digest,source_digest,receipt_digest,epoch,state,cleanup,failure,expires_at,created_at,updated_at FROM environment_leases WHERE lease_id=?`), id)
	lease, err := scanEnvironmentLease(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return verify.EnvironmentLease{}, verify.ErrLeaseNotFound
	}
	return lease, err
}

func (s *SQL) ListEnvironmentLeases(ctx context.Context, q verify.EnvironmentLeaseQuery) ([]verify.EnvironmentLease, error) {
	query := `SELECT lease_id,plan_id,project_id,snapshot_id,owner,provider,environment_id,image_digest,source_digest,receipt_digest,epoch,state,cleanup,failure,expires_at,created_at,updated_at FROM environment_leases`
	clauses := []string{}
	args := []any{}
	if q.Owner != "" {
		clauses = append(clauses, "owner=?")
		args = append(args, q.Owner)
	}
	if len(q.State) > 0 {
		clauses = append(clauses, "state IN ("+placeholders(len(q.State))+")")
		for _, state := range q.State {
			args = append(args, string(state))
		}
	}
	if len(q.Cleanup) > 0 {
		clauses = append(clauses, "cleanup IN ("+placeholders(len(q.Cleanup))+")")
		for _, cleanup := range q.Cleanup {
			args = append(args, string(cleanup))
		}
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY expires_at, lease_id"
	if q.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, q.Limit)
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []verify.EnvironmentLease{}
	for rows.Next() {
		lease, err := scanEnvironmentLease(rows.Scan)
		if err != nil {
			return nil, err
		}
		if q.ExpiredOnly && !environmentLeaseExpired(lease, q.Now) {
			continue
		}
		out = append(out, lease)
	}
	return out, rows.Err()
}

func (s *SQL) environmentLeaseTx(ctx context.Context, tx *sql.Tx, id string) (verify.EnvironmentLease, bool, error) {
	row := tx.QueryRowContext(ctx, s.rebind(`SELECT lease_id,plan_id,project_id,snapshot_id,owner,provider,environment_id,image_digest,source_digest,receipt_digest,epoch,state,cleanup,failure,expires_at,created_at,updated_at FROM environment_leases WHERE lease_id=?`+s.forUpdate()), id)
	lease, err := scanEnvironmentLease(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return verify.EnvironmentLease{}, false, nil
	}
	if err != nil {
		return verify.EnvironmentLease{}, false, err
	}
	return lease, true, nil
}

func (s *SQL) writeEnvironmentLeaseTx(ctx context.Context, tx *sql.Tx, lease verify.EnvironmentLease) error {
	_, err := tx.ExecContext(ctx, s.rebind(`UPDATE environment_leases SET plan_id=?,project_id=?,snapshot_id=?,owner=?,provider=?,environment_id=?,image_digest=?,source_digest=?,receipt_digest=?,epoch=?,state=?,cleanup=?,failure=?,expires_at=?,created_at=?,updated_at=? WHERE lease_id=?`),
		lease.PlanID, lease.ProjectID, lease.SnapshotID, lease.Owner, lease.Provider,
		lease.EnvironmentID, lease.ImageDigest, lease.SourceDigest, lease.ReceiptDigest,
		lease.Epoch, string(lease.State), string(lease.Cleanup), lease.Failure,
		lease.ExpiresAt, lease.CreatedAt, lease.UpdatedAt, lease.ID)
	return mapEnvironmentLeaseError(err)
}

func scanEnvironmentLease(scan func(...any) error) (verify.EnvironmentLease, error) {
	var lease verify.EnvironmentLease
	var state, cleanup string
	if err := scan(&lease.ID, &lease.PlanID, &lease.ProjectID, &lease.SnapshotID, &lease.Owner,
		&lease.Provider, &lease.EnvironmentID, &lease.ImageDigest, &lease.SourceDigest,
		&lease.ReceiptDigest, &lease.Epoch, &state, &cleanup, &lease.Failure,
		&lease.ExpiresAt, &lease.CreatedAt, &lease.UpdatedAt); err != nil {
		return verify.EnvironmentLease{}, err
	}
	lease.State = verify.EnvironmentState(state)
	lease.Cleanup = verify.CleanupState(cleanup)
	return lease, nil
}

func mapEnvironmentLeaseError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate key") {
		return verify.ErrLeaseHeld
	}
	return err
}

func environmentLeaseExpired(lease verify.EnvironmentLease, now time.Time) bool {
	expires, err := time.Parse(time.RFC3339, lease.ExpiresAt)
	return err != nil || !expires.After(now)
}

func activeEnvironmentState(state verify.EnvironmentState) bool {
	return state == verify.EnvironmentProvisioning || state == verify.EnvironmentReady || state == verify.EnvironmentRunning
}
