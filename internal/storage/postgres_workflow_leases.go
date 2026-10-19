package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func (s *SQL) WorkflowLeaseClock() bool { return s.postgres }

func (s *SQL) AcquireWorkflowLease(ctx context.Context, project, id, owner string, ttl time.Duration) (workflow.Run, workflow.Lease, error) {
	if !s.postgres || owner == "" || ttl <= 0 || ttl > 5*time.Minute {
		return workflow.Run{}, workflow.Lease{}, workflow.ErrInvalid
	}
	run, err := s.GetWorkflowRun(ctx, project, id)
	if err != nil {
		return run, workflow.Lease{}, err
	}
	var lease workflow.Lease
	err = s.snapshotWrite(ctx, run.Scope.SnapshotID, func(tx *sql.Tx) error {
		var raw string
		if err := tx.QueryRowContext(ctx, `SELECT document_json FROM workflow_runs WHERE run_id=$1 AND project_id=$2 FOR UPDATE`, id, project).Scan(&raw); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(raw), &run); err != nil {
			return err
		}
		if workflow.RunTerminal(run.Status) {
			return workflow.ErrConflict
		}
		var currentOwner string
		var epoch int64
		var until time.Time
		err := tx.QueryRowContext(ctx, `SELECT owner,epoch,lease_until FROM workflow_leases WHERE run_id=$1 FOR UPDATE`, id).Scan(&currentOwner, &epoch, &until)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		now, err := databaseTime(ctx, tx)
		if err != nil {
			return err
		}
		if currentOwner != "" && until.After(now) {
			return workflow.ErrConflict
		}
		if currentOwner != owner || epoch == 0 || !until.After(now) {
			epoch++
		}
		expiry := now.Add(ttl)
		_, err = tx.ExecContext(ctx, `INSERT INTO workflow_leases(run_id,owner,epoch,lease_until) VALUES($1,$2,$3,$4) ON CONFLICT(run_id) DO UPDATE SET owner=excluded.owner,epoch=excluded.epoch,lease_until=excluded.lease_until`, id, owner, epoch, expiry)
		if err != nil {
			return err
		}
		if epoch > 1 {
			if err := s.reclaimWorkflowPathsTx(ctx, tx, run, now); err != nil {
				return err
			}
		}
		lease = workflow.Lease{RunID: id, Owner: owner, Epoch: epoch, ExpiresAt: expiry.Format(leaseTimeLayout)}
		return err
	})
	return run, lease, err
}

// Controls append to the durable run under its row/snapshot lock. They never
// acquire execution authority, so any API host can pause a leased coordinator.
func (s *SQL) ControlWorkflowRun(ctx context.Context, project, id, action string) (workflow.Run, error) {
	run, err := s.GetWorkflowRun(ctx, project, id)
	if err != nil {
		return run, err
	}
	err = s.snapshotWrite(ctx, run.Scope.SnapshotID, func(tx *sql.Tx) error {
		var raw string
		if err := tx.QueryRowContext(ctx, `SELECT document_json FROM workflow_runs WHERE run_id=$1 AND project_id=$2 FOR UPDATE`, id, project).Scan(&raw); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(raw), &run); err != nil {
			return err
		}
		target, kind := "", ""
		switch action {
		case "pause":
			if run.Status == "PAUSING" || run.Status == "PAUSED" {
				return nil
			}
			if run.Status != "RUNNING" && run.Status != "CREATED" {
				return workflow.ErrConflict
			}
			target, kind = "PAUSING", "run_pause_requested"
		case "resume":
			if run.Status == "RUNNING" {
				return nil
			}
			if run.Status != "PAUSED" && run.Status != "PAUSING" && run.Status != "CREATED" {
				return workflow.ErrConflict
			}
			target, kind = "RUNNING", "run_resumed"
		case "cancel":
			if run.Status == "CANCELLING" || run.Status == "CANCELLED" {
				return nil
			}
			if workflow.RunTerminal(run.Status) {
				return workflow.ErrConflict
			}
			target, kind = "CANCELLING", "run_cancel_requested"
		default:
			return workflow.ErrInvalid
		}
		now, err := databaseTime(ctx, tx)
		if err != nil {
			return err
		}
		run.Status = target
		run.Version++
		run.UpdatedAt = now.Format(time.RFC3339Nano)
		run.Events = append(run.Events, workflow.RunEvent{Seq: int64(len(run.Events) + 1), Type: kind, Status: target, CreatedAt: run.UpdatedAt})
		document, err := json.Marshal(run)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE workflow_runs SET status=$1,version=$2,document_json=$3 WHERE run_id=$4`, run.Status, run.Version, string(document), id)
		return err
	})
	return run, err
}

func (s *SQL) RenewWorkflowLease(ctx context.Context, lease workflow.Lease, ttl time.Duration) error {
	if ttl <= 0 || ttl > 5*time.Minute {
		return workflow.ErrInvalid
	}
	result, err := s.db.ExecContext(ctx, `UPDATE workflow_leases SET lease_until=clock_timestamp()+($1 * interval '1 millisecond') WHERE run_id=$2 AND owner=$3 AND epoch=$4 AND lease_until>clock_timestamp()`, ttl.Milliseconds(), lease.RunID, lease.Owner, lease.Epoch)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return workflow.ErrConflict
	}
	return nil
}

func (s *SQL) ReleaseWorkflowLease(ctx context.Context, lease workflow.Lease) error {
	_, err := s.db.ExecContext(ctx, `UPDATE workflow_leases SET owner='',lease_until=clock_timestamp() WHERE run_id=$1 AND owner=$2 AND epoch=$3`, lease.RunID, lease.Owner, lease.Epoch)
	return err
}

func validateWorkflowLeaseTx(ctx context.Context, tx *sql.Tx, id string) error {
	lease, ok := workflow.ContextLease(ctx)
	if !ok || lease.RunID != id || lease.Owner == "" {
		return workflow.ErrConflict
	}
	var valid bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM workflow_leases WHERE run_id=$1 AND owner=$2 AND epoch=$3 AND lease_until>clock_timestamp())`, id, lease.Owner, lease.Epoch).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return workflow.ErrConflict
	}
	return nil
}

func recordWorkflowClaimsTx(ctx context.Context, tx *sql.Tx, run workflow.Run) error {
	lease, _ := workflow.ContextLease(ctx)
	for _, node := range run.Nodes {
		if node.Status != "RUNNING" || node.InvocationID == "" {
			continue
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO workflow_node_claims(invocation_id,run_id,epoch) VALUES($1,$2,$3) ON CONFLICT(invocation_id) DO NOTHING`, node.InvocationID, run.ID, lease.Epoch)
		if err != nil {
			return err
		}
		var epoch int64
		var runID string
		if err := tx.QueryRowContext(ctx, `SELECT run_id,epoch FROM workflow_node_claims WHERE invocation_id=$1`, node.InvocationID).Scan(&runID, &epoch); err != nil {
			return err
		}
		if runID != run.ID || epoch != lease.Epoch {
			return workflow.ErrConflict
		}
	}
	return nil
}

func checkWorkflowInvocationTx(ctx context.Context, tx *sql.Tx, id string, cancelling bool) error {
	var linked, valid bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM workflow_node_claims WHERE invocation_id=$1),EXISTS(SELECT 1 FROM workflow_node_claims n JOIN workflow_leases l ON n.run_id=l.run_id AND n.epoch=l.epoch JOIN workflow_runs r ON r.run_id=l.run_id WHERE n.invocation_id=$1 AND l.owner<>'' AND l.lease_until>clock_timestamp() AND (r.status IN ('RUNNING','PAUSING') OR ($2 AND r.status='CANCELLING')))`, id, cancelling).Scan(&linked, &valid)
	if err != nil {
		return err
	}
	if linked && !valid {
		return plugin.ErrConflict
	}
	return nil
}
