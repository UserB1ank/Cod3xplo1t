package storage

import (
	"context"
	"database/sql"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

func (s *SQL) checkAgentPathTx(ctx context.Context, tx *sql.Tx, run agent.Run, terminal bool) error {
	current, err := s.loadPathTx(ctx, tx, run.PathID)
	if err != nil {
		return err
	}
	if current.LeaseEpoch != run.LeaseEpoch {
		return agent.ErrConflict
	}
	if current.LeaseOwner == "" {
		if terminal {
			return nil
		}
		return agent.ErrConflict
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return err
	}
	if checkPostgresLease(current, run.Owner, run.LeaseEpoch, now) != nil {
		return agent.ErrConflict
	}
	return nil
}

func (s *SQL) checkAgentAuthorityTx(ctx context.Context, tx *sql.Tx, id string, terminal bool) error {
	var run agent.Run
	var owner, workflowID string
	var epoch, workflowEpoch int64
	err := tx.QueryRowContext(ctx, `SELECT path_id,owner,lease_epoch,host_id,host_epoch,workflow_run_id,workflow_epoch FROM agent_runs WHERE run_id=$1 FOR UPDATE`, id).Scan(&run.PathID, &run.Owner, &run.LeaseEpoch, &owner, &epoch, &workflowID, &workflowEpoch)
	if err != nil {
		return mapAgentSQLError(err)
	}
	if owner != s.instanceID || epoch != s.hostEpoch.Load() {
		return agent.ErrConflict
	}
	if s.checkHostLeaseTx(ctx, tx, owner, epoch) != nil {
		return agent.ErrConflict
	}
	if workflowID != "" {
		var valid bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM workflow_leases l JOIN workflow_runs r ON r.run_id=l.run_id WHERE l.run_id=$1 AND l.epoch=$2 AND l.owner<>'' AND l.lease_until>clock_timestamp() AND r.status IN ('RUNNING','PAUSING'))`, workflowID, workflowEpoch).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return agent.ErrConflict
		}
	}
	if run.LeaseEpoch > 0 {
		return s.checkAgentPathTx(ctx, tx, run, terminal)
	}
	return nil
}
