package storage

import (
	"context"
	"database/sql"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

func (s *SQL) failAgentRunTx(ctx context.Context, tx *sql.Tx, id, pathID, now, reason string) error {
	result, err := tx.ExecContext(ctx, `UPDATE agent_runs SET status='FAILED',version=version+1,finished_at=$1,updated_at=$1,stop_reason=$2,error=$2 WHERE run_id=$3 AND status NOT IN (`+terminalAgentStates+`)`, now, reason, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count == 0 {
		return err
	}
	seq, err := s.agentEventMaxSeqTx(ctx, tx, id)
	if err != nil {
		return err
	}
	return s.insertAgentEventTx(ctx, tx, agent.Event{RunID: id, PathID: pathID, Seq: seq + 1, Type: agent.EventRunFinished, Actor: "recovery", Summary: "run interrupted: " + reason, CreatedAt: now, Detail: map[string]string{"status": "FAILED", "stop_reason": reason}}, now)
}

func (s *SQL) recoverHostRunsTx(ctx context.Context, tx *sql.Tx) error {
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return err
	}
	stamp := now.Format(leaseTimeLayout)
	rows, err := tx.QueryContext(ctx, `SELECT run_id,path_id FROM agent_runs r WHERE status NOT IN (`+terminalAgentStates+`) AND (NOT EXISTS(SELECT 1 FROM runtime_hosts h WHERE h.host_id=r.host_id AND h.epoch=r.host_epoch AND h.lease_until>clock_timestamp()) OR (r.lease_epoch>0 AND EXISTS(SELECT 1 FROM audit_paths p WHERE p.path_id=r.path_id AND p.lease_epoch<>r.lease_epoch)) OR (r.workflow_run_id<>'' AND NOT EXISTS(SELECT 1 FROM workflow_leases l WHERE l.run_id=r.workflow_run_id AND l.epoch=r.workflow_epoch AND l.owner<>'' AND l.lease_until>clock_timestamp()))) FOR UPDATE`)
	if err != nil {
		return err
	}
	type expired struct{ id, path string }
	runs := []expired{}
	for rows.Next() {
		var item expired
		if err := rows.Scan(&item.id, &item.path); err != nil {
			rows.Close()
			return err
		}
		runs = append(runs, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, run := range runs {
		if err := s.failAgentRunTx(ctx, tx, run.id, run.path, stamp, "host_restarted"); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE verification_runs r SET status='FAILED',outcome='BLOCKED',version=version+1,finished_at=$1,updated_at=$1,stop_reason='host_restarted',error='verification host lease expired',reproduction='',exit_code=NULL WHERE status NOT IN (`+terminalVerificationStates+`) AND NOT EXISTS(SELECT 1 FROM runtime_hosts h WHERE h.host_id=r.host_id AND h.epoch=r.host_epoch AND h.lease_until>clock_timestamp())`, stamp)
	return err
}

func (s *SQL) expirePathRunsTx(ctx context.Context, tx *sql.Tx, pathID, now string) error {
	rows, err := tx.QueryContext(ctx, `SELECT run_id FROM agent_runs WHERE path_id=$1 AND status NOT IN (`+terminalAgentStates+`) FOR UPDATE`, pathID)
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
		if err := s.failAgentRunTx(ctx, tx, id, pathID, now, "path_lease_expired"); err != nil {
			return err
		}
	}
	return nil
}
