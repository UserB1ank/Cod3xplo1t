package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func (s *SQL) renewHost(ctx context.Context) error {
	var epoch int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO runtime_hosts(host_id,epoch,lease_until) VALUES($1,1,clock_timestamp()+interval '10 seconds') ON CONFLICT(host_id) DO UPDATE SET epoch=CASE WHEN runtime_hosts.lease_until>clock_timestamp() THEN runtime_hosts.epoch ELSE runtime_hosts.epoch+1 END,lease_until=clock_timestamp()+interval '10 seconds' RETURNING epoch`, s.instanceID).Scan(&epoch)
	if err == nil {
		s.hostEpoch.Store(epoch)
	}
	return err
}

func (s *SQL) ensureHostLease(ctx context.Context) error {
	var initial error
	s.hostOnce.Do(func() {
		s.hostMu.Lock()
		defer s.hostMu.Unlock()
		if s.hostClosed {
			initial = plugin.ErrConflict
			return
		}
		initial = s.renewHost(ctx)
		worker, stop := context.WithCancel(context.Background())
		s.hostCancel = stop
		s.hostDone = make(chan struct{})
		go func() {
			defer close(s.hostDone)
			timer := time.NewTicker(2 * time.Second)
			defer timer.Stop()
			for {
				select {
				case <-worker.Done():
					return
				case <-timer.C:
					probe, done := context.WithTimeout(worker, 3*time.Second)
					if s.renewHost(probe) == nil {
						_ = s.recoverPostgresInvocations(probe)
					}
					done()
				}
			}
		}()
	})
	if initial != nil {
		return initial
	}
	if s.hostEpoch.Load() == 0 {
		return plugin.ErrConflict
	}
	return nil
}

func (s *SQL) checkHostLeaseTx(ctx context.Context, tx *sql.Tx, owner string, epoch int64) error {
	var actual int64
	err := tx.QueryRowContext(ctx, `SELECT epoch FROM runtime_hosts WHERE host_id=$1 AND lease_until>clock_timestamp() FOR SHARE`, owner).Scan(&actual)
	if err == sql.ErrNoRows || (err == nil && actual != epoch) {
		return plugin.ErrConflict
	}
	return err
}

func (s *SQL) recoverPostgresInvocations(ctx context.Context) error {
	const orphan = `status IN ('CREATED','RUNNING') AND (NOT EXISTS(SELECT 1 FROM runtime_hosts h WHERE h.host_id=plugin_invocations.host_id AND h.epoch=plugin_invocations.host_epoch AND h.lease_until>clock_timestamp()) OR (EXISTS(SELECT 1 FROM workflow_node_claims n WHERE n.invocation_id=plugin_invocations.invocation_id) AND NOT EXISTS(SELECT 1 FROM workflow_node_claims n JOIN workflow_leases l ON l.run_id=n.run_id AND l.epoch=n.epoch JOIN workflow_runs r ON r.run_id=l.run_id WHERE n.invocation_id=plugin_invocations.invocation_id AND l.owner<>'' AND l.lease_until>clock_timestamp() AND r.status IN ('RUNNING','PAUSING','CANCELLING'))))`
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT document_json FROM plugin_invocations WHERE `+orphan+` FOR UPDATE`)
	if err != nil {
		return err
	}
	active := []plugin.Invocation{}
	for rows.Next() {
		var raw string
		var inv plugin.Invocation
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err := json.Unmarshal([]byte(raw), &inv); err != nil {
			rows.Close()
			return err
		}
		active = append(active, inv)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, inv := range active {
		inv.Status = "FAILED"
		inv.ErrorCode = "host_restarted"
		inv.Version++
		inv.Outputs = []artifact.Ref{}
		inv.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		raw, err := json.Marshal(inv)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE plugin_invocations SET status=$1,version=$2,document_json=$3 WHERE invocation_id=$4`, inv.Status, inv.Version, string(raw), inv.ID); err != nil {
			return err
		}
	}
	if err := s.recoverHostRunsTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}
