package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

// SaveCheckpointAndPause implements agent.Store. The run update, the checkpoint
// insert and the final events share one transaction.
func (s *SQL) SaveCheckpointAndPause(run agent.Run, expectedVersion int64, checkpoint agent.Checkpoint, events []agent.Event) error {
	ctx := context.Background()
	return s.snapshotWrite(ctx, run.SnapshotID, func(tx *sql.Tx) error {
		if err := s.updateAgentRunTx(ctx, tx, run, expectedVersion); err != nil {
			return err
		}
		document, err := json.Marshal(checkpoint)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO agent_checkpoints
			(checkpoint_id, run_id, audit_id, path_id, snapshot_id, version, digest, document_json, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			checkpoint.ID, checkpoint.RunID, checkpoint.AuditID, checkpoint.PathID, checkpoint.SnapshotID,
			checkpoint.Version, checkpoint.Digest, string(document), checkpoint.CreatedAt)
		if err != nil {
			return mapAgentSQLError(err)
		}
		return s.appendAgentTailTx(ctx, tx, run, events)
	})
}

// GetCheckpoint implements agent.Store: the latest pause document of a run.
func (s *SQL) GetCheckpoint(runID string) (*agent.Checkpoint, error) {
	row := s.db.QueryRowContext(context.Background(), s.rebind(
		`SELECT document_json FROM agent_checkpoints WHERE run_id = ? ORDER BY created_at DESC, checkpoint_id DESC LIMIT 1`), runID)
	var document string
	if err := row.Scan(&document); err != nil {
		return nil, mapAgentSQLError(err)
	}
	var checkpoint agent.Checkpoint
	if err := json.Unmarshal([]byte(document), &checkpoint); err != nil {
		return nil, err
	}
	return &checkpoint, nil
}

// ClaimCheckpointResume implements agent.Store. The primary key is the CAS: the
// database decides one winner across every application instance.
func (s *SQL) ClaimCheckpointResume(checkpointID string) error {
	ctx := context.Background()
	var exists int
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT COUNT(1) FROM agent_checkpoints WHERE checkpoint_id = ?"), checkpointID).Scan(&exists); err != nil {
		return mapAgentSQLError(err)
	}
	if exists == 0 {
		return fmt.Errorf("%w: checkpoint %s", agent.ErrNotFound, checkpointID)
	}
	_, err := s.db.ExecContext(ctx, s.rebind("INSERT INTO agent_checkpoint_resumes (checkpoint_id, claimed_at) VALUES (?, ?)"), checkpointID, agentNow())
	return mapAgentSQLError(err)
}
