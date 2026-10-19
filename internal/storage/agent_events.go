package storage

import (
	"context"
	"database/sql"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func (s *SQL) CreateRunEvents(run agent.Run, events []agent.Event) error {
	return s.CreateRunEventsContext(context.Background(), run, events)
}

func (s *SQL) CreateRunEventsContext(ctx context.Context, run agent.Run, events []agent.Event) error {
	if s.postgres {
		if err := s.ensureHostLease(ctx); err != nil {
			return err
		}
	}
	return s.snapshotWrite(ctx, run.SnapshotID, func(tx *sql.Tx) error {
		if err := s.createAgentRunTx(ctx, tx, run); err != nil {
			return err
		}
		if lease, ok := workflow.ContextLease(ctx); s.postgres && ok {
			if err := validateWorkflowLeaseTx(ctx, tx, lease.RunID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE agent_runs SET workflow_run_id=$1,workflow_epoch=$2 WHERE run_id=$3`, lease.RunID, lease.Epoch, run.ID); err != nil {
				return err
			}
		}
		return s.appendAgentTailTx(ctx, tx, run, events)
	})
}

func (s *SQL) appendAgentTailTx(ctx context.Context, tx *sql.Tx, run agent.Run, events []agent.Event) error {
	seq, err := s.agentEventMaxSeqTx(ctx, tx, run.ID)
	if err != nil {
		return err
	}
	for _, event := range events {
		if (event.RunID != "" && event.RunID != run.ID) || (event.PathID != "" && event.PathID != run.PathID) {
			return agent.ErrConflict
		}
		seq++
		event.Seq = seq
		event.RunID = run.ID
		event.PathID = run.PathID
		if err := s.insertAgentEventTx(ctx, tx, event, agentNow()); err != nil {
			return err
		}
	}
	return nil
}

// SaveRunEvents updates the run and allocates a contiguous event tail in the
// same transaction. A malformed or conflicting event rolls back the state too.
func (s *SQL) SaveRunEvents(run agent.Run, expected int64, events []agent.Event) error {
	ctx := context.Background()
	return s.snapshotWrite(ctx, run.SnapshotID, func(tx *sql.Tx) error {
		if err := s.updateAgentRunTx(ctx, tx, run, expected); err != nil {
			return err
		}
		return s.appendAgentTailTx(ctx, tx, run, events)
	})
}
