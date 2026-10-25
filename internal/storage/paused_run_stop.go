package storage

import (
	"context"
	"database/sql"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func pausedRunStopped(run agent.Run, actor string) agent.Event {
	return agent.Event{RunID: run.ID, PathID: run.PathID, Type: agent.EventRunFinished, Actor: actor, Summary: "paused run cancelled after project path stop", CreatedAt: agentNow(), Detail: map[string]string{"status": string(agent.RunCancelled), "stop_reason": agent.StopCancelled}}
}
func (m *Memory) CancelPausedRun(ctx context.Context, id, actor string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, ok := m.agentRuns[id]
	if !ok {
		return agent.ErrNotFound
	}
	if doc.run.Status != agent.RunPaused {
		return nil
	}
	if err := m.snapshotWritableLocked(doc.run.SnapshotID); err != nil {
		return err
	}
	_, p, ok := m.findPathDocLocked(doc.run.PathID)
	if !ok || p.Status != path.StatusCancelled {
		return agent.ErrConflict
	}
	event := pausedRunStopped(doc.run, actor)
	doc.run.Status = agent.RunCancelled
	doc.run.StopReason = agent.StopCancelled
	doc.run.FinishedAt = event.CreatedAt
	doc.run.UpdatedAt = event.CreatedAt
	doc.run.Version++
	event.Seq = doc.maxSeq + 1
	event.ID = agent.EventID(id, event.Seq)
	doc.appendEventLocked(event)
	return nil
}
func (s *SQL) CancelPausedRun(ctx context.Context, id, actor string) error {
	run, err := s.GetRun(id)
	if err != nil {
		return err
	}
	return s.snapshotWrite(ctx, run.SnapshotID, func(tx *sql.Tx) error {
		var status string
		if err := tx.QueryRowContext(ctx, s.rebind("SELECT status FROM agent_runs WHERE run_id=?"+s.forUpdate()), id).Scan(&status); err != nil {
			return mapAgentSQLError(err)
		}
		if status != string(agent.RunPaused) {
			return nil
		}
		var pathStatus string
		if err := tx.QueryRowContext(ctx, s.rebind("SELECT status FROM audit_paths WHERE path_id=?"), run.PathID).Scan(&pathStatus); err != nil {
			return mapAgentSQLError(err)
		}
		if pathStatus != string(path.StatusCancelled) {
			return agent.ErrConflict
		}
		event := pausedRunStopped(*run, actor)
		if _, err := tx.ExecContext(ctx, s.rebind("UPDATE agent_runs SET status=?,stop_reason=?,finished_at=?,updated_at=?,version=version+1 WHERE run_id=? AND status=?"), agent.RunCancelled, agent.StopCancelled, event.CreatedAt, event.CreatedAt, id, agent.RunPaused); err != nil {
			return err
		}
		seq, err := s.agentEventMaxSeqTx(ctx, tx, id)
		if err != nil {
			return err
		}
		event.Seq = seq + 1
		event.ID = agent.EventID(id, event.Seq)
		return s.insertAgentEventTx(ctx, tx, event, event.CreatedAt)
	})
}
