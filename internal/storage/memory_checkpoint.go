package storage

import (
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

// SaveCheckpointAndPause implements agent.Store. The checkpoint, the paused run
// and its final events become visible together, so a reader never sees PAUSED
// without the document that makes it resumable.
func (m *Memory) SaveCheckpointAndPause(run agent.Run, expectedVersion int64, checkpoint agent.Checkpoint, events []agent.Event) error {
	storedRun, err := cloneAgent(run)
	if err != nil {
		return err
	}
	storedCheckpoint, err := cloneAgent(checkpoint)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, ok := m.agentRuns[run.ID]
	if !ok {
		return fmt.Errorf("%w: run %s", agent.ErrNotFound, run.ID)
	}
	if err := m.snapshotWritableLocked(run.SnapshotID); err != nil {
		return err
	}
	if expectedVersion != 0 && doc.run.Version != expectedVersion {
		return fmt.Errorf("%w: run %s is at version %d", agent.ErrConflict, run.ID, doc.run.Version)
	}
	if _, exists := m.agentCheckpoints[checkpoint.ID]; exists {
		return fmt.Errorf("%w: checkpoint %s already exists", agent.ErrConflict, checkpoint.ID)
	}
	now := agentNow()
	seq := doc.maxSeq
	for _, event := range events {
		seq++
		event.Seq = seq
		event.RunID = run.ID
		event.PathID = run.PathID
		if event.ID == "" {
			event.ID = agent.EventID(run.ID, seq)
		}
		if event.CreatedAt == "" {
			event.CreatedAt = now
		}
		doc.appendEventLocked(event)
	}
	storedRun.Version = doc.run.Version + 1
	doc.run = storedRun
	m.agentCheckpoints[checkpoint.ID] = storedCheckpoint
	return nil
}

// GetCheckpoint implements agent.Store: the latest pause document of a run.
func (m *Memory) GetCheckpoint(runID string) (*agent.Checkpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var latest *agent.Checkpoint
	for _, checkpoint := range m.agentCheckpoints {
		if checkpoint.RunID != runID {
			continue
		}
		if latest == nil || checkpoint.CreatedAt > latest.CreatedAt ||
			(checkpoint.CreatedAt == latest.CreatedAt && checkpoint.ID > latest.ID) {
			copied := checkpoint
			latest = &copied
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("%w: checkpoint of run %s", agent.ErrNotFound, runID)
	}
	return latest, nil
}

// ClaimCheckpointResume implements agent.Store: the first caller consumes the
// checkpoint and every other resume gets a conflict.
func (m *Memory) ClaimCheckpointResume(checkpointID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if checkpointID == "" {
		return fmt.Errorf("%w: a checkpoint id is required", agent.ErrInvalidArgument)
	}
	if _, exists := m.agentCheckpoints[checkpointID]; !exists {
		return fmt.Errorf("%w: checkpoint %s", agent.ErrNotFound, checkpointID)
	}
	if _, claimed := m.agentCheckpointResumes[checkpointID]; claimed {
		return fmt.Errorf("%w: checkpoint %s was already consumed", agent.ErrConflict, checkpointID)
	}
	m.agentCheckpointResumes[checkpointID] = struct{}{}
	return nil
}
