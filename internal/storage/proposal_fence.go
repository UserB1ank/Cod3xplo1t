package storage

import (
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// ValidateSupervisorProposalRun is the shared write fence for agent-proposed
// paths. The caller must lock the supervisor session while evaluating it.
func ValidateSupervisorProposalRun(
	session SupervisorSession,
	projectID, snapshotID string,
	observation path.PathDiscovery,
	origin path.ProposalOrigin,
	now time.Time,
) error {
	if observation.Source != "supervisor" {
		return nil
	}
	if origin.SessionID == "" || origin.RunID == "" || origin.ExecutionOwner == "" || origin.LeaseEpoch <= 0 ||
		observation.SessionID != origin.SessionID || observation.RunID != origin.RunID {
		return path.ErrInvalidArgument
	}
	if session.ProjectID != projectID || session.SnapshotID != snapshotID {
		return path.ErrConflict
	}
	for _, run := range session.Runs {
		if run.ID != origin.RunID {
			continue
		}
		if run.SessionID != "" && run.SessionID != session.ID {
			return path.ErrConflict
		}
		if run.ProjectID != "" && run.ProjectID != projectID {
			return path.ErrConflict
		}
		if run.Status != "RUNNING" || run.ExecutionOwner == "" || run.ExecutionOwner != origin.ExecutionOwner ||
			run.LeaseEpoch <= 0 || run.LeaseEpoch != origin.LeaseEpoch {
			return path.ErrConflict
		}
		lease, err := time.Parse(time.RFC3339Nano, run.LeaseUntil)
		if err != nil || !lease.After(now) {
			return path.ErrConflict
		}
		return nil
	}
	return path.ErrConflict
}
