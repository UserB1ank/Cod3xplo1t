package storage

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/reviewbatch"
)

func (m *Memory) CreateReviewBatch(_ context.Context, batch reviewbatch.Batch) (reviewbatch.Batch, error) {
	batch = batch.Normalize()
	if batch.ID == "" || batch.ProjectID == "" || batch.SnapshotID == "" || batch.AuditID == "" {
		return reviewbatch.Batch{}, fmt.Errorf("%w: batch identity is incomplete", reviewbatch.ErrInvalid)
	}
	if len(batch.PathIDs) == 0 || batch.MaxConcurrent <= 0 || !reviewbatch.ValidState(batch.State) {
		return reviewbatch.Batch{}, fmt.Errorf("%w: batch paths, concurrency and state are required", reviewbatch.ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.reviewBatches {
		if existing.AuditID == batch.AuditID && existing.State.BlocksNewBatch() {
			return reviewbatch.Batch{}, fmt.Errorf("%w: audit %s already has review batch %s", reviewbatch.ErrConflict, batch.AuditID, existing.ID)
		}
	}
	if _, exists := m.reviewBatches[batch.ID]; exists {
		return reviewbatch.Batch{}, fmt.Errorf("%w: batch %s already exists", reviewbatch.ErrConflict, batch.ID)
	}
	if batch.Version == 0 {
		batch.Version = 1
	}
	m.reviewBatches[batch.ID] = batch.Normalize()
	return batch.Normalize(), nil
}

func (m *Memory) GetReviewBatch(_ context.Context, id string) (*reviewbatch.Batch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	batch, ok := m.reviewBatches[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", reviewbatch.ErrNotFound, id)
	}
	copy := batch.Normalize()
	return &copy, nil
}

func (m *Memory) ListReviewBatches(_ context.Context, query reviewbatch.Query) ([]reviewbatch.Batch, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := make([]reviewbatch.Batch, 0, len(m.reviewBatches))
	for _, batch := range m.reviewBatches {
		if query.ProjectID != "" && batch.ProjectID != query.ProjectID {
			continue
		}
		if query.AuditID != "" && batch.AuditID != query.AuditID {
			continue
		}
		if query.State != "" && batch.State != query.State {
			continue
		}
		all = append(all, batch.Normalize())
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].CreatedAt != all[j].CreatedAt {
			return all[i].CreatedAt > all[j].CreatedAt
		}
		return all[i].ID < all[j].ID
	})
	total := len(all)
	offset := max(0, query.Offset)
	if offset >= total {
		return []reviewbatch.Batch{}, total, nil
	}
	limit := query.Limit
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	end := min(offset+limit, total)
	return all[offset:end], total, nil
}

func (m *Memory) ControlReviewBatch(_ context.Context, req reviewbatch.ControlRequest) (*reviewbatch.Batch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.reviewBatches[req.BatchID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", reviewbatch.ErrNotFound, req.BatchID)
	}
	if req.ExpectedVersion <= 0 || current.Version != req.ExpectedVersion {
		return nil, fmt.Errorf("%w: batch %s changed", reviewbatch.ErrConflict, req.BatchID)
	}
	switch req.Target {
	case reviewbatch.StatePaused:
		if current.State != reviewbatch.StateRunning {
			return nil, fmt.Errorf("%w: batch %s is %s", reviewbatch.ErrConflict, current.ID, current.State)
		}
		current.State = reviewbatch.StatePaused
		current.ExecutionOwner = ""
		current.HeartbeatAt = ""
		current.LeaseUntil = ""
	case reviewbatch.StateRunning:
		if current.State != reviewbatch.StatePaused || req.Owner == "" || req.LeaseUntil == "" {
			return nil, fmt.Errorf("%w: batch %s is %s", reviewbatch.ErrConflict, current.ID, current.State)
		}
		current.State = reviewbatch.StateRunning
		current.ExecutionOwner = req.Owner
		current.LeaseEpoch = nextReviewBatchEpoch(current.LeaseEpoch)
		current.HeartbeatAt = req.Now
		current.LeaseUntil = req.LeaseUntil
	case reviewbatch.StateCancelling:
		if current.State == reviewbatch.StateCancelling {
			copy := current.Normalize()
			return &copy, nil
		}
		if current.State != reviewbatch.StateRunning && current.State != reviewbatch.StatePaused {
			return nil, fmt.Errorf("%w: batch %s is %s", reviewbatch.ErrConflict, current.ID, current.State)
		}
		current.State = reviewbatch.StateCancelling
	default:
		return nil, fmt.Errorf("%w: unsupported control target %s", reviewbatch.ErrInvalid, req.Target)
	}
	current.Reason = req.Reason
	current.UpdatedAt = req.Now
	current.Version++
	m.reviewBatches[current.ID] = current.Normalize()
	copy := current.Normalize()
	return &copy, nil
}

func (m *Memory) ClaimReviewBatch(_ context.Context, req reviewbatch.ClaimRequest) (*reviewbatch.Batch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.reviewBatches[req.BatchID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", reviewbatch.ErrNotFound, req.BatchID)
	}
	if current.State != reviewbatch.StateRunning && current.State != reviewbatch.StateCancelling {
		return nil, fmt.Errorf("%w: batch %s is %s", reviewbatch.ErrConflict, current.ID, current.State)
	}
	if current.ExecutionOwner != "" && !reviewBatchLeaseExpired(current.LeaseUntil, req.Now) {
		return nil, fmt.Errorf("%w: batch %s lease is held by %s", reviewbatch.ErrConflict, current.ID, current.ExecutionOwner)
	}
	current.ExecutionOwner = req.Owner
	current.LeaseEpoch = nextReviewBatchEpoch(current.LeaseEpoch)
	current.HeartbeatAt = req.Now
	current.LeaseUntil = req.LeaseUntil
	current.UpdatedAt = req.Now
	current.Version++
	m.reviewBatches[current.ID] = current.Normalize()
	copy := current.Normalize()
	return &copy, nil
}

func (m *Memory) RenewReviewBatch(_ context.Context, req reviewbatch.RenewRequest) (*reviewbatch.Batch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.reviewBatches[req.BatchID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", reviewbatch.ErrNotFound, req.BatchID)
	}
	if current.ExecutionOwner != req.Owner || current.LeaseEpoch != req.Epoch ||
		(current.State != reviewbatch.StateRunning && current.State != reviewbatch.StateCancelling) {
		return nil, fmt.Errorf("%w: batch %s lease is no longer owned by %s", reviewbatch.ErrConflict, current.ID, req.Owner)
	}
	current.HeartbeatAt = req.HeartbeatAt
	current.LeaseUntil = req.LeaseUntil
	current.UpdatedAt = req.HeartbeatAt
	current.Version++
	m.reviewBatches[current.ID] = current.Normalize()
	copy := current.Normalize()
	return &copy, nil
}

func (m *Memory) FinalizeReviewBatch(_ context.Context, req reviewbatch.FinalizeRequest) (*reviewbatch.Batch, error) {
	if !req.State.Terminal() {
		return nil, fmt.Errorf("%w: final state %s is not terminal", reviewbatch.ErrInvalid, req.State)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.reviewBatches[req.BatchID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", reviewbatch.ErrNotFound, req.BatchID)
	}
	if current.Version != req.ExpectedVersion || current.ExecutionOwner != req.Owner ||
		current.LeaseEpoch != req.Epoch ||
		(current.State != reviewbatch.StateRunning && current.State != reviewbatch.StateCancelling) {
		return nil, fmt.Errorf("%w: batch %s lease or version changed", reviewbatch.ErrConflict, current.ID)
	}
	current.State = req.State
	current.LastError = req.LastError
	current.ExecutionOwner = ""
	current.HeartbeatAt = ""
	current.LeaseUntil = ""
	current.UpdatedAt = req.Now
	current.Version++
	m.reviewBatches[current.ID] = current.Normalize()
	copy := current.Normalize()
	return &copy, nil
}

func (m *Memory) ListReclaimableReviewBatches(_ context.Context, now string, limit int) ([]reviewbatch.Batch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]reviewbatch.Batch, 0)
	for _, batch := range m.reviewBatches {
		if (batch.State == reviewbatch.StateRunning || batch.State == reviewbatch.StateCancelling) &&
			(batch.ExecutionOwner == "" || reviewBatchLeaseExpired(batch.LeaseUntil, now)) {
			out = append(out, batch.Normalize())
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func reviewBatchLeaseExpired(leaseUntil, now string) bool {
	if leaseUntil == "" {
		return true
	}
	lease, err := time.Parse(time.RFC3339Nano, leaseUntil)
	if err != nil {
		return true
	}
	current, err := time.Parse(time.RFC3339Nano, now)
	return err != nil || !lease.After(current)
}

func nextReviewBatchEpoch(current int64) int64 {
	if current < 1 {
		return 1
	}
	return current + 1
}
