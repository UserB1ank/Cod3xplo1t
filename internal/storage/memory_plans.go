package storage

import (
	"context"
	"sort"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func (m *Memory) PutPlan(ctx context.Context, record verify.PlanRecord, expectedVersion int64) (verify.PlanRecord, error) {
	if err := ctx.Err(); err != nil {
		return verify.PlanRecord{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := record.Plan.ProjectID + "/" + record.Plan.ID
	prior, exists := m.plans[key]
	if expectedVersion == 0 && exists {
		return verify.PlanRecord{}, verify.ErrPlanConflict
	}
	if expectedVersion > 0 && (!exists || prior.Version != expectedVersion) {
		return verify.PlanRecord{}, verify.ErrPlanConflict
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if !exists && record.CreatedAt == "" {
		record.CreatedAt = now
	}
	record.Version = expectedVersion + 1
	record.UpdatedAt = now
	m.plans[key] = record
	return record, nil
}

func (m *Memory) GetPlan(ctx context.Context, projectID, planID string) (verify.PlanRecord, error) {
	if err := ctx.Err(); err != nil {
		return verify.PlanRecord{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, ok := m.plans[projectID+"/"+planID]
	if !ok {
		return verify.PlanRecord{}, verify.ErrPlanNotFound
	}
	return record, nil
}

func (m *Memory) ListPlans(ctx context.Context, projectID, state string, limit, offset int) ([]verify.PlanRecord, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if limit < 1 || limit > 200 || offset < 0 {
		return nil, 0, verify.ErrPlanInvalid
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rows := []verify.PlanRecord{}
	for _, record := range m.plans {
		if record.Plan.ProjectID != projectID || (state != "" && string(record.State) != state) {
			continue
		}
		rows = append(rows, record)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CreatedAt != rows[j].CreatedAt {
			return rows[i].CreatedAt > rows[j].CreatedAt
		}
		return rows[i].Plan.ID < rows[j].Plan.ID
	})
	total := len(rows)
	if offset >= total {
		return []verify.PlanRecord{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return append([]verify.PlanRecord(nil), rows[offset:end]...), total, nil
}
