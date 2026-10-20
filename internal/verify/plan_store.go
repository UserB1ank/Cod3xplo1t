package verify

import (
	"context"
	"errors"
	"time"
)

var (
	ErrPlanNotFound = errors.New("verify: plan not found")
	ErrPlanConflict = errors.New("verify: plan was changed by another writer")
)

// PlanRecord is the persisted lifecycle of one fixed execution plan. The plan
// itself is immutable data; the state and approval move under a version CAS.
type PlanRecord struct {
	Plan      ExecutionPlan `json:"plan"`
	State     PlanState     `json:"state"`
	Approval  *PlanApproval `json:"approval,omitempty"`
	Version   int64         `json:"version"`
	CreatedAt string        `json:"created_at"`
	UpdatedAt string        `json:"updated_at"`
}

// PlanRepository stores plans by project. expectedVersion 0 creates; a positive
// value must match the stored version.
type PlanRepository interface {
	PutPlan(context.Context, PlanRecord, int64) (PlanRecord, error)
	GetPlan(context.Context, string, string) (PlanRecord, error)
	ListPlans(context.Context, string, string, int, int) ([]PlanRecord, int, error)
}

// NewPlanRecord stamps a plan and its initial pending state.
func NewPlanRecord(plan ExecutionPlan, now time.Time) (PlanRecord, error) {
	if plan.ID == "" || plan.ProjectID == "" {
		return PlanRecord{}, ErrPlanInvalid
	}
	if plan.CreatedAt == "" {
		plan.CreatedAt = now.UTC().Format(time.RFC3339)
	}
	plan.Digest = plan.DigestOf()
	return PlanRecord{Plan: plan, State: PlanPending, Version: 0, CreatedAt: plan.CreatedAt, UpdatedAt: plan.CreatedAt}, nil
}
