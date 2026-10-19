package workflow

import (
	"context"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

// Lease grants one coordinator authority over a run. Epochs never repeat.
type Lease struct {
	RunID, Owner string
	Epoch        int64
	ExpiresAt    string
}
type leaseContextKey struct{}

func WithLease(ctx context.Context, lease Lease) context.Context {
	return context.WithValue(ctx, leaseContextKey{}, lease)
}
func ContextLease(ctx context.Context) (Lease, bool) {
	lease, ok := ctx.Value(leaseContextKey{}).(Lease)
	return lease, ok
}

// LeaseRepository coordinates workers through database time and durable fences.
type LeaseRepository interface {
	WorkflowLeaseClock() bool
	AcquireWorkflowLease(context.Context, string, string, string, time.Duration) (Run, Lease, error)
	RenewWorkflowLease(context.Context, Lease, time.Duration) error
	ReleaseWorkflowLease(context.Context, Lease) error
	ControlWorkflowRun(context.Context, string, string, string) (Run, error)
}

type NodeRecovery interface {
	RecoverNode(context.Context, artifact.Scope, NodeRun) (NodeResult, error)
}
