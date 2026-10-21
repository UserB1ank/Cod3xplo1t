package storage

import (
	"context"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// leaseStore returns the in-memory lease store, initialising it for a zero-value
// Memory as well as the constructor.
func (m *Memory) leaseStore() *verify.MemoryEnvironmentLeases {
	m.leaseInit.Do(func() {
		if m.environmentLeases == nil {
			m.environmentLeases = verify.NewMemoryEnvironmentLeases()
		}
	})
	return m.environmentLeases
}

func (m *Memory) AcquireEnvironmentLease(ctx context.Context, lease verify.EnvironmentLease, now time.Time) (verify.EnvironmentLease, error) {
	return m.leaseStore().AcquireEnvironmentLease(ctx, lease, now)
}

func (m *Memory) RenewEnvironmentLease(ctx context.Context, id, owner string, epoch int64, until, now time.Time) (verify.EnvironmentLease, error) {
	return m.leaseStore().RenewEnvironmentLease(ctx, id, owner, epoch, until, now)
}

func (m *Memory) BindEnvironmentLease(ctx context.Context, id, owner string, epoch int64, environmentID, receiptDigest, imageDigest string, until, now time.Time) (verify.EnvironmentLease, error) {
	return m.leaseStore().BindEnvironmentLease(ctx, id, owner, epoch, environmentID, receiptDigest, imageDigest, until, now)
}

func (m *Memory) ReleaseEnvironmentLease(ctx context.Context, id, owner string, epoch int64, cleanup verify.CleanupState, failure string, now time.Time) (verify.EnvironmentLease, error) {
	return m.leaseStore().ReleaseEnvironmentLease(ctx, id, owner, epoch, cleanup, failure, now)
}

func (m *Memory) GetEnvironmentLease(ctx context.Context, id string) (verify.EnvironmentLease, error) {
	return m.leaseStore().GetEnvironmentLease(ctx, id)
}

func (m *Memory) ListEnvironmentLeases(ctx context.Context, q verify.EnvironmentLeaseQuery) ([]verify.EnvironmentLease, error) {
	return m.leaseStore().ListEnvironmentLeases(ctx, q)
}
