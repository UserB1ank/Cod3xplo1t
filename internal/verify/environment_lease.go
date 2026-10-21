package verify

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// CleanupState is tracked separately from the environment's run state: an
// environment can be destroyed while its cleanup failed, and a failed cleanup must
// never be rendered as a successful teardown.
type CleanupState string

const (
	CleanupNotStarted CleanupState = "not_started"
	CleanupPending    CleanupState = "pending"
	CleanupSucceeded  CleanupState = "succeeded"
	CleanupFailed     CleanupState = "failed"
)

// EnvironmentLease is the host's durable claim on one provisioned environment.
//
// Epoch is monotonic per plan: a worker that lost its lease can never write a
// result under a newer epoch. The lease is deliberately separate from the run so a
// cleanup failure is visible even after the verdict is settled.
type EnvironmentLease struct {
	ID            string           `json:"lease_id"`
	PlanID        string           `json:"plan_id"`
	ProjectID     string           `json:"project_id"`
	SnapshotID    string           `json:"snapshot_id"`
	Owner         string           `json:"owner"`
	Provider      string           `json:"provider"`
	EnvironmentID string           `json:"environment_id,omitempty"`
	ImageDigest   string           `json:"image_digest,omitempty"`
	SourceDigest  string           `json:"source_digest,omitempty"`
	ReceiptDigest string           `json:"receipt_digest,omitempty"`
	Epoch         int64            `json:"epoch"`
	State         EnvironmentState `json:"state"`
	Cleanup       CleanupState     `json:"cleanup"`
	Failure       string           `json:"failure,omitempty"`
	ExpiresAt     string           `json:"expires_at"`
	CreatedAt     string           `json:"created_at"`
	UpdatedAt     string           `json:"updated_at"`
}

var (
	ErrLeaseHeld     = errors.New("verify: the environment is leased by another execution")
	ErrLeaseLost     = errors.New("verify: the environment lease was lost")
	ErrLeaseNotFound = errors.New("verify: environment lease not found")
	ErrLeaseExpired  = errors.New("verify: environment lease expired")
)

// EnvironmentLeaseQuery filters leases. An empty filter lists every lease.
type EnvironmentLeaseQuery struct {
	Owner   string
	State   []EnvironmentState
	Cleanup []CleanupState
	// ExpiredOnly restricts the answer to leases whose ExpiresAt is not after Now.
	ExpiredOnly bool
	Now         time.Time
	Limit       int
}

// EnvironmentLeaseStore persists environment ownership. Acquire, Renew, Bind and
// Release are fenced by owner and epoch; a stale worker's write is rejected.
type EnvironmentLeaseStore interface {
	AcquireEnvironmentLease(context.Context, EnvironmentLease, time.Time) (EnvironmentLease, error)
	RenewEnvironmentLease(ctx context.Context, id, owner string, epoch int64, until, now time.Time) (EnvironmentLease, error)
	BindEnvironmentLease(ctx context.Context, id, owner string, epoch int64, environmentID, receiptDigest, imageDigest string, until, now time.Time) (EnvironmentLease, error)
	ReleaseEnvironmentLease(ctx context.Context, id, owner string, epoch int64, cleanup CleanupState, failure string, now time.Time) (EnvironmentLease, error)
	GetEnvironmentLease(context.Context, string) (EnvironmentLease, error)
	ListEnvironmentLeases(context.Context, EnvironmentLeaseQuery) ([]EnvironmentLease, error)
}

// MemoryEnvironmentLeases is the in-process implementation used by tests and by
// deployments without a durable store. It keeps the exact fencing semantics of the
// SQL implementations.
type MemoryEnvironmentLeases struct {
	mu     sync.Mutex
	leases map[string]EnvironmentLease
}

func NewMemoryEnvironmentLeases() *MemoryEnvironmentLeases {
	return &MemoryEnvironmentLeases{leases: map[string]EnvironmentLease{}}
}

func (m *MemoryEnvironmentLeases) AcquireEnvironmentLease(ctx context.Context, lease EnvironmentLease, now time.Time) (EnvironmentLease, error) {
	if err := ctx.Err(); err != nil {
		return EnvironmentLease{}, err
	}
	if strings.TrimSpace(lease.ID) == "" || strings.TrimSpace(lease.Owner) == "" || strings.TrimSpace(lease.ExpiresAt) == "" {
		return EnvironmentLease{}, fmt.Errorf("%w: a lease needs an id, an owner and an expiry", ErrLeaseLost)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, found := m.leases[lease.ID]
	if found {
		if activeState(existing.State) && leaseExpired(existing, now) {
			// Do not hand out a new epoch while the old environment may still be
			// running. The reclaimer must terminate it and record the cleanup first.
			existing.State = EnvironmentFailed
			existing.Cleanup = CleanupPending
			existing.Failure = "lease expired"
			existing.UpdatedAt = now.UTC().Format(time.RFC3339)
			m.leases[lease.ID] = existing
			return EnvironmentLease{}, ErrLeaseExpired
		}
		if existing.Owner == lease.Owner && activeState(existing.State) {
			return existing, nil
		}
		if activeState(existing.State) {
			return EnvironmentLease{}, ErrLeaseHeld
		}
		if existing.Cleanup == CleanupPending || existing.Cleanup == CleanupFailed {
			return EnvironmentLease{}, fmt.Errorf("%w: the previous environment still needs cleanup (%s)", ErrLeaseHeld, existing.Cleanup)
		}
		lease.Epoch = existing.Epoch + 1
		lease.CreatedAt = existing.CreatedAt
	} else {
		lease.Epoch = 1
		lease.CreatedAt = now.UTC().Format(time.RFC3339)
	}
	lease.State = EnvironmentProvisioning
	lease.Cleanup = CleanupNotStarted
	lease.UpdatedAt = now.UTC().Format(time.RFC3339)
	m.leases[lease.ID] = lease
	return lease, nil
}

func (m *MemoryEnvironmentLeases) RenewEnvironmentLease(ctx context.Context, id, owner string, epoch int64, until, now time.Time) (EnvironmentLease, error) {
	if err := ctx.Err(); err != nil {
		return EnvironmentLease{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	lease, err := m.ownedLocked(id, owner, epoch, now)
	if err != nil {
		return EnvironmentLease{}, err
	}
	if !until.After(now) {
		return EnvironmentLease{}, fmt.Errorf("%w: the new expiry is not in the future", ErrLeaseLost)
	}
	lease.ExpiresAt = until.UTC().Format(time.RFC3339)
	lease.UpdatedAt = now.UTC().Format(time.RFC3339)
	m.leases[id] = lease
	return lease, nil
}

func (m *MemoryEnvironmentLeases) BindEnvironmentLease(ctx context.Context, id, owner string, epoch int64, environmentID, receiptDigest, imageDigest string, until, now time.Time) (EnvironmentLease, error) {
	if err := ctx.Err(); err != nil {
		return EnvironmentLease{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	lease, err := m.ownedLocked(id, owner, epoch, now)
	if err != nil {
		return EnvironmentLease{}, err
	}
	lease.EnvironmentID = environmentID
	lease.ReceiptDigest = receiptDigest
	lease.ImageDigest = imageDigest
	lease.State = EnvironmentReady
	if !until.After(now) {
		return EnvironmentLease{}, fmt.Errorf("%w: the new expiry is not in the future", ErrLeaseLost)
	}
	lease.ExpiresAt = until.UTC().Format(time.RFC3339)
	lease.UpdatedAt = now.UTC().Format(time.RFC3339)
	m.leases[id] = lease
	return lease, nil
}

func (m *MemoryEnvironmentLeases) ReleaseEnvironmentLease(ctx context.Context, id, owner string, epoch int64, cleanup CleanupState, failure string, now time.Time) (EnvironmentLease, error) {
	if err := ctx.Err(); err != nil {
		return EnvironmentLease{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cleanup != CleanupSucceeded && cleanup != CleanupFailed && cleanup != CleanupPending {
		return EnvironmentLease{}, fmt.Errorf("%w: unknown cleanup state %q", ErrLeaseLost, cleanup)
	}
	lease, found := m.leases[id]
	if !found {
		return EnvironmentLease{}, ErrLeaseNotFound
	}
	if lease.Owner != owner || lease.Epoch != epoch {
		return EnvironmentLease{}, ErrLeaseLost
	}
	lease.Cleanup = cleanup
	lease.Failure = strings.TrimSpace(failure)
	if cleanup == CleanupSucceeded {
		lease.State = EnvironmentDestroyed
	} else {
		lease.State = EnvironmentFailed
	}
	lease.UpdatedAt = now.UTC().Format(time.RFC3339)
	m.leases[id] = lease
	return lease, nil
}

func (m *MemoryEnvironmentLeases) GetEnvironmentLease(ctx context.Context, id string) (EnvironmentLease, error) {
	if err := ctx.Err(); err != nil {
		return EnvironmentLease{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	lease, found := m.leases[id]
	if !found {
		return EnvironmentLease{}, ErrLeaseNotFound
	}
	return lease, nil
}

func (m *MemoryEnvironmentLeases) ListEnvironmentLeases(ctx context.Context, q EnvironmentLeaseQuery) ([]EnvironmentLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []EnvironmentLease{}
	for _, lease := range m.leases {
		if q.Owner != "" && lease.Owner != q.Owner {
			continue
		}
		if len(q.State) > 0 && !containsEnvironmentState(q.State, lease.State) {
			continue
		}
		if len(q.Cleanup) > 0 && !containsCleanupState(q.Cleanup, lease.Cleanup) {
			continue
		}
		if q.ExpiredOnly && !leaseExpired(lease, q.Now) {
			continue
		}
		out = append(out, lease)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (m *MemoryEnvironmentLeases) ownedLocked(id, owner string, epoch int64, now time.Time) (EnvironmentLease, error) {
	lease, found := m.leases[id]
	if !found {
		return EnvironmentLease{}, ErrLeaseNotFound
	}
	if lease.Owner != owner || lease.Epoch != epoch {
		return EnvironmentLease{}, ErrLeaseLost
	}
	if leaseExpired(lease, now) {
		lease.State = EnvironmentFailed
		lease.Cleanup = CleanupPending
		lease.Failure = "lease expired"
		lease.UpdatedAt = now.UTC().Format(time.RFC3339)
		m.leases[id] = lease
		return EnvironmentLease{}, ErrLeaseExpired
	}
	return lease, nil
}

func leaseExpired(lease EnvironmentLease, now time.Time) bool {
	expires, err := time.Parse(time.RFC3339, lease.ExpiresAt)
	return err != nil || !expires.After(now)
}

func activeState(state EnvironmentState) bool {
	return state == EnvironmentProvisioning || state == EnvironmentReady || state == EnvironmentRunning
}

func containsEnvironmentState(values []EnvironmentState, want EnvironmentState) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsCleanupState(values []CleanupState, want CleanupState) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
