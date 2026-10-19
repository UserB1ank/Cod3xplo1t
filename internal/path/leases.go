package path

import (
	"context"
	"time"
)

type leaseProof struct {
	ID    string
	Epoch int64
}
type leaseProofKey struct{}

func WithLease(ctx context.Context, id string, epoch int64) context.Context {
	return context.WithValue(ctx, leaseProofKey{}, leaseProof{ID: id, Epoch: epoch})
}
func ContextLease(ctx context.Context, id string) (int64, bool) {
	proof, ok := ctx.Value(leaseProofKey{}).(leaseProof)
	return proof.Epoch, ok && proof.ID == id
}

// ServerLeases accepts durations rather than trusting a worker's wall clock.
type ServerLeases interface {
	ServerLeaseClock() bool
	ClaimPathTTL(context.Context, string, string, time.Duration, []Status, string) (*Path, error)
	RenewPathTTL(context.Context, string, string, int64, time.Duration, string) (*Path, error)
	ReleasePathEpoch(context.Context, string, string, int64, string, string) (*Path, error)
}

func (s *Service) LeasePath(ctx context.Context, id, owner string, ttl time.Duration, from []Status, actor string) (*Path, error) {
	if store, ok := s.Store.(ServerLeases); ok && store.ServerLeaseClock() {
		return store.ClaimPathTTL(ctx, id, owner, ttl, from, actor)
	}
	return s.Store.ClaimPath(id, owner, NowString(s.now().Add(ttl)), from, actor)
}

func (s *Service) HeartbeatEpoch(ctx context.Context, id, owner string, epoch int64, ttl time.Duration) (*Path, error) {
	p, err := s.Store.GetPath(id)
	if err != nil {
		return nil, err
	}
	if p.LeaseEpoch != epoch {
		return nil, ErrLeaseExpired
	}
	if ttl <= 0 {
		audit, err := s.Store.GetAudit(p.AuditID)
		if err != nil {
			return nil, err
		}
		ttl = time.Duration(audit.Limits.Normalize().LeaseTTLSeconds) * time.Second
	}
	if store, ok := s.Store.(ServerLeases); ok && store.ServerLeaseClock() {
		return store.RenewPathTTL(ctx, id, owner, epoch, ttl, owner)
	}
	return s.Store.RenewLease(id, owner, NowString(s.now().Add(ttl)), owner)
}

func (s *Service) ReleaseEpoch(ctx context.Context, id, owner string, epoch int64, reason string) (*Path, error) {
	p, err := s.Store.GetPath(id)
	if err != nil {
		return nil, err
	}
	if p.LeaseEpoch != epoch {
		return nil, ErrLeaseExpired
	}
	if store, ok := s.Store.(ServerLeases); ok && store.ServerLeaseClock() {
		return store.ReleasePathEpoch(ctx, id, owner, epoch, owner, reason)
	}
	return s.Store.ReleaseLease(id, owner, owner, reason)
}

func (s *Service) TransitionEpoch(id, owner string, epoch int64, to Status, reason string) (*Path, error) {
	current, err := s.Store.GetPath(id)
	if err != nil {
		return nil, err
	}
	if current.LeaseEpoch != epoch {
		return nil, ErrLeaseExpired
	}
	return s.Store.Transition(TransitionRequest{PathID: id, Owner: owner, LeaseEpoch: epoch, ExpectedVersion: current.Version, To: to, ClearLease: !to.Active(), Actor: owner, Reason: reason, EventType: EventPathStatusChange})
}
