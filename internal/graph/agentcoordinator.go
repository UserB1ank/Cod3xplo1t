package graph

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// AgentCoordinator adapts *path.Service to the orchestrator's lease vocabulary.
//
// It exists in the query layer, and not in internal/agent, for the same reason
// AgentFacts and PathFacts do: the storage layer implements agent.Store, so
// `agent → graph → storage → agent` would be an import cycle.
//
// Every method returns the path engine's sentinels untouched. RunOnce decides
// "there is no work" from "the queue is broken" with errors.Is(err,
// path.ErrNotFound), and a coordinator that wrapped the sentinel would turn an
// empty queue into a failed run.
type AgentCoordinator struct {
	Paths *path.Service
	// Owner is the fallback lease holder when a call does not name one. The
	// orchestrator always names its own, so this only matters to a direct caller.
	Owner string
}

// coordinatorDefaultOwner mirrors the orchestrator's own default: a lease without
// an owner cannot be renewed or released, so the coordinator never claims without
// one.
const coordinatorDefaultOwner = "orchestrator"

// NewAgentCoordinator builds the adapter over the path service.
func NewAgentCoordinator(svc *path.Service, owner string) *AgentCoordinator {
	return &AgentCoordinator{Paths: svc, Owner: strings.TrimSpace(owner)}
}

// ClaimSpecificPath leases exactly the named path, never the next one in the
// queue. It is what lets a scheduler that has already chosen a path hand that
// choice to the orchestrator without the orchestrator re-deciding.
//
// The rules of the claim are the engine's, spelled out here because they are what
// makes concurrent schedulers safe:
//
//   - a path in another owner's live lease is refused with path.ErrLeaseHeld;
//   - a path the requested owner already holds is renewed, not refused: the
//     scheduler claims the path before dispatching it and RunPath then claims it
//     for the run, and refusing the second claim would make every scheduled run
//     fail;
//   - a path that is not QUEUED is refused with path.ErrNotClaimable;
//   - the audit's active-lease ceiling is enforced, because taking a lease is what
//     spends it (the engine's Service.Claim does the same for its queue claim).
func (c *AgentCoordinator) ClaimSpecificPath(ctx context.Context, pathID, owner string, ttl time.Duration) (*path.Path, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pathID = strings.TrimSpace(pathID)
	if pathID == "" {
		return nil, fmt.Errorf("%w: a path id is required", path.ErrInvalidArgument)
	}
	owner = c.owner(owner)
	current, err := c.Paths.Store.GetPath(pathID)
	if err != nil {
		return nil, err
	}
	// A claim by the holder extends the lease: it is a transfer of nothing.
	if current.LeaseOwner == owner {
		return c.Paths.Heartbeat(pathID, owner, ttl)
	}
	if current.LeaseOwner != "" {
		return nil, fmt.Errorf("%w: path %s is leased by %s", path.ErrLeaseHeld, pathID, current.LeaseOwner)
	}
	if !current.Status.Claimable() {
		return nil, fmt.Errorf("%w: path %s is %s", path.ErrNotClaimable, pathID, current.Status)
	}
	audit, err := c.Paths.Store.GetAudit(current.AuditID)
	if err != nil {
		return nil, err
	}
	limits := audit.Limits.Normalize()
	active, err := c.activeLeases(current.AuditID)
	if err != nil {
		return nil, err
	}
	if active >= limits.MaxActiveLeases {
		return nil, fmt.Errorf("%w: %d active lease(s) of a maximum of %d in audit %s",
			path.ErrBudgetExceeded, active, limits.MaxActiveLeases, current.AuditID)
	}
	if ttl <= 0 {
		ttl = time.Duration(limits.LeaseTTLSeconds) * time.Second
	}
	until := path.NowString(c.now().Add(ttl))
	return c.Paths.Store.ClaimPath(pathID, owner, until, []path.Status{path.StatusQueued}, owner)
}

// activeLeases counts the paths of an audit currently held by a worker. It mirrors
// the engine's own accounting: the ceiling is a property of the audit, not of one
// row, so it has to be counted over the audit's whole path set.
func (c *AgentCoordinator) activeLeases(auditID string) (int, error) {
	active := 0
	offset := 0
	for {
		paths, total, err := c.Paths.Store.ListPaths(path.PathQuery{AuditID: auditID, Limit: 1000, Offset: offset})
		if err != nil {
			return 0, err
		}
		for _, p := range paths {
			if p.Status.Active() {
				active++
			}
		}
		offset += len(paths)
		if len(paths) == 0 || offset >= total {
			return active, nil
		}
	}
}

// now is the coordinator's clock. It follows the path service's injected clock so
// a test that fixes the service's clock fixes the coordinator's too.
func (c *AgentCoordinator) now() time.Time {
	if c.Paths != nil && c.Paths.Now != nil {
		return c.Paths.Now()
	}
	return time.Now().UTC()
}

// ClaimPathForRun leases the next claimable path of an audit. path.ErrNotFound —
// the queue is empty — is returned unchanged.
func (c *AgentCoordinator) ClaimPathForRun(ctx context.Context, auditID, owner string, ttl time.Duration) (*path.Path, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Paths.Claim(ctx, auditID, c.owner(owner), ttl)
}

// HeartbeatPath renews a lease the owner still holds.
func (c *AgentCoordinator) HeartbeatPath(ctx context.Context, pathID, owner string, ttl time.Duration) error {
	if err := c.ready(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := c.Paths.Heartbeat(pathID, c.owner(owner), ttl)
	return err
}

// ReleasePath returns a path to the queue so another attempt can run it.
func (c *AgentCoordinator) ReleasePath(ctx context.Context, pathID, owner, reason string) error {
	if err := c.ready(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := c.Paths.Release(pathID, c.owner(owner), reason)
	return err
}

// CompletePath records the end of a successful run: the path advances to
// HYPOTHESIS_FORMED and the lease is cleared in the same atomic change.
//
// HYPOTHESIS_FORMED is deliberately not an active status, so the engine's own
// Transition clears the lease (ClearLease is `!to.Active()`). That matters twice
// over: a finished run must not keep spending the audit's active-lease ceiling,
// and ReclaimExpired must never be handed a path whose status it cannot legally
// leave. The invariant is asserted in the tests rather than assumed here.
func (c *AgentCoordinator) CompletePath(ctx context.Context, pathID, owner, reason string) error {
	if err := c.ready(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// TransitionOwned, not Transition: a run may only settle the path it holds, and
	// the store enforces that atomically.
	_, err := c.Paths.TransitionOwned(pathID, c.owner(owner), path.StatusHypothesisFormed, c.owner(owner), reason)
	return err
}

// AdvancePath moves a claimed path to any status the state machine accepts, which
// is how a run that spent its attempts takes a path out of the queue without
// pretending it was released.
func (c *AgentCoordinator) AdvancePath(ctx context.Context, pathID, owner string, to path.Status, reason string) error {
	if err := c.ready(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The owned form as well: taking a path out of the queue after a spent attempt is
	// still settling work the run was holding.
	_, err := c.Paths.TransitionOwned(pathID, c.owner(owner), to, c.owner(owner), reason)
	return err
}

// ready reports a coordinator that was built without a path service. It is a
// wiring bug, not a path condition, so it is not one of the path.* sentinels.
func (c *AgentCoordinator) ready() error {
	if c == nil || c.Paths == nil {
		return errors.New("graph: agent coordinator has no path service")
	}
	return nil
}

func (c *AgentCoordinator) owner(owner string) string {
	if owner = strings.TrimSpace(owner); owner != "" {
		return owner
	}
	if c != nil {
		if c.Owner = strings.TrimSpace(c.Owner); c.Owner != "" {
			return c.Owner
		}
	}
	return coordinatorDefaultOwner
}
