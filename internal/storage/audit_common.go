package storage

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// This file holds the state-change rules the two audit backends share.
//
// Keeping them in one place is what makes the memory and the SQL store behave
// identically: the implementations differ only in how the resulting document and
// its event are persisted, never in what a transition means. The rules mirror the
// engine's own in-package reference store (`internal/path/fake_test.go`) so the
// contract the engine was written against is the contract storage enforces.

// auditNow is the store-side clock. The Store contract carries no clock, so the
// storage layer stamps the timestamps of the changes it applies itself.
func auditNow() string { return path.NowString(time.Now().UTC()) }

// jsonString marshals a document value for a TEXT column. A nil slice or map is
// stored as JSON null, so a document read back compares equal to the one written
// (nil stays nil, an empty collection stays empty).
func jsonString(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("storage: encode audit document: %w", err)
	}
	return string(data), nil
}

// decodeJSON fills a document field from a TEXT column. An empty column is left
// as the zero value.
func decodeJSON(raw string, target any) error {
	if raw == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(raw), target); err != nil {
		return fmt.Errorf("storage: decode audit document: %w", err)
	}
	return nil
}

// planPathTransition validates one state change against a value copy of a stored
// path and returns the updated document together with the event that must be
// written in the same transaction.
//
// It is pure: both backends run it and then persist the pair atomically, which is
// what keeps the state machine and the log from disagreeing.
func planPathTransition(current path.Path, req path.TransitionRequest, now string) (path.Path, path.Event, error) {
	if req.ExpectedVersion > 0 && current.Version != req.ExpectedVersion {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: path %s is at version %d, expected %d",
			path.ErrConflict, current.ID, current.Version, req.ExpectedVersion)
	}
	if err := path.ValidateTransition(current.Status, req.To); err != nil {
		return path.Path{}, path.Event{}, err
	}
	// An empty owner means "the store itself" (a scheduler or an operator). Only a
	// named worker has to prove it holds the lease.
	if current.LeaseOwner != "" && req.Owner != "" && current.LeaseOwner != req.Owner {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: path %s is leased by %s", path.ErrLeaseHeld, current.ID, current.LeaseOwner)
	}

	from := current.Status
	updated := current
	updated.Status = req.To
	switch {
	case req.ClearLease:
		// Releasing a path clears the heartbeat too: a stale heartbeat on a queued
		// path reads as an active lease.
		updated.LeaseOwner = ""
		updated.LeaseUntil = ""
		updated.HeartbeatAt = ""
	case req.SetLeaseOwner != "":
		updated.LeaseOwner = req.SetLeaseOwner
		updated.LeaseUntil = req.SetLeaseUntil
		updated.HeartbeatAt = now
	}
	if req.Score != nil {
		updated.Score = *req.Score
	}
	if req.Features != nil {
		updated.Features = *req.Features
	}
	if req.IncrementAttempts {
		updated.Attempts++
	}
	if req.LastError != "" {
		updated.LastError = req.LastError
	}
	updated.Version = current.Version + 1
	updated.UpdatedAt = now

	eventType := req.EventType
	if eventType == "" {
		eventType = path.EventPathStatusChange
	}
	return updated, path.Event{
		AuditID: current.AuditID, PathID: current.ID, Type: eventType, From: from, To: req.To,
		Actor: req.Actor, Reason: req.Reason, Detail: req.Detail, CreatedAt: updated.UpdatedAt,
	}, nil
}

// planLeaseRenewal extends a lease the owner still holds. It is not a transition:
// the status does not change, so it does not go through the state machine.
func planLeaseRenewal(current path.Path, owner, until, actor, now string) (path.Path, path.Event, error) {
	if owner == "" {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: a lease needs an owner", path.ErrInvalidArgument)
	}
	if until == "" {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: a lease needs an expiry", path.ErrInvalidArgument)
	}
	if current.LeaseOwner == "" {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: path %s holds no lease", path.ErrLeaseExpired, current.ID)
	}
	if current.LeaseOwner != owner {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: path %s is leased by %s", path.ErrLeaseHeld, current.ID, current.LeaseOwner)
	}
	// Lease timestamps are RFC3339 strings, and they are compared as strings: that
	// is the documented contract, and it is a time comparison for as long as every
	// writer formats them the same way (path.NowString).
	if current.LeaseUntil != "" && current.LeaseUntil < now {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: the lease of path %s expired at %s", path.ErrLeaseExpired, current.ID, current.LeaseUntil)
	}
	if actor == "" {
		actor = owner
	}
	updated := current
	updated.LeaseUntil = until
	updated.HeartbeatAt = now
	updated.UpdatedAt = now
	updated.Version = current.Version + 1
	return updated, path.Event{
		AuditID: current.AuditID, PathID: current.ID, Type: path.EventPathHeartbeat,
		From: current.Status, To: current.Status, Actor: actor, Reason: "lease extended", CreatedAt: now,
	}, nil
}

// planClaim leases a claimable path to an owner and moves it to ANALYZING.
func planClaim(current path.Path, owner, until string, from []path.Status, actor, now string) (path.Path, path.Event, error) {
	if owner == "" {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: a lease needs an owner", path.ErrInvalidArgument)
	}
	if until == "" {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: a lease needs an expiry", path.ErrInvalidArgument)
	}
	if !containsStatus(from, current.Status) {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: path %s is %s", path.ErrNotClaimable, current.ID, current.Status)
	}
	if actor == "" {
		actor = owner
	}
	return planPathTransition(current, path.TransitionRequest{
		PathID: current.ID, To: path.StatusAnalyzing, ExpectedVersion: current.Version,
		Owner: owner, SetLeaseOwner: owner, SetLeaseUntil: until, Actor: actor,
		EventType: path.EventPathClaimed, Reason: "leased to " + owner,
	}, now)
}

// planRelease returns a leased path to the queue. Releasing a path nobody holds
// is not an error: the caller asked for it to be queued, and it is.
func planRelease(current path.Path, owner, actor, reason, now string) (path.Path, path.Event, error) {
	if current.LeaseOwner != "" && current.LeaseOwner != owner {
		return path.Path{}, path.Event{}, fmt.Errorf("%w: path %s is leased by %s", path.ErrLeaseHeld, current.ID, current.LeaseOwner)
	}
	if actor == "" {
		actor = owner
	}
	return planPathTransition(current, path.TransitionRequest{
		PathID: current.ID, To: path.StatusQueued, ExpectedVersion: current.Version,
		Owner: owner, ClearLease: true, Actor: actor, EventType: path.EventPathReleased, Reason: reason,
	}, now)
}

// planReclaim recovers one path whose lease expired.
func planReclaim(current path.Path, actor, now string) (path.Path, path.Event, error) {
	return planPathTransition(current, path.TransitionRequest{
		PathID: current.ID, To: path.StatusQueued, ExpectedVersion: current.Version,
		ClearLease: true, Actor: actor, EventType: path.EventPathLeaseExpired,
		Reason: "the lease expired and the path returned to the queue",
	}, now)
}

// leaseExpired reports whether a path holds a lease that ran out at `now`. Both
// values are RFC3339 strings, so the comparison is a string comparison by design.
func leaseExpired(p path.Path, now string) bool {
	return p.LeaseOwner != "" && p.LeaseUntil != "" && p.LeaseUntil < now
}

// containsStatus reports whether a status is one of the accepted sources.
func containsStatus(list []path.Status, want path.Status) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// containsPathStatus reports whether a path status is one of the accepted values.
func containsPathStatus(list []path.PathStatus, want path.PathStatus) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// matchesPathQuery applies the filters of a PathQuery to one document. Only the
// filters a backend cannot push into SQL need it, but both backends share the
// predicate so the results cannot drift.
func matchesPathQuery(p path.Path, q path.PathQuery) bool {
	if q.AuditID != "" && p.AuditID != q.AuditID {
		return false
	}
	if q.SnapshotID != "" && p.SnapshotID != q.SnapshotID {
		return false
	}
	if len(q.Status) > 0 && !containsStatus(q.Status, p.Status) {
		return false
	}
	if len(q.PathStatus) > 0 && !containsPathStatus(q.PathStatus, p.PathStatus) {
		return false
	}
	if q.EntryNodeID != "" && p.EntryNodeID != q.EntryNodeID {
		return false
	}
	if q.TargetNodeID != "" && p.TargetNodeID != q.TargetNodeID {
		return false
	}
	// MinPriority of 0 means "no floor": a priority of 0 is a legitimate score.
	if q.MinPriority > 0 && p.Score.Priority < q.MinPriority {
		return false
	}
	return true
}

// sortPathDocuments applies the documented listing order: priority (the queue
// order) is the default, "created" keeps generation order and "path_id" makes the
// listing stable for a diff.
func sortPathDocuments(paths []path.Path, order string) {
	sort.SliceStable(paths, func(i, j int) bool {
		switch order {
		case "path_id":
			return paths[i].ID < paths[j].ID
		case "created":
			if paths[i].CreatedAt != paths[j].CreatedAt {
				return paths[i].CreatedAt < paths[j].CreatedAt
			}
			return paths[i].ID < paths[j].ID
		default: // "priority"
			if paths[i].Score.Priority != paths[j].Score.Priority {
				return paths[i].Score.Priority > paths[j].Score.Priority
			}
			return paths[i].ID < paths[j].ID
		}
	})
}
