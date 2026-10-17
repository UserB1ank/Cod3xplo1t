package path

import (
	"errors"
	"fmt"
	"sort"
)

// Errors the store and the service agree on. The audit lifecycle has failure
// modes that callers must be able to tell apart: "you lost the race" is not "the
// path is gone", and "the lease expired" is not "someone else owns it".
var (
	ErrNotFound          = errors.New("path: not found")
	ErrConflict          = errors.New("path: version conflict")
	ErrInvalidTransition = errors.New("path: invalid transition")
	ErrInvalidArgument   = errors.New("path: invalid argument")
	ErrLeaseHeld         = errors.New("path: lease is held by another owner")
	ErrLeaseExpired      = errors.New("path: lease has expired")
	ErrNotClaimable      = errors.New("path: not claimable in its current status")
	ErrBudgetExceeded    = errors.New("path: budget exceeded")
	ErrNoASG             = errors.New("path: snapshot has no attack surface")
	ErrTaskActive        = errors.New("path: pause scheduling and finish active paths or runs before archiving")
	ErrTaskArchived      = errors.New("path: restore the archived task before resuming scheduling")
)

// transitions is the audit state machine of the design (§7) and the
// implementation guide (§11). It is data, and it is the only place where a status
// change is legal.
//
// Two properties matter for scheduling:
//   - a path only becomes claimable through QUEUED, so a lease can never be taken
//     on a path a human paused or a verdict concluded;
//   - BLOCKED, PAUSED, INTERRUPTED and FAILED all return to QUEUED, which is what
//     makes recovery from a crashed worker possible without inventing states.
var transitions = map[Status][]Status{
	StatusDiscovered:     {StatusQueued, StatusCancelled},
	StatusQueued:         {StatusAnalyzing, StatusPaused, StatusCancelled},
	StatusAnalyzing:      {StatusLocalExploring, StatusHypothesisFormed, StatusConcluded, StatusBlocked, StatusFailed, StatusPaused, StatusInterrupted, StatusCancelled, StatusQueued},
	StatusLocalExploring: {StatusAnalyzing, StatusHypothesisFormed, StatusBlocked, StatusFailed, StatusPaused, StatusInterrupted, StatusCancelled},
	// QUEUED is a legal target from HYPOTHESIS_FORMED: a claim whose verification
	// never started (a crash, a cancelled verification task, a workspace rebuilt
	// from scratch) must be re-analysable instead of sticking forever.
	StatusHypothesisFormed: {StatusVerifying, StatusAnalyzing, StatusQueued, StatusConcluded, StatusBlocked, StatusFailed, StatusPaused, StatusCancelled},
	StatusVerifying:        {StatusConcluded, StatusBlocked, StatusFailed, StatusPaused, StatusInterrupted, StatusCancelled},
	StatusBlocked:          {StatusQueued, StatusFailed, StatusCancelled},
	StatusPaused:           {StatusQueued, StatusCancelled},
	StatusInterrupted:      {StatusQueued, StatusFailed, StatusCancelled},
	StatusFailed:           {StatusQueued, StatusCancelled},
	StatusConcluded:        {},
	StatusCancelled:        {},
}

// NextStatuses returns the statuses reachable from a status, sorted, so an error
// message can tell a caller what would have been legal.
func NextStatuses(from Status) []Status {
	out := append([]Status(nil), transitions[from]...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CanTransition reports whether the state machine allows a change.
func CanTransition(from, to Status) bool {
	for _, allowed := range transitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// ValidateTransition returns an error describing an illegal change, including the
// legal alternatives: a scheduler that silently drops a transition is a scheduler
// whose state cannot be trusted.
func ValidateTransition(from, to Status) error {
	if !ValidStatus(from) {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidTransition, from)
	}
	if !ValidStatus(to) {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidTransition, to)
	}
	if from == to {
		// Re-entering the same status is not a transition; callers that mean
		// "renew the lease" must say so instead.
		return fmt.Errorf("%w: %s -> %s is not a change", ErrInvalidTransition, from, to)
	}
	if !CanTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s is not allowed; from %s the legal targets are %v",
			ErrInvalidTransition, from, to, from, NextStatuses(from))
	}
	return nil
}
