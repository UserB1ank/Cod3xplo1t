package path

import (
	"hash/fnv"
	"math"
	"time"
)

// Backoff is the retry policy of a failed attempt.
//
// It exists because "retry until it works" is how a scheduler turns one broken path
// into a busy loop. The schedule is exponential with a cap and a deterministic
// jitter derived from the path id: two workers computing the next attempt for the
// same path agree, while different paths do not line up into a thundering herd.
type Backoff struct {
	// Base is the delay after the first failure.
	Base time.Duration
	// Factor multiplies the delay per attempt. Values below 1 are clamped to 1, so a
	// misconfiguration cannot make retries more frequent than the base.
	Factor float64
	// Max caps the delay; zero means no cap beyond the base growth.
	Max time.Duration
	// Jitter is the fraction of the delay that may be shaved off or added, in
	// [0, 1). Deterministic per path, so a replay of the scheduler makes the same
	// decision.
	Jitter float64
}

// DefaultBackoff returns the documented starting policy: one second, doubling, at
// most five minutes, with 20% jitter.
func DefaultBackoff() Backoff {
	return Backoff{Base: time.Second, Factor: 2, Max: 5 * time.Minute, Jitter: 0.2}
}

// Normalize fills unset fields with the defaults and clamps nonsense.
func (b Backoff) Normalize() Backoff {
	d := DefaultBackoff()
	if b.Base <= 0 {
		b.Base = d.Base
	}
	if b.Factor < 1 {
		// The comment above is the contract: a factor below one would mean retrying
		// faster after each failure, so it becomes a constant delay (1), not the
		// default (2) — the caller's intent is honoured as far as it is sane.
		b.Factor = 1
	}
	if b.Max <= 0 {
		b.Max = d.Max
	}
	if b.Jitter < 0 {
		b.Jitter = 0
	}
	if b.Jitter >= 1 {
		b.Jitter = 0.5
	}
	return b
}

// Delay is how long to wait after a failure on the given attempt (1-based: the
// attempt that just failed).
func (b Backoff) Delay(attempt int, pathID string) time.Duration {
	policy := b.Normalize()
	if attempt < 1 {
		attempt = 1
	}
	// Cap the exponent before converting: 2^40 seconds overflows any duration, and a
	// path with 40 failed attempts is not going to be fixed by a longer wait.
	if attempt > 16 {
		attempt = 16
	}
	delay := float64(policy.Base) * math.Pow(policy.Factor, float64(attempt-1))
	if policy.Max > 0 && delay > float64(policy.Max) {
		delay = float64(policy.Max)
	}
	if policy.Jitter > 0 {
		// Deterministic per (path, attempt): same input, same delay.
		offset := jitterFraction(pathID, attempt) * policy.Jitter
		delay *= 1 + offset
	}
	if delay > float64(math.MaxInt64-1) {
		// `>` alone is not enough: at exactly MaxInt64 the conversion below is out of
		// int64 range, and a duration that wraps negative would schedule a retry in the
		// past. Only reachable with an absurd cap, which is precisely when a silent
		// wrap is hardest to diagnose.
		delay = float64(math.MaxInt64 - 1)
	}
	return time.Duration(delay)
}

// NextAttemptAt is when a path that just failed may run again.
func (b Backoff) NextAttemptAt(attempt int, pathID string, now time.Time) time.Time {
	return now.Add(b.Delay(attempt, pathID))
}

// jitterFraction returns a stable value in [-1, 1) for a path and attempt.
func jitterFraction(pathID string, attempt int) float64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(pathID))
	_, _ = h.Write([]byte{byte(attempt), byte(attempt >> 8), byte(attempt >> 16), byte(attempt >> 24)})
	return float64(h.Sum64()%2000)/1000 - 1
}

// Retryable reports whether an attempt may be retried at all.
//
// A cancelled path is not retried: an operator cancelled it. A failed adapter may
// be retried until the attempt ceiling is reached, which is what the ceiling is for.
func Retryable(status Status, attempts, maxAttempts int) bool {
	if maxAttempts <= 0 {
		maxAttempts = DefaultLimits().MaxAttempts
	}
	if attempts >= maxAttempts {
		return false
	}
	switch status {
	case StatusFailed, StatusInterrupted, StatusBlocked:
		return true
	default:
		return false
	}
}
