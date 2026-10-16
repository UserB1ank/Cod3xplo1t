package path

import (
	"testing"
	"time"
)

// TestBackoffGrowsMonotonicallyToItsCap pins the exponential shape: every attempt
// waits at least as long as the previous one, the growth is the documented
// doubling, and the cap is a ceiling that further attempts cannot pass.
func TestBackoffGrowsMonotonicallyToItsCap(t *testing.T) {
	t.Parallel()
	// Jitter is left at zero: the jittered schedule is bounded, not monotone (a
	// capped delay may be jittered down while the previous one was jittered up).
	policy := Backoff{Base: time.Second, Factor: 2, Max: 5 * time.Minute}

	if got := policy.Delay(1, "path-0001"); got != time.Second {
		t.Errorf("Delay(1) = %v, want the base %v", got, time.Second)
	}
	if got := policy.Delay(5, "path-0001"); got != 16*time.Second {
		t.Errorf("Delay(5) = %v, want 16s (the base doubled four times)", got)
	}
	// An attempt below 1 is the first attempt, not a negative exponent.
	if got := policy.Delay(0, "path-0001"); got != policy.Delay(1, "path-0001") {
		t.Errorf("Delay(0) = %v, want the first attempt's %v", got, policy.Delay(1, "path-0001"))
	}

	previous := time.Duration(0)
	for attempt := 1; attempt <= 12; attempt++ {
		delay := policy.Delay(attempt, "path-0001")
		if delay < previous {
			t.Fatalf("Delay(%d) = %v, want at least the previous %v", attempt, delay, previous)
		}
		if delay > policy.Max {
			t.Fatalf("Delay(%d) = %v, above the cap %v", attempt, delay, policy.Max)
		}
		previous = delay
	}
	if got := policy.Delay(9, "path-0001"); got != 256*time.Second {
		t.Errorf("Delay(9) = %v, want 256s, the last step below the cap", got)
	}
	for _, attempt := range []int{10, 11, 12, 16, 17, 1000} {
		if got := policy.Delay(attempt, "path-0001"); got != policy.Max {
			t.Errorf("Delay(%d) = %v, want the cap %v", attempt, got, policy.Max)
		}
	}
}

// TestBackoffClampsADegenerateFactor pins that a factor below 1 cannot make
// retries more frequent than the base: Normalize replaces it with the policy
// default, so the delay never shrinks and never falls below Base.
func TestBackoffClampsADegenerateFactor(t *testing.T) {
	t.Parallel()
	policy := Backoff{Base: time.Second, Factor: 0.5, Max: time.Hour}
	if normalized := policy.Normalize(); normalized.Factor < 1 {
		t.Errorf("Normalize().Factor = %v, want at least 1 so a retry is never sooner than the base", normalized.Factor)
	}

	previous := time.Duration(0)
	for attempt := 1; attempt <= 6; attempt++ {
		delay := policy.Delay(attempt, "path-0001")
		if delay < policy.Base {
			t.Fatalf("Delay(%d) = %v, below the base %v", attempt, delay, policy.Base)
		}
		if delay < previous {
			t.Fatalf("Delay(%d) = %v, shorter than the previous %v", attempt, delay, previous)
		}
		previous = delay
	}
}

// TestBackoffJitterIsDeterministicAndBounded pins the two properties the
// scheduler relies on: the same (path, attempt) always yields the same delay, so
// a replay makes the same decision, and the delay stays inside the declared
// fraction of the un-jittered one, so a thundering herd cannot be created and the
// policy cannot be stretched past its bounds.
func TestBackoffJitterIsDeterministicAndBounded(t *testing.T) {
	t.Parallel()
	policy := DefaultBackoff()
	if policy.Jitter <= 0 {
		t.Fatalf("DefaultBackoff().Jitter = %v, want a positive fraction", policy.Jitter)
	}
	// The same policy with jitter switched off is the reference delay.
	plain := Backoff{Base: policy.Base, Factor: policy.Factor, Max: policy.Max}

	differed := false
	for _, pathID := range []string{"path-0001", "path-0002", "path-0003", "path-abcdef"} {
		for attempt := 1; attempt <= 6; attempt++ {
			first := policy.Delay(attempt, pathID)
			if second := policy.Delay(attempt, pathID); second != first {
				t.Fatalf("Delay(%d, %s) is not deterministic: %v then %v", attempt, pathID, first, second)
			}
			base := plain.Delay(attempt, pathID)
			if first != base {
				differed = true
			}
			// jitterFraction is in [-1, 1), so the offset is in [-Jitter, Jitter).
			// One nanosecond of slack absorbs the float-to-Duration truncation.
			low := time.Duration(float64(base) * (1 - policy.Jitter))
			high := time.Duration(float64(base)*(1+policy.Jitter)) + time.Nanosecond
			if first < low || first > high {
				t.Errorf("Delay(%d, %s) = %v, want within [%v, %v]", attempt, pathID, first, low, high)
			}
			if first < 0 {
				t.Errorf("Delay(%d, %s) = %v, want a positive delay", attempt, pathID, first)
			}
		}
	}
	if !differed {
		t.Error("jitter never changed a delay, so it is not applied")
	}
}

// TestBackoffDoesNotOverflowPastTheAttemptCeiling pins the exponent clamp: an
// absurd attempt count must not wrap the duration, and every attempt past the
// ceiling waits exactly as long as the ceiling.
func TestBackoffDoesNotOverflowPastTheAttemptCeiling(t *testing.T) {
	t.Parallel()
	// 1ms doubled fifteen times is 32.768s, still below the one-hour cap, so the
	// clamp itself is visible instead of being hidden by the cap.
	policy := Backoff{Base: time.Millisecond, Factor: 2, Max: time.Hour}
	ceiling := policy.Delay(16, "path-0001")
	if ceiling != 32768*time.Millisecond {
		t.Fatalf("Delay(16) = %v, want 32.768s", ceiling)
	}
	for _, attempt := range []int{17, 18, 32, 64, 1000, 1 << 20} {
		if got := policy.Delay(attempt, "path-0001"); got != ceiling {
			t.Errorf("Delay(%d) = %v, want the ceiling's %v", attempt, got, ceiling)
		}
	}

	// The documented default policy caps long before the exponent matters, and it
	// stays positive for any attempt count.
	fallback := DefaultBackoff()
	for _, attempt := range []int{17, 100, 1 << 20} {
		if got := fallback.Delay(attempt, "path-0001"); got <= 0 || got > fallback.Max {
			t.Errorf("DefaultBackoff().Delay(%d) = %v, want a positive delay at most %v", attempt, got, fallback.Max)
		}
	}
}

// TestNextAttemptAtIsNowPlusTheDelay pins the helper the scheduler uses to write
// the durable due time.
func TestNextAttemptAtIsNowPlusTheDelay(t *testing.T) {
	t.Parallel()
	now := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)
	policy := DefaultBackoff()
	for attempt := 1; attempt <= 4; attempt++ {
		want := now.Add(policy.Delay(attempt, "path-0001"))
		if got := policy.NextAttemptAt(attempt, "path-0001", now); !got.Equal(want) {
			t.Errorf("NextAttemptAt(%d) = %v, want %v", attempt, got, want)
		}
	}
}

// TestRetryableStopsAtTheAttemptCeilingAndOnlyForRetryableStates pins which
// statuses may be retried and where the ceiling stops them.
func TestRetryableStopsAtTheAttemptCeilingAndOnlyForRetryableStates(t *testing.T) {
	t.Parallel()

	retryable := []Status{StatusFailed, StatusInterrupted, StatusBlocked}
	for _, status := range retryable {
		if !Retryable(status, 0, 3) {
			t.Errorf("Retryable(%s, 0, 3) = false, want true", status)
		}
		if !Retryable(status, 2, 3) {
			t.Errorf("Retryable(%s, 2, 3) = false, want true below the ceiling", status)
		}
		if Retryable(status, 3, 3) {
			t.Errorf("Retryable(%s, 3, 3) = true, want false at the ceiling", status)
		}
		if Retryable(status, 4, 3) {
			t.Errorf("Retryable(%s, 4, 3) = true, want false above the ceiling", status)
		}
	}

	// A terminal path is a verdict, a cancelled one is an operator decision, and an
	// active one is already being worked on: none of them is retried.
	notRetryable := []Status{
		StatusCancelled, StatusConcluded,
		StatusAnalyzing, StatusLocalExploring, StatusVerifying,
		StatusPaused, StatusQueued, StatusHypothesisFormed, StatusDiscovered,
	}
	for _, status := range notRetryable {
		if Retryable(status, 0, 3) {
			t.Errorf("Retryable(%s, 0, 3) = true, want false", status)
		}
	}

	// A missing ceiling falls back to the documented default instead of meaning
	// "unlimited".
	max := DefaultLimits().MaxAttempts
	if !Retryable(StatusFailed, max-1, 0) {
		t.Errorf("Retryable(FAILED, %d, 0) = false, want true below the default ceiling", max-1)
	}
	if Retryable(StatusFailed, max, 0) {
		t.Errorf("Retryable(FAILED, %d, 0) = true, want false at the default ceiling", max)
	}
}
