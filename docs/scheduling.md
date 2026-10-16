# Scheduling, retries and fault recovery (P7)

P7 makes the queue run itself. Until now a path was claimed by whoever asked and a
failed attempt simply returned to the queue; now a resident scheduler picks due work,
dispatches it under a concurrency budget, defers failures with a durable backoff, and
recovers the work of a worker that died.

Design references: `codexploit_design.md` §7 (state machine) and §9 (storage and
caching); `codexploit_implementation_guide.md` §11 (scheduling, state machine and
fault recovery) and §12 (cost control). This document describes the implemented
behaviour.

## The loop

```text
Tick:
  reclaim expired leases          (a worker that died holds nothing)
  for each configured audit:
      list due QUEUED paths        (status QUEUED and next_attempt_at elapsed)
      while free budget:
          claim the path           (the claim *is* the dispatch right)
          dispatch it              (run the path; one goroutine per path)
  wait for the dispatches it started
  record the pass in the metrics
```

`Run` repeats `Tick` every interval until the context is cancelled, then releases the
leases it still holds. `TickScoped` serves one audit; `Tick` serves all configured
ones. `TickResult{Held, Dispatched, Reclaimed, Skipped, Failed, Due}` is an accurate
summary because the pass waits for the work it started, which also makes
`MaxConcurrent` exact in-process.

## Leases are the concurrency primitive

The scheduler claims a path **before** dispatching it, and `Runner.RunPath` executes
exactly that path. Two properties fall out of this:

- the scheduler never dispatches a path it does not hold a lease on, so it can never
  disturb a worker that owns one;
- two schedulers — or two ticks of one scheduler — cannot dispatch the same path,
  because `Store.ClaimPath` is the cross-process atomic guard. The in-process
  in-flight set only makes the budget exact; it is not the safety mechanism.

A claim by the current holder is treated as a lease renewal, which is what lets the
scheduler hold the dispatch right and the runner settle the path without a gap in
between.

## Retries are bounded, durable and jittered

A failed dispatch is deferred, not retried immediately:

| Concept | Behaviour |
|---|---|
| due time | `next_attempt_at` on the path, so a crash loses nothing and the scheduler never sleeps while holding a lease |
| policy | exponential: base (1s), factor (2), cap (5m), jitter (20%) |
| jitter | deterministic per `(path_id, attempt)`, so two schedulers agree and different paths do not line up into a thundering herd |
| ceiling | the path's own `max_attempts` (default 3); at the ceiling the path is taken out as `FAILED` |
| cancelled paths | never retried — an operator cancelled them, and retrying would overrule that |
| attempts | incremented exactly once per failed dispatch |

`path.Retryable(status, attempts, maxAttempts)` decides, and `Backoff.Normalize`
clamps a factor below one to a constant delay rather than silently substituting the
default: a caller who asks for "at least as slow each time" gets exactly that.

The state machine is why a failed path is deferred and then re-queued rather than
retried in place: `ANALYZING → FAILED` records the failure with its due time, and
`FAILED → QUEUED` returns it to the queue with the deferral intact. `FAILED` on its
own is never due.

## Crash recovery

A worker that dies stops heartbeating; its lease expires; the next `Tick` reclaims it
(`ReclaimExpired`) and the path becomes claimable again with a recovery event in the
audit log. Nothing depends on the dead worker's cooperation, and no state lives only
in a process. The case is pinned by tests named for it in `internal/schedule`,
`internal/api` and, for the lease half, in `internal/storage`.

## Metrics

`GET /api/scheduler` exposes a stable JSON snapshot: dispatched / succeeded / failed /
retried / reclaimed totals, current active leases, queue depth, the age of the oldest
queued path, the last tick time and its duration, plus the effective configuration and
whether the loop is running. These are the design's §14 metrics that this layer owns.

`codexploit scheduler status` in a one-shot CLI process cannot read a running
server's in-process counters; it reports the configuration, whether the loop is
running in this process, and a durable queue view. The server endpoint is the metrics
source for a live scheduler.

## Surfaces

| Surface | Purpose |
|---|---|
| `GET /api/scheduler` | metrics snapshot, effective configuration, running state |
| `POST /api/scheduler/tick` | one pass (`withIdempotency`, write capability) |
| `POST /api/scheduler/reclaim` | manual sweep of expired leases |
| `codexploit scheduler status` | configuration, running state, queue view |
| `codexploit scheduler tick [--audits a,b] [--concurrency N]` | one pass from the CLI |
| `codexploit scheduler reclaim [--limit N]` | manual sweep |
| `codexploit scheduler run [--interval N]` | foreground loop; Ctrl-C stops it and releases the leases it holds |

Server flags: `--scheduler`, `--scheduler-audit` (repeatable; empty means every audit
with queued work), `--scheduler-interval`, `--scheduler-concurrency`,
`--scheduler-lease-ttl`, `--scheduler-owner`,
`--scheduler-backoff-base/-factor/-max/-jitter`. A misconfiguration fails startup; a
disabled scheduler logs an explicit line, because "no work is being scheduled" is a
state an operator must be able to see.

## What P7 does not do

- **No incremental analysis.** The design's productisation phase (change-impact
  analysis, cross-commit cache reuse, benchmark comparison) is not implemented; every
  snapshot is still analysed in full. Recorded in `docs/known-issues.md`.
- **No score calibration.** Priorities remain the documents' initial heuristics.
- **No distributed queue.** Leases make concurrent schedulers *safe*, not
  *coordinated*: there is no leader election, no sharding by region and no
  work-stealing. More than a few schedulers would spend their time contending on the
  same audit's queue.
- **No WebUI.** The metrics endpoint and the existing read APIs are what a UI would
  consume.
