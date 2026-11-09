# Durable review batches

A review batch is an operator-requested, fixed set of queued paths from one
audit. It runs through the normal Agent runner, so path leases, `agent_runs`,
hypotheses, cancellation and evidence remain authoritative in their existing
stores.

## Lifecycle and leases

Batch records persist `execution_owner`, a monotonic `lease_epoch`,
`heartbeat_at` and `lease_until`. Only the coordinator holding the current
owner/epoch can renew the lease, finalize a batch or submit a late terminal
state. A second application instance reclaims an expired `RUNNING` or
`CANCELLING` batch without restarting; the previous owner is fenced by the new
epoch.

Pause blocks new path work at the next boundary and clears the coordinator lease.
Resume performs a new epoch-bearing claim. Cancel moves the batch to
`CANCELLING`, stops queued work and lets the current owner settle active path
runs before the terminal `CANCELLED` state. A coordinator that stops while
cancelling can be reclaimed by another healthy instance.

`Manager.Start` and `Manager.Resume` call `Agent.Ready()` before creating or
continuing active work. If the configured runtime is unavailable, no active
batch is created.

## HTTP and ETags

```
POST /api/v1/projects/{projectID}/review-batches
GET  /api/v1/projects/{projectID}/review-batches
GET  /api/v1/projects/{projectID}/review-batches/{batchID}
POST /api/v1/projects/{projectID}/review-batches/{batchID}/pause
POST /api/v1/projects/{projectID}/review-batches/{batchID}/resume
POST /api/v1/projects/{projectID}/review-batches/{batchID}/cancel
```

Single-batch reads and the start response return an `ETag`. `pause`, `resume`
and `cancel` require `If-Match`; missing preconditions return 428 and stale
versions return 412. Repeatable identity and response replay remains available
through the normal `Idempotency-Key` middleware.

## Progress

Batch state and path progress are separate. `progress.blocked`,
`progress.paused`, `progress.failed` and `progress.cancelled` are reported
independently, so a blocked verification is not shown as an execution failure.
The public schema is `contracts/v1/review-batch.schema.json`.
