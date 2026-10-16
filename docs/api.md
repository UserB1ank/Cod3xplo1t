# Codexploit REST API

The API exposes the P1 snapshot chain and the P2 Source Code Graph. Every
endpoint is read-only except project creation, snapshot creation and graph
building; every error body is `{"error": "...", "code": "..."}`.

The implementation guide writes these endpoints in shorthand (`GET
/symbols/{id}/callers`, `POST /graph/paths`). Here every graph path is nested
under its snapshot (`/api/snapshots/{id}/symbols/{symbolID}/callers`), because
design §8 requires every query to carry a snapshot id — a global symbol id would
make that requirement easy to forget and impossible to enforce.

## Authentication

Every API route is classified in one capability table; there is no route that is
protected by accident.

| Capability | Allows |
|---|---|
| `reader` | all `GET` endpoints, plus `POST /graph/paths` and `POST /graph/slice` (query-shaped, they only take a body) |
| `writer` | everything a reader may do, plus `POST /api/projects`, `POST /api/projects/{id}/snapshots`, `POST /api/snapshots/{id}/graph` |
| `admin` | everything a writer may do, plus `PATCH /api/projects/{id}` and `DELETE /api/snapshots/{id}` |

Configure tokens with `--api-token name:role:secret` (repeatable) or the
`CODEXPLOIT_API_TOKENS` environment variable (semicolon separated). A secret may
be given pre-hashed as `sha256:<hex digest>` so a deployment file holds no usable
credential; plaintext secrets must be at least 16 characters. The first two `:`
separate the fields, so a secret may itself contain `:`.

```bash
bin/server --api-token ci:writer:$(openssl rand -hex 16) --api-token ops:admin:sha256:<hex>
```

Clients present the secret as `Authorization: Bearer <secret>` (or `X-API-Key`).
A missing or wrong secret returns `401` with a `WWW-Authenticate: Bearer`
challenge; a valid token without the required capability returns `403`. Secrets
are compared as SHA-256 digests with a constant-time comparison and are never
logged; write operations log the token *name*.

Two deliberate exceptions:

- `GET /healthz` needs no credential and returns only liveness.
- With `--insecure-anonymous` (local development) anonymous callers receive
  `writer`, never `admin`: destructive operations still require a token. Without
  tokens and without that flag the server refuses to start, and a `Server`
  constructed without an authenticator answers `401` to every API request.

An unknown path is a `404` for an authenticated caller, never a capability
question, so the table cannot be used to enumerate routes.

## Status codes

Status codes used across the API:

| Code | Meaning |
|---|---|
| `400` | malformed request, unknown flag value, missing required argument |
| `401` | missing or invalid API token (`WWW-Authenticate: Bearer`) |
| `403` | valid token without the required capability, or a remote source used while network access is disabled |
| `404` | unknown project, snapshot, symbol — or a snapshot without a graph or an attack surface |
| `405` | wrong method for an existing path |
| `409` | conflicting immutable write, source changed mid-snapshot, snapshot tree unavailable, `idempotency_in_progress`, `idempotency_key_reuse`, `scg_missing` |
| `412` | `If-Match` did not match the current `ETag` |
| `428` | a mutation that requires `If-Match` (`PATCH /api/projects/{id}`, `POST /api/paths/{id}/pause`, `/resume`, `/cancel`) without the header |
| `413` | request body larger than 1 MiB |
| `422` | snapshot limit exceeded |
| `501` | the server was started without the graph, attack-surface or audit service (`graph_unavailable`, `asg_unavailable`, `audit_unavailable`) |
| `503` | query exceeded its time budget |

## Idempotency and optimistic concurrency

`Idempotency-Key` on any `POST` makes retries safe, and the claim is stored in
the database, so it survives a restart, a crash or a load-balancer hop to another
process:

- the key, a fingerprint of the request body and the authenticated caller are all
  part of the claim;
- a repeat of the same request replays the stored status and body with
  `Idempotent-Replay: true`;
- the same key with a different body, or from a different token, is refused with
  `409 idempotency_key_reuse` instead of being answered with someone else's
  response;
- a key whose request is still running answers `409 idempotency_in_progress`
  with `Retry-After`;
- a `5xx` response releases the claim, so a client may retry the same key;
- claims expire (`--idempotency-ttl`, default 24h) and expired rows are purged on
  the write path.

Writes to mutable state are optimistic: `GET /api/projects/{id}` returns an
`ETag`, and `PATCH /api/projects/{id}` requires `If-Match` (`428` when the header
is missing, `412` when the ETag is stale). The `ETag` changes whenever the
project does.

## Projects and snapshots

### `POST /api/projects`

```json
{"source": "/path/to/repo", "name": "optional display name"}
```

Creates a project, or returns the existing one for the same repository identity
(`200` with `"existing": true`). The id is derived from the normalised identity,
so the same repository always maps to the same project.

### `GET /api/projects`, `GET /api/projects/{id}`

List or read projects. `GET` by id returns an `ETag` for use with `PATCH`.

### `PATCH /api/projects/{id}`

```json
{"name": "new display name"}
```

Renames a project. Requires `If-Match` with the current `ETag` (capability
`admin`); the response carries the new `ETag`.

### `POST /api/projects/{id}/snapshots`

```json
{"ref": "v1.2.3", "skip_analysis": false, "build_graph": true, "build_asg": true}
```

Freezes the pinned revision, writes `repository_manifest.json`, and — with
`build_graph` — builds and stores the SCG. With `build_asg` it also derives and
stores the attack surface and adds its summary to the response as `"asg"`. The
response contains the snapshot summary, the manifest summary and the graph
summary.

`build_asg` needs an SCG from this request or an earlier one. Without one the
request fails with `409 scg_missing` instead of returning an empty attack surface.

A repeat for an unchanged revision returns `200` with `"existing": true` and the
same snapshot id: `snapshot_id = hash(repo_identity, commit, submodule_state)`.

### `GET /api/snapshots?project_id=`, `GET /api/snapshots/{id}`

List snapshot records or read one metadata summary.

### `DELETE /api/snapshots/{id}`

Removes the records, the graph and the frozen tree (unfreezing it first).

### `GET /api/snapshots/{id}/manifest`

The full repository manifest: languages, frameworks with evidence, dependencies
per manager, entrypoints, build descriptors, layout, coverage and unknowns.

## Source Code Graph

### `POST /api/snapshots/{id}/graph`

```json
{"force": false}
```

Builds the SCG (or returns the stored one for `force: false`), writes the graph
document next to the frozen tree as `scg-<graph-version>-<content-hash>.json` and
stores it for queries. `201` when built, `200` when reused.

### `GET /api/snapshots/{id}/graph`

Graph summary: counts, edges by kind, resolution mix, coverage and limitations.

### `GET /api/snapshots/{id}/modules`

Modules (build units) of the snapshot.

### `GET /api/snapshots/{id}/symbols`

Query parameters: `module_id`, `file_id`, `kind` (comma separated), `name`
(substring), `qualified_name` (exact), `limit`, `offset`. Qualified names contain
slashes and dots, so they are a query parameter rather than a path segment.

### `GET /api/snapshots/{id}/symbols/{symbolID}`

One symbol by id. The response carries the query `meta` block.

### `GET /api/snapshots/{id}/symbols/{symbolID}/callers`

### `GET /api/snapshots/{id}/symbols/{symbolID}/callees`

Bounded traversal over `CALLS` edges. Query parameters: `max_depth`,
`max_nodes`, `max_edges`, `limit`, `timeout_ms`.

The response contains the reached nodes with their distance, the edges that were
followed, and `unresolved_call_sites`: call sites inside the visited symbols that
have no edge. Those are the places where the graph is blind.

### `GET /api/snapshots/{id}/unresolved-calls`

Call sites with no resolved target. Query parameters: `caller_symbol_id`,
`limit`, `offset`.

### `POST /api/snapshots/{id}/graph/paths`

```json
{"source": "sym-...", "sink": "sym-...", "max_paths": 5}
```

Enumerates up to `max_paths` distinct simple routes along `CALLS` edges. A call
path is a reachability fact, not a dataflow fact; the response says so in its
limitations.

### `POST /api/snapshots/{id}/graph/slice`

```json
{"symbol_id": "sym-...", "include": "callers", "max_lines": 60}
```

Reads excerpts from the frozen tree. `include` is `declaration` (default),
`callers`, `calls` or `neighbors`. A `file` with `start_line`/`end_line` can be
used instead of `symbol_id`.

## Attack surface (ASG)

The attack surface is derived from the stored SCG. Every endpoint is scoped to a
snapshot, and every answer carries `limitations` and `coverage`: an
attack-surface answer without them reads as more complete than it is. `REACHES`
means call-graph reachability, not dataflow.

| Endpoint | Capability | Description |
|---|---|---|
| `POST /api/snapshots/{id}/asg` | `writer` | build (or reuse) the attack surface |
| `GET /api/snapshots/{id}/asg` | `reader` | stored summary |
| `GET /api/snapshots/{id}/asg/nodes` | `reader` | page of nodes |
| `GET /api/snapshots/{id}/asg/nodes/{nodeID}` | `reader` | one node with its edges and resolved evidence |
| `GET /api/snapshots/{id}/asg/entrypoints` | `reader` | route table with boundaries, controls and reachable sinks |
| `GET /api/snapshots/{id}/asg/edges` | `reader` | page of edges |

### `POST /api/snapshots/{id}/asg`

```json
{"force": false}
```

With `force: false` and a stored attack surface, returns `200 {"asg": <summary>,
"built": false}`. Otherwise it derives the ASG from the SCG, writes
`asg-<asg-version>-<content-hash>.json` next to the frozen tree and stores it,
returning `201 {"asg": <summary>, "built": true}`. The route accepts an
`Idempotency-Key`.

Status codes beyond the table above: `409 scg_missing` when the snapshot has no
SCG (build the graph first), `501 asg_unavailable` when the server was started
without the attack-surface service.

### `GET /api/snapshots/{id}/asg`

The stored summary: node and edge counts by kind, evidence counts, coverage,
limitations. A snapshot without an attack surface is `404 asg_missing`.

### `GET /api/snapshots/{id}/asg/nodes`

Query parameters: `kind` (comma-separated `EntryPoint`, `AttackerControlledInput`,
`TrustBoundary`, `SecurityControl`, `SensitiveOperation`, `Asset`, `Hypothesis`),
`subject` (exact), `generator`, `file`, `limit`, `offset`. An unknown `kind` is
`400`.

### `GET /api/snapshots/{id}/asg/nodes/{nodeID}`

One node with its `outgoing` and `incoming` edges and its `derived_from` entries:
the SCG symbols and call sites the node was read from, resolved for display.

### `GET /api/snapshots/{id}/asg/entrypoints`

Query parameters: `limit`, `offset`. Returns `entry_points` (entry point,
`boundary`, `controls`, `inputs`, `sinks`, `observed_controls`), plus the stored
summary's `limitations`, `coverage` and `evidence_counts`.

```json
{
  "entry_points": [
    {"entry_point": {"label": "GET /users/:id", "detail": {"framework": "gin"}},
     "boundary": {"subject": "boundary:network"},
     "controls": [{"subject": "control:authentication:AuthRequired"}],
     "sinks": [{"subject": "sink:sql_execution"}],
     "observed_controls": 1}
  ],
  "total": 1,
  "limitations": ["REACHES means call-graph reachability, not dataflow: ..."],
  "coverage": {"call_sites_examined": 20, "entry_points_truncated": 0},
  "evidence_counts": {"observed": 16, "inferred": 5}
}
```

### `GET /api/snapshots/{id}/asg/edges`

Query parameters: `kind` (comma-separated `REACHES`, `CROSSES`, `PROTECTED_BY`,
`MAY_AFFECT`, `DERIVED_FROM`, `SUPPORTED_BY`, `VERIFIED_BY`), `from`, `to`
(comma-separated node ids) and `limit`.

## Audits and paths (P4)

An audit turns the stored attack surface of one snapshot into ranked AuditPaths:
each path is an entry point, a target sensitive operation and the chain between
them, plus the evidence and the score that justify its position in the queue.
Every path carries `path_status`, `open_questions`, `limitations` and a score
stamped with `score_version`, so a ranking can be challenged without re-running
the analysis. Paths derived from `REACHES` are call-graph reachability, not
dataflow: they say a sensitive operation is reachable from an entry point, never
that attacker-controlled data reaches it.

`POST /api/audits` is the only route that does generation work; the lease and
lifecycle verbs change scheduling state, and everything else is a read.

| Endpoint | Capability | Description |
|---|---|---|
| `POST /api/audits` | `writer` | generate and rank the audit paths (accepts `Idempotency-Key`) |
| `GET /api/audits` | `reader` | list audits |
| `GET /api/audits/{id}` | `reader` | one audit |
| `GET /api/audits/{id}/paths` | `reader` | page of paths in queue order |
| `GET /api/audits/{id}/events` | `reader` | bounded page of the audit's event log |
| `GET /api/audits/{id}/next` | `reader` | the path a scheduler would serve next, without leasing it |
| `POST /api/audits/{id}/reclaim-expired` | `writer` | recover paths whose lease expired |
| `POST /api/audits/{id}/rescore` | `writer` | replay the ranking from the stored feature snapshots |
| `GET /api/paths/{id}` | `reader` | one path with its feature history and its events |
| `POST /api/audits/{id}/claim` | `writer` | lease the audit queue's next pick to an owner (canonical) |
| `POST /api/paths/{id}/claim` | `writer` | same operation reached through a path id (alias) |
| `POST /api/paths/{id}/heartbeat` | `writer` | extend a lease the owner still holds |
| `POST /api/paths/{id}/release` | `writer` | return a path to the queue without a verdict |
| `POST /api/paths/{id}/pause` | `writer` | pause a path (requires `If-Match`) |
| `POST /api/paths/{id}/resume` | `writer` | queue a paused path again (requires `If-Match`) |
| `POST /api/paths/{id}/cancel` | `writer` | remove a path from the queue for good (requires `If-Match`) |

### `POST /api/audits`

```json
{
  "snapshot_id": "snap-...",
  "force": false,
  "budget": {"max_depth": 2, "max_branches": 4, "max_tool_calls": 30},
  "limits": {"max_paths": 2000, "max_active_leases": 4, "exploration_fraction": 0.2},
  "sensitivity": {"substring": 0.9}
}
```

`budget`, `limits` and `sensitivity` are optional; unset values take the engine
defaults and are stored with the audit. The request is identified by a
configuration hash over the snapshot and those inputs, so repeating the same
request returns the same audit:

- `201 {"audit": {...}, "path_count": 12, "replayed": false}` on generation;
- `200 {"audit": {...}, "path_count": 12, "replayed": true}` when the audit
  already exists and `force` is false — the audit id is unchanged;
- `force: true` regenerates and rescores, keeping the same path ids because they
  are derived from the attack surface, so two runs are comparable.

A negative bound or a sensitivity outside `[0,1]` is `400 invalid_request`.
Errors: `404 not_found` for a snapshot that was never frozen, `409 asg_missing`
for a snapshot without an attack surface — that message names
`POST /api/snapshots/{id}/asg`, which is the fix.

### `GET /api/audits` and `GET /api/audits/{id}`

Parameters: `snapshot_id`, `status` (`GENERATING`, `READY`, `FAILED`), `limit`,
`offset`. The listing answers `{"audits": [...], "total": N}`. An unknown audit
id is `404 not_found`.

### `GET /api/audits/{id}/paths`

Parameters: `status` (comma-separated lifecycle statuses), `path_status`
(comma-separated `candidate`, `statically_supported`, `unresolved`), `entry` and
`target` (ASG node ids), `min_priority`, `sort` (`priority` — the default and the
queue order — `created` or `path_id`), `limit`, `offset`. The page is
`{"audit_id": ..., "paths": [...], "total": N, "objective_counts": {...}}`. A
typo in `status`, `path_status`, `sort` or `min_priority` is `400
invalid_request` rather than a silently empty page.

### `GET /api/audits/{id}/events`

Parameters: `path_id`, `after_seq` (strictly greater than), `limit`. The answer
is `{"audit_id": ..., "events": [...], "total": N, "next_after_seq": N}`.

Server-sent events are deferred to the WebUI phase: the browser client and its
reconnection semantics do not exist yet, and `after_seq` already makes a poll a
resumable cursor, so streaming now would add a transport without adding an
answer.

### `GET /api/audits/{id}/next`

Returns `{"audit_id": ..., "path": {...}, "leased": false}` — the path the
scheduler would serve next, with no lease taken, so two callers see the same
answer until one of them claims. An audit with nothing queued is `404 not_found`.

### `GET /api/paths/{id}`

Returns `{"path": {...}, "features": [...], "events": [...]}` and sets an `ETag`
over the path version. `features` is the append-only score history: a rescore or
a forced audit adds a version instead of overwriting the ranking it replaces.

### Lease verbs

`POST /api/audits/{id}/claim` with `{"owner": "...", "ttl_seconds": 300}` leases
the path the scheduler picks next in that audit and moves it to `ANALYZING`. The
route is audit-scoped because the decision is: the ceiling on active leases is a
property of the audit, and the schedule is chosen by marginal coverage over the
whole queue rather than row by row. The answer is the path that was actually
leased.

`POST /api/paths/{id}/claim` is the same operation reached through a path id: it
resolves that path's audit and then leases the scheduler's next pick. It is a
convenience for a worker that already holds a path id, **not** a request for that
particular path — use the audit route when you want the queue, and treat the
leased id in the answer as authoritative.

`POST /api/paths/{id}/heartbeat` with the same body extends a lease the owner
still holds. `POST /api/paths/{id}/release` with `{"owner": "...", "reason":
"..."}` returns the path to `QUEUED` without a verdict.

The codes separate the ways a lease can fail: `409 lease_held` (another owner
holds it), `409 lease_expired` (the lease is gone), `409 budget_exceeded` (the
audit's active-lease ceiling is reached) and `404 not_found` (nothing is queued).
`POST /api/audits/{id}/reclaim-expired` with `{"limit": 10}` recovers expired
leases; the engine's sweep is store-wide, so the answer reports the paths of this
audit plus `recovered_total` for the whole sweep.

### Lifecycle verbs

`POST /api/paths/{id}/pause`, `/resume` and `/cancel` take `{"reason": "..."}`
and require `If-Match` with the path's `ETag` from `GET /api/paths/{id}` (`428`
without the header, `412` when it is stale), exactly like the project rename.
When the state machine refuses the change — a cancelled path cannot be resumed —
the answer is `409 invalid_transition` and the message lists the legal targets
from the current status. A concluded path must be re-audited rather than
resurrected.

### Audit error codes

| Code | HTTP | Meaning |
|---|---|---|
| `not_found` | `404` | the snapshot, audit, path or queued work does not exist |
| `invalid_request` | `400` | malformed body or an unknown filter value |
| `invalid_transition` | `409` | the state machine refuses the change (the legal targets are in the message) |
| `version_conflict` | `409` | the optimistic-concurrency check lost |
| `lease_held` | `409` | another owner holds the lease |
| `lease_expired` | `409` | the lease expired; claim the path again |
| `budget_exceeded` | `409` | the audit's active-lease ceiling is reached |
| `asg_missing` | `409` | the snapshot has no attack surface yet |
| `audit_unavailable` | `501` | the server was started without the path engine |
| `precondition_required` / `precondition_failed` | `428` / `412` | `If-Match` is missing or stale |

## Agent runs and hypotheses (P5)

A run is one bounded agent execution over one claimed path. The Go orchestrator
owns the process, the lease, the deadline and the budget; the adapter receives a
task and returns events, and it never sees a lease or a registry. A run is a
database row rather than a session, so it survives a crashed process and every
exchange is auditable afterwards. Nothing here stores or requests a chain of
thought: a run persists the task, the tool exchanges, the expansion decisions and
the structured answer.

A hypothesis is the claim a run asserts. It is not a finding: `status` may be
`candidate`, `inconclusive` or `refuted` — confirmation belongs to the
verification phase, and an adapter that answers `confirmed` is rejected as
`INVALID_OUTPUT`.

| Endpoint | Capability | Description |
|---|---|---|
| `POST /api/audits/{id}/runs` | `writer` | run up to `max_runs` paths of the audit's queue (canonical) |
| `POST /api/paths/{id}/runs` | `writer` | same operation reached through a path id (alias) |
| `GET /api/runs` | `reader` | page of runs (`path_id`, `audit_id`, `snapshot_id`, `status`, `limit`, `offset`) |
| `GET /api/runs/{id}` | `reader` | one run, including the task the agent was given |
| `GET /api/runs/{id}/events` | `reader` | bounded page of the run's exchange log (`type`, `after_seq`, `limit`) |
| `GET /api/paths/{id}/hypotheses` | `reader` | page of the claims recorded for one path |
| `GET /api/hypotheses` | `reader` | page of claims (`audit_id`, `path_id`, `status`, `finding_candidates`, `limit`, `offset`) |
| `GET /api/hypotheses/{id}` | `reader` | one claim with its supporting and contradicting evidence |

Both POSTs accept `Idempotency-Key`: a retry must not run a second path.

### `POST /api/audits/{id}/runs` and `POST /api/paths/{id}/runs`

```json
{
  "max_runs": 1,
  "policy": {
    "max_hops": 2,
    "max_branches": 4,
    "max_tool_calls": 30,
    "max_expansions": 3,
    "timeout_seconds": 600,
    "token_budget": 0,
    "allowed_tools": ["graph.slice"]
  }
}
```

`max_runs` defaults to `1` and is capped at `10`; a larger value is `400
invalid_request`, not a silently clamped batch. The answer is
`{"runs": [...], "count": N, "stop_reason": "..."}` where `stop_reason` is the
last run's reason (`completed`, `tool_call_budget_exceeded`, `deadline_exceeded`,
`invalid_output`, `repeated_output_without_new_evidence`, `adapter_failed`,
`lease_lost`, ...).

The request policy only narrows the configured one. Every field is optional; a
field that is sent is capped at the configured value, so a caller may spend less
of the agent's budget but never more, and `allowed_tools` is the configured
allowlist intersected with what the request asked for. `max_expansions` and
`token_budget` are the exception to the usual "zero means default": zero is a
real ceiling there.

**The advertised allowlist is the enforced one.** `allowed_tools` must name tools
the deployment actually registered; an unknown tool is `400 invalid_request` and
the message names it. A tool the registry cannot execute is refused rather than
advertised, because an allowlist the orchestrator would deny teaches the agent to
waste its budget on refusals.

`POST /api/paths/{id}/runs` resolves that path's audit and then runs the audit's
next pick. It is a convenience for a caller that already holds a path id, **not**
a request for that particular path — the run that starts may be over a different
path, exactly as with `POST /api/paths/{id}/claim`. Treat the `path_id` in the
answer as authoritative.

The HTTP status describes the request; the run's own status describes the run. A
run that ended `FAILED`, `INVALID_OUTPUT` or `BUDGET_EXCEEDED` was still started
successfully, so the POST answers `200` with that run in the body — the operator
reads `status` and `stop_reason` rather than inferring them from a transport
error. The POST is only a non-2xx answer when the request itself could not be
honoured:

| Code | HTTP | Meaning |
|---|---|---|
| `not_found` | `404` | the audit or path does not exist, or the queue is empty |
| `invalid_request` | `400` | malformed body, `max_runs` over the cap, an unknown tool or filter value |
| `budget_exceeded` | `409` | the audit's active-lease ceiling is already reached |
| `version_conflict` | `409` | the optimistic-concurrency check lost |
| `agent_unavailable` | `501` | the server was started without the agent runtime |

### `GET /api/runs` and `GET /api/runs/{id}`

Parameters: `path_id`, `audit_id`, `snapshot_id` (comma-separated `status`
values), `limit`, `offset`. The listing answers `{"runs": [...], "total": N}`. A
run document includes its `task` verbatim, so a reviewer can see what the agent
was asked before judging what it answered, and its `answer` when one was
accepted. `status` values are `CREATED`, `RUNNING`, `PAUSING`, `PAUSED`,
`CANCELLING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, `TIMED_OUT`,
`BUDGET_EXCEEDED` and `INVALID_OUTPUT`; an unknown one is `400 invalid_request`,
not a silently empty page.

### `GET /api/runs/{id}/events`

The exchange log, ordered by `seq` and numbered per run. Parameters: `type` (a
comma-separated event type, e.g. `run_created`, `run_started`, `task_delivered`,
`tool_requested`, `tool_allowed`, `tool_denied`, `tool_result`,
`expansion_requested`, `expansion_decided`, `output_received`,
`output_rejected`, `hypothesis_recorded`, `run_heartbeat`, `run_error`,
`run_finished`), `after_seq` (strictly greater than) and `limit`. The answer is
`{"run_id": ..., "events": [...], "total": N, "next_after_seq": N}`, and
`after_seq` makes a poll a resumable cursor, exactly as on the audit log.

### Expansion approval is policy-driven for this phase

There is deliberately no operator approval route for an expansion. The runner
decides each expansion inline under the run's policy — approve, shrink, defer or
reject — and records the decision as an `expansion_decided` event carrying the
decision, the reason and what was granted. An expansion buys exploration room,
never permissions: the granted tool list is always a subset of the run's own
allowlist.

`GET /api/runs/{id}/events?type=expansion_decided` is therefore the approval
audit trail. A separate operator approval queue is a later phase, and adding one
now would give the control plane a second, divergent way to widen a run's budget.

### `GET /api/hypotheses` and `GET /api/paths/{id}/hypotheses`

Both answer `{"hypotheses": [...], "total": N}`. The global listing accepts
`audit_id`, `path_id`, `snapshot_id`, comma-separated `status`,
`finding_candidates` (a boolean — `finding_candidates=true` is what a
verification phase schedules from), `limit` and `offset`. `GET
/api/paths/{id}/hypotheses` is the same page scoped to one path, and it reports
`404 not_found` for an unknown path rather than an empty page, because a typo and
a path whose run has not finished would otherwise look identical. A claim carries
its `supporting_evidence` and `contradicting_evidence` as resolved refs, so a
reviewer can check a citation without re-running the agent.

## Verification, evidence and findings (P6)

P6 turns a hypothesis into a finding — or into an honestly unresolved one. The
distinction it protects is the one the design states plainly: **failing to
reproduce a vulnerability is not evidence that it does not exist.** A verification
runs inside a declared scope and budget, its plan is validated before anything
executes it, and only the derivation in `internal/verify` decides a verdict.

| Endpoint | Capability | Description |
|---|---|---|
| `POST /api/hypotheses/{id}/finding` | `writer` | derive the finding for a hypothesis and store its citations as evidence (idempotent) |
| `POST /api/hypotheses/{id}/verifications` | `writer` | build or accept a plan, authorize it, execute it, derive the verdict |
| `GET /api/verifications` | `reader` | page of runs (`hypothesis_id`, `finding_id`, `path_id`, `audit_id`, `snapshot_id`, `status`, `outcome`, `limit`, `offset`) |
| `GET /api/verifications/{id}` | `reader` | one run with its plan, environment digest, approval record, outcome, reason and evidence ids |
| `GET /api/verifications/{id}/evidence` | `reader` | the run's immutable evidence objects (`kind`, `limit`, `offset`) |
| `GET /api/findings` | `reader` | page of findings (`audit_id`, `snapshot_id`, `path_id`, `status`, `conclusive`, `candidates`, `limit`, `offset`) |
| `GET /api/findings/{id}` | `reader` | one finding with its evidence grouped and its verification runs |
| `GET /api/evidence/{id}` | `reader` | one evidence object |
| `GET /api/audits/{id}/report` | `reader` | render the audit's findings (`format=md\|json\|sarif`, `include_candidates`) |

Every POST accepts `Idempotency-Key`. Both POSTs are writes: deriving a finding
changes durable state, and starting a verification spends a budget and records an
approval. A reader may read all of it and start none of it. A deployment without
the verification layer answers `501 verification_unavailable` on every route here.

### The three-way distinction

| Status / outcome | What it means | What it requires |
|---|---|---|
| `confirmed` / `CONFIRMED` | the behaviour was reproduced | reproduction evidence (`runtime_log` or `test`) **and** the steps that reproduced it, **and** nothing contradicting it |
| `refuted` / `REFUTED` | there is evidence against the claim | at least one contradicting evidence object: a control that demonstrably blocks the path, or a sink that cannot be reached with attacker data |
| `inconclusive` / `INCONCLUSIVE` | verification ran and settled nothing | insufficient evidence — **not** a refutation |
| `blocked` / `BLOCKED` | verification could not run | missing approval, missing environment, unsupported step, refused network access — **not** a refutation either |

A `candidate` finding is an unverified hypothesis: it appears in a report only with
`include_candidates=true`, because a report of findings must not read as a report of
vulnerabilities. The HTTP status describes the request while `status` and `outcome`
describe the run: a run that ended `BLOCKED` was still started successfully, so the
POST answers `200` with that run in the body.

### `POST /api/hypotheses/{id}/finding`

Derives the finding id from the hypothesis, stores the hypothesis's own citations
as evidence (kind `source` for a file and line, `static_query` for an id-only ref,
tool `hypothesis-evidence@1`) and answers `200` with the finding. Re-running it is
idempotent in the strong sense: it seeds once and never again. A second derivation
of an unchanged finding returns the stored document without writing, so `updated_at`
and `version` do not move, and a finding verification has already touched — a
conclusive status, or any evidence list — is returned untouched.

Every citation the hypothesis records is claim-time context and lands in
`supporting_evidence`; the `contradicting_evidence` and `inconclusive_evidence`
lists belong to the verification service, and a citation the planner wrote into
them would read as a verdict it never reached. A citation the hypothesis itself
records as contradicting keeps that polarity on the evidence object (the
`contradicts:` marker in `redaction_notes`), so it stays distinguishable without
inventing a verdict.

### `POST /api/hypotheses/{id}/verifications`

```json
{
  "approved": true,
  "approved_by": "operator-name",
  "scope": {
    "repository": "example.invalid/svc",
    "snapshot_id": "snap-...",
    "allowed_targets": ["app.invalid"],
    "allow_network": false,
    "requires_human_approval": true
  },
  "environment": {
    "profile": "sandbox-default",
    "source_read_only": true,
    "network": "none",
    "cpu_millis": 1000,
    "memory_mb": 512,
    "timeout_seconds": 300
  }
}
```

`plan` is optional. When it is absent the server builds one from the hypothesis and
the path with the graph-side planner: a `static_check` of the reachability claim, a
`dataflow_probe` that names the missing dataflow fact as the gap to close, and — only
when the scope allows network access — a `dynamic_proof` marked as requiring
approval. The plan carries the claim verbatim, the security goal, and the
limitations inherited from the path and the hypothesis (reachability is not
dataflow; a control's presence is not its effectiveness), and it is normalized and
hashed before it is returned. When `plan` is present it is validated the same way,
and it must describe the hypothesis in the URL.

**The environment's quotas are ceilings, not defaults.** A plan may ask for less
than the caps in `verify.Max*`, never more, and `source_read_only` is required:
a verification reads the snapshot and writes only inside its own scratch space.
`mount_host_socket` exists to be refused.

**Approval is an explicit write, never an inference.** When a plan contains a
`dynamic_proof` or any step marked `requires_approval`, the request must carry both
`approved: true` and a non-empty `approved_by`; the name is recorded on the run
together with the approval time. There is deliberately no approval key, token or
header: a refusal and an approval are both ordinary request outcomes.

| Code | HTTP | Meaning |
|---|---|---|
| `approval_required` | `409` | the plan needs a recorded approval and `approved_by` is missing — nothing was written |
| `scope_denied` | `409` | the environment wants egress the scope withholds — nothing was written |
| `invalid_request` | `400` | the plan or environment does not validate (the message names the field), an unknown filter value, or a bad body |
| `unsupported_step` | `409` | the configured executor cannot run a step of the plan |
| `not_found` | `404` | the hypothesis, finding, verification or evidence does not exist |
| `version_conflict` | `409` | an optimistic-concurrency check lost |
| `verification_unavailable` | `501` | the server was started without the verification layer |

The same plan for the same hypothesis is the same verification: the run id is
derived from the hypothesis and the plan hash, so re-submitting an identical plan
returns the existing run and executes nothing.

### `GET /api/findings/{id}`

The `finding` object carries its three evidence id lists, its verification run ids,
its environments, its reproduce steps and its limitations. The `evidence` object
groups the referenced objects into `supporting`, `contradicting` and `inconclusive`,
and `verifications` holds every run recorded for the finding. The three lists stay
apart because a contradiction is the interesting part and "we could not tell" is
not "we disproved it".

### Evidence

Evidence is immutable and content-addressed: the id is derived from its kind, its
snapshot and the hash of its content, and there is no update path. A correction is a
new object whose `supersedes` field points at the old one, and both stay readable.
Every object names the tool and version that produced it and the snapshot,
hypothesis, path, finding and verification run it belongs to.

**Evidence content is never returned unredacted, because it is never stored
unredacted.** Credentials, authorization headers, private key blocks, e-mail
addresses and long opaque values are replaced before storage, the transformation is
recorded in `redaction_notes` with `redacted: true`, and the content hash covers the
stored (redacted) bytes so the hash and the content always agree. `GET
/api/evidence/{id}` therefore returns the stored object as it is: there is no
unredacted form behind it to leak.

### `GET /api/audits/{id}/report`

Renders the audit's findings and their evidence. `format` is `md` (`text/markdown`),
`json` (`application/json`) or `sarif` (`application/sarif+json`, SARIF 2.1.0); an
unknown format is `400 invalid_request` and the message names the three. Candidate
findings appear only with `include_candidates=true`. Every renderer restates the
caveats — confirmed was reproduced, refuted means contradicting evidence exists,
inconclusive and blocked are not refutations — because a report that hides those
distinctions would undo the layer.

### Configuring the executor and the scripted dry run

`--verify-executor` chooses the adapter (`scripted`, `cli` or `unsupported`), and
omitting it leaves the whole verification layer unwired, so every route above
answers `501`. `--verify-command` is the argv prefix of the command a `cli` step
runs (repeatable, no shell), `--verify-env` is the complete extra environment
allowlist as `KEY=VALUE` (repeatable), `--verify-working-dir` is the scratch
directory that must already exist, and `--verify-max-output` bounds the bytes one
step may return. `--verify-allow-network` declares that `--verify-command` is
deployed inside a network-capable restricted container: it is a property of the
deployment, not an approval, and a plan that needs egress still requires the
request's `approved` and `approved_by`.

`--verify-scripted-steps` gives the `scripted` executor its script as a raw JSON
array (or `@file` to read one), which is what turns `--verify-executor scripted`
into a real dry run: prepare, authorize, replay each step, derive the outcome,
store the evidence and upsert the finding. The CLI spelling is
`codexploit verify <hypothesis-id> --executor scripted --scripted-steps '<json>'`
(or `@file`); each entry uses `verify.StepOutcome`'s own field names
case-insensitively — `kind` (`test` or `runtime_log` for reproduction evidence,
`source`/`static_query` for a lead), `content`, `command`, `contradicts`, `err`,
`file`, `line`, `exitCode` — and malformed JSON fails startup with the shape named
rather than failing a run later.

**A scripted executor with no steps blocks every plan step.** That outcome is
recorded as `BLOCKED` (`unsupported_step`) and the finding is `blocked`, which is
**not a refutation**: nothing was reproduced and nothing was disproved. The server
logs an explicit warning when it is wired that way, and the CLI refuses the run
and names `--scripted-steps` instead of printing a bare `BLOCKED` result.

## Scheduler (P7)

P7 is the resident loop that serves the path queue: it claims due `QUEUED` paths,
hands each to the agent runtime, settles the result, recovers leases whose owner
stopped renewing them, and keeps a durable retry schedule per path. It is wired
with `--scheduler` and is off by default; when it is off the server logs
`scheduler disabled` and the queue only advances through an explicit run, claim or
tick.

The three routes below are the operator surface. `GET` needs `reader`; both `POST`
routes claim leases or change path state, so they need `writer`. A server started
without `--scheduler` answers all three with `501 scheduler_unavailable` — never
with zeros that read like a healthy idle scheduler.

### `GET /api/scheduler`

Reports whether the resident loop is running, how it is configured, and the
metrics snapshot.

```json
{
  "running": false,
  "configured": true,
  "config": {
    "owner": "scheduler",
    "interval_seconds": 30,
    "max_concurrent": 4,
    "lease_ttl_seconds": 0,
    "audits": [],
    "backoff": {"Base": 1000000000, "Factor": 2, "Max": 300000000000, "Jitter": 0.2}
  },
  "metrics": {
    "ticks": 12,
    "dispatched_total": 9,
    "succeeded_total": 7,
    "failed_total": 2,
    "retried_total": 2,
    "reclaimed_total": 1,
    "active_leases": 2,
    "queue_depth": 41,
    "oldest_queued_seconds": 183.5,
    "last_tick_at": "2024-05-01T12:00:30Z",
    "last_tick_ms": 128
  }
}
```

| Field | Meaning |
|---|---|
| `ticks` | completed scheduler passes |
| `dispatched_total` | paths claimed and handed to the runtime |
| `succeeded_total` / `failed_total` | dispatches that settled as completed / returned an error |
| `retried_total` | failed attempts requeued with a durable next-attempt time |
| `reclaimed_total` | expired leases recovered from workers that stopped renewing |
| `active_leases` | leases active in the audits the last pass looked at |
| `queue_depth` | queued paths in those audits |
| `oldest_queued_seconds` | how long the oldest queued path has waited |
| `last_tick_at` / `last_tick_ms` | when the last pass finished and how long it took |

`running` is `true` only while the server's own loop is inside `Run`; a
one-shot CLI invocation always reports `false`. `configured` is `false` for a
server that was started without the scheduler.

### `POST /api/scheduler/tick`

Runs one pass synchronously and answers with the pass's own summary. The body is
optional and overrides only this pass: `{"audits": ["audit-..."], "concurrency": 2}`.
Like every write it accepts `Idempotency-Key`, so a retried tick does not dispatch
a second time.

```json
{"held": 0, "dispatched": 2, "reclaimed": 1, "skipped": 3, "failed": 0, "due": 5}
```

`due` is how many due queued paths the pass saw, `dispatched` how many it claimed
within the concurrency budget, `failed` how many dispatches returned an error, and
`skipped` how many due paths it did not take (already in flight, at their attempt
ceiling, or lost to another scheduler's claim).

### `POST /api/scheduler/reclaim`

Runs one recovery sweep of expired leases and returns the paths it recovered. The
body is optional: `{"limit": 10}`. This is the route to call after killing a
worker, and it is what makes a crashed process recoverable instead of permanent.

```json
{"recovered": [{"path_id": "path-...", "status": "QUEUED", "...": "..."}], "count": 1}
```

### Configuring the scheduler

| Flag | Meaning |
|---|---|
| `--scheduler` | run the resident loop in this server (needs `--agent-runtime`) |
| `--scheduler-audit` | audit id to serve, repeatable; empty serves every audit with due work |
| `--scheduler-interval` | seconds between passes (default 30) |
| `--scheduler-concurrency` | maximum paths run at once (default: the active-lease ceiling) |
| `--scheduler-lease-ttl` | lease duration in seconds asked for on a claim (default: the audit's own) |
| `--scheduler-owner` | lease owner the scheduler records (default `scheduler`) |
| `--scheduler-backoff-base` / `-factor` / `-max` / `-jitter` | retry policy: first delay, multiplier, cap and deterministic jitter |

An enabled scheduler without an agent runtime fails startup, and so does a
negative interval, concurrency, lease TTL or backoff value: a misconfigured
scheduler must not run because it would claim leases it cannot execute.

The CLI mirrors the routes: `codexploit scheduler status [--json]`,
`codexploit scheduler tick [--audits a,b] [--concurrency N] [--json]`,
`codexploit scheduler reclaim [--limit N] [--json]` and
`codexploit scheduler run [--interval N] [--json]`. `run` is the foreground loop;
Ctrl-C stops it and releases every lease the process still holds. `tick` and `run`
need the agent adapter flags (`--runtime scripted|cli` and its options) exactly
like `codexploit run`.

Retries are bounded: a failed dispatch is requeued with `NextAttemptAt` computed by
an exponential backoff (`base × factor^attempt`, capped, with deterministic
per-path jitter), so two schedulers that restart agree on the due time and a
restart does not forget it, and the path stops being retried once it reaches its
own `max_attempts` ceiling. **A cancelled path is never retried** —
`path.Retryable` refuses it, because an operator cancelled it on purpose. Leases
are what make concurrent schedulers safe: a path can only be claimed once, so the
scheduler that holds the lease is the only one that dispatches it, and a lease that
is no longer renewed is recovered by the next sweep rather than held forever.

## Provenance

Every graph answer carries a `meta` block:

```json
{
  "snapshot_id": "snap-...",
  "graph_version": "graph-...",
  "engine": "codexploit/scg@0.1.0",
  "query": "callees",
  "args": {"symbol_id": "sym-...", "max_depth": "2"},
  "budget": {"max_depth": 2, "max_nodes": 200, "max_edges": 1000, "limit": 100, "timeout": 5000000000},
  "elapsed_ms": 3,
  "cache_hit": false,
  "nodes_visited": 12,
  "edges_visited": 14,
  "depth_reached": 2,
  "more_beyond_depth": true,
  "truncated": false
}
```

`truncated` with a `truncation_reason` means a budget cut the answer short.
`more_beyond_depth` means the answer is complete for the requested depth but
deeper neighbours exist. The two are deliberately distinct.
