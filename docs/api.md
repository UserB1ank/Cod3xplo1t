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
