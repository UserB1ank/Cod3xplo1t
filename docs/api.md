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
| `428` | `PATCH` without the `If-Match` it requires |
| `413` | request body larger than 1 MiB |
| `422` | snapshot limit exceeded |
| `501` | the server was started without the graph or attack-surface service (`graph_unavailable`, `asg_unavailable`) |
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
