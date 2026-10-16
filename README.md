# Codexploit

> Map the Code. Trace the Attack. Verify the Evidence.

Codexploit is a static-analysis-driven code security auditing platform. This
repository currently contains the **P1 vertical slice**: the deterministic,
Agent-free foundation that pins a repository to an immutable revision, freezes a
read-only snapshot and produces a reviewed `repository_manifest.json`.

Design and implementation references:

- [`docs/codexploit_design.md`](docs/codexploit_design.md) — architecture
- [`docs/codexploit_implementation_guide.md`](docs/codexploit_implementation_guide.md) — engineering guide

## Status

| Phase | Scope | State |
|---|---|---|
| P1 | Workspace, snapshot, repository analyzer | **implemented** |
| P2 | SCG (modules, symbols, call sites, call edges), bounded graph queries, REST + MCP | **implemented** (Go frontend; see gaps) |
| P3 | Attack surface extraction, ASG candidate | not started |
| P4–P7 | Path engine, Agent runtime, verification, productisation | not started |

Nothing in this repository executes repository code: no build scripts, no hooks,
no installers, no tests from the audited project.

## Quick start

```bash
make build                 # bin/server and bin/cli

# freeze a snapshot and write its manifest (works on a git URL or a local path)
bin/cli manifest --source /path/to/repo --workspace .codexploit
bin/cli snapshot --source https://example.invalid/org/repo.git --ref v1.2.3 --allow-network
bin/cli snapshots list --workspace .codexploit
bin/cli snapshots remove --id snap-0123456789abcdef0123456789abcdef

# REST API: authentication is mandatory, so pass at least one token
bin/server --addr :8080 --workspace .codexploit --db .codexploit/codexploit.db \
  --api-token ci:admin:$(openssl rand -hex 16)
# or, for local development only (anonymous writers, no destructive operations):
bin/server --insecure-anonymous

# the whole chain in one step: snapshot + manifest + source code graph
bin/cli scg build --source /path/to/repo --workspace .codexploit
bin/cli scg modules --snapshot snap-0123456789abcdef0123456789abcdef
bin/cli scg symbols --snapshot snap-… --name Save --kind method
bin/cli scg callees --snapshot snap-… --symbol example.invalid/app/internal/store.Store.Save --depth 2
bin/cli scg paths   --snapshot snap-… --from example.invalid/app.main --to example.invalid/app/internal/store.write
bin/cli scg slice   --snapshot snap-… --symbol example.invalid/app.main --include calls
bin/cli scg unresolved --snapshot snap-…
```

```bash
curl -s localhost:8080/healthz
curl -s -X POST localhost:8080/api/projects \
     -H 'Content-Type: application/json' -d '{"source":"/path/to/repo"}'
curl -s -X POST localhost:8080/api/projects/<project-id>/snapshots \
     -H 'Content-Type: application/json' -H 'Idempotency-Key: run-1' -d '{}'
curl -s localhost:8080/api/snapshots/<snapshot-id>/manifest
```

## Layout

```text
cmd/cli/            developer entry point (snapshot, manifest, snapshots list/remove)
cmd/server/         REST API process
internal/app/       wiring: workspace, store, migrations (the only place the SQL driver is chosen)
internal/repository/  P1 snapshot chain: identity, snapshot id, git/local sources, limits, freeze
internal/analysis/    P1 analyzer: pluggable detectors, repository manifest
internal/scg/         P2 SCG model, stable ids, builder, pluggable frontend interface
internal/scg/gofrontend/ the Go frontend (standard library AST) and its call resolver
internal/graph/       P2 graph service: bounded queries, code slices, result cache
internal/storage/     Store interface, in-memory store, database/sql store, migrations runner
internal/api/         REST handlers, JSON errors, idempotency keys
internal/mcp/         MCP server exposing the graph to agents
cmd/mcp/              stdio MCP binary
migrations/           SQL schema (embedded at build time)
```

Detailed REST reference: [`docs/api.md`](docs/api.md). MCP tool catalogue:
[`docs/mcp-tools.md`](docs/mcp-tools.md).

## Contracts

These invariants are enforced by code and covered by tests; changing one is a
schema or identity change, not a refactor.

1. **Deterministic identity.**
   `snapshot_id = hash(repo_identity, commit, submodule_state)` (length-prefixed,
   `snap-` + 128-bit digest) and
   `analysis_id = hash(snapshot_id, engine, engine_version, ruleset_hash, config_hash)`.
   The same inputs always produce the same ids; changing the rule set or the
   analyzer configuration yields a new `analysis_id`.
2. **Immutable artifacts.** `snapshot.json` and `repository_manifest.json` are
   written once and never overwritten. A conflicting write is an error
   (`409 Conflict` over HTTP), so evidence cannot be silently replaced.
3. **Read-only trees.** `snapshots/<id>/repo` is frozen (`0444` files, `0555`
   directories). Delete snapshots through the CLI/API, which unfreeze first;
   `rm -rf` on a frozen tree fails on every supported platform.
4. **Explicit coverage.** Every dropped file is counted, and the bounded sample
   carries a reason (`ignored`, `binary`, `file_too_large`, `max_depth`,
   `symlink`, `unreadable`, `submodule`, `limit`). The snapshot lists its
   limitations; the manifest lists its unknowns. "Not found" is never presented
   as "not present".
5. **No silent inference.** Framework hits cite a dependency declaration, a
   source marker or a marker file, and carry a confidence *class*
   (`observed` / `inferred` / `unresolved`) — never a probability.
6. **Offline by default.** Remote git URLs are refused unless network access is
   explicitly enabled. Git runs with hooks, credential helpers, system/global
   config, prompts and LFS smudge disabled.
7. **Deterministic documents.** Manifests are byte-identical for identical
   inputs (timestamps aside) and list fields serialise as arrays, never `null`.
8. **Authentication fails closed.** Every API route is classified as `reader`,
   `writer` or `admin` in one table; secrets are compared as SHA-256 digests with
   a constant-time comparison, and a server without tokens refuses to start (a
   `Server` without an authenticator answers `401` to every API call) unless
   `--insecure-anonymous` was passed deliberately. `DELETE` and `PATCH` are
   `admin`, and anonymous access is never administrative.
9. **Write retries are safe across processes.** `Idempotency-Key` claims live in
   the store: key, request fingerprint and caller are part of the claim, so a
   retry after a restart replays the first answer, a different body is refused
   with `409 idempotency_key_reuse`, and a key that is still running answers
   `409 idempotency_in_progress` with `Retry-After` instead of doing the work
   twice.
10. **Writes are optimistic.** `GET /api/projects/{id}` returns an `ETag` and
   `PATCH` requires `If-Match` (`428` when missing, `412` when stale).

### Snapshot semantics worth knowing

- The tree always comes from the pinned commit, never from the working copy. A
  dirty worktree is recorded (`worktree_dirty`, `dirty_path_count`,
  `dirty_paths`) and stated as a limitation, but does not change the snapshot id.
  **Consequence:** the same commit yields the same snapshot, so the recorded
  dirty state describes the moment the snapshot was first taken.
- Directory sources without VCS metadata are pinned to a content digest of the
  accepted file set (`commit = content:<digest>`); the files are re-hashed while
  copying and a concurrent edit aborts the snapshot instead of producing a tree
  that does not match its id.
- Submodule gitlinks are recorded and their content is **not** expanded; an empty
  directory is not planted in the tree. Untracked or ignored paths (including
  `.gitignore`d files) are never part of a git snapshot.
- Symlinks are recorded, not followed and not materialised.
- Git LFS content is never fetched automatically: tracked files stay pointers and
  the limitation is stated.
- Binary files are skipped unless enabled, identified by a NUL byte in the first
  8000 bytes.

### Default limits

| Limit | Default | Override |
|---|---|---|
| Total accepted bytes | 512 MiB | `repository.Limits.MaxRepoBytes` |
| Files | 50 000 | `MaxFiles` |
| Single file | 4 MiB | `MaxFileBytes` |
| Path depth | 32 | `MaxDepth` |
| Ignored directories | generated, vendor, cache | `ExtraIgnoreDirs`, `IncludeIgnoredDirs` |
| Symlinks / submodules / LFS | record | `Symlinks`, `Submodules`, `LFS` |

`IncludeIgnoredDirs` is the documented escape hatch when a normally generated
directory holds audited source (for example `vendor`).

## Source Code Graph (P2)

The SCG is the deterministic fact layer: modules, files, symbols, call sites and
the (possibly unresolved) relationships between them. It is built by static
analysis only — no agent, no LLM — and every assertion carries its provenance
(`analyzer`, `analyzer_version`, source location, resolution status).

Facts and their limits:

1. **Ids are content derived.** `symbol_id = hash(snapshot_id, language, file,
   qualified_name, signature, start position)`, so editing a function body does
   not change its id while a different snapshot produces different ids.
2. **Resolution is classified, never boolean.** `resolved`,
   `resolved_best_effort`, `unresolved_ambiguous`, `unresolved_dynamic`,
   `unresolved_external`, `builtin`, `unresolved_unsupported`. Best-effort edges
   come from inference (a local type assignment or a constructor's declared
   result type) and are marked `inferred`.
3. **Unresolved calls are kept.** A call site with no edge stays in the graph, is
   listed by `list_unresolved_calls` / `scg unresolved`, and travels with every
   neighbourhood answer as `unresolved_call_sites`.
4. **Every query is snapshot-scoped and bounded.** `max_depth`, `max_nodes`,
   `max_edges`, `limit`, `offset` and `timeout_ms` are enforced; a query that
   runs out of budget returns partial results with `truncated` and a
   `truncation_reason` instead of an answer that looks complete.
5. **Depth is not truncation.** `more_beyond_depth` reports that deeper
   neighbours exist when the requested depth was reached.
6. **Results are cached by content.** The cache key follows design §9:
   `hash(snapshot_id, graph_version, query_type, canonical args)`.
7. **Coverage is stated.** Files without a frontend, files that are not source,
   oversized files, parse failures, symbols and call sites dropped by a budget,
   and the overall resolved/unresolved split all appear in the summary and as
   limitations. `FLOWS_TO` and `CONTROLS` edges are declared but not produced in
   P2: dataflow and control-flow analysis are later phases, and the graph says so.

## REST API

| Method | Path | Notes |
|---|---|---|
| `GET` | `/healthz` | liveness |
| `POST` | `/api/projects` | create or reuse a project; id derives from the repository identity |
| `GET` | `/api/projects` | list projects |
| `GET` | `/api/projects/{id}` | read one project |
| `POST` | `/api/projects/{id}/snapshots` | freeze + analyse; body `{"ref":"...","skip_analysis":false}` |
| `GET` | `/api/snapshots?project_id=` | list snapshot records |
| `GET` | `/api/snapshots/{id}` | snapshot metadata summary |
| `DELETE` | `/api/snapshots/{id}` | remove record and unfreeze/delete the tree |
| `GET` | `/api/snapshots/{id}/manifest` | full repository manifest |
| `POST` | `/api/snapshots/{id}/graph` | build or reuse the SCG; body `{"force":false}` |
| `GET` | `/api/snapshots/{id}/graph` | graph summary, resolution mix, coverage |
| `GET` | `/api/snapshots/{id}/modules` | modules of the snapshot |
| `GET` | `/api/snapshots/{id}/symbols` | filters: `module_id`, `file_id`, `kind`, `name`, `qualified_name`, `limit`, `offset` |
| `GET` | `/api/snapshots/{id}/symbols/{symbolID}` | one symbol plus query metadata |
| `GET` | `/api/snapshots/{id}/symbols/{symbolID}/callers` | bounded traversal, `max_depth`/`max_nodes`/`limit` |
| `GET` | `/api/snapshots/{id}/symbols/{symbolID}/callees` | bounded traversal |
| `GET` | `/api/snapshots/{id}/unresolved-calls` | call sites with no edge |
| `POST` | `/api/snapshots/{id}/graph/paths` | `{source, sink, max_paths}` over `CALLS` edges |
| `POST` | `/api/snapshots/{id}/graph/slice` | `{symbol_id\|file, include, max_lines}` |

Status codes: `400` malformed request, `403` remote source without network
permission, `404` unknown record/source, `405` wrong method, `409` conflicting
immutable write or a source that changed mid-snapshot, `413` oversized body,
`422` limit exceeded. Every error body is `{"error": "...", "code": "..."}`.

`Idempotency-Key` on `POST` replays the first response for that key
(`Idempotent-Replay: true`). The cache is **per process and in memory**; durable
exactly-once semantics belong to P7.

## Storage

SQLite is the default through `modernc.org/sqlite` (pure Go, no cgo, identical
behaviour on Linux, macOS and Windows). `internal/storage` talks to
`database/sql` and only rebinds placeholders per dialect, so pointing it at
PostgreSQL means changing the driver name and DSN:

```go
sqlStore, err := storage.OpenSQL(ctx, "postgres", dsn) // "?" -> "$1" rebinding
err = sqlStore.EnsureSchema(ctx, migrations.FS)
```

Migrations live in `migrations/` and are applied in order inside transactions;
`schema_migrations` makes reruns a no-op. Only the P1 tables exist
(`projects`, `snapshots`, `analyses`); graph, path, agent and evidence tables
arrive with the phases that use them.

## Testing

```bash
make test         # go test ./... -count=1 -shuffle=on -race -timeout 240s (identical to CI)
make test-stress  # same suite three times, for filesystem and lifecycle races
make vet
```

CI (`.github/workflows/test.yml`) runs the suite on ubuntu, macos and windows.
Tests never need the network: git fixtures are created locally, remotes are
rejected by policy, and the SQL store runs against a temporary SQLite file. Use
`t.TempDir()` and remember that frozen trees must be removed through the
repository manager, not `os.RemoveAll`.

The `.cache/` directory in this workspace is a local Go module/build cache used
only in sandboxed runs (`GOMODCACHE`/`GOCACHE` cannot write outside the
workspace). It is git-ignored and can be deleted at any time; normal
development uses the standard Go cache.

## Known gaps

- **Language coverage**: the Go frontend is the only frontend. Files in other
  source languages are listed with `unsupported_language` and counted, never
  silently dropped; adding a language means implementing `scg.Frontend` (and
  optionally `scg.Resolver`).
- **No type checking**: the Go frontend is AST-only. Interface dispatch,
  function values, reflection, calls whose receiver type cannot be inferred from
  syntax, and methods of external types are unresolved. Struct-field types and
  cross-package result types are not resolved, which is why a large share of call
  sites in a real repository are reported as `unresolved_dynamic`.
- **No dataflow**: `FLOWS_TO` and `CONTROLS` edges, local taint and constraint
  solving are later phases. A call path is reachability, not propagation.
- **Token lifecycle**: tokens are static configuration; there is no rotation,
  revocation, expiry or per-token rate limit yet, and the audit trail is a
  structured log line rather than the append-only event table of design §9.
- **Authorisation granularity**: three roles (`reader`, `writer`, `admin`) is
  coarser than a per-project ACL — a token may act on every project in the store.
- **Submodule expansion, LFS fetching, incremental (diff-based) analysis**: not
  implemented; each is stated as a limitation in the documents rather than being
  quietly absent.
- **Module path case**: `go.mod` declares
  `github.com/open-mcp-ai/Codexploit`, matching the repository name exactly as
  the go command requires. Requests for a differently cased path do not resolve;
  adopting all-lowercase would mean renaming the repository and rewriting the
  module path and every import.
