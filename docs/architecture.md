# Codexploit architecture

The target extensible architecture and ARTEX-inspired interactive prototype are
documented in [layered interfaces v1](design/interfaces/v1/README.md). That design
covers explicit source types, plugin workflows and an independent PostgreSQL
data service. It distinguishes target interfaces from the implemented system
described below. The design prototype is available at `/prototype/` after building.

How the implemented system is put together: the pipeline, what each package is
responsible for, what is stored where, which way dependencies point, and where
configuration is wired. Interface references live in [`api.md`](api.md) (REST)
and [`mcp-tools.md`](mcp-tools.md) (MCP tools); the graph model itself is in
[`scg.md`](scg.md).

The module path is `github.com/open-mcp-ai/Codexploit`.

## Pipeline

```text
source (git URL | local git | plain directory)
        │  internal/repository: resolve, pin to an immutable revision, count and
        │  explain every skipped file, materialise and freeze a read-only tree
        ▼
snapshots/<snapshot-id>/repo        + snapshot.json           (immutable)
        │  internal/analysis: detectors produce observations with evidence
        ▼
snapshots/<snapshot-id>/repository_manifest.json              (immutable)
        │  internal/scg: discovery → parse → index → resolve
        ▼
snapshots/<snapshot-id>/scg-<graph-version>-<hash>.json       (immutable)
        │  internal/storage: persisted relationally for queries
        ▼
internal/graph: bounded, provenance-carrying queries
        │
        ├── internal/api   → REST over HTTP
        └── internal/mcp   → read-only tools over stdio
```

Each stage consumes the previous stage's artifact and never re-derives it. A
snapshot can be frozen without a manifest (`snapshot`), and a graph is built only
for a snapshot that already exists (`scg build` produces snapshot + manifest +
graph in one command). The Attack Surface Graph (ASG) phase derives the security
semantics from the SCG: entry points, attacker-controlled inputs, trust
boundaries, security controls, sensitive operations and the assets they touch,
plus bounded call-graph reachability between them. It is rule-based and derived —
it reads the SCG and never writes to it — and every node and edge records the SCG
facts it came from. The semantic-agent and verification layers that attach
hypotheses and confirmed results are later phases. See [`asg.md`](asg.md).

The AuditPath engine turns that attack surface into scheduled work: bounded
candidate enumeration over observed call chains, exact dedup by canonical edge
sequence, approximate clustering by entry/target/boundary, a versioned
risk/value/utility score, and a queue with leases, heartbeats, an audit-scoped
event log and a state machine. Paths are reproducible — ids and scores are derived
and the score carries its weights and feature snapshot — and each states its
evidence class instead of asserting exploitability. See
[`audit-paths.md`](audit-paths.md).

The agent runtime (P5) then analyses one scheduled path at a time: a bounded task
carrying a minimal code slice and the facts already established, a read-only tool
allowlist enforced in Go, an expansion policy the orchestrator decides, and a
structured answer that may only claim a candidate hypothesis with cited evidence.
Runs, their event logs and the resulting hypotheses are stored; nothing about an
agent's internal reasoning is. See [`agent-runtime.md`](agent-runtime.md).

## Package map

| Package | Responsibility | Must not | Called by |
|---|---|---|---|
| `internal/lifecycle` | Shared snapshot/project registration, manifest persistence and recoverable filesystem/store deletion | never invent records on reads; never discard the recovery marker before cleanup finishes | `internal/app`, `internal/api`, `cmd/cli` |
| `internal/repository` | P1 snapshot chain: source resolution (git URL, local git, directory), commit pinning, submodule/dirty/LFS/symlink accounting, deterministic `snapshot_id`, overlay of limits and ignore rules, freeze/unfreeze, artifact writes, snapshot list/remove | never modify or analyse the user's working copy; never run repository code; never fetch LFS content or expand submodules | `internal/app`, `internal/analysis`, `internal/scg`, `internal/graph`, `internal/api`, `internal/storage` |
| `internal/analysis` | P1 repository manifest: a bounded, read-only view of the frozen tree (`Input`), a pluggable `Detector` registry, coverage accounting, confidence classes, unknowns | never execute code, never read outside the snapshot tree, never exceed the per-file read limit, never state a fact without evidence | `internal/app`, `internal/api`, `internal/scg` (reuses `LanguageRules`) |
| `internal/scg` | P2 Source Code Graph model, content-derived ids, module discovery, the frontend/registry contracts, call resolution and deterministic serialisation | never guess a target: every unresolved construct keeps its call site and its resolution class; `FLOWS_TO`/`CONTROLS` are declared but not produced | `internal/app`, `internal/storage`, `internal/graph`, `internal/api` |
| `internal/scg/gofrontend` | The only language frontend: Go, parsed with `go/parser` (AST only, no type checking), including the call resolver | never type-check, build or download anything; never invent a symbol outside the snapshot index | `internal/app` (registered by default); through the `scg.Frontend` interface, only `internal/scg` |
| `internal/graph` | P2 graph service: snapshot-scoped bounded queries (summary, modules, files, symbols, callers/callees, call paths, code slices), budgets, truncation reporting, in-memory result cache; plus the ASG query service and the adapters the ASG and path engines read through | never mix snapshots, never return a partial answer without `truncated`/`truncation_reason`, never treat "depth reached" as truncation | `internal/app`, `internal/api`, `internal/mcp` |
| `internal/asg` | P3 attack surface: the ASG document model, the rule tables (frameworks, sources, sinks, controls, assets), bounded reachability, the extractor and its builder, and the validation that rejects any claim without SCG evidence | never overwrite an SCG fact, never emit `SUPPORTED_BY`/`VERIFIED_BY`/`Hypothesis` (later phases), never assert that a control is effective | `internal/app`, `internal/graph` (as a store document), `internal/storage` (implements the ASG store in terms of its types) |
| `internal/agent` | P5 agent runtime: the task and answer protocol (strict JSON, length caps, no reasoning transcript), run/event/hypothesis model, deterministic and subprocess adapters, and the orchestrator that owns the lease, the budget, the deadline and the tool gate | never let an adapter widen its own allowlist, budget or deadline; never store a reasoning transcript; never accept `confirmed` from an agent | `internal/graph` (implements the facts/tools/coordinator), `internal/storage` (implements the store), `internal/app`, `internal/api`, `cmd` |
| `internal/verify` | P6 verification: plan validation and approval/scope gates, verdict derivation that refuses to overstate, immutable content-addressed (and redacted) evidence, findings, executors (scripted, restricted CLI, unsupported) and the report renderers | never let an executor decide a verdict, never store unredacted output, never invent an approval, never expose the host container socket | `internal/graph` (builds plans), `internal/storage` (implements the store), `internal/app`, `internal/api`, `cmd` |
| `internal/schedule` | P7 scheduler: the resident loop that reclaims expired leases, dispatches due paths under a concurrency budget, defers failures with a durable backoff, and exposes the metrics this layer owns | never dispatch a path it does not hold a lease on, never retry a cancelled path, never busy-loop, never widen a run's policy | `internal/app`, `internal/api`, `cmd` |
| `internal/path` | P4 AuditPath engine: bounded candidate enumeration, exact dedup by canonical edge sequence, approximate clustering, versioned scoring with a stored feature snapshot, the state machine, the marginal-coverage picker and the audit service | never claim dataflow, never make a path without evidence refs, never write an illegal transition, never let a score lose its version or its reasons | `internal/app`, `internal/storage` (implements `path.Store`), `internal/graph` (provides the readers) |
| `internal/storage` | Persistence: `Store` (projects, snapshots, manifests), `GraphStore` (SCG documents, relationally), `ASGStore` (attack-surface documents), `AuditStore` (audits, paths, score snapshots, events; an alias of `path.Store`), `IdempotencyStore` (durable write claims), the migration runner, in-memory and `database/sql` implementations | never choose a driver (the caller passes one), never interpret an artifact beyond comparing identity, never overwrite an immutable record with different content | `internal/app`; through `app.Runtime`, `internal/api`, `internal/mcp` |
| `internal/api` | REST adapter: routing, request decoding and body limits, capability-based authentication, `Idempotency-Key` handling, ETag/If-Match, JSON error mapping | contains no analysis logic and no driver choice; never exposes a route without a capability rule | `cmd/server` |
| `internal/mcp` | MCP adapter: nine read-only graph tools, argument validation, error classification, provenance block | no writes, no shell, no arbitrary file access, no free-form query language | `cmd/mcp` |
| `internal/app` | Composition root: the single place where the SQLite driver, the migration set, the frontends, the store, the graph service, the attack-surface service and the path engine are chosen and wired | must stay free of HTTP and CLI concerns | `cmd/cli`, `cmd/server`, `cmd/mcp` |
| `cmd/cli` | Developer entry point: `manifest`, `snapshot`, `snapshots list\|remove`, all `scg` subcommands; human summaries or `--json` | does not own a database (stateless commands use an in-memory store; `scg` commands open the file store) | operator |
| `cmd/server` | REST process: flags, authentication construction, HTTP server timeouts, graceful shutdown | does not build tokens from anywhere but flags or `CODEXPLOIT_API_TOKENS` | operator |
| `cmd/mcp` | stdio MCP process: flags, refuses any transport but stdio, logs to stderr so the protocol stream on stdout stays clean | never opens a listening socket | MCP client |
| `migrations` | The SQL schema as Go-embedded `*.sql` files, applied in order | — | `internal/app` via `storage.EnsureSchema` |

## Storage schema

`migrations/` is embedded at build time (`migrations/embed.go`) and applied in
lexicographic order by `internal/storage`. One line per table:

| Migration | Table | Holds |
|---|---|---|
| `0001_init.sql` | `projects` | one audited repository: id, display name, source, identity kind and value, timestamps |
| `0001_init.sql` | `snapshots` | snapshot record: id, owning project, commit, VCS, dirty flag, creation time, the full metadata document, and the manifest document once analysed |
| `0001_init.sql` | `analyses` | analysis identity: id, snapshot, engine, engine version, ruleset hash, config hash, and the manifest document |
| `0002_scg.sql` | `graph_builds` | one row per snapshot: graph version, engine, frontends, counts, coverage/limitations/resolution/edge-kind JSON, build time and duration |
| `0002_scg.sql` | `scg_modules` | modules of a snapshot: path, declared name, language, manifest file, file/symbol/line counts |
| `0002_scg.sql` | `scg_files` | files of a snapshot: module, path, language, size, lines, parse status and parse error |
| `0002_scg.sql` | `scg_symbols` | declarations: module, file, kind, name, qualified name, signature, receiver, result type, export flag, line/column span |
| `0002_scg.sql` | `scg_call_sites` | call expressions, resolved or not: caller, position, callee text, target, resolution, confidence, detail, analyzer provenance |
| `0002_scg.sql` | `scg_edges` | relationships: from/to ids, kind, resolution, confidence, source location, analyzer, call site id, detail JSON |
| `0003_idempotency.sql` | `idempotency_keys` | durable write claims: `(scope, key)` primary key, request hash, principal, status (`0` = still running), stored response, creation and expiry |
| `0004_call_site_arguments.sql` | `scg_call_sites.args_json`, `scg_call_sites.receiver_from` | P3 call-site argument facts: literals, symbol references, expressions, and the receiver's provenance |
| `0005_attack_surface.sql` | `asg_builds`, `asg_nodes`, `asg_edges` | the attack-surface document, replaced as a whole per snapshot and deleted with it |
| `0009_retry_schedule.sql` | `audit_paths.next_attempt_at` + its index | P7 retry timing: a failed attempt is deferred durably instead of being retried immediately, and the scheduler never sleeps while holding a lease |
| `0008_verification.sql` | `verification_runs`, `evidence`, `findings` | P6 verification attempts keyed by `(hypothesis_id, plan_hash)` so a rerun replays, append-only content-addressed evidence with a `supersedes` link, and one finding per hypothesis with its three evidence lists |
| `0007_agent_runtime.sql` | `agent_runs`, `agent_events`, `hypotheses` | P5 agent runs (task, policy, consumed budget, lease, stop reason, answer), per-run append-only event log, and claims keyed by `(path_id, digest)` with support/contradiction lists |
| `0006_audit_paths.sql` | `audits`, `audit_paths`, `path_features`, `path_events` | P4 audits, their paths (steps, signature, cluster, evidence, score, lease), append-only score snapshots and the audit-scoped event log |
| created by the runner | `schema_migrations` | applied migration versions, so a rerun is a no-op |

The DDL is deliberately dialect-neutral (`TEXT`/`INTEGER`/`BIGINT`, timestamps as
fixed-width RFC3339 UTC strings), so the same files run on SQLite and PostgreSQL.
The graph is stored relationally because queries filter and traverse it by id and
kind; the full documents (snapshot metadata, manifest, SCG artifact) stay as JSON
text and on disk next to the frozen tree. Later phases add their own tables in
their own migrations; an unused table is a promise the code does not keep yet.

`ReplaceGraph` is the only graph write: it replaces one snapshot's graph inside a
single transaction, so a rebuild is idempotent and a reader never sees a
half-written graph. Every graph read is scoped to one snapshot id.

## Layering rules

Dependencies point in one direction — from adapters and composition toward facts
and storage — and the import graph contains no cycle:

```text
repository          (no internal imports)
   ▲
analysis            imports repository
   ▲
scg                 imports analysis, repository
   ▲
storage             imports scg, analysis, repository
   ▲
graph               imports storage, scg, repository
   ▲
api, mcp            import graph, storage, scg, (api: analysis, repository)
   ▲
app                 imports all of the above; cmd/* import app (+ api for the server)
```

The rules behind that order:

- **`scg` is the fact layer.** It produces statements about source code and
  carries provenance for each one. It does not know about HTTP, SQL, CLI flags
  or agents: those are consumers.
- **`scg` reuses `analysis.LanguageRules`** so the manifest and the graph agree on
  what a file is; that is why the fact layer depends on the analyzer rather than
  duplicating the extension table.
- **`storage` depends on `scg`** because persisting a graph means understanding
  its model (modules, files, symbols, call sites, edges). The reverse — `scg`
  importing `storage` — would make the model depend on a database, so it is
  forbidden.
- **`graph` depends on `storage` and `scg`, never on `api` or `mcp`.** Same
  queries serve both adapters; if the service knew about HTTP it could not serve
  stdio.
- **`api` and `mcp` are adapters, not layers of truth.** They decode input,
  enforce capability and budget rules, and delegate. Neither contains analysis
  logic.
- **`app` is the only composition root**, so there is exactly one place that
  chooses a driver, a migration set and a frontend set.

## Configuration wiring

`internal/app` (`app.Build`) is the only place where components are constructed:

| `app.Config` field | Effect |
|---|---|
| `Workspace` | snapshot root; required, made absolute |
| `DBPath` | `""` or `memory` selects the in-process store, any other value a SQLite file (its directory is created, the schema is migrated) |
| `AllowNetwork` | forwarded to the repository manager: remote git URLs are refused without it |
| `GitBin` | overrides the git executable |
| `Freeze` | `*bool`; the tree is made read-only unless a caller explicitly disables it |
| `Limits` | repository limits (see `docs/contracts.md`) |
| `Analysis` | analyzer read/package limits |
| `Frontends` | SCG frontends; the Go frontend is registered when empty |
| `BuildLimits` | graph build budgets |

`Build` returns an `app.Runtime` bundling `Store` (`storage.FullStore`),
`Manager`, `Analyzer`, `Builder`, `Graph` and `Workspace`, and `Close` releases
what it opened (the SQL store). The two failure modes are deliberate: a SQLite
database that cannot be opened or migrated fails startup, and a workspace that
cannot be created fails startup — a runtime that cannot freeze a snapshot must
not pretend to be usable.

The SQL driver name (`app.SQLiteDriver`, `"sqlite"`) and the embedded migration
set are compiled in, so `cmd/cli`, `cmd/server` and `cmd/mcp` share identical
storage behaviour. `cmd/server` adds only the pieces the CLI does not have:
authenticator construction from flags or `CODEXPLOIT_API_TOKENS`, the
idempotency TTL, HTTP timeouts and graceful shutdown.
