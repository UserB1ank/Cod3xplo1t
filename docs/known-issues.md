# Known issues, deviations and open gaps

This is the register of everything the current tree does **not** do, does
differently from the design, or does in a way that carries risk. It exists because
the alternative — finding out in production — is worse, and because a limitation
that is written down can be planned for.

How to read an entry:

| Field | Meaning |
|---|---|
| `GAP` | the capability does not exist yet; it belongs to a later phase or was deliberately deferred |
| `DEVIATION` | the behaviour differs from the design or the guide; the reason is recorded |
| `RISK` | the behaviour is correct as shipped but unsafe or expensive at scale |
| `DEBT` | tooling, documentation or test debt that will slow the next phase down |
| **Impact** | what actually goes wrong if it is ignored |
| **Evidence** | the file or command that shows it |
| **Action** | the smallest honest next step |

An entry is a statement about the code, not an excuse. Anything listed here has
been verified in the tree; nothing is listed from memory alone.

## Summary

| Area | Open entries | Classes |
|---|---|---|
| Repository and release tooling | 3 | `DEBT` |
| P1 snapshot chain | 0 | closed; see §9 |
| P2 source code graph | 5 | `GAP`, `DEVIATION`, `DEBT` |
| P3 attack surface | 6 | `GAP`, `DEVIATION`, `RISK` |
| P4 audit paths | 6 | `DEVIATION`, `RISK` |
| Platform and deployment | 5 | `RISK`, `DEVIATION` |
| Runtime limits and future interfaces | 8 | `GAP`, `DEVIATION`, `RISK` |

There are 33 active entries. Closed entries below retain their old identifiers.

---

## 1. Repository and release tooling

### 1.1 `DEBT` — the module path does not match the repository

- **Symptom**: `go.mod` declares `github.com/open-mcp-ai/Codexploit`, the checkout
  lives in `cod3expl1t/`, and `origin` is `https://github.com/UserB1ank/Cod3xplo1t.git`.
- **Impact**: `go get`/`go install` of the module cannot work, and published
  releases would be attributed to a path that is not where the code is. CI is
  unaffected because it builds from a checkout.
- **Evidence**: `go.mod`; `git remote -v`; `git log --oneline`.
- **Action**: decide the canonical module path and change it in one mechanical
  commit (all imports, `go.mod`, `docs/`), exactly as the earlier rename did.

### 1.2 `DEBT` — files that `AGENTS.md` points at do not exist

- **Symptom**: the agent instructions reference `docs/agents/issue-tracker.md`,
  `docs/agents/triage-labels.md`, `docs/agents/testing.md`, `docs/releasing.md`,
  `server.json`, and `make prepare-release`.
- **Impact**: every agent session that follows those instructions wastes a step
  discovering that the files and the target are missing, and the release process
  they describe cannot be run at all.
- **Evidence**: `for f in docs/agents/*.md docs/releasing.md server.json; do test -e
  "$f" || echo missing; done`; `grep -E '^[a-z-]+:' Makefile` (no
  `prepare-release`).
- **Action**: either write those documents and the target, or trim `AGENTS.md` to
  what exists. Do not leave the references dangling.

### 1.4 `DEBT` — no release workflow

- **Symptom**: nothing builds and publishes the binaries, and nothing runs the
  `server.json`/changelog checks that `AGENTS.md` describes. A release is manual
  and unreproducible.
- **Impact**: "the binary we shipped" is a claim about someone's laptop rather
  than about a tag. (The static-analysis half of this entry was closed by the CI
  `lint` job; see §10.)
- **Evidence**: `ls .github/workflows/`.
- **Action**: add a release workflow only after 1.1 and 1.2 are settled — it
  needs a canonical module path and the `server.json`/changelog files that 1.2
  lists as missing.

---

## 2. P1 snapshot chain

The registration gaps 2.1 and 2.2 are closed; see §9. Stateless snapshot and
manifest commands deliberately remain usable without a database and can be
registered explicitly with `snapshots register`.

---

## 3. P2 source code graph

### 3.1 `GAP` — no dataflow edges

- **Symptom**: `FLOWS_TO` and `CONTROLS` are declared in the model but never
  produced; the frontend builds an AST-only call graph.
- **Impact**: nothing downstream can order paths by data propagation. This is the
  single largest capability gap in the product, and every later phase works around
  it by saying "reachability, not dataflow".
- **Evidence**: `internal/scg/model.go` (edge kinds), `internal/scg/gofrontend/`
  (no dataflow pass), `docs/scg.md`.
- **Action**: treat dataflow as its own project (a solver or a taint engine), with
  its own evidence class, rather than extending the rule tables.

### 3.2 `DEVIATION` — the Go frontend does not type-check

- **Symptom**: resolution is name- and package-based; calls on external or unknown
  receiver types stay `unresolved_dynamic`, and framework attribution has to guess
  from receiver provenance.
- **Impact**: a share of call sites has no target, so some sinks and controls are
  invisible. On the repository used for the P3/P4 smoke tests, 20 of 25 call sites
  in the fixture were unresolved (10 external, 10 dynamic) — a small fixture that
  is unusually dependency-heavy, but the direction is real.
- **Evidence**: `internal/scg/gofrontend/frontend.go`; the coverage block printed by
  `codexploit scg build`.
- **Action**: index field and variable types (`unresolved_dynamic` is the largest
  bucket), or add `go/types` in a mode that tolerates missing dependencies. Both
  are analysis work with measurable output: the unresolved share must drop.

### 3.3 `GAP` — one language only

- **Symptom**: `internal/scg/gofrontend` is the only frontend; Python, JavaScript,
  Java and C/C++ are not parseable.
- **Impact**: the product only sees Go repositories. The design explicitly
  suggests proving the loop on one language first, so this is planned rather than
  accidental.
- **Evidence**: `internal/scg/frontend.go` (registry), `internal/app/app.go`
  (registered frontends).
- **Action**: add the second frontend only after the P5/P6 loop closes on Go;
  another frontend now would double the unresolved-call problem instead of
  fixing it.

### 3.4 `GAP` — no incremental analysis

- **Symptom**: every snapshot builds a complete graph; there is no change-impact
  analysis and no cross-commit cache reuse.
- **Impact**: large repositories pay full cost per commit, and the design's
  "unchanged files may still be affected by cross-module changes" caveat applies in
  full.
- **Evidence**: `internal/scg/builder.go` (no diff input), `internal/graph`
  (cache key includes the snapshot, so nothing is reused across snapshots).
- **Action**: implement dependency-impact analysis before any incremental cache;
  a cache keyed on file hashes alone would be wrong for cross-module changes.

### 3.5 `DEBT` — `internal/graph` reports low coverage because its tests live elsewhere

- **Symptom**: a package-local `-cover` result omits executions from other packages.
  The graph layer now has direct tests, while some query/adapter integration
  coverage also comes from `internal/asg` and `internal/path` tests.
- **Impact**: the number invites the wrong conclusion ("the query layer is
  under-tested") and hides real gaps in the coverage report used for review.
- **Evidence**: `go test ./internal/graph/ -cover` versus
  `internal/asg/extract_test.go` (`TestASGQueryServiceExposesTheRouteTable`).
- **Action**: either measure coverage across packages
  (`-coverpkg=./internal/...`) when reporting, or move the service-level tests next
  to the code they test.

---

## 4. P3 attack surface

### 4.1 `DEVIATION` — `REACHES` is call-graph reachability, not dataflow

- **Symptom**: an ASG `REACHES` edge means the handler can reach the sensitive
  operation within the reachability budget. It is marked `inferred` and every
  document and path states that propagation is not established.
- **Impact**: some paths are noise (the input never reaches the sink) and some are
  missed (the sink is reached through a call the graph could not resolve). The
  number of paths an audit queues is therefore not a measure of risk.
- **Evidence**: `internal/asg/extract.go` (`walkReachability`),
  `docs/asg.md` ("What P3 does not do").
- **Action**: none in P3 — this is the designed evidence class. It is listed here so
  that no later phase treats a path count as a severity.

### 4.2 `DEVIATION` — control presence is not effectiveness

- **Symptom**: a `SecurityControl` node records that a control exists
  (registration, reachable call, literal with placeholders). Nothing analyses
  ordering, coverage, bypass branches or configuration.
- **Impact**: `PROTECTED_BY` is not a mitigation claim; a reviewer must not read a
  protected path as a safe one.
- **Evidence**: `internal/asg/extract.go` (`controlFrom`,
  `parameterizationControl`), `docs/asg.md`.
- **Action**: an effectiveness question needs a slice plus an agent or a solver, and
  it belongs to the verification phase, not to a rule.

### 4.3 `RISK` — one sink rule is name-based and can be wrong

- **Symptom**: `sink:sensitive_output` fires on print/log calls whose arguments
  mention secret-like words (`password`, `token`, `key`, …). It is marked
  `inferred` and flagged `heuristic`.
- **Impact**: false positives inflate the queue; false negatives miss a real secret
  log. Both directions are possible.
- **Evidence**: `internal/asg/rules.go` (`DefaultSinkRules`, last entry),
  `internal/asg/extract_test.go`.
- **Action**: keep it flagged, and replace it with a dataflow-backed rule when 3.1
  exists. Do not tune the word list as a substitute.

### 4.4 `GAP` — framework attribution can be unknown

- **Symptom**: a route-shaped registration is attributed to a framework only when
  the receiver's provenance or the resolved package is visible; otherwise the entry
  point records `framework_attribution: unknown` and lists candidate frameworks.
- **Impact**: entry points are still discovered, but their handler chain and
  middleware story is weaker, and the entry can be under-scored (the exposure
  feature falls back to the neutral value).
- **Evidence**: `internal/asg/extract.go` (`entryPointFrom`).
- **Action**: field-type indexing (see 3.2) would resolve most of these; until
  then, the honest `unknown` label must stay.

### 4.5 `GAP` — assets and secrets come only from literals

- **Symptom**: tables, paths, commands, endpoints and the sensitive-output rule
  need a string literal in the call; a value assembled at runtime yields no asset.
- **Impact**: the asset side of the graph is sparse on real code, and `MAY_AFFECT`
  under-reports.
- **Evidence**: `internal/asg/extract.go` (`sinkFrom`, `sqlTables`).
- **Action**: constant propagation for the common cases (adjacent string
  concatenation, package-level constants) is a bounded improvement; full dataflow
  is 3.1.

### 4.6 `GAP` — no MCP surface for the attack surface or paths

- **Symptom**: the MCP server exposes nine read-only graph tools and nothing for
  the ASG or AuditPath; the design suggests `find_dataflow_paths`,
  `get_attack_path(path_id)` and `get_evidence(evidence_id)`.
- **Impact**: the P5 agent cannot read a path over MCP; it would have to go through
  the REST API or a bespoke adapter.
- **Evidence**: `internal/mcp/server.go` (tool list), `docs/mcp-tools.md`.
- **Action**: add read-only `list_attack_surfaces`, `get_attack_path` and
  `list_audit_paths` tools when P5 starts; `get_evidence` needs the evidence store
  from P6.

---

## 5. P4 audit paths

### 5.1 `DEVIATION` — the event endpoint is a bounded page, not a stream

- **Symptom**: `GET /api/audits/{id}/events` returns a JSON page ordered by
  audit-scoped sequence. The design lists it as SSE.
- **Impact**: no live progress in a UI; a client polls with `after_seq`, which is a
  resumable cursor.
- **Evidence**: `internal/api/audit.go`, `docs/api.md` ("Audits and paths (P4)").
- **Action**: add SSE together with the WebUI, when there is a consumer that needs
  push rather than poll. The event log can already serve both.

### 5.2 `DEVIATION` — `reclaim-expired` sweeps the whole store

- **Symptom**: `path.Service.ReclaimExpired` recovers expired leases across every
  audit; the route validates one audit and reports that audit's recoveries plus the
  store-wide total.
- **Impact**: a scheduled sweep can affect audits the caller did not name, which is
  intended for a scheduler but surprising for a per-audit endpoint.
- **Evidence**: `internal/path/service.go` (`ReclaimExpired`),
  `internal/api/audit.go` (`handleReclaimExpired`).
- **Action**: keep the store-wide sweep for the scheduler and add an audit-scoped
  variant if per-audit recovery is ever needed; document the current behaviour
  (done).

### 5.3 `DEVIATION` — claiming through a path id leases the audit's next pick

- **Symptom**: `POST /api/audits/{id}/claim` (canonical) and
  `POST /api/paths/{id}/claim` (alias) both lease the scheduler's next pick for the
  audit. The path id in the alias only identifies the audit, so the leased path may
  differ from the id in the URL. The answer carries the leased path.
- **Impact**: a worker that wants to retry one specific path cannot ask for it; it
  must release and hope the picker returns it. The audit-scoped route exists to
  remove the ambiguity, but the alias remains for convenience.
- **Evidence**: `internal/api/audit.go` (`handleClaimAudit`, `handleClaimPath`),
  `internal/api/audit_test.go` (`TestClaimIsAuditScopedThroughBothRoutes`).
- **Action**: add a path-scoped claim (`Store.ClaimPath` already supports it) when
  a worker runtime needs deterministic re-claiming; that is P5 work.

### 5.4 `RISK` — dropping a path from a generation drops its score history

- **Symptom**: `ReplacePaths` replaces an audit's paths atomically. Score snapshots
  of paths that survive are kept; snapshots of paths that leave the generation are
  deleted with them, because their sequence numbers would otherwise collide when a
  path returns under different limits.
- **Impact**: after changing limits, the historical ranking of a removed path is
  gone; only live paths keep their full score history.
- **Evidence**: `internal/storage/audit_common.go`, `internal/storage/sql_audit.go`,
  `docs/audit-paths.md` (storage details).
- **Action**: if history must outlive a generation, key score snapshots by
  `(path_id, generation)` instead of `(path_id, seq)` and never delete them.

### 5.5 `RISK` — the score weights are uncalibrated

- **Symptom**: the coefficients are the documents' initial heuristics, marked as
  subject to calibration; nothing validates them against known findings.
- **Impact**: priorities order attention, not expected value. A biased weight can
  starve a whole class of weakness.
- **Evidence**: `internal/path/score.go` (weight tables), `docs/audit-paths.md`.
- **Action**: build a benchmark corpus with known findings and calibrate; the
  exploration reserve (15%–25%) is the current mitigation, not a substitute for
  measurement.

### 5.7 `RISK` — the in-memory store is unbounded

- **Symptom**: `storage.Memory` keeps snapshots, graphs, ASGs and audits in maps
  with no capacity limit or eviction.
- **Impact**: a long-lived server started with `--db memory` grows without bound.
  The SQLite path is bounded by the file.
- **Evidence**: `internal/storage/memory.go` (`struct Memory`), `memory_audit.go`.
- **Action**: memory mode is for tests and demos; if it is ever offered as a server
  mode, add an explicit cap and document that it is not durable.

---

## 6. Platform and deployment

### 6.1 `RISK` — PostgreSQL is anticipated but never exercised

- **Symptom**: the SQL layer has a dialect switch (`s.postgres`, `isPostgresDriver`,
  `rebind`), but the application wiring selects only the SQLite driver, the
  migrations are written for SQLite, and no test or CI job runs PostgreSQL.
- **Impact**: "switchable to PostgreSQL" is an assumption, not a tested property.
  Anyone switching will hit placeholder, type and migration-dialect issues.
- **Evidence**: `internal/storage/sql.go` (`isPostgresDriver`), `internal/app/app.go`
  (`SQLiteDriver`), `grep -rn postgres go.mod` → no driver dependency.
- **Action**: either add a PostgreSQL job to CI with driver-specific coverage and
  dialect-aware migrations, or state plainly in the README that PostgreSQL is not
  supported yet. Do not leave it implied.

### 6.2 `RISK` — no TLS and no rate limiting

- **Symptom**: the server calls `ListenAndServe`; there is no TLS configuration, no
  request throttling and no per-client quota.
- **Impact**: the binary must sit behind a terminating proxy; exposed directly it
  speaks plaintext HTTP and accepts unbounded request rates.
- **Evidence**: `cmd/server/main.go`, `internal/api/server.go` (no TLS or limiter).
- **Action**: document the deployment contract (terminate TLS and rate-limit at the
  proxy) and add a request limit if the server is ever exposed directly.

### 6.3 `RISK` — one capability per token, no per-project authorization

- **Symptom**: capabilities are `read`/`write`/`admin` globally; any writer can
  touch any project, snapshot, audit or path.
- **Impact**: multi-tenant use is impossible to reason about; a leaked write token
  is a full-workspace write.
- **Evidence**: `internal/api/auth.go` (capability table), `internal/api/server.go`
  (capability check only).
- **Action**: introduce a project scope on tokens before any multi-tenant
  deployment; the capability check is the single place that has to change.

### 6.4 `DEVIATION` — `--insecure-anonymous` grants write, never admin

- **Symptom**: the flag grants anonymous `CapWrite` (and therefore `CapRead`);
  anonymous admin is rejected at startup.
- **Impact**: a development convenience that would be a real vulnerability if used
  in production; it is refused for admin, and the startup path logs it.
- **Evidence**: `internal/api/auth.go` (`WithAnonymousAccess`), `cmd/server/main.go`
  (`buildAuthenticator`).
- **Action**: none, provided it stays documented as development-only — which it is,
  in the README and `docs/api.md`.

### 6.5 `RISK` — expired idempotency claims are purged only on the write path

- **Symptom**: `PurgeExpiredIdempotency` is called from `withIdempotency`, so a
  workspace that stops receiving writes keeps expired rows indefinitely.
- **Impact**: dead rows accumulate; nothing is served incorrectly, because reads of
  an expired claim are treated as absent.
- **Evidence**: `internal/api/server.go` (purge call inside `withIdempotency`),
  `internal/storage/idempotency.go`.
- **Action**: add a periodic sweeper (or purge on read) if the table's growth ever
  matters; the TTL keeps the window bounded today.

---

## 7. Runtime limits and future interfaces

| # | Class | Gap | Why it matters |
|---|---|---|---|
| 7.1 | `DEVIATION` | **P5 is implemented** but two pieces are deferred by design: expansion requests are decided by policy inside the run rather than approved by an operator, and adapters cannot be network-sandboxed by Go alone (the deployment contract is a restricted container/VM). See `docs/agent-runtime.md` | the design's `EXPAND_REQUEST` approval flow assumed an operator in the loop; recording every decision in the run events keeps it auditable, and isolation remains an operational requirement |
| 7.1b | `GAP` | MCP exposes no run, hypothesis or attack-path tools; the agent's own tool access is the orchestrator's registry, not MCP | an external agent or UI cannot read runs/hypotheses over MCP; REST covers it for now | `internal/mcp/server.go` |
| 7.1c | `RISK` | A run's tool results are truncated (20 000 characters) and its slice is bounded (240 lines), so an agent can reason from incomplete evidence | a conclusion drawn from a truncated slice can be wrong; every truncation is recorded in the result and the task carries the upstream limitations | `docs/agent-runtime.md`, `internal/agent/protocol.go` (`MaxToolResultChars`) |
| 7.2 | `DEVIATION` | **P6 is implemented**, with four recorded limits: no exploit synthesis (a plan is built from path evidence; a real PoC is supplied as an explicit plan), Go cannot network-sandbox a subprocess (the deployment contract is a restricted container/VM), severity stays the hypothesis's hint rather than a verified model, and verification has no worker queue (it is requested per hypothesis) | a `confirmed` finding is reproduced, `refuted` needs contradicting evidence, and `inconclusive`/`blocked` are not refutations — those distinctions are enforced in code; the limits are operational |
| 7.3 | `GAP` | HTML report rendering is not implemented; P6 evidence, findings and Markdown/JSON/SARIF reports are implemented | add HTML only when an export consumer needs it; see `internal/verify/report.go` |
| 7.4 | `GAP` | Incremental analysis, dependency-impact caching and benchmark calibration (P7) | full rebuilds per commit and uncalibrated weights are the two costs that grow fastest |
| 7.5 | `GAP` | WebUI (design §12): SCG/ASG views, path workbench, agent monitoring, finding centre, reports | all read-only APIs it needs exist; the ASG route table and the path queue are already shaped for it |
| 7.6 | `GAP` | Process plugin v1 ships one deployment-installed first-party Go pattern scanner; CodeQL/Semgrep/OSV are not bundled, installation is a deployment directory rather than an HTTP upload, plugin events are transport-only (not restarted), and the adapter cannot enforce network isolation (`network=restricted` returns unsupported) | the boundary and limits are exercised end to end, but third-party/worker coverage and approved network execution remain later work; see `docs/process-scanner.md` |

---

## Maintaining this file

- Add an entry when a capability is deferred, when the implementation deviates from
  the documents, or when a real limitation is discovered during verification. Every
  entry needs **evidence** (a file, a command, a measured number) and a **next
  action** that a later phase can pick up.
- Remove an entry in the same change that closes it, and say so in the commit
  message. An entry that quietly outlives its fix is worse than no entry.
- Keep the class honest: a designed evidence class is a `DEVIATION`, not a bug; an
  uncalibrated heuristic is a `RISK`, not a `GAP`.

## 8. Closed by P7 (scheduling and fault recovery)

Two entries above were closed by the P7 work; they are listed here rather than
silently deleted, so a reader of an older report knows where they went:

- **5.3 (path-scoped claim)** — closed. `AgentCoordinator.ClaimSpecificPath` and
  `agent.Runner.RunPath` claim and execute a *named* path, which is what a scheduler
  needs; the audit-scoped route remains the canonical HTTP spelling for a queue pick,
  and the path route is still documented as an alias.
- **5.6 (no worker loop, no retry policy)** — closed. `internal/schedule` runs the
  loop, retries are bounded and deferred through `audit_paths.next_attempt_at`,
  cancelled paths are never retried, and `Run` releases its leases when it stops.

Still open from that list, and now recorded as such: no distributed coordination
beyond lease safety, no incremental analysis or change-impact cache, no score
calibration, and no MCP surface for paths, runs or findings.


## 9. Closed by the snapshot lifecycle and concurrency fixes

- **2.1 / 2.2 — CLI/API snapshot registration**: persistent CLI builds and API
  snapshot creation use the same repository-derived project registration.
  `snapshots register` (alias `import`) registers historical/stateless snapshots
  and manifests explicitly. Existing project names are preserved.
- **LR-01 — audit active-lease ceiling**: `Store.ClaimPath` checks the audit's
  active count atomically with the claim/event in Memory and SQLite, including
  independent SQLite connections. Lease renewal does not spend another slot.
- **LR-03 / LR-04 — deletion consistency and recovery**: CLI and API share
  `lifecycle.Snapshots.Remove`. A durable pending marker survives cleanup errors
  and restarts. Unfinished work is refused, completed tombstones reject late
  writes, and explicit materialized re-registration permits rebuilding.
- **LR-05 — concurrent project updates**: versioned storage CAS makes a stale
  concurrent PATCH return 412 and returns the exact updated project/ETag.

Evidence: `internal/lifecycle/snapshots_test.go`, `internal/api/lifecycle_test.go`,
`internal/graph/claim_budget_test.go`, `internal/storage/lifecycle_test.go`,
`cmd/cli/lifecycle_test.go`, and migration `0010_snapshot_lifecycle.sql`.
The original observations and proposed scope are retained in
[the dated review](legacy-review-2026-10-16.md).

## 10. Closed by the CI lint gate

- **1.3 — the formatting gate scanned ignored workspace caches**: closed. The gate
  is `make fmt-check`, which formats the Go files `git ls-files` returns, so a
  git-ignored `.cache/gomod` (dependency fixtures that are intentionally not
  parseable) can no longer fail it, and a formatter error is propagated as a
  non-zero exit instead of hiding behind an empty diff.
- **1.4 — no lint job**: the static-analysis half is closed by the same change.
  The `lint` job runs `make lint` on ubuntu: `make fmt-check`, `go vet`, and
  Staticcheck `v0.8.2`, pinned in the Makefile and resolved with `go run` so it
  never enters this module's graph. The 17 findings on the pre-change tree were
  fixed rather than suppressed —
  - dead private code removed: `(*Graph).normalize`,
    `(*symbolIndex).packagesSorted`, `resolvedTarget`, `unresolved`,
    `asgToolMeta`, `(RunStatus).running`, `(FrameworkRule).isMiddlewareMethod`,
    `asgEdgeOf`, `fakeStore.failNext`, and the stale `idempotencyTTL` /
    `maxIdempotencyEntries` constants (`defaultIdempotencyTTL` is the one in
    force);
  - `tar.TypeRegA` dropped from a read path, where `archive/tar` already
    normalises it to `tar.TypeReg` (`reader.go`, `next`);
  - the redundant same-type assertions removed in `cmd/mcp/main.go` and
    `internal/asg/extract_test.go`;
  - `runnerErrNotConfigured` renamed to `errRunnerNotConfigured`;
  - a copy loop replaced with `append(notes, slice.Limitations...)`;
  - the unused `out` in `TestSchedulerCLIRun`'s follow-up command discarded.

Evidence: `.github/workflows/test.yml` (`lint` job), `Makefile` (`lint`,
`fmt-check`, `staticcheck`), `docs/testing.md`.
