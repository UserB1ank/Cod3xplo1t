# Codexploit contracts

Every invariant this codebase enforces, and the file that enforces it. These are
not style preferences: changing one of them is an identity, schema or security
change. Read [`architecture.md`](architecture.md) for where the components sit
and [`scg.md`](scg.md) for the graph model in full.

Paths below are relative to the repository root.

## 1. Deterministic identity

| Identity | Formula | Enforced in |
|---|---|---|
| `snapshot_id` | `sha256("codexploit/snapshot/v1", identity.kind, identity.name, commit, submodule_state…)`, length-prefixed, `snap-` + 32 hex chars | `internal/repository/id.go` |
| `analysis_id` | `sha256("codexploit/analysis/v1", snapshot_id, engine, engine_version, ruleset_hash, config_hash)`, `analysis-` + 32 hex chars | `internal/repository/id.go`, inputs from `internal/analysis/analysis.go` |
| `project_id` | `sha256(identity_kind, identity)`, `proj-` + 16 hex chars | `internal/api/server.go` |
| `module_id` / `file_id` | `sha256(domain, snapshot_id, canonical path)`, `mod-` / `file-` + 32 hex chars | `internal/scg/id.go` |
| `symbol_id` | `sha256("codexploit/scg/symbol/v1", snapshot_id, language, canonical file, qualified_name, signature, "line:col")`, `sym-` + 32 hex chars | `internal/scg/id.go` |
| `call_site_id` | `sha256(domain, snapshot_id, file, line:col, callee text)`, `cs-` + 32 hex chars | `internal/scg/id.go` |
| `edge_id` | `sha256(domain, from, to, kind, file, line:col, call_site_id)`, `edge-` + 32 hex chars | `internal/scg/id.go` |
| `graph_version` | `sha256(domain, snapshot_id, engine name/version, sorted frontend `name@version[languages]`)`, `graph-` + 32 hex chars | `internal/scg/id.go` |
| artifact digest (directory sources) | length-prefixed hash of the sorted accepted-file list (path, size, mode, content digest) | `internal/repository/source.go` (`digestEntries`) |

Why the digest inputs are separated and length-prefixed: moving content between
fields must not be able to forge another identity (commit `ab` + submodule `c`
must not collide with commit `a` + submodule `bc`). `internal/repository/id.go`
and `internal/scg/id.go` both write `len:value` for this reason.

**Only the declaration's start position participates in `symbol_id`.** Editing a
function body must not change the symbol's id — the identity of a declaration is
its language, file, qualified name, signature and where it begins, not its
content. Across snapshots, ids are *matched*, never assumed equal: a different
snapshot always yields different ids (`internal/scg/id.go`, `SymbolID`).

The graph version is part of every cached answer, so a graph built by a different
frontend set is a different graph and cannot serve as evidence for the old one
(`internal/scg/id.go`, `GraphVersion`).

## 2. Immutable artifacts

- `snapshot.json` is written atomically (temp file + rename) and a reader refuses
  an unknown `schema_version` instead of interpreting it optimistically —
  `internal/repository/snapshot.go` (`Save`, `LoadSnapshot`).
- `repository_manifest.json` is opened with `O_CREATE|O_EXCL`: an existing file is
  never overwritten in place, because downstream evidence points at it —
  `internal/repository/snapshot.go` (`WriteManifest`).
- Graph documents are content-addressed (`scg-<graph-version>-<content hash>.json`);
  writing identical bytes is a no-op, writing different bytes under the same name
  is an error, and a rebuild adds a file instead of replacing evidence —
  `internal/scg/model.go` (`ArtifactName`), `internal/repository/snapshot.go`
  (`WriteArtifact`, `validArtifactName`).
- The store enforces the same rule at record level: the same document is a no-op,
  the same analysis identity is a no-op, anything else is `ErrConflict` —
  `internal/storage/sql.go` (`PutSnapshot`, `PutManifest`), `internal/storage/memory.go`,
  `internal/storage/graph.go` (`sameAnalysis`, `validateGraph`).
- `ErrConflict` maps to HTTP `409` — `internal/api/server.go` (`writeStorageError`).

A graph submitted for one snapshot whose elements claim another snapshot id is
rejected outright: `validateGraph` refuses rows that would leak across snapshots
or collide on ids (`internal/storage/graph.go`).

## 3. Read-only frozen trees, and delete through the manager

- `Freeze` chmods files `0444` and directories `0555`, files first and
  directories afterwards, so a concurrent reader never sees a half-frozen tree —
  `internal/repository/snapshot.go` (`Freeze`, `freezeTree`).
- `Unfreeze` restores `0644`/`0755`; `Manager.Remove` and `CleanTemp` unfreeze
  before deleting, because a read-only directory cannot be removed on any
  supported platform — `internal/repository/snapshot.go` (`Unfreeze`),
  `internal/repository/manager.go` (`Remove`, `CleanTemp`).
- `DELETE /api/snapshots/{id}` deletes the records first and then removes the
  tree through the manager; a tree that is already gone is not an error —
  `internal/api/server.go` (`handleDeleteSnapshot`).
- The CLI states the same rule in its own help text and only exposes deletion as
  `snapshots remove` — `cmd/cli/main.go`.

## 4. Explicit coverage: counted skips, bounded samples, stated unknowns

- Every omission is counted exactly *and* explained: `ignored`, `binary`,
  `file_too_large`, `max_depth`, `symlink`, `unreadable`, `special_file`,
  `submodule`, `limit` — `internal/repository/snapshot.go` (`SkipReason`, `Stats`).
- The counters are exact; the per-entry list is a bounded sample capped by
  `MaxSkippedEntries` (default 200) — `internal/repository/limits.go`,
  `internal/repository/source.go` (`addSkip`, `ensureSkipCapacity`).
- Every non-zero counter and every special condition becomes a stated snapshot
  limitation (submodules not expanded, symlinks not materialised, LFS content not
  fetched, dirty worktree, directory source without VCS metadata) —
  `internal/repository/manager.go` (`describeLimitations`).
- The manifest lists its `unknowns` and restates the snapshot limitations: read
  truncation, no recognised language, unparsed/partial dependency manifests, the
  rule-based nature of framework and entrypoint detection —
  `internal/analysis/manifest.go` (`coverageUnknowns`, `finishUnknowns`),
  `internal/analysis/analysis.go` (`Analyze`).
- The graph states its own coverage and limitations, including files too large,
  files that are not source, languages without a frontend, budget drops and the
  unresolved share — `internal/scg/builder.go` (`BuildTree`, `finalizeCoverage`).
- "Not found" is therefore never presented as "not present": absence of a result
  always travels with the coverage statement that bounds it.

Repository limits (defaults from `internal/repository/limits.go`):

| Limit | Default | Meaning |
|---|---|---|
| `MaxRepoBytes` | 512 MiB | total accepted content |
| `MaxFiles` | 50 000 | accepted files |
| `MaxFileBytes` | 4 MiB | larger files are skipped and counted |
| `MaxDepth` | 32 | path segments below the root |
| `MaxSkippedEntries` | 200 | size of the skip *sample* (counters stay exact) |
| `AllowBinary` | `false` | binary detection is a NUL byte in the first 8000 bytes |
| `Symlinks` / `Submodules` / `LFS` | `record` | record and state; `require` turns submodules/LFS into a hard error |

`IncludeIgnoredDirs` is the documented escape hatch when a normally generated
directory holds audited source (for example `vendor`).

## 5. Confidence is a class, never a probability

- The analyzer labels every detection `observed`, `inferred` or `unresolved`, and
  a detection with no label is downgraded to `unresolved` rather than guessed —
  `internal/analysis/analysis.go` (`ConfidenceClass`, `AnalyzeInput`).
- A manager's status is the *worst* of its parsers and a framework hit is
  `observed` only when a source marker was actually read — 
  `internal/analysis/manifest.go` (`worseStatus`, `worseConfidence`),
  `internal/analysis/framework.go`.
- The graph labels every call site and edge `observed`, `inferred` or
  `unresolved`; `resolved_best_effort` always carries `inferred` —
  `internal/scg/model.go`, `internal/scg/builder.go` (`resolveCalls`).
- No numeric confidence or probability exists anywhere in the model: the class is
  the whole claim.

## 6. No fabricated inference

- A resolver that returns a symbol id which is not in the snapshot index is
  downgraded to `unresolved_unsupported` instead of being trusted —
  `internal/scg/builder.go` (`resolveCall`).
- An argument that looks like a symbol but does not resolve keeps its text and
  resolution class and is reclassified as a plain expression; it never claims a
  target — `internal/scg/builder.go` (`resolveArgs`).
- The Go frontend resolves only what syntax plus the snapshot symbol table can
  decide: interface dispatch, function values, external method sets, chained
  receivers it cannot name and immediately invoked function literals are recorded
  as unresolved with a reason — `internal/scg/gofrontend/frontend.go`
  (`ResolveCall`).
- Every graph claim cites its producer: analyzer name and version, source
  location, and for SCG edges the originating call site id —
  `internal/scg/model.go` (`Edge`, `CallSite`), `internal/scg/builder.go`.

## 7. Bounded queries: `truncated`, `truncation_reason`, `more_beyond_depth`

- Defaults and hard caps: `max_depth` 1 (cap 10), `max_nodes` 200, `max_edges`
  1000, `limit` 100 (cap 1000), `timeout` 5s (cap 60s); path search uses larger
  defaults (depth 6, 5000 nodes, 20000 edges) and at most 50 paths; slices use 60
  lines per section (cap 400), 20 sections (cap 100), 2 context lines (cap 20) and
  a 4 MiB file limit — `internal/graph/service.go`, `internal/graph/traverse.go`,
  `internal/graph/slice.go`.
- A budget that cuts an answer short sets `truncated` and names the budget in
  `truncation_reason` (node budget, edge budget, time budget, path count, section
  budget, page size) — `internal/graph/service.go` (`Meta`),
  `internal/graph/traverse.go`, `internal/graph/slice.go`.
- `more_beyond_depth` reports that neighbours exist beyond the *requested* depth.
  That is not truncation: the caller asked for exactly that depth, so the two are
  reported separately and never merged — `internal/graph/traverse.go`
  (`neighborhood`).
- Store-level reads cannot be asked for an unbounded page: `normaliseLimit`
  applies a default and a cap — `internal/storage/graph.go`, used by
  `internal/storage/sql_graph.go` and `internal/storage/memory_graph.go`.
- A dangling edge found during a traversal is surfaced as a limitation rather
  than hidden — `internal/graph/traverse.go`.
- `internal/api/graph.go` reads budgets from the query string and leaves missing
  values to the service defaults; the CLI exposes the subset documented in the
  README.

## 8. The cache key

The result cache key is `sha256("codexploit/graph-cache/v1", snapshot_id,
graph_version, query_type, sorted argument names, argument values)`. Argument
names are sorted and every field is length-prefixed, so two different searches
can never share an entry, and a rebuilt graph (new graph version) can never serve
a stale answer — `internal/graph/service.go` (`cacheKey`). The cache is
in-process, bounded (512 entries) and TTL-bounded (5 minutes); a miss is always
safe.

## 9. Determinism of documents

Identical inputs produce byte-identical documents apart from timestamps:

- Snapshots normalise nil lists to empty arrays and sort skipped entries and
  limitations — `internal/repository/snapshot.go` (`normalizeLists`,
  `sortSkipped`, `Save`).
- Manifests start every list field empty rather than nil, sort detections,
  languages, formats, frameworks, entrypoints, build configs, packages, managers,
  layout lists and unknowns, and cap evidence — `internal/analysis/analysis.go`
  (`AnalyzeInput`, `sortDetections`), `internal/analysis/manifest.go`
  (`applyDetections`, `finishUnknowns`).
- Graphs normalise nil collections, then sort modules, files, symbols, call sites,
  edges and limitations by id before serialisation — `internal/scg/model.go`
  (`normalize`, `sortForDeterminism`), `internal/scg/builder.go`.
- Query answers sort nodes, edges and paths deterministically before returning —
  `internal/graph/traverse.go`.

Consumers never have to distinguish `null` from `[]`, and a diff between two
builds of the same snapshot shows only real changes.

## 10. Offline by default, hardened git environment

- A remote git URL is refused unless network access was explicitly enabled;
  `ErrNetworkDisabled` maps to HTTP `403 network_disabled` —
  `internal/repository/source.go`, `internal/api/server.go`.
- `cmd/mcp` never enables network access at all — `cmd/mcp/main.go`.
- Every git invocation runs with a hardened environment (no terminal prompt, no
  askpass, system and global config disabled, optional locks off, LFS smudge
  skipped, non-interactive credential manager, `LC_ALL=C`) and with
  `core.hooksPath=`, `credential.helper=`, detached-head advice off and protocol
  v2 — `internal/repository/git.go` (`gitEnv`, `gitArgs`).
- Revisions that could be mistaken for options or that contain whitespace are
  rejected, and `rev-parse` / `ls-tree` / `archive` are called with
  `--end-of-options` semantics and verified 40/64-hex SHAs —
  `internal/repository/git.go` (`validRef`, `resolveCommit`, `extractCommitTree`).
- Archive entries that would escape the snapshot root (`..`, absolute paths,
  Windows drive letters) abort the snapshot —
  `internal/repository/git.go` (`safeRelPath`).

## 11. Authentication fails closed

- Every API route is classified in one capability table; a route with no rule is
  treated as "no capability required" only so the mux can answer `404` — it is
  never implicitly granted. The table lives in one function —
  `internal/api/auth.go` (`requiredCapability`, `authenticate`).

| Capability | Allows |
|---|---|
| `reader` | every `GET`, plus `POST /api/snapshots/{id}/graph/paths` and `/graph/slice` (query-shaped) |
| `writer` | reader + `POST /api/projects`, `POST /api/projects/{id}/snapshots`, `POST /api/snapshots/{id}/graph` |
| `admin` | writer + `PATCH /api/projects/{id}`, `DELETE /api/snapshots/{id}` |

- Secrets are compared as SHA-256 digests with `subtle.ConstantTimeCompare`, so
  the comparison leaks neither length nor prefix, and the plaintext secret is not
  retained (only its digest) — `internal/api/auth.go` (`Authenticate`,
  `storedToken`).
- A token without a name, with an unknown role, with a secret shorter than 16
  characters, or with a duplicate name is a configuration error, not a warning —
  `internal/api/auth.go` (`NewAuthenticator`, `secretDigest`, `ParseTokenSpecs`).
- A pre-hashed secret must be `sha256:` plus a 64-character hex digest, so a
  deployment file can hold no usable credential.
- Anonymous access must never be administrative: `WithAnonymousAccess(CapAdmin)`
  is rejected, and `--insecure-anonymous` grants `writer` — 
  `internal/api/auth.go` (`NewAuthenticatorWithOptions`), `cmd/server/main.go`.
- A server with no tokens and no `--insecure-anonymous` refuses to start; a
  `Server` without an authenticator answers `401` to every API call —
  `cmd/server/main.go` (`buildAuthenticator`), `internal/api/auth.go`.
- Missing or invalid credentials return `401` with
  `WWW-Authenticate: Bearer realm="codexploit"`; a valid token without the
  capability returns `403`. Secrets are never logged; write operations log the
  token *name*.
- `GET /healthz` requires no credential and reveals only liveness.

## 12. Durable idempotency

`Idempotency-Key` on any `POST` makes retries safe, and the claim lives in the
store, so the guarantee survives a restart, a crash or a load-balancer hop —
`internal/api/server.go` (`withIdempotency`), `internal/storage/idempotency.go`.

- A claim consists of `scope` (`METHOD /path`), `key`, a fingerprint of the
  request body, the authenticated principal name and an expiry.
- Outcomes: `ClaimNew` (execute), `ClaimReplay` (replay the stored status and
  body with `Idempotent-Replay: true`), `ClaimInProgress` (`409
  idempotency_in_progress` with `Retry-After: 1`), `ClaimMismatch` (`409
  idempotency_key_reuse` — same key, different body or different principal, and
  the stored body is dropped so it cannot be turned into a response).
- A `5xx` response releases the claim, so a transient failure may be retried with
  the same key; success completes it with the stored status and body —
  `internal/api/server.go`.
- Exactly one caller may receive `ClaimNew` for a `(scope, key)` pair: the SQL
  store decides inside a transaction, deleting the expired row first and letting a
  unique-key violation on a concurrent claim lose the race and re-read the
  winner — `internal/storage/sql_idempotency.go` (`ClaimIdempotent`,
  `decideClaim`).
- Expiry is checked per claim and swept on the write path (no background worker),
  with the TTL defaulting to **24h** (`--idempotency-ttl`) — 
  `internal/api/server.go` (`defaultIdempotencyTTL`), `cmd/server/main.go`,
  `internal/storage/sql_idempotency.go` (`PurgeExpiredIdempotency`).
- Timestamps in the idempotency table use a fixed-width UTC layout so an ordinary
  string comparison is also chronological — `internal/storage/sql_idempotency.go`
  (`idempotencyTimeLayout`).

## 13. Writes are optimistic

- `GET /api/projects/{id}` (and project creation) returns a strong `ETag` over
  id, name, source, identity and update time —
  `internal/api/server.go` (`projectETag`).
- `PATCH /api/projects/{id}` requires `If-Match`: missing → `428
  precondition_required`, stale → `412 precondition_failed`; `*` and weak
  validators are accepted in the header comparison —
  `internal/api/server.go` (`handlePatchProject`, `etagMatches`).
- The response carries the new `ETag`. Snapshot and graph endpoints are
  append-only/idempotent by identity, so they use idempotency keys rather than
  ETags.

## 14. Requests are bounded and strict

- Request bodies are capped at 1 MiB; larger bodies return `413 body_too_large` —
  `internal/api/server.go` (`maxBodyBytes`, `decode`, `withIdempotency`).
- Unknown JSON fields are rejected (`DisallowUnknownFields`) instead of being
  ignored — `internal/api/server.go` (`decode`).
- Every error body has the same shape, `{"error": "...", "code": "..."}`, and the
  mux's own plain-text `404`/`405` responses are rewritten into it —
  `internal/api/server.go` (`writeError`, `jsonErrors`).
- The MCP surface is closed: unknown symbol kinds and unknown slice `include`
  values are rejected rather than silently widening a search —
  `internal/mcp/server.go` (`parseKind`, `sliceIncludes`).

## 15. Attack-surface claims cite SCG evidence

- No ASG node or edge exists without `scg_refs` and without the rule that produced
  it; `Document.Validate` rejects the document otherwise —
  `internal/asg/model.go` (`Validate`), `internal/asg/extract.go` (`addNode`,
  `addEdge`).
- A rule states its class: callee name, package and text classes are ANDed and the
  members inside a class are ORed, so "the name matches" never alone justifies a
  finding — `internal/asg/rules.go` (`MatchRule.matches`).
- Presence is not effectiveness: every control node carries
  `effectiveness: not assessed`, and the document always lists the limitations that
  say so — `internal/asg/extract.go` (`controlFrom`,
  `addStructuralLimitations`).
- Framework attribution is reported, not assumed: `framework_attribution` is
  `receiver provenance or resolved package`, `ambiguous` or `unknown`, and an
  unknown attribution lists its candidates — `internal/asg/extract.go`
  (`entryPointFrom`).
- The document is versioned by `hash(snapshot, scg_version, engine, ruleset_hash)`,
  so an edited rule table produces a new attack surface instead of quietly changing
  an old one — `internal/asg/model.go` (`Version`), `internal/asg/build.go`.

## 16. AuditPaths are reproducible and bounded

- `path_id` covers audit, snapshot, entry, target and the canonical edge sequence;
  `signature` covers the same without the audit, which is the cross-audit identity.
  Two audits may hold the same path; one audit may not hold it twice — that is a
  unique index, not a convention — `internal/path/model.go` (`PathID`,
  `Signature`), `migrations/0006_audit_paths.sql`.
- Every path carries evidence: SCG refs (symbols and call edges) and ASG refs
  (entry, boundary, inputs, controls, target, assets) are filled by the generator
  and never empty — `internal/path/generate.go` (`buildPath`).
- Scoring is versioned and replayable: features are normalised to `[0,1]`,
  `dataflow_evidence` is always `0` with a stated reason, weights and a feature
  snapshot are stored per path, and `Rescore` reports priority drift instead of
  absorbing it — `internal/path/score.go`, `internal/path/service.go` (`Rescore`),
  `migrations/0006_audit_paths.sql` (`path_features`).
- Generation is bounded and says where it stopped: entry points, sinks per entry
  point, chain queries, paths and depth all have caps, each hit is recorded in
  `coverage` and restated in the audit's limitations —
  `internal/path/generate.go` (`GenerateResult.Coverage`).
- A call chain is not a taint chain: `path_status` distinguishes
  `statically_supported`, `candidate` and `unresolved` by how much observed
  evidence exists, and no path claims data propagation —
  `internal/path/generate.go` (`PathCandidate` handling), `internal/path/model.go`.
- `audit_id` covers the snapshot, the configuration hash and the score version, so
  the same request replays the same audit and a changed configuration produces a
  different one — `internal/path/service.go` (`ConfigHash`, `AuditID`).

## 17. Path state, leases and events are atomic

- Only the declared transitions are legal; an illegal one returns the list of legal
  targets and writes nothing — `internal/path/statemachine.go`
  (`ValidateTransition`), `internal/path/store.go` (`Transition`).
- Only `QUEUED` is claimable; a claim sets `lease_owner`/`lease_until` and moves the
  path to `ANALYZING` atomically, so two workers can never win the same path —
  `internal/path/service.go` (`Claim`), `internal/path/store.go` (`ClaimPath`).
- Lease expiry is a string comparison on RFC3339 timestamps, and `ReclaimExpired`
  returns expired leases to the queue with a recovery event, so a crashed worker
  needs no cooperation — `internal/path/service.go`, `internal/path/store.go`.
- The active-lease ceiling is a property of the audit and is enforced there, not per
  row — `internal/path/service.go` (`activeLeases`, `Claim`).
- Every state change and its event are one transaction, and events are numbered per
  audit so appending after a rerun cannot collide —
  `internal/path/store.go` (`Transition`, `NextEventSeq`),
  `migrations/0006_audit_paths.sql` (`path_events`).
- An incomplete generation cannot look complete: the audit is written as
  `GENERATING` and becomes `READY` only after its paths, features and events are
  stored — `internal/path/service.go` (`CreateAudit`).
- Deleting a snapshot deletes its audits, paths, score snapshots and events, so a
  deleted snapshot cannot keep answering audit queries —
  `internal/storage/memory.go`, `internal/storage/sql.go` (`DeleteSnapshot`),
  `internal/path/store.go` (`DeleteAuditsForSnapshot`).

## 18. Agent runs are bounded, evidence-linked and auditable

- A run receives a validated task: identity, a non-empty `security_goal`, both ends
  of the path, at least one evidence reference and a bounded code slice. A builder
  that can produce an invalid task fails loudly instead of handing an agent an
  unanswerable question — `internal/agent/protocol.go` (`ValidateTask`),
  `internal/graph/agentfacts.go` (`BuildTask`).
- An answer is strict JSON: unknown fields are rejected, every citation must carry
  a resolvable reference or a file and line, free text is capped, and `status` may
  only be `candidate`, `inconclusive` or `refuted`. **`confirmed` belongs to
  verification** — `internal/agent/protocol.go` (`DecodeAnswer`, `ValidateAnswer`,
  `ValidHypothesisStatus`).
- No reasoning transcript is stored or requested: `agent_events` holds the task,
  tool exchanges, expansion decisions and the structured answer —
  `migrations/0007_agent_runtime.sql`, `internal/agent/model.go` (`Event`).
- The agent cannot widen its own limits. Tool calls are validated against the run's
  allowlist before execution (`ValidateToolRequest`), results are truncated
  (`TruncateToolResult`), and an expansion only ever adds hops and tool calls:
  `ApplyExpansion` cannot touch the allowlist — `internal/agent/protocol.go`,
  `internal/agent/runner.go`.
- Each stop condition sets its own status and reason, and a clean end with no
  acceptable answer is `INVALID_OUTPUT`, not an adapter failure —
  `internal/agent/runner.go` (`finish`, `acceptAnswer`).
- Worker-driven path changes carry the lease owner
  (`path.Service.TransitionOwned`), so a run can only settle the path it holds; the
  operator form (`Transition`) deliberately stays ownerless so a stuck path remains
  recoverable — `internal/path/service.go`, `internal/graph/agentcoordinator.go`.
- A finished run releases its lease atomically with the `HYPOTHESIS_FORMED`
  transition, because that status is not active — `internal/path/model.go`
  (`Status.Active`), `internal/path/service.go` (`transition`).
- Deleting a snapshot deletes its runs, events and hypotheses —
  `internal/storage/memory.go`, `internal/storage/sql.go` (`DeleteSnapshot`).
