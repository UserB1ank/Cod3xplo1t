# AuditPath generation, dedup and ranking (P4)

An AuditPath is the third object of the design: the SCG holds code facts, the ASG
holds security semantics, and an AuditPath is the unit of work the orchestrator
schedules and an audit agent will consume. This document describes how paths are
generated, deduplicated and ranked, and what the numbers do and do not mean.

Design references: `codexploit_design.md` §3.3, §6, §7; `codexploit_implementation_guide.md`
§8, §11. The upstream specification remains authoritative; this document describes
the implemented behaviour.

## Pipeline position

```text
SCG (facts) ──► ASG (semantics) ──► AuditPath (work item) ──► agent / verification
                                        │
                                        ├─ generation: bounded enumeration      (this document)
                                        ├─ dedup: exact signature + clustering
                                        ├─ ranking: R, C, U → P, versioned
                                        └─ scheduling: queue, leases, events
```

Three properties are structural, not stylistic:

1. **A path is reproducible.** Its id is content-derived, its score is a pure
   function of the path plus prior coverage, and every score is stored with its
   version, its feature snapshot and its weights. Recomputing a ranking must
   reproduce it; `Rescore` reports drift instead of absorbing it.
2. **A path is bounded.** Enumeration, chain resolution, depth and queue sizes all
   have limits, and every limit that was hit is recorded in the audit coverage and
   restated in its limitations. A short list of paths is never evidence that there
   is nothing to audit.
3. **A path is a question, not a conclusion.** It names an entry point, a target,
   the chain between them and the evidence for each hop. It never claims that data
   flows and never claims that a control works.

## Generation

Inputs, per entry point of the attack surface (implementation guide §8.1):

| Fact | Source | Use |
|---|---|---|
| entry point, boundary, controls, inputs, sinks, assets | ASG nodes and `CROSSES`/`REACHES`/`PROTECTED_BY`/`MAY_AFFECT` edges | what the path is about |
| handler symbol | `EntryPoint.scg_refs` and the entry's `handler_symbol_id` detail | where the chain starts |
| symbol containing the sensitive call | the sink's call-site ref (`cs-…`) → the call site's caller symbol | where the chain ends |
| call chain between them | SCG `CALLS` edges, resolved per (handler, caller) pair | the hops that make the path reviewable |

Algorithm:

1. Index the attack surface by entry point; sort entry points by id, sinks by
   impact and id.
2. For each sink, resolve the symbol that contains the call. If it is the handler
   itself the chain is empty — the sensitive operation sits in the entry's own
   handler, which is a real and common case.
3. Otherwise resolve up to `max_chains_per_pair` observed chains with a bounded
   search. The number of chain queries is capped by `chain_query_budget`; hitting
   it is recorded and later entry points are marked incomplete.
4. Build the canonical step sequence: boundary crossing, the inputs read, the call
   chain, the reachability edge to the sensitive operation, its controls, its
   assets. The sorted step list is the path's identity.
5. Derive objectives (security goals) from the sink kind and the controls found on
   the path, and open questions from what the path cannot answer — whether an input
   reaches the target, whether an observed control is effective, whether a missing
   handler hid part of the chain.
6. Deduplicate exactly, score, cluster, sort by priority.

### `path_status`

| Value | Meaning |
|---|---|
| `statically_supported` | every hop is an observed call edge and the target is an observed sensitive operation |
| `candidate` | attack-surface reachability supports the path, but a hop is best-effort, unresolved, or no chain could be resolved |
| `unresolved` | a fact the path needs is missing: an unresolved handler, truncated reachability, or an exhausted chain budget |

`statically_supported` is **not** a taint statement. A call chain proves the call
can happen; the guide is explicit that a call chain must not be treated as a
taint chain, so the dataflow feature stays at zero and every path says so.

### Bounds

| Bound | Default | On hit |
|---|---|---|
| entry points | 200 | `entry_points_skipped` + truncation reason |
| sinks per entry point | 20 | `sinks_skipped` + truncation reason |
| chains per (entry, target) | 2 | the path keeps the chains found |
| chain query budget (per audit) | 2000 | later paths marked `unresolved` |
| paths per audit | 2000 | `paths_skipped` + truncation reason |
| chain depth | `budget.max_depth` (2) | path becomes `candidate`/`unresolved` |

## Dedup and clustering

**Exact** (implementation guide §8.2): `signature = hash(snapshot, entry, target,
canonical_edge_sequence)`. The audit is *not* part of the signature — it is the
cross-audit identity of a path — but it *is* part of the `path_id`, because two
audits are two scheduling units that may hold the same path. A unique index on
`(audit_id, signature)` makes exact dedup a database invariant.

**Approximate**: paths cluster when they share entry point, target and the sequence
of trust boundaries crossed. Members are never deleted. Each records its cluster
id, its size, whether it is the representative (the highest-priority member) and
the intermediate nodes it does not share with the representative — the branches
worth keeping apart.

**Marginal coverage**: the scheduler discounts a candidate by how much of it is
already dispatched:

```text
effective_priority = stored_priority × (0.5 + 0.5 × novelty)
```

`novelty` is the share of the path's attack-surface nodes not yet covered by
dispatched work in the audit. Scores are never rewritten by this: the stored
priority stays the reproducible score, and the discount exists only inside the
picker.

**Exploration reserve**: a documented 15%–25% of picks (default 20%) ignores
priority and takes the least-covered candidate, so a score model cannot close off a
region permanently. The reserve is taken periodically rather than randomly, which
keeps a scheduling decision replayable.

## Ranking

The formulas are the design's initial heuristics (design §6.3, implementation guide
§8.3):

```text
R = 0.25E + 0.20I + 0.20S + 0.20T + 0.15B
C = 0.35F + 0.25D + 0.25V + 0.15Q
U = 0.40N + 0.35G + 0.25H
P = 100 × (0.55R + 0.25C + 0.20U) × D_dup / (1 + 0.30K)
```

All features are normalised to `[0,1]`. `score_version` is `1`; the weights and the
feature snapshot are stored per path in `path_features`, and every feature writes a
human-readable reason.

| Feature | How it is derived |
|---|---|
| `E` exposure | entry kind: `http_route` 1.0, `rpc_handler`/`graphql_handler` 0.9, `message_consumer` 0.7, `cli_command` 0.5, unknown 0.5 |
| `I` impact | target sink kind: process execution 1.0, SQL 0.9, file write 0.8, deserialisation 0.7, network request 0.6, sensitive output 0.5 |
| `S` controllability | strongest input on the path: body 1.0, query 0.9, path/form/message 0.8, CLI/file 0.7, header/cookie 0.6, environment 0.4 |
| `T` trust boundary | strongest boundary crossed: network 1.0, message 0.9, process 0.7, filesystem 0.6 |
| `B` business sensitivity | an explicit override, else built-in name hints (payment/credential 0.95 … tmp 0.30), else a documented neutral prior of 0.5. Business value cannot be read out of source code, and the engine does not pretend otherwise |
| `F` reachability evidence | 1.0 for a fully observed chain, 0.6 for attack-surface reachability alone, 0.3 when the path is unresolved |
| `D` dataflow evidence | always 0 in this phase: there is no dataflow analysis |
| `V` control suspicion | 1.0 when no control was observed on the path, 0.6 when controls are reachable but none is registered middleware, 0.3 when a control is registered. The documents define `V` as "suspicion about a security control"; this mapping is this implementation's reading of it, and it is the only place where the MVP formula accounts for a missing control |
| `Q` analysis quality | share of observed call hops, penalised for truncated or unresolved paths |
| `N` novelty | share of attack-surface nodes not covered by earlier dispatched paths |
| `G` information gain | open questions, presence of controls, input variety |
| `H` reuse value | shared controls and assets this path would resolve |
| `K` estimated cost | normalised chain depth and internal branching |
| `D_dup` | `1 − 0.4 × overlap − 0.2 × (in a cluster)`, floored at 0.2 |

None of `R`, `C`, `U` or `P` is a probability of a vulnerability. Priorities and
severity are stored separately: severity belongs to a finding, priority only decides
what is audited first.

## State machine

```text
DISCOVERED → QUEUED → ANALYZING → LOCAL_EXPLORING → ANALYZING
                          │             └────────► HYPOTHESIS_FORMED → VERIFYING → CONCLUDED
                          ├────────► CONCLUDED / BLOCKED
                          └────────► PAUSED / FAILED / INTERRUPTED / CANCELLED
BLOCKED / PAUSED / INTERRUPTED / FAILED → QUEUED
CONCLUDED, CANCELLED are terminal
```

The lifecycle states are deliberately independent of the audit conclusion: a paused
path has no verdict, and a cancelled path is not a refuted one. Illegal transitions
are rejected with the list of legal targets, so a scheduler bug cannot silently
write an impossible state.

Only `QUEUED` is claimable. Pausing, cancelling or re-queueing clears the lease, so
a worker notices at its next heartbeat instead of continuing to spend budget.

## Leases, budgets and recovery

| Concept | Behaviour |
|---|---|
| lease | `lease_owner` + `lease_until` (RFC3339, so expiry is a string comparison), set when a path is claimed |
| heartbeat | extends the lease; fails with `ErrLeaseHeld` for another owner and `ErrLeaseExpired` when there is none |
| active-lease ceiling | `limits.max_active_leases` (default 4, the design's "at most 4 active branches") enforced per audit, because it is a property of the audit rather than of one row |
| reclaim | `ReclaimExpired` returns expired leases to `QUEUED` and appends a recovery event; a crashed worker needs no cooperation |
| attempts | `max_attempts` (default 3) is carried on the path for the retry policy of later phases |
| atomicity | every state change and its event are written in one transaction |
| audit-level recovery | generation writes a `GENERATING` audit first and flips it to `READY` only after paths, features and events are stored; a repeated request replaces an unfinished audit |

## Events

Events are append-only and numbered per audit, so appending after a rerun can never
collide. Types: `audit_created`, `audit_ready`, `path_queued`, `path_claimed`,
`path_heartbeat`, `path_released`, `path_lease_expired`, `path_status_changed`,
`score_recomputed`. Each carries actor, reason and detail (for example the priority
and cluster of a queued path, or the drift count of a rescore).

## Idempotency and replay

`audit_id = hash(snapshot, config_hash, score_version)` where `config_hash` covers
budget, limits and sensitivity overrides. The same request therefore maps to the
same audit and is answered as a replay instead of producing a second ranking.
`force: true` regenerates: path ids stay identical because they are derived from the
attack surface, and a new score snapshot is appended (`score_seq` increments) rather
than overwriting the previous ranking.

## Storage

| Table | Contents |
|---|---|
| `audits` | one row per audit: versions, status, budgets, coverage, counts, limitations |
| `audit_paths` | one row per path: steps, signature, cluster, evidence refs, objectives, questions, features, score, lease |
| `path_features` | append-only score snapshots `(path_id, seq)` |
| `path_events` | append-only event log, `(audit_id, seq)` unique |

Deleting a snapshot deletes its audits, paths, features and events: a deleted
snapshot must not keep answering audit queries.

Two storage details worth knowing when reading history:

- `Score.ComputedAt` has no column of its own on `audit_paths`; it travels inside
  the stored weights so that a path read back is exactly the document that was
  written. `path_features` has its own `computed_at`.
- A regeneration replaces the audit's paths as a whole. Score snapshots of paths
  that survive are kept (append-only across reruns and replays); snapshots of paths
  that leave the generation are dropped with them, because their sequence numbers
  would otherwise collide when a path returns under a different set of limits.

## What P4 does not do

- **No dataflow.** Paths are call-graph reachability; the dataflow feature is zero
  and stays zero until an analysis can justify otherwise.
- **No agent.** The engine produces and schedules work; it does not reason. Agent
  runtime, expansion requests and hypotheses are the next phase.
- **No verification.** `VERIFYING` and `CONCLUDED` exist in the state machine, but
  a path reaches them only through an explicit transition by a later phase.
- **No calibration.** The coefficients are the documents' initial heuristics. Until
  they are calibrated against benchmarks, treat priorities as ordering, not as
  expected value.
- **No incremental reuse.** Every audit regenerates from the current attack
  surface; cross-snapshot caching and change-impact analysis are a later phase.

## Tuning and extension

- Changing how a feature is derived or weighted **must** bump `ScoreVersion`: the
  version is part of the audit id, so a bump produces a new audit instead of
  silently mixing two rankings.
- New features go into `Features` with a reason, a weight entry and a row in this
  table; `Rescore` will then report drift for audits scored with the old mapping,
  which is the intended signal.
- Calibration is a scoring change, not a code change to the generator: the path set
  is evidence-driven and should not move when weights do.
