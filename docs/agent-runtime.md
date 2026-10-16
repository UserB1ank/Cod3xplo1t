# Agent runtime and skill adapters (P5)

P5 closes the loop the earlier phases set up: the SCG records code facts, the ASG
records security semantics, an AuditPath is a scheduled unit of work — and a
bounded agent now analyses one path and produces structured, evidence-linked
hypotheses.

Design references: `codexploit_design.md` §7 (state machine and bounded
divergence), §10 (agent runtime) and §11 (isolation); `codexploit_implementation_guide.md`
§9 (P5) and §11 (scheduling, leases, recovery). The upstream documents remain the
authority; this one describes the implemented behaviour.

## The split that shapes everything

The Go orchestrator owns the process, the lease, the deadline and the budget. The
agent owns nothing but its bounded reasoning. Concretely, an adapter receives a
task and returns events — it never receives the lease, the budget controller, the
tool registry or a shell. That is why:

- **a run is a database row, not a session.** It survives a crashed adapter, it can
  be inspected after the fact, and a restart resumes from stored state rather than
  from an agent's own account of what it did (guide §9.3, §11);
- **no hidden reasoning is stored or requested.** `agent_events` holds the task
  delivered, the tool exchanges, the expansion decisions and the structured answer.
  Nothing in the schema or the protocol can carry a chain of thought, and the
  answer's free-text field has a hard length cap;
- **the agent cannot widen its own limits.** Exploration is bounded by a policy that
  arrives with the task, and the only way to get more room is an explicit request
  the orchestrator approves, shrinks, defers or rejects.

## The task (implementation guide §9.2)

A task is the minimal, sufficient input for one path:

| Field | Content |
|---|---|
| `snapshot_id`, `path_id`, `audit_id` | identity, so every later artefact can be traced |
| `security_goal` | what the run is answering, taken from the path's objectives; a task without a goal is rejected |
| `path_summary` | one sentence: entry → target, evidence class, depth, boundaries |
| `source_sink_refs` | the two ends plus inputs, controls, assets, boundaries and the SCG/ASG ids |
| `minimal_code_slice` | bounded source windows for the path's symbols, produced by the graph service, never gathered by the agent |
| `evidence_refs` | the facts already established, each with a location or a resolvable id |
| `unresolved_questions` | the reason the run exists |
| `exploration_policy` | hops, branches, tool calls, expansions, timeout, token budget and the tool allowlist |
| `token_budget` | the same budget in the shape the design names |
| `limitations` | what the upstream layers could not establish, so the agent does not treat it as settled |

The slice is bounded at build time (240 lines in at most 6 windows by default,
truncated on a rune boundary with an explicit reason), and the task is validated
before it is stored: a builder that can produce an invalid task fails loudly rather
than handing an agent a question that cannot be answered.

## The answer (structured, validated, no prose channel)

An answer carries `hypothesis{statement,status,confidence}`, separate
`supporting_evidence` and `contradicting_evidence` lists, `next_action`, an optional
`requested_expansion`, `finding_candidate`, `severity_hint` and a short `notes`
justification.

- Unknown JSON fields are **rejected**, not ignored: an adapter that invents a field
  is producing something the orchestrator would silently drop.
- A citation must carry either a resolved reference or a file and line. An
  unverifiable claim is not evidence.
- `status` may be `candidate`, `inconclusive` or `refuted`. **`confirmed` is
  absent on purpose**: only the verification phase may confirm a finding. An answer
  that claims it fails validation and the run ends as invalid output.
- A `finding_candidate` must cite supporting evidence.

## Bounded divergence and expansion (guide §9.3)

Defaults: 2 hops, 4 active branches, 30 tool calls, 3 expansion requests, 600
seconds.

An agent asks for a whitelisted read-only tool call by name; the orchestrator
validates it against the run's current policy (fail-closed), executes it, truncates
the result to 20 000 characters and records the exchange as `tool_requested` →
`tool_allowed` → `tool_result` under one `call_id`, or as `tool_denied` naming the
allowlist. Nothing else is callable: there is no shell, no network, no filesystem
access from the agent.

When the agent needs more room it sends an expansion request carrying a target node,
a purpose, an expected gain and an estimated cost. The orchestrator decides:

| Decision | When |
|---|---|
| `approved` | within the policy |
| `shrunk` | fewer hops or tool calls than asked for |
| `deferred` | the run already holds its maximum active branches |
| `rejected` | the run has spent its expansion requests |

An approved expansion buys room, never permission: `ApplyExpansion` adds hops and
tool calls, and the tool allowlist is never widened by a decision. Every decision is
recorded as `expansion_decided` with the granted amounts, which is the audit trail
`GET /api/runs/{id}/events?type=expansion_decided` exposes. Operator-gated approval
is deliberately not implemented in this phase: the policy decides inside the run.

## Stop conditions

| Condition | Run status | Stop reason |
|---|---|---|
| a valid answer was produced | `SUCCEEDED` | `completed` |
| the adapter ended without an acceptable answer | `INVALID_OUTPUT` | `invalid_output` |
| the same answer repeated without new evidence | `FAILED` | `repeated_output_without_new_evidence` |
| tool-call or token budget exhausted | `BUDGET_EXCEEDED` | `tool_call_budget_exceeded` / `token_budget_exceeded` |
| the wall-clock deadline passed | `TIMED_OUT` | `deadline_exceeded` |
| the path lease was lost | `FAILED` | `lease_lost` |
| the adapter failed (non-zero exit, protocol error) | `FAILED` | `adapter_failed` |
| the run was cancelled | `CANCELLED` | `cancelled` |

A clean end with no structured answer is **invalid output**, not an adapter
failure: the adapter produced nothing the protocol accepts, and asking it again in
the same run will not change that.

## Path settlement

- claim → `ANALYZING` (the run holds the path lease);
- success → the hypotheses are stored, then the path moves to `HYPOTHESIS_FORMED`
  **and releases its lease** — the analysis run is over, so no worker holds the path
  any more (`HYPOTHESIS_FORMED` is deliberately not an active status);
- failure with attempts left → the path returns to `QUEUED` for another attempt;
- failure on the final attempt → the path moves to `FAILED`;
- lost lease → the orchestrator stops and does **not** touch the path;
- cancellation → the path is released with bookkeeping that survives the dead
  context.

## Runtimes

| Runtime | Purpose |
|---|---|
| `scripted` | deterministic replay of a fixed script: tests, dry runs, demonstrations. Every answer still goes through the same validation, so an invalid script fails exactly as an invalid model would |
| `cli` | any external agent CLI that speaks the protocol: the task is written to stdin as one JSON document, events are read from stdout as newline-delimited JSON. This is how the design's "first version: a CLI adapter" is realised without binding the product to one vendor |

The CLI adapter enforces: a stdout byte cap (a truncated partial line is never
parsed), the deadline plus a 5-second wait delay (a grandchild holding the pipe
cannot hang the adapter), process-group kill on cancel, a minimal environment
(configured variables plus `PATH`, `HOME`, `TMPDIR`; proxy variables are **not**
inherited), a 4 KiB stderr tail attached to the error, and heartbeats. Its
capabilities report `Resume: false`: CLI session resume is not process resume, so
the orchestrator checkpoints through the database instead.

An adapter cannot be fully network-sandboxed by Go alone. The deployment contract
(design §11) is to run `cli` adapters inside a restricted container or VM with no
default egress, minimal privileges and a read-only copy of the source snapshot.

## Storage

| Table | Contents |
|---|---|
| `agent_runs` | one row per run: runtime, status, the task verbatim, the exploration policy, consumed budget, lease/deadline/heartbeat, stop reason and the answer |
| `agent_events` | append-only exchange log, numbered per run; a request and its result share a `call_id` |
| `hypotheses` | claims keyed by `(path_id, digest)`, with supporting and contradicting evidence, status, confidence and whether they are finding candidates |

Deleting a snapshot deletes its runs, events and hypotheses. The audit and run logs
use different method names (`AppendEvents` versus `AppendRunEvents`) because Go has
no overloading and because a reader should never have to guess which log they hold.

## What P5 does not do

- **No verification.** A hypothesis is a claim with evidence, not a finding.
  `confirmed` and `refuted` outcomes, isolated execution and evidence capture are
  the next phase.
- **No hidden reasoning, no transcript.** Explicit decisions and citations only.
- **No operator-gated expansion.** The policy decides inside the run; the decisions
  are recorded and reviewable.
- **No multi-agent fan-out.** `RunAudit` is a bounded sequential batch; horizontal
  scaling, retry with backoff and a resident worker loop are later work
  (see `docs/known-issues.md` 5.6).
- **No MCP surface for runs yet.** The agent's own tool access is the orchestrator's
  registry, not MCP; exposing `get_attack_path`/run tools over MCP is a later step.
