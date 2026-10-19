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

## Obligations (task schema 2)

A path is not answered by prose: it is answered by closing a checklist. The task
builder derives four obligations from the path's shape — no model call is involved,
so the same path always yields the same questions in the same order:

| Kind | Question | Subject |
|---|---|---|
| `source_is_attacker_controlled` | Is the input attacker-controlled at its source? | the path's inputs, or the entry point when none is named |
| `flow_reaches_sink` | Does the input reach the sensitive operation, with every hop observed or explicitly unresolved? | the `entry→target` chain |
| `control_ineffective_or_absent` | Is a control absent or ineffective on this path? Presence is not effectiveness. | the controls, or `none_observed` |
| `sink_is_sensitive` | Is the target operation sensitive? | the target node id |

Each obligation carries an id derived from `(path_id, kind)`, so rebuilding the task
reproduces the ids and a stored task can be compared with a rebuilt one. The answer
closes them **by kind**, not by id: a scripted or external adapter never saw the ids.

Rules the protocol enforces:

- a version 2 task must carry exactly one obligation per kind, with unique ids, a
  subject and a question — the builder cannot emit half a checklist;
- an answer to a task with a checklist must carry exactly one verdict per kind;
- a verdict is `met`, `not_met` or `unknown`; `unknown` **must** name a blocker
  (`unresolved_call`, `dynamic_dispatch`, `external_dependency`,
  `control_unassessed`, `budget`), and a closed verdict must not;
- a `candidate` or `refuted` hypothesis requires every obligation closed. Leaving
  one open is allowed only for an `inconclusive` hypothesis, which is the honest
  form of "I could not decide this".

A version 1 task predates the checklist and is still validated as version 1, so
stored runs stay readable. The blocker vocabulary is also the vocabulary the
scheduler will group by when it asks which capability is missing; no tool is added
because a model asked for one, only because a blocker keeps recurring.

## The answer (structured, validated, no prose channel)

An answer carries `hypothesis{statement,status,confidence}`, the `obligations`
verdicts described above, separate `supporting_evidence` and `contradicting_evidence`
lists, `next_action`, an optional `requested_expansion`, `finding_candidate`,
`severity_hint` and a short `notes` justification.

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
validates it against the run's current policy (fail-closed), executes it, bounds
the result structurally (an answer over the limit becomes a complete
`result_too_large` error, never a document cut at a byte offset) and records the
exchange as `tool_requested` →
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

## Protocol repairs

Structural mistakes are corrected, not fatal. Once the model runtime accepts a
turn, two shapes are repairable, up to `modelRepairLimit` (2) corrections per run:

| Mistake | Correction the model receives |
|---|---|
| tool arguments are not a JSON object of strings (a number where a string is required, a truncated object) | a paired `tool` message naming `invalid_tool_arguments` and the expected shape |
| more than one tool call in a turn | one paired `tool` message per rejected call, naming `one_tool_call_per_turn` |
| a structured answer the protocol rejects (unknown field, `confirmed` status, missing evidence) | one `user` message naming the first problem, bounded to 300 characters |

A repair is one more turn but **not** one more tool call: it is counted separately
from the tool budget and its tokens still count against the token budget. Every
correction is recorded as a `run_note` event with the reason. When the budget is
spent, the run ends as `INVALID_OUTPUT` with the protocol's own message — the
correction is a courtesy, not an infinite retry.

Denials are not repairs: a tool outside the allowlist, an unregistered tool and an
exhausted budget keep their existing semantics and stop reasons.

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

## Runtime selection and run pins

The deployment owns the catalog: `--agent-runtimes=llm,pi` lists what a task may
choose, and `--agent-runtime` names the default. A client never supplies an
executable, environment or module path. `GET /api/agent/runtimes` reports each
entry's readiness, capabilities and secret-free versions; a runtime that is not
ready is refused at task creation instead of falling back to another adapter.

A task stores its choice (`audit.runtime`); an empty value means the deployment
default. The orchestrator resolves the choice when the run starts and fails
closed if the catalog no longer offers it. Every run records a pin — runtime and
adapter version, protocol and worker versions where applicable, prompt version,
model, encrypted-settings version and the native tool schema digest. The pin is
public and never contains credentials; the run detail shows the runtime, model
and configuration version it used.

A workflow task carries the same choice. The workflow run freezes the selected
runtime when it starts — including the private Pi init and the settings version —
and records it in the run's `model` pin. The candidate-analysis node uses that
frozen runtime, so changing the settings mid-run cannot affect it. On a recovery
the run's own pin selects the runtime again; if the current encrypted-settings
version differs from the pinned one, the bind fails with
`config_version_unavailable` instead of running the old plan under new
credentials.

## Deploying the Pi runtime

`--agent-runtime=pi` selects the worker; `--pi-worker` points at its entrypoint
(default `/app/pi-worker/dist/main.js`) and `--pi-node` at the Node binary
(default `node`). The runtime image contains a locked Node 22 and the worker
build; the three Compose deployments accept `CODEXPLOIT_AGENT_RUNTIME=pi` and
keep their existing ports, volumes and secrets. The default stays `llm`.

The worker reads the model endpoint and credentials from the encrypted settings
through the private init frame. It never reads a user `pi` login, model catalog,
extension or session directory. An unsupported protocol or a missing settings
manager leaves the runtime unavailable (`features.agent` false); it is never
silently replaced by `llm`. Without Node or the worker entrypoint, `llm`, `cli`
and `scripted` keep working.

The worker is trusted deployment code, not a sandbox. It is started in a
temporary directory with an empty private `HOME`, a minimal environment and the
application's non-root user, but strong isolation of untrusted scanners remains
a separate concern.

## Pi worker protocol (v1)

A Pi run is one fixed worker process spawned with deployment argv and spoken to
over JSONL. The worker is trusted code, not a sandbox; what makes it safe is that
it owns no authority. It never receives the lease, the registry or the budget, and
every distinct action is a request the host answers.

The worker speaks first: `hello` inside five seconds. The host then sends a
private `init` frame — model endpoint and credentials, never logged, recorded or
projected — followed by the public `start` frame with the rendered task, native
tool descriptors and limits. Public frames carry `run_id`, `generation` and a
strictly increasing `seq`; requests and replies pair through `request_id` and
`reply_to`. The frame types are `request_permit`, `tool_request`,
`answer_proposed`, `usage`, `settled` and `error`.

The host translates those frames into the same runtime events the built-in model
runtime emits, so permits, answer acceptance, repairs, tool validation and the
ledger have one implementation. A tool request is executed by the host, with the
task's trusted scope injected; the worker only forwards the call and receives the
result envelope. An answer is accepted only after the host's validator says so,
and then a `settled` frame closes the run.

Limits: one frame is at most 1 MiB, cumulative public output 16 MiB, stderr 64 KiB,
the handshake 5 seconds, cancellation grace 2 seconds, and the run deadline bounds
everything. A frame with a stale generation or an old sequence, a stream that ends
before `settled`, a non-zero exit or a protocol error fails the run explicitly.
The worker is started with an isolated temporary working directory and an empty
private `HOME`; the environment is the minimal set plus the explicit configuration.

## Native tool contracts

Every tool has one contract: `ToolDescriptor{name, description, input_schema,
version}`. The registry validates the schema at registration time — a missing,
malformed or open schema is a startup panic, not a runtime surprise — and refuses
to register a tool whose descriptor disagrees with its name. The model runtime
compiles exactly these schemas into provider tools; it does not wrap them in a
generic query tool, so an argument means the same thing to every runtime.

Arguments are native JSON. Integers and booleans are numbers and booleans, not
strings; enums and length/range limits live in the schema. Before a tool runs the
host validates the request against that same schema: unknown fields, wrong types,
quoted numbers, out-of-range values and a missing required field are denials, not
coercions. The tool then decodes the validated object.

**Scope is not an argument.** Snapshot, path, audit and run ids are absent from
every schema. The host injects them into the tool context from the task, so a
client cannot substitute another object even by sending a field the schema does
not declare. A protocol-v1 adapter (the CLI JSON lines, a scripted Go value) may
still report string-valued arguments; the host converts only the fields the schema
declares, drops legacy scope fields, and validates the result exactly like a
native request.

**Receipts.** Every tool result is returned in one envelope: `{ok, result, error,
budget}`. The budget is the host's count — `calls_left`, `tokens_left` (or null
when no token budget is enforced), `repairs_left`, `obligations{closed,total}`,
`budget_enforced` and `usage_source`. A model never estimates its own remaining
budget from the conversation. Reservations still outstanding are subtracted from
`tokens_left`, so the number is what can still be spent.

The run records `tool_schema_digest`, a digest of the contracts its allowlist
resolved to. A resumed run under a different schema is a different contract and
must not reinterpret old tool calls.

## Alias table and task rendering

The model never reads the canonical task JSON. Once per run the orchestrator builds
a versioned **alias table** and a deterministic rendered projection; the table is
stored with the run, the projection is bound to the adapter context. The ledger,
events, hypotheses, findings and reports keep canonical ids — only the model-facing
projection and the table entry themselves use short names.

Aliases are allocated by first appearance and are typed: `P` path, `A` audit, `E`
evidence, `S` symbol or ASG node, `C` call site. The same task always produces the
same table, so a prompt can be compared across runs and a resumed run can prove
which vocabulary it was given.

Resolution happens in the host, never in the adapter:

- Tool arguments that carry ids (`symbol_id`, `node_id`, `call_site_id`,
  `path_id`, `audit_id`, `evidence_id`, `ref`, `from`, `to`) are resolved before
  policy checks. An alias that is not in this run's table, or a canonical id from
  outside the task's scope, is denied and counted as an invalid call — it never
  reaches a tool. Free-text arguments are not rewritten.
- Structured tool results are projected back: only known id fields and id arrays
  are shortened; free text and unknown fields keep the text the tool produced.
- A proposed answer is resolved before validation, so the stored hypothesis and
  finding cite canonical evidence. Prose is never rewritten.

The rendered task states the goal, path endpoints, evidence, prior findings,
untrusted source blocks, unresolved questions, limitations, obligations, budget and
output contract. Repository content is fenced with a fence longer than any backtick
run inside it and labelled untrusted; it is data, never instructions. The renderer
reads no files, so a repository's `AGENTS.md` or skills cannot enter the prompt.

## Tool batches

A model turn may contain several tool calls. The adapter submits the whole batch
before anything runs, so the host reserves the tool budget in source order: calls
that fit are executed, the rest receive paired denials instead of being dropped.
A batch larger than the per-turn limit is denied as a whole, one paired result per
identifiable call.

`max_calls_per_turn` defaults to 4 (hard cap 8) and `tool_concurrency` to 1 (hard
cap 4); both are part of the run's exploration policy, so the values a run used
are persisted with it. Calls execute concurrently up to the limit, but the
provider history is paired in source order and every completed call records its
event in completion order. A replayed call id with the same bytes returns the
earlier result; the same id would not execute twice. When the batch exhausts the
tool budget the run stops with `BUDGET_EXCEEDED` before another provider request;
pausing instead of stopping belongs to #45.

Adapters that cannot batch keep the one-call path and the same host rules.

## Turn control

An adapter that declares `TurnControl` may not act on its own: every provider
request, every accepted answer and every correction is a decision the host makes.
The protocol is in-process for the built-in model runtime and will be the same
frames the Pi worker uses over JSONL (#58), so the rules exist once.

**Permits.** Before each provider request the adapter sends a `permit` with a
request id, round id, run generation, model, a conservative input-token estimate
and the provider's output limit. The host answers `continue`, `repair`, `stop` or
`pause`. `pause` is reserved until the domain checkpoint exists (#45) and is not
claimed by the current runtime. A permit is bound to one request: a late, replayed
or stale-generation frame is refused, and a refused permit ends the run with the
host's stop reason.

**Token reservation.** When a token budget is set, the host reserves
`input estimate + output limit` before the request instead of discovering the cost
after it. Both numbers are required; an adapter that cannot bound its input or the
provider's output is refused, because pretending the budget is enforced is worse
than admitting it is not. Usage reported by the provider reconciles the
reservation, and a duplicate report for the same request id is ignored rather than
billed twice. Cancellation stops new requests but cannot refund tokens the
provider already billed in flight.

**Answers.** The adapter proposes raw bytes with `answer_proposed`; the host runs
the same `DecodeAnswer` validation as every other path and replies `accepted`,
`repair` (with the first problem, bounded) or `rejected`. The shared repair policy
covers answer validation, malformed tool calls and invalid arguments: two
corrections per run by default, each at most 300 bytes. A retransmitted proposal
with the same request id and bytes returns the earlier decision without consuming
a second repair; the same id with different bytes is rejected.

**Counters.** A turn-controlled run records `model_requests` (permitted provider
requests, repair turns included), `repairs`, exchanges and tool calls separately.
`rounds` is the real request count when `source` is `reported`. An adapter without
turn control is labelled `legacy_estimate` and keeps the old `exchanges + 1`
number; a stored record with no source is unknown, never zero.

## Run metrics

Every run records what it cost as the orchestrator observed it, not as the adapter
claimed it (`agent.RunMetrics`, stored in `agent_runs.metrics_json`):

| Field | Meaning |
|---|---|
| `rounds` | model requests when `source` is `reported`; otherwise the legacy `exchanges + 1` estimate |
| `model_requests` | permitted provider requests, repair turns included |
| `repairs` | corrections granted by the host's single repair budget |
| `source` | `reported`, `legacy_estimate`, or empty for a record that predates the field |
| `exchanges` | tool calls actually executed; a denied request is not an exchange |
| `novelty` | per exchange, how many evidence ids were reported that no earlier exchange had reported |
| `invalid_calls` | executions where the tool answered with an error (`OK=false`) |
| `truncations` | results the protocol limit replaced with a `result_too_large` error before they reached the adapter |

`metrics` is `null` for a run whose adapter never started and for rows stored
before the column existed; it is never a zero-valued record pretending to be a
measurement. The stop-quality baseline built on these counters is
[`agent-baseline.md`](agent-baseline.md); regenerate it with `make bench-agent`.

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

## Native HTTP model adapter

The Docker deployment uses `--agent-runtime llm` with administrator settings
in the Web UI. Both OpenAI-compatible Chat Completions and Responses protocols
support the existing read-only graph tool loop, reported token usage and the
same structured-answer validation as other adapters. Configuration is captured
once per run; later saves apply to subsequent runs. The adapter exposes no
shell, file-write or arbitrary network tool to the model. See
[model configuration and Docker deployment](webui.md#docker-deployment).
