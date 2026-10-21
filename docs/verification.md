# Verification, evidence and findings (P6)

P6 turns a hypothesis into a finding — or into an honestly unresolved one. The
distinction it exists to protect is the one the design states plainly: **failing to
reproduce a vulnerability is not evidence that it does not exist.**

Design references: `codexploit_design.md` §3.4 (evidence), §11 (isolated
verification and security boundaries), §14 (metrics and risks);
`codexploit_implementation_guide.md` §10 (verification flow) and §11 (task
scheduling and recovery). This document describes the implemented behaviour.

## Where it sits

```text
AuditPath ──► agent run ──► hypothesis (+ supporting / contradicting evidence)
                                 │
                                 ▼
                    verification plan (steps, environment, scope)
                                 │
                    authorise (scope + approval)
                                 │
                    execute in a bounded environment
                                 │
                    derive outcome from the evidence
                                 ▼
                    finding: confirmed / refuted / inconclusive / blocked
                                 │
                                 ▼
                    immutable evidence objects + report (md/json/sarif)
```

A hypothesis is a claim with citations. A finding is what verification established
about that claim, plus the evidence that carries it.

## The four verdicts, and why they stay apart

| Verdict | Meaning | What it requires |
|---|---|---|
| `CONFIRMED` | the behaviour was reproduced | reproduction evidence (a test or a runtime log) **and** the steps that reproduced it, **and** nothing contradicting it |
| `REFUTED` | there is evidence against the claim | at least one contradicting evidence object: a control that demonstrably blocks the path, or a sink that cannot be reached with attacker data |
| `INCONCLUSIVE` | verification ran and settled nothing | insufficient evidence — and it is **not** a refutation |
| `BLOCKED` | verification could not run | missing approval, missing environment, unsupported step, refused network access |

The derivation is code, not convention (`internal/verify/protocol.go`,
`DeriveOutcome`): a claimed confirmation without reproduction evidence is demoted to
`INCONCLUSIVE` with the reason recorded, a claimed refutation without contradicting
evidence is demoted the same way, and only the derivation — never an executor —
decides a verdict. A `blocked` run produces a `blocked` finding, never a `refuted`
one.

## Evidence

Evidence is the only thing a conclusion may rest on, so it is built to be checkable:

- **Immutable and content-addressed, per claim.** The id is derived from kind, the
  snapshot, the claim the evidence is about (its hypothesis, finding or path) and the
  content hash. The verification run is stamped on afterwards as provenance and is
  deliberately **not** part of the id: an object's fields must always reproduce its
  own id, and the run is only known once the service attaches it. Scoping matters: if the id
  covered the content alone, a second run producing identical bytes would collapse
  onto the first object and inherit its provenance, leaving the second run with an
  empty evidence list. There is no update path: a correction is a new object whose
  `supersedes` field points at the old one, and both stay readable.
- **Redacted before it is stored.** Credentials, authorization headers, private key
  blocks, e-mail addresses and long opaque values are replaced with `[redacted]`
  markers, and the transformation is recorded in `redaction_notes` with
  `redacted: true`. The hash covers the **stored** (redacted) bytes, so the hash and
  the content always agree — a log whose hash disagreed with its text would be
  worthless as evidence. Redaction never happens silently.
- **Traced to provenance.** Every object names the tool and version that produced
  it, the snapshot, and the hypothesis, path, finding and verification run it
  belongs to; source evidence carries a file and line.
- **Typed.** `source`, `static_query`, `rule`, `runtime_log`, `test`, `environment`,
  `artifact`. Only `runtime_log` and `test` count as reproduction evidence, which is
  what keeps a static restatement from being accepted as proof.

Contradicting evidence is marked explicitly (`MarkContradicting`) and kept in its own
list on the finding, because the contradiction is the interesting part.

## Plans

A plan says what will be done, and states up front what would disprove the claim:

| Field | Why |
|---|---|
| `steps[].kind` | `static_check`, `dataflow_probe`, `dynamic_proof`, `dependency_probe`, `manual_review` |
| `steps[].command` | argv, never a shell string; an executor that needs a shell is a red flag |
| `steps[].expectation` | a step that does not say what it expects cannot fail |
| `steps[].contradiction` | stating the disproof condition in advance is what keeps a confirmation from being a coincidence |
| `environment` | profile, quotas, network policy, read-only source |
| `scope` | authorized repository and snapshot, allowed targets, network permission, human-approval requirement |
| `limitations` | inherited from the path and the hypothesis, so a verification is judged against what upstream could not establish |

`PlanHashOf` covers the claim, the environment digest and every step, and
`VerificationRunID(hypothesis, planHash)` makes **the same plan for the same
hypothesis the same verification**: a rerun is a replay, not a second attempt.

## Scope, approval and isolation

- Verification runs only against an authorized repository and snapshot. A plan whose
  environment asks for network access when the scope forbids it is refused with
  `scope_denied` and **writes nothing**.
- A dynamic proof-of-concept, or any step marked `requires_approval`, needs a
  recorded human approval: `approved_by` is stored on the run together with the
  approval time. An approval cannot be asserted by the caller of a plan-builder; it
  is an explicit write on the verification request.
- The environment is least-privilege by default: read-only source, scratch writes
  only, no network (`none`), bounded CPU (≤ 8 cores), memory (≤ 8 GiB), disk
  (≤ 4 GiB), processes (≤ 512) and time (≤ 1 h), with **`mount_host_socket`
  rejected outright** — the design forbids exposing the host container socket to a
  worker, so the field exists to be refused rather than to be configured.
- Go alone cannot sandbox a subprocess's network access. The deployment contract
  (design §11) is to run verification executors inside a restricted container or VM
  with no default egress, minimal privileges and a read-only copy of the snapshot.
  The CLI executor refuses network-requiring plans by default and says so.

## Executors

| Executor | Purpose |
|---|---|
| `scripted` | deterministic per-step outcomes: tests and dry runs. The verdict still goes through `DeriveOutcome`, so an invalid script fails exactly as an invalid result would |
| `cli` | runs the plan's argv steps in a restricted subprocess: process-group kill, per-step and whole-plan timeouts, output caps, minimal environment (proxy variables are not inherited), scratch working directory, sequential steps, no shell |
| `unsupported` | the honest fallback: reports `BLOCKED` with `unsupported_step` rather than pretending a step ran |

Every executor produces evidence for what it did: a `runtime_log` or `test` object
with the command, exit code and a bounded redacted output tail, an `environment`
object describing the profile and quotas, and contradicting evidence when an
observation matched a step's disproof condition.

## Storage

| Table | Contents |
|---|---|
| `verification_runs` | one row per attempt: the plan verbatim, the environment digest, status, outcome, the approval record, exit code, stop reason, reproduction steps and evidence ids. `(hypothesis_id, plan_hash)` is unique |
| `evidence` | append-only, content-addressed objects with provenance, location, content hash, redaction notes and a `supersedes` link |
| `findings` | one row per hypothesis: status, severity, confidence, the three evidence lists, the verification runs, the environments and the limitations |

Deleting a snapshot deletes its runs, evidence and findings.

`verification_runs` deliberately has no evidence list: a run's evidence is derived
on read from the evidence objects that name it. A stored copy could drift and let a
run cite evidence that no longer exists, so the durable direction is the evidence
pointing at the run — the reverse is a projection.

Two writers touch a finding's evidence lists, and the rule between them is explicit:
the planner seeds the initial `candidate` finding from the hypothesis's own
citations exactly once, and the verification service owns every later change,
merging by evidence kind and contradiction marker. A conclusive finding is never
re-seeded back to a candidate's list.

## Reports

`RenderReport` produces Markdown, a stable JSON document, or SARIF 2.1.0:

- Markdown: a findings table followed by one section per finding with its evidence,
  reproduce steps and limitations. Candidate findings appear only when asked for.
- JSON: `{schema_version, generated_at, audit_id, snapshot_id, findings, evidence}`.
- SARIF: findings as results, with the level mapped from the status (confirmed →
  `error`, inconclusive → `warning`, blocked → `note`, refuted → suppressed with a
  `suppressions` entry rather than silently dropped) and locations from the evidence
  that carries a file and line.

Every renderer restates the caveats: a `confirmed` finding was reproduced, `refuted`
means contradicting evidence exists, and `inconclusive`/`blocked` are not
refutations. A report that hides those distinctions would undo the package.

## What P6 does not do

- **No exploit synthesis.** A plan is built from the path's evidence and the
  hypothesis; writing a working proof-of-concept is operator work today.
- **No enforced sandbox in Go.** Isolation is a deployment property (restricted
  container/VM); what the code enforces is scope, approval, quotas, argv-only
  execution, redaction and the honest derivation of findings.
- **No severity scoring.** `severity_hint` travels from the hypothesis; verified
  severity needs a scoring model of its own and stays a reported gap.
- **No multi-worker verification queue.** Verification is requested per hypothesis;
  scheduling, retries with backoff and a resident worker are later work (see
  `docs/known-issues.md`).
- **No WebUI.** The read APIs and the report formats are what a UI would consume.

## Maintaining this document

The verdict table, the evidence rules and the isolation boundaries are the parts a
reviewer must be able to check against the code. If any of them change, change this
document in the same commit — a verification layer whose documentation overstates it
is worse than one with no documentation at all.

## Versioned execution plans (v2)

Issue #30 adds a fixed, reviewable plan that is approved before dynamic execution.
The v2 `ExecutionPlan` (schema version 2) records the hypothesis/finding/path/audit
and snapshot, the knowledge pin, the claim and security goal, the verifier adapter
and version, the steps, structured assertions (expectation, contradiction,
required, evidence refs), a budget, limitations and an expiry.

The plan embeds a `PlanEnvironment` instead of only the runtime limits:

- OS/arch and the **provider** (name, version, capabilities), kept separate from
  the plugin runtime;
- a template reference and input digests;
- one entry per service role, with its template, dependencies and readiness
  probes;
- network mode (`none` or `allowlist`), allowed hosts and rules;
- read-only source, scratch size, TTL, required permissions, resources and
  credential **references** (never secrets).

`DecodeExecutionPlan` uses strict JSON decoding, so an unsupported environment or
assertion field is rejected instead of being silently ignored. `ValidateExecutionPlan`
also rejects a network allowance the scope does not grant, a scope snapshot that
differs from the plan, missing resource limits, a sensitive environment name and
an already-expired plan. A plan with no structured assertion is structurally
valid, but the container executor will not confirm it: an exit code or text match
alone is not enough.

The plan digest covers every execution-relevant field (identity, claim, verifier,
steps, assertions, environment, scope, budget, knowledge pin, expiry) and excludes
only record metadata (`plan_id`, `created_at`). An `PlanApproval` binds that digest,
the decision, a trusted actor and role, the granted permissions and the approval
expiry; `ApplyApproval` rejects a stale plan digest, an expired approval and any
permission the plan did not request. The state machine is monotonic:
`pending → approved | rejected | unsupported`, and only `invalidated` follows an
approval or rejection. v1 plans and runs remain readable; v2 plans use their own
schema version and hash.

The plan lifecycle is persisted through `verify.PlanRepository` with a version
CAS: Memory and SQL (SQLite migration `0033`, PostgreSQL `0015`) store the fixed
plan, its state and the optional approval; a restart keeps the pending/approved
state, a stale version is a conflict, another project cannot read the plan and the
list filters by state. The authenticated plan/approval API is implemented. Dynamic execution under the
approved v2 plan is described below.

## Container environment provider (#31)

`internal/verify/container.Provider` is a real Docker backend, separate from the
plugin runtime. It never receives the host socket and every guarantee is either
enforced or refused:

- runs as a fixed non-root user (`10001:10001`), with `--read-only`,
  `--cap-drop ALL` and `--security-opt no-new-privileges`;
- mounts the frozen source with `readonly` at `/source`, and gives the container
  only `/tmp` and `/scratch` as bounded tmpfs;
- applies `--network none`, `--memory`/`--memory-swap`, `--cpus` and
  `--pids-limit`; an `allowlist` plan is **refused** because Docker's bridge is not
  an allowlist, not silently widened to one;
- rejects environment entries whose names contain `KEY`, `TOKEN`, `SECRET`,
  `PASSWORD` or `CREDENTIAL`; a credential travels as an opaque reference, never
  as an environment value;
- never mounts `docker.sock`; the source path is also checked for it.

`Provision` reads the container back with `docker inspect` and builds
`EnvironmentReceipt` from the daemon's answer — user, read-only rootfs, network
mode, memory, CPU, PIDs, tmpfs, source mount and image digest. If any requested
limit is missing, provisioning destroys the container and fails; a receipt is
evidence of what was applied, not a copy of the request. The request digest labels
the container, so repeating the same plan and source returns the same environment.
`Exec` runs one argv with the same identity and limits, `Logs` returns a bounded
tail, and `Destroy` is idempotent. `ListOwned`/`Reconcile` only touch containers
carrying this host's verification labels and remove those past their TTL.

## Verification execution and host verdicts (#32)

`container.Executor` implements the existing `verify.Executor` port. It is bound to
one fixed `ExecutionPlan`, one `PlanApproval` and one read-only source:

1. acquire the environment lease; a held or expired lease blocks the run before
   anything is provisioned;
2. `Provision` the container and bind its id and receipt digest to the lease;
3. wait for every service readiness probe (only `command` probes are enforceable
   by this backend; `http`/`tcp` are refused rather than approximated from the
   host);
4. run each plan step as a structured argv, recording stdout, stderr, exit code,
   truncation and timeouts as `runtime_log` evidence;
5. evaluate every structured assertion against the observation and record each as
   `test` evidence; a contradiction marker is attached only when the assertion's
   own contradiction matched;
6. record an `environment` evidence object with the applied receipt, image and
   source digests, network mode and TTL;
7. always destroy the environment and release the lease, recording cleanup
   separately from the verdict.

The adapter never calls `DeriveOutcome`; it returns observations to the host, which
validates the result, persists evidence and derives `CONFIRMED`, `REFUTED`,
`INCONCLUSIVE` or `BLOCKED`. A provisioning, readiness or timeout failure is
`BLOCKED`, never a refutation. The Docker lifecycle and single-service tests are
gated by `CODEXPLOIT_DOCKER_TESTS=1` and run a real build, start, readiness check,
controlled probe, assertion, evidence write and destroy.

`POST /api/v1/projects/{id}/verification-plans/{planID}/execute` starts an approved
plan (writer). It resolves the plan's snapshot through the project and mounts the
frozen tree read-only; the optional `attempt` field (default 1) makes a retry a new
run instead of replaying the earlier verdict. Without `--verify-executor container`
the endpoint answers 501; the legacy verification route remains available for its
own executors and refuses container plans it cannot bind.

## Environment leases, expiry and cleanup (#34)

`verify.EnvironmentLeaseStore` persists one lease per plan with a monotonic epoch,
a TTL, the environment id, image/receipt digests, run state and a separate cleanup
state. Memory and SQL implementations share the same fence:

- acquire is idempotent for the same owner, refuses another owner while the lease
  is active, and increments the epoch after a released or expired lease;
- renew/bind/release require the exact owner and epoch; a stale worker's write is
  `ErrLeaseLost` and its result is discarded;
- a failed renew marks the lease failed and cleanup pending; the executor cancels
  the in-flight work immediately rather than letting it run while only refusing its
  result;
- release records `succeeded` or `failed` cleanup separately from the verdict;
  `Reconcile` removes expired owned containers by their labels.

SQLite migration `0034` and PostgreSQL `0016` add `environment_leases`. Tests cover
epoch fencing, takeover, expiry, cleanup failure and SQLite restart persistence.

### Known limits of this slice

- Only one service, `network none`, command readiness probes and Docker are
  implemented; multi-service topology, allowlist enforcement and a VM provider are
  later issues (#33, #35).
- The v2 plan/execute surface is API-only; a formal page for plan creation,
  approval and execution is not part of this slice.
- A lease loss records a `BLOCKED` run; starting a fresh attempt requires
  `attempt > 1`, which the API supports and the page does not expose yet.
