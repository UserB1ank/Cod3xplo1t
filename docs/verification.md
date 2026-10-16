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
