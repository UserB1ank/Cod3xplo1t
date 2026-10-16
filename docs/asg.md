# Attack Surface Graph (ASG)

The ASG is Codexploit's security-semantics layer: the candidate attack surface
derived from the Source Code Graph. This document describes what P3 produces, how
each fact is justified, and — just as importantly — what it does not claim.

Design references: `codexploit_design.md` §3.2 and §4,
`codexploit_implementation_guide.md` §7. The upstream specifications remain the
authority on the model; this document describes the implemented behaviour.

## Position in the pipeline

```text
snapshot ──► repository manifest            (P1)
          └─► SCG: modules, files, symbols, call sites + argument facts   (P2)
                    │
                    ├─ framework / source / sink / control rules ──► ASG candidate   (P3, this document)
                    │
                    ├─ bounded call-graph reachability ─────────► REACHES / PROTECTED_BY
                    │
                    ├─ local code slices ──► semantic agent (P5)  ──► Hypothesis, SUPPORTED_BY
                    └─ isolated verification (P4) ────────────────► VERIFIED_BY / refuted
```

Two rules are load-bearing:

1. **The ASG is derived, never authoritative.** It reads the SCG and never writes
   to it. Every ASG node and edge records the SCG ids it came from, and
   `Document.Validate` rejects a document containing a node or edge without
   evidence. Deleting an ASG and rebuilding it must be possible without touching
   a single SCG fact.
2. **Presence is not effectiveness.** A rule may observe that an authentication
   middleware is registered. It may not claim the check works. That distinction
   lives in the evidence status, in per-node `detail`, and in the document's
   limitations.

## Node kinds

| Kind | Subject shape | What it records | What it does not claim |
|---|---|---|---|
| `EntryPoint` | `http_route:GET /users/:id`, `rpc_handler:RegisterUserService`, `message_consumer:Consume:events`, `cli_command:listen` | A registration that lets something outside the process reach code inside it | That the route is reachable at runtime, or that its handler is the only handler |
| `AttackerControlledInput` | `input:query_param:id`, `input:path_param:id`, `input:body:`, `input:file_content:` | A value read from an external source at a known call site | That the value is attacker-controlled, or where it flows |
| `TrustBoundary` | `boundary:network`, `boundary:message`, `boundary:process` | The external boundary an entry point crosses; one shared node per boundary kind | Anything about the traffic that crosses it |
| `SecurityControl` | `control:authentication:Use`, `control:parameterization:sql_placeholders` | A control that is present: a middleware registration, a validation call, an escaping call, a parameterised statement | That the control is correct, complete, or on the path of any particular input |
| `SensitiveOperation` | `sink:sql_execution`, `sink:file_write`, `sink:process_execution`, `sink:network_request`, `sink:deserialization`, `sink:sensitive_output` | One call site that performs an operation worth guarding | Whether its arguments are attacker-influenced |
| `Asset` | `asset:database_table:users`, `asset:file_path:/tmp/out`, `asset:command:sh`, `asset:endpoint:https://…` | Something a sensitive operation acts on, only when a literal names it | That the asset exists or is the one that matters |
| `Hypothesis` | — | Reserved for the semantic-agent phase | Never produced by P3 rules |

Node ids are `asgn-` + a 128-bit digest of `(snapshot, kind, subject,
discriminator)`. The discriminator is the call-site id or the file:line, so two
registrations of the same route are two entry points with independent evidence.

## Edge kinds

| Kind | Produced in P3 | Meaning and evidence |
|---|---|---|
| `CROSSES` | yes (`observed`) | entry point → trust boundary. The entry point's kind determines the boundary, which is a fact about the registration. |
| `REACHES` | yes (`inferred`) | entry point → sensitive operation or input, when the handler can reach it over `CALLS` edges within the reachability budget. Reachability, not dataflow. |
| `PROTECTED_BY` | yes (`observed` and `inferred`) | entry point → security control. `observed` when the control is middleware registered on the same receiver before the route in the same file; `inferred` when a control is merely reachable from the handler. |
| `MAY_AFFECT` | yes (`inferred`) | sensitive operation → asset, when a literal in the call names the asset. |
| `DERIVED_FROM` | yes (`observed`) | ASG node → SCG node id. This is the provenance backbone; the target id belongs to the SCG id space, not to this document. |
| `SUPPORTED_BY` | no | Reserved for the semantic-agent phase, which attaches hypotheses to evidence. |
| `VERIFIED_BY` | no | Reserved for the verification phase, which attaches confirmed or refuted results. |

## Evidence

| Field | Values | Meaning |
|---|---|---|
| `evidence_status` | `observed`, `inferred` (P3); `verified`, `refuted` (later phases) | `observed` means a rule read the fact out of the SCG; `inferred` means a rule derived it, for example through reachability |
| `confidence` | `observed`, `inferred`, `unresolved` | The confidence class of the underlying SCG fact, carried up rather than re-invented |
| `generator` | `entrypoint/framework`, `sink/sql_execution`, … | The rule that produced the claim, so a reviewer can find and challenge it |
| `scg_refs` | SCG node ids | The facts the claim rests on. Empty is invalid. |
| `detail` | free-form, rule-specific | Includes the rule and the reasons it matched (`rule=... (callee suffix .Query; qualified name contains ...)`), plus `effectiveness: not assessed` on controls |

## Rules

Rules are data, in `internal/asg/rules.go`, because they are the part most likely
to be wrong and most likely to be extended. Matching works on the call-site facts
the SCG records: callee text, resolved qualified name, and arguments (`args`,
including string literals and resolved symbol references) plus `receiver_from`,
which records the call a selector's receiver was bound from.

**Class-AND, member-OR.** A rule's *callee-name* class, *package* class and
*text* class are ANDed; inside a class the alternatives are ORed. This is what
keeps `db.Query` from being read as a request parameter, `os.ReadFile` from being
read as a file write, and `http.Get` from being read as SQL.

| Class | Matched against |
|---|---|
| callee name / suffix / prefix | the callee as written and its resolved qualified name |
| package | `QualifiedContains`, matched against the resolved qualified name and the callee text |
| text | `NameContainsCaseInsensitive`, matched against callee text, qualified name and argument texts |

### Entry points

| Source | Recognised by | Boundary |
|---|---|---|
| Frameworks: gin, echo, fiber, chi, net/http, gorilla/mux, httprouter | the rule's route methods on a receiver, where the receiver's provenance (`r := gin.Default()`) or the resolved package attributes the framework, plus a path-shaped string argument | network |
| gRPC | `Register…` registration methods, which carry no path; the entry is recorded without inventing one | network |
| Message consumers | `Consume`, `ConsumePartition`, `Subscribe`, `ReceiveMessage`, `Poll` | message |
| CLI | `flag.String/StringVar/Int/…/Arg/Args/Parse` | process |

Attribution is reported, not assumed: `framework_attribution` is
`receiver provenance or resolved package`, `ambiguous`, or `unknown`, and an
unknown attribution also lists `framework_candidates`. A registration whose
handler is a closure or a value produced elsewhere is recorded with
`handler: unresolved` and a limitation, because its reachable sinks are unknown.

### Sources, sinks, controls

*Sources*: query and URL parameters, path parameters, headers, cookies, bodies
and form values, decoders, file and stream reads, message payloads, environment
variables, CLI arguments.

*Sinks*: SQL execution, filesystem mutation, process execution, outbound
requests, deserialisation, and a deliberately narrow name-based rule for
sensitive output (see limitations).

*Controls*: authentication (middleware registration whose argument mentions an
authentication mechanism; JWT/OAuth/session/bcrypt calls), authorisation
(role/permission verbs, casbin/rbac packages), input validation (validation
verbs and validator packages), encoding (escaping functions in `html`, `net/url`,
`strconv`), path normalisation (`path/filepath`), and parameterisation derived
from placeholder-bearing SQL literals.

*Assets* are derived from literals only: table names in SQL, paths in filesystem
calls, executables in process calls, URLs in outbound requests.

## Reachability

For each entry point with a resolved handler symbol, the extractor walks `CALLS`
edges with a bounded depth and node budget, and links what it finds:

- `REACHES` to the sensitive operations and inputs of the reached symbols;
- `PROTECTED_BY` (inferred) to controls reachable from the handler;
- `PROTECTED_BY` (observed) to middleware registered on the receiver before the
  route in the same file.

Reachability that hits a budget sets `coverage.entry_points_truncated` and the
entry point's `reachability_truncated` detail, and the document states that a
short sink list is not evidence of absence. An entry point with no reachable sink
adds an explicit limitation.

## Limits and coverage

| Limit | Default |
|---|---|
| call sites examined | 50 000 |
| symbols examined | 100 000 |
| nodes / edges in the document | 20 000 / 60 000 |
| reachability depth / nodes per entry point | 3 / 200 |
| entry points walked | 2 000 |
| `REACHES` edges per entry point | 50 |
| evidence ids kept per shared control node | 10 (observations keep counting) |
| total build time | 5 minutes |

Coverage records how much was examined (`call_sites_examined`,
`symbols_examined`), what was dropped (`nodes_skipped`, `edges_skipped`), and how
the reachability walk was bounded. Every limit that was reached is also stated as
a limitation.

## Versioning, storage and artefacts

- `asg_version = hash(snapshot_id, scg_version, engine, ruleset_hash)`. A rebuilt
  SCG or an edited rule table is a different attack surface; results from
  different versions must not be compared.
- The document is stored next to the frozen tree as
  `asg-<version>-<content-hash>.json`, so a rebuild adds an artefact instead of
  replacing one.
- Queries read the relational tables (`asg_builds`, `asg_nodes`, `asg_edges`),
  which are replaced as a whole inside one transaction on rebuild and deleted
  with their snapshot.
- The REST surface is documented in [`api.md`](api.md); it exposes the summary,
  nodes, one node with its evidence, the entry-point route table, and edges.

## What P3 does not do

- **No dataflow.** `REACHES` is calculated from the call graph. Nothing here
  proves that an input reaches a sink; that requires local taint analysis or a
  solver, which is a later phase. Every document says so.
- **No effectiveness claim for controls.** A registered middleware may be
  bypassable, misordered or misconfigured. Bypass branches are not analysed.
- **No hypotheses.** `Hypothesis` nodes and `SUPPORTED_BY` edges belong to the
  semantic-agent phase, which must attach them to evidence rather than to prose.
- **No verification.** `VERIFIED_BY`, `verified` and `refuted` belong to the
  isolated verification phase.
- **Name-based false positives.** The sensitive-output rule matches secret-like
  words in a print/log call and is marked `inferred`; it can be wrong in both
  directions. Framework attribution can be `unknown` when neither the receiver's
  provenance nor the package is visible. Sinks reached only through unresolved
  calls are invisible, and the document states the share of unresolved call sites
  in the SCG it read.

## Extending the rules

1. Add a row to the relevant table in `internal/asg/rules.go` — a framework row,
   or a source/sink/control rule. State the callee class and, when the name alone
   is ambiguous, the package class.
2. Add a test in `internal/asg/extract_test.go` with a fixture that has both a
   positive case and a near-miss that must not fire.
3. Expect `ruleset_hash` (and therefore every `asg_version`) to change: rule
   edits are analysis-version changes. Rebuild rather than compare.

A new *node kind* is a model change: add it to `AllNodeKinds`, give it a rule
that cites evidence, and extend the storage round-trip test.
