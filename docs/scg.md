# The Source Code Graph (SCG)

The SCG is Codexploit's fact layer: a deterministic description of a snapshot's
modules, files, declarations, call sites and the (possibly unresolved)
relationships between them, produced by static analysis alone — no agent, no
LLM, no execution. Everything the graph asserts carries its provenance
(analyzer, analyzer version, source location, resolution class), because static
call edges are approximations and the graph must say so instead of pretending to
be exact.

Implementation: `internal/scg` (model, ids, builder), `internal/scg/gofrontend`
(Go frontend and resolver). Query service: `internal/graph`. Invariants that
also apply elsewhere: [`contracts.md`](contracts.md). Interface references:
[`api.md`](api.md), [`mcp-tools.md`](mcp-tools.md).

## Two levels

| Level | Nodes | Edges |
|---|---|---|
| Module level | `Module` (a build unit: a directory with its own manifest, or the repository root), `File` | `IMPORTS` (module → module, aggregated with a use count), `CONTAINS` (module → file) |
| Symbol level | `Symbol` (declaration), `CallSite` (call expression, resolved or not) | `CONTAINS` (file → symbol, caller or file → call site), `CALLS`, `REFERENCES` |

A module is a directory that contains a module manifest (`go.mod`,
`package.json`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `Cargo.toml`,
`pyproject.toml`, `composer.json`, `Gemfile`, `Chart.yaml`, `*.csproj`,
`*.sln`). The repository root is always a module, so a repository without any
manifest still produces a usable module graph; the most specific (longest
matching) module root owns a file. The declared module name is read only when the
manifest format is cheap to parse (bounded by `MaxManifestBytes`, default 64
KiB): `module` in `go.mod`, `name` in `package.json`/`composer.json`,
`[package] name` in `Cargo.toml`, `[project] name` in `pyproject.toml`. Unknown
formats leave the name empty, which the graph reports rather than guesses.

An import path is mapped to a module by exact module name first, then by longest
module-name prefix, so nested modules resolve correctly.

## Node and edge kinds

Node kinds (`internal/scg/model.go`): `Repository`, `Module`, `File`, `Symbol`,
`CallSite`. The P2 builder materialises `Module`, `File`, `Symbol` and
`CallSite` nodes; `Repository` and the two flow kinds below are declared
vocabulary, not P2 output.

Edge kinds:

| Kind | From → To | Produced in P2 |
|---|---|---|
| `CONTAINS` | module → file, file → symbol, caller symbol (or file) → call site | yes (`observed`) |
| `IMPORTS` | module → module, with an `import_path` and a use `count` | yes (`observed`) |
| `CALLS` | caller symbol or file → the callee symbol | yes when resolved |
| `REFERENCES` | a call-shaped reference whose resolved target is a type or interface (conversion, type use) | yes when resolved |
| `FLOWS_TO` | data movement | **no** — declared for later phases |
| `CONTROLS` | control dependence | **no** — declared for later phases |

Every P2 graph states in its own `limitations` that `CALLS` edges are static
approximations and that `FLOWS_TO`/`CONTROLS` are not produced.

Symbol kinds: `function`, `method`, `type`, `interface`, `const`, `var`,
`package`. The Go frontend emits all but `package` (which remains part of the
tool vocabulary).

Call sites exist whether or not the callee could be resolved: a call with no
edge is kept, listed by `scg unresolved` / `list_unresolved_calls`, and travels
with every neighbourhood answer as `unresolved_call_sites`. Those are the blind
spots that bound a reachability answer.

## Identifiers

Ids are content-derived (`internal/scg/id.go`), so the same snapshot always
yields the same ids and two different facts never share one:

| Id | Inputs | Prefix |
|---|---|---|
| `module_id` | snapshot, canonical module path | `mod-` |
| `file_id` | snapshot, canonical file path | `file-` |
| `symbol_id` | snapshot, language, canonical file, qualified name, signature, declaration start `line:col` | `sym-` |
| `call_site_id` | snapshot, file, call `line:col`, callee text | `cs-` |
| `edge_id` | from, to, kind, file, `line:col`, call-site id | `edge-` |
| `graph_version` | snapshot, engine name/version, sorted frontends (`name@version[languages]`) | `graph-` |

All digests are length-prefixed and truncated to 128 bits (32 hex characters).
**Only the declaration's start position participates in `symbol_id`**, so editing
a function body does not change its id; across snapshots ids are matched, never
assumed equal. `graph_version` changes when the frontend set or its versions
change, and results from different graph versions are not comparable.

Qualified names are built as `<package path>[.<receiver type>].<name>`; the
package path comes from the frontend's `Packager` capability (for Go: the module
name plus the file's directory relative to the module root).

## Resolution classes

A relationship's resolution says how it was established. It is deliberately
finer than a boolean, because "we could not resolve this" has several meanings
with different consequences for an audit (`internal/scg/model.go`):

| Class | Meaning | What it means for an audit |
|---|---|---|
| `resolved` | the target is a symbol in this snapshot, found by an unambiguous language rule | treat as a fact; still a static call edge, not a runtime one |
| `resolved_best_effort` | the target was selected by a heuristic (local type inference, constructor result type, dot-imported name, base-name package match) | re-check before relying on it; the method set may be wrong |
| `unresolved_ambiguous` | several candidates matched and the analysis refused to pick one | the graph is blind here by design; disambiguate or read the call site |
| `unresolved_dynamic` | the target depends on run time: interface dispatch, function value, field of unknown type, shadowed identifier, immediately invoked function literal | no static edge can exist; this is where dataflow-style reasoning must take over |
| `unresolved_external` | the target is outside the snapshot (a dependency) | out of scope for this snapshot; its behaviour is unmodelled |
| `builtin` | a language builtin (for Go: `append`, `len`, …) | not a snapshot symbol; intentionally not an edge target |
| `unresolved_unsupported` | the construct is not understood by the frontend, or a resolver returned a symbol that is not in the index | a known frontend gap; do not read "nothing" into it |

A call site's *confidence* is the class of evidence: `observed` (syntax plus the
snapshot symbol table), `inferred` (heuristic — always paired with
`resolved_best_effort`) or `unresolved`. Never a probability.

Resolution summary counts (`resolved`, `resolved_best_effort`, `ambiguous`,
`dynamic`, `external`, `builtin`, `unsupported`) are part of the graph's coverage
statement, not a quality score.

## Call-site argument facts

Arguments are what turn "`GET` was called" into
"`GET("/users/:id", handler)` was called" — the fact attack-surface extraction
needs. A call site carries `args` and, when known, `receiver_from`
(`internal/scg/model.go`, `internal/scg/frontend.go`, `internal/scg/builder.go`).

Each argument is an `ArgRef`:

| Field | Meaning |
|---|---|
| `position` | 0-based argument index |
| `kind` | `string_literal`, `literal`, `symbol_ref` or `expression` |
| `text` | the argument as written, bounded (`maxArgText` = 120 characters) |
| `string_value` | the unquoted value of a string literal (route paths, SQL prefixes, file paths) |
| `symbol_id`, `symbol_qualified` | set when the argument named a symbol in the snapshot |
| `resolution`, `confidence` | how that symbol-shaped argument resolved |

Only the first `maxArgFacts` = 8 arguments of a call are described; the call
itself is always recorded, so a generated call with hundreds of arguments cannot
inflate the graph. A symbol-shaped argument that does **not** resolve keeps its
text and its resolution class but is reclassified as `expression`: the graph
never invents a target.

`receiver_from` names the call a selector's receiver was bound from — for
example `gin.Default` for `r := gin.Default(); r.GET(...)`. It is how a rule
attributes a route to a framework without type checking. The Go frontend fills
it from the local binding of the selector base; chained forms such as
`pkg.New().Method()` carry the same information as an inferred receiver target
(`infer_target_parts`) with the hint `receiver_from_chained_call`.

Receiver knowledge is itself classified: `receiver_parameter` means the type came
from a declared parameter or variable type (observed), `receiver_inferred` means
it came from a `:=` heuristic (inferred, so the resulting edge is best effort).
Argument and receiver text is never type-checked.

## What the Go frontend resolves

`internal/scg/gofrontend` is AST-only (`go/parser`, `SkipObjectResolution`): no
type checking, no build, no dependency download. Its resolver works through the
snapshot-wide symbol index in this order (`ResolveCall`):

1. a selector whose receiver type is known → method lookup in the file's package;
   several matches are `unresolved_ambiguous`, an interface type is
   `unresolved_dynamic`, a type not declared in the snapshot is dynamic with the
   reason "the method set of an external type is unknown here";
2. a receiver assigned from a call → look up that function's declared result
   type, then the method on it; always `resolved_best_effort`;
3. a method expression on a type of the package (`T.Method(...)`) → observed;
4. a package selector (`pkg.F(...)`) → resolved through the import list; an
   import matched only by package base name is best effort; a snapshot package
   whose symbol is not indexed is `unresolved_unsupported`; a package outside
   the snapshot is `unresolved_external`; a package-level variable or constant
   being called is `unresolved_dynamic`;
5. a bare identifier → package-level declaration (observed), dot-imported symbol
   (best effort), otherwise dynamic with a reason.

Go builtins are reported as `builtin`, not as unresolved. A file whose module
path is unknown (no `go.mod` module directive) adds a coverage note and limits
cross-package resolution to its own package.

Parse statuses (`internal/scg/frontend.go`): `ok`, `partial`, `unparsed`,
`unsupported_language`, `not_source`. A frontend must not fail on malformed
input: an unparseable file becomes `partial`/`unparsed` so the failure is visible
coverage, never an error that hides the file.

## Build budgets

`scg.BuildLimits` (defaults in `internal/scg/builder.go`):

| Limit | Default | Effect when reached |
|---|---|---|
| `MaxFiles` | 20 000 | later files are not parsed; stated as a limitation |
| `MaxFileBytes` | 2 MiB | file is a node but contributes no symbols; stated as a limitation |
| `MaxSymbols` | 200 000 | remaining files are skipped; counted in `coverage.symbols_skipped` |
| `MaxCallSites` | 500 000 | extra call sites are dropped; counted in `coverage.call_sites_skipped` |
| `MaxEdges` | 1 000 000 | extra edges are dropped; stated as a limitation |
| `MaxManifestBytes` | 64 KiB | module name is not read (stays empty) |
| `PerFileTimeout` | 5 s | that file's parse is abandoned |
| `TotalTimeout` | 10 min | build stops and states that it may be incomplete |

Every reached budget becomes an explicit limitation on the graph.

## Queries and default budgets

The graph service answers only snapshot-scoped questions, and every answer
carries a `meta` provenance block (snapshot, graph version, engine, query,
arguments, budget, elapsed time, cache flag, counters, `truncated` and
`truncation_reason`). Query types: summary, modules, files, symbols, symbol,
module, callers, callees, unresolved calls, call paths, slice.

| Budget | Default | Cap | Applies to |
|---|---|---|---|
| `max_depth` | 1 (path search 6) | 10 | callers/callees, call paths |
| `max_nodes` | 200 (path search 5000) | — | traversals |
| `max_edges` | 1000 (path search 20000) | — | traversals |
| `limit` | 100 (CLI default 50) | 1000 | list pages and attached unresolved call sites |
| `offset` | 0 | — | list pages |
| `timeout` (`timeout_ms`) | 5 s | 60 s | every query, including store round trips |
| `max_paths` | 5 | 50 | call paths |
| `max_lines` (slice) | 60 | 400 | lines per slice section |
| `max_sections` (slice) | 20 | 100 | sections per slice |
| `context_lines` (slice) | 2 | 20 | lines of context around a call site |

Semantics:

- `truncated` + `truncation_reason` mean a budget cut the answer short (node,
  edge, time, depth, path count, section or page budget).
- `more_beyond_depth` means the answer is complete **for the requested depth**
  but deeper neighbours exist. Depth is not truncation: the caller asked for
  exactly that depth, and the two conditions are reported separately.
- In the CLI, `--timeout-ms` is accepted by the traversal flag sets but is not
  forwarded, so the service default (5 s) applies; the REST API's `timeout_ms`
  query parameter does set the budget.
- The result cache is keyed by snapshot, graph version, query type and canonical
  arguments, so a rebuilt graph invalidates previous answers.

The service, not the store, owns the budgets: even a direct store read is capped
by `normaliseLimit` (default 100, cap 1000).

## Coverage

`coverage` states how much of the snapshot the build actually examined
(`internal/scg/model.go`):

| Field | Meaning |
|---|---|
| `files_in_snapshot` | every regular file found in the frozen tree |
| `files_too_large` | files over `MaxFileBytes`: nodes, but no symbols or calls |
| `files_parsed` | files parsed successfully (includes partial ones) |
| `files_partial` | parsed with errors: symbols and calls may be incomplete |
| `files_unparsed` | could not be parsed at all |
| `files_unsupported` | source language with no registered frontend |
| `files_not_source` | data formats and tooling descriptors: nodes for traceability, not gaps |
| `symbols_skipped` | files not parsed because the symbol budget was reached |
| `call_sites_skipped` | call sites dropped by the call-site budget |

Together with `limitations`, `resolution` and `edges_by_kind`, this is what makes
an empty answer interpretable: `graph_summary` is the intended first call, and an
answer without its `meta` block must not be cited as coverage.

## Known limits

- **Go only.** The Go frontend is the only frontend. Files in other source
  languages are listed with parse status `unsupported_language` and counted,
  never silently dropped. Adding a language means implementing
  `scg.Frontend` (and optionally `scg.Resolver`/`scg.Packager`).
- **No type checking.** Analysis is AST-only. Interface dispatch, function
  values, reflection, calls whose receiver type cannot be named from syntax, and
  methods of types declared outside the snapshot are unresolved. Struct-field
  types and cross-package result types are not resolved, which is why a real
  repository reports a large share of `unresolved_dynamic` call sites.
- **No dataflow.** `FLOWS_TO` and `CONTROLS` are declared but not produced: local
  taint, propagation and constraint solving are later phases. **A call path is
  reachability, not propagation** — it never shows that attacker-controlled data
  reaches the sink, and `find_call_paths` states this in its own limitations.
- **Paths can be broken by unresolved calls.** A path that would cross an
  unresolved call site is simply not represented; read
  `unresolved_call_sites` in every neighbourhood answer.
- **No incremental analysis.** Each graph is built from a whole snapshot; there
  is no diff-based rebuild.
- **One graph per snapshot.** A rebuild replaces the stored graph inside one
  transaction; the previous document remains on disk as a content-addressed
  artifact.
