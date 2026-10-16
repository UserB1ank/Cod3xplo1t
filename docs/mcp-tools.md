# Codexploit MCP tools

`codexploit-mcp` (or `cmd/mcp`) serves the Source Code Graph over the Model
Context Protocol on stdio:

```bash
go build -o bin/mcp ./cmd/mcp
bin/mcp --workspace .codexploit --db .codexploit/codexploit.db
```

The surface is closed on purpose: **nine read-only tools**, no writes, no shell,
no arbitrary file access and no free-form query language. Every tool requires a
`snapshot_id`, is bounded by the graph service's budgets and returns the
service's provenance block (`meta`) unchanged. An answer without that block must
not be cited as coverage.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `graph_summary` | `snapshot_id` | node/edge counts, resolution mix, coverage, limitations |
| `list_modules` | `snapshot_id` | modules with file, symbol and line counts |
| `list_symbols` | `snapshot_id`, `module_id?`, `kind?`, `name_contains?`, `limit?`, `offset?` | a bounded page of declarations plus the total match count |
| `get_symbol` | `snapshot_id`, `symbol_id` (id **or** qualified name) | one declaration plus `meta` |
| `get_callers` | `snapshot_id`, `symbol_id`, `max_depth?`, `max_nodes?`, `limit?` | reached callers with distance, the edges followed, and the unresolved call sites inside them |
| `get_callees` | `snapshot_id`, `symbol_id`, `max_depth?`, `max_nodes?`, `limit?` | reached callees, same shape |
| `find_call_paths` | `snapshot_id`, `source_symbol_id`, `sink_symbol_id`, `max_depth?`, `max_paths?` | bounded distinct call paths with their edge ids |
| `get_code_slice` | `snapshot_id`, `symbol_id?`, `file?`, `include?`, `max_lines?` | source excerpts with the reason each was included |
| `list_unresolved_calls` | `snapshot_id`, `caller_symbol_id?`, `limit?` | call sites whose callee could not be resolved |

`kind` is one of `function`, `method`, `type`, `interface`, `const`, `var`,
`package`; an unknown value is rejected instead of silently widening the search.
`include` is one of `declaration`, `callers`, `calls`, `neighbors`; an unknown
value is rejected instead of silently returning a declaration-only slice.

## Authentication

MCP is served over stdio by a process the operator starts, so there is no network
surface and no token: authority comes from being able to run the binary and from
the permissions of the workspace and database it opens. The REST API, which does
listen on a socket, is authenticated separately — see
[`docs/api.md`](api.md#authentication).

## Error codes

Tool failures travel as text, so each message starts with a code. The names match
the REST API's error body codes, which lets a client branch on them without
parsing prose:

| Code | Meaning |
|---|---|
| `invalid_argument` | a required argument is missing or malformed |
| `not_found` | unknown snapshot, or a snapshot without a graph or symbol |
| `tree_unavailable` | the snapshot's frozen tree is not on this machine, so no slice can be read |
| `budget_exceeded` | the query hit its time budget |
| `internal` | unexpected failure |

## What the tools deliberately do not promise

- A call path is **reachability, not dataflow**: it never shows that
  attacker-controlled data reaches the sink. `find_call_paths` states this in
  its own limitations.
- "No callers" only means no *resolved* edge points at the symbol. Prefer
  `graph_summary` first, then read `unresolved_call_sites` in every
  neighbourhood answer: those are the blind spots that bound the result.
- Coverage is per snapshot and per rule set. `meta.graph_version` changes when
  the frontends change, and results from different graph versions are not
  comparable.
