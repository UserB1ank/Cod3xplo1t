# Agent path proposals

The project supervisor can turn an evidence-backed investigation into a review
candidate without writing graph facts directly. The host validates every
proposal against the fixed knowledge view and records it in a separate
`Agent 新发现` task, where a human chooses whether to review it.

## HTTP

`POST /api/v1/projects/{projectID}/knowledge/views/{viewID}/path-proposals`
requires writer permission. The view must still be current and pin SCG, ASG and
path layers.

```json
{
  "request_key": "audit-entry-17",
  "entry_ref": "asgn-entry",
  "target_ref": "asgn-sink",
  "basis": "hypothesis",
  "steps": [],
  "evidence": [
    {
      "kind": "source",
      "file": "src/Handler.java",
      "start_line": 20,
      "end_line": 35
    }
  ],
  "related_path_ids": [],
  "limitations": ["The source-to-sink connection still needs investigation."]
}
```

`basis=call_reachability` asks the host to resolve the entry handler and sink
caller through the pinned SCG. When no explicit ASG steps are supplied, the host
uses `find_call_paths` equivalent domain logic and stores the actual symbol
sequence and edge IDs. A same-symbol entry/sink is supported without inventing an
interprocedural edge. `basis=hypothesis` keeps an unresolved or not-yet-proven
connection explicit and stores it as `path_status=unresolved`.

Explicit `steps` are ASG `REACHES` edges. Every step must exist, connect in
order and have observed evidence. A caller cannot submit a fabricated relation
ID or promote an inferred edge to `statically_supported`.

Evidence may reference a source range, an existing evidence or artifact ID,
an ASG node, a symbol or a call site. The host rechecks project/snapshot scope;
source ranges are read from the frozen source and existing artifacts are checked
for integrity. At least one evidence item is required.

## Identity and lifecycle

The structural path identity remains
`snapshot + entry + target + path kind + canonical edges`. The request key is
separate:

- replaying the same request key and path returns the original path with
  `created=false`;
- replaying the same request key with changed steps, evidence, related paths or
  limitations returns 409; the request digest is persisted with the discovery;
- the same key naming a different path returns 409;
- the same path found by another request/run appends a discovery observation and
  event without overwriting the first source;
- per-run proposals default to 20 and never exceed the discovery task's path
  limit;
- proposals carry `awaiting_selection=true`; the automatic scheduler leaves them
  in `QUEUED` without a lease or run until a writer explicitly selects a path;
- the snapshot deletion fence and the normal path persistence rules still apply.

Each `Path` carries `discoveries[]` with source, tool, session/run, knowledge view,
request key, basis, evidence references and time. These fields are persisted in
the existing path feature document, so historical rows and database schema remain
compatible. The path score is deliberately conservative: call reachability is
supported evidence for review order only; hypothesis is lower priority. Neither
is dataflow, a confirmed vulnerability or an instruction to auto-review.

## MCP and UI

The private project MCP registers `open_knowledge_view` and `propose_path`.
`open_knowledge_view` pins the current SCG, ASG and path layers for the bound
snapshot; its returned `view_id` is the only form accepted by `propose_path`.
Publication revision IDs are not layer pins and receive an explicit
`invalid_path_view` error. The host injects the active supervisor
session/run, execution owner and monotonic lease epoch. Persistence locks the
supervisor session and rechecks all three values plus the lease deadline; after
that run is cancelled, reclaimed or no longer running, late proposal calls fail
with a conflict. PostgreSQL uses the database clock for the deadline check. The
model still chooses the endpoints and tools after graph/source exploration;
there is no fixed proposal script.

The formal path page shows the `Agent 新发现` task next to ordinary analysis
tasks. Proposed paths enter `QUEUED` but are not automatically selected for
review. The path inspector displays every discovery source, fixed view, run,
request key and evidence. Existing selection rules create the actual review
subtask only after a human chooses a path.

## Verification

Tests cover source/symbol/ASG evidence, observed ASG chains, inferred call paths,
stable path and request-key idempotency, source observation retention, per-run
limits, cancellation-late rejection, project/snapshot scope and path directory
visibility. PostgreSQL integration covers concurrent duplicate submission,
two-connection restart reads and source-appending.
