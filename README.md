# Codexploit

> Map the Code. Trace the Attack. Verify the Evidence.

Codexploit is a static-analysis-driven code security auditing platform. It pins a
repository to an immutable revision, freezes a read-only snapshot, writes a
reviewed `repository_manifest.json`, and builds a deterministic Source Code
Graph (SCG) that humans and agents query through a bounded REST API or an MCP
server. Nothing in an audited repository is ever executed: no build scripts, no
hooks, no installers and no tests of the audited project.

This file is the introduction and user manual. Process, design and interface
documentation lives under [`docs/`](docs/) — see the
[documentation index](#documentation-index).

## Status

| Phase | Scope | State |
|---|---|---|
| P1 | Workspace, immutable snapshot chain, repository manifest (languages, frameworks, dependencies, entrypoints, build descriptors, coverage, unknowns) | **implemented** |
| P2 | Source Code Graph (modules, files, symbols, call sites, arguments, call edges), bounded graph queries, REST API and MCP server | **implemented** (Go frontend) |
| P3 | Attack surface extraction: entry points, inputs, sinks, controls, assets, bounded reachability, ASG candidate, REST + CLI | **implemented** (rule-based; the semantic-agent and verification layers are later phases) |
| P4–P7 | Path engine, agent runtime, verification, productisation | not started |

The Go frontend is currently the only language frontend; files in other source
languages are listed and counted, never silently dropped. See
[`docs/scg.md`](docs/scg.md) for the graph's guarantees and its known limits.

## Install and build

Requirements:

- Go 1.26 or newer (see `go.mod`);
- `git` on `PATH` for git sources (`--git` overrides the executable).

```bash
make build          # builds bin/cli, bin/server and bin/mcp
make vet            # go vet ./...
make fmt            # go fmt ./...
```

Equivalent without make:

```bash
go build -o bin/cli    ./cmd/cli
go build -o bin/server ./cmd/server
go build -o bin/mcp    ./cmd/mcp
```

SQLite is provided by `modernc.org/sqlite`, a pure-Go driver: there is no cgo
and the binaries behave identically on Linux, macOS and Windows.

## Workspace

Every command writes under a workspace directory (`--workspace`, default
`.codexploit`):

```text
.codexploit/
  snapshots/<snapshot-id>/snapshot.json              snapshot metadata
  snapshots/<snapshot-id>/repository_manifest.json   analyzer output
  snapshots/<snapshot-id>/repo/                      frozen source tree (read-only)
  snapshots/<snapshot-id>/scg-<version>-<hash>.json  stored graph document
  cache/git/                                         bare clone caches for remote sources
  codexploit.db                                      SQLite store (server, scg commands)
```

A snapshot tree is frozen read-only. `rm -rf` on a workspace therefore fails on
every supported platform: delete snapshots with
[`snapshots remove`](#managing-snapshots) or the `DELETE` API, which unfreeze the
tree first.

## CLI

```bash
bin/cli <command> [flags]
```

Commands: `snapshot`, `manifest` (alias `scan`), `snapshots`, `scg` (alias
`graph`), `version`, `help`.

### Snapshot and manifest

`manifest` freezes a snapshot **and** writes its repository manifest;
`snapshot` freezes it without analysing. Both work on a git URL or a local path,
and are stateless (they do not need the database).

```bash
# freeze a local repository at HEAD and write its manifest
bin/cli manifest --source /path/to/repo --workspace .codexploit

# pin a tag, keep the tree writable for debugging, print the full document
bin/cli snapshot --source /path/to/repo --ref v1.2.3 --no-freeze --json

# a remote URL requires an explicit network opt-in
bin/cli snapshot --source https://host/org/repo.git --ref main --allow-network
```

| Flag | Default | Meaning |
|---|---|---|
| `--source` | — (required) | repository URL or local path |
| `--ref` | `HEAD` for git sources | revision to pin (tag, branch or commit SHA) |
| `--workspace` | `.codexploit` | workspace directory |
| `--allow-network` | `false` | permit cloning remote git URLs |
| `--no-freeze` | `false` | keep the snapshot tree writable (debugging only) |
| `--json` | `false` | print the full document instead of a summary |

### Source Code Graph

`scg build` runs the whole chain in one step: snapshot → manifest → graph, and
writes the graph document next to the frozen tree. The other subcommands are
read-only queries against the stored graph and need the database
(`--db`, default `<workspace>/codexploit.db`).

```bash
# build everything for one revision
bin/cli scg build --source /path/to/repo --workspace .codexploit

# where am I? counts, resolution mix and coverage of a snapshot
bin/cli scg summary --snapshot snap-0123456789abcdef0123456789abcdef

# the build units (module roots) of the snapshot
bin/cli scg modules --snapshot snap-0123456789abcdef0123456789abcdef

# the files of one module (module id or path is optional)
bin/cli scg files --snapshot snap-0123456789abcdef0123456789abcdef example.com/app/internal/store

# search declarations
bin/cli scg symbols --snapshot snap-0123456789abcdef0123456789abcdef --name Save --kind method

# who calls this symbol, and what it calls
bin/cli scg callers --snapshot snap-0123456789abcdef0123456789abcdef \
  --symbol example.com/app/internal/store.Store.Save --depth 2
bin/cli scg callees --snapshot snap-0123456789abcdef0123456789abcdef \
  --symbol example.com/app/main.main --depth 3

# bounded call paths between two symbols
bin/cli scg paths --snapshot snap-0123456789abcdef0123456789abcdef \
  --from example.com/app/main.main --to example.com/app/internal/store.write --max-paths 5

# source excerpts around a symbol or a file window
bin/cli scg slice --snapshot snap-0123456789abcdef0123456789abcdef \
  --symbol example.com/app/main.main --include callers
bin/cli scg slice --snapshot snap-0123456789abcdef0123456789abcdef \
  --file internal/store/store.go --start-line 40 --end-line 120

# call sites whose callee could not be resolved (where the graph is blind)
bin/cli scg unresolved --snapshot snap-0123456789abcdef0123456789abcdef
```

| Flag | Used by | Default | Meaning |
|---|---|---|---|
| `--source` | `build` | — (required) | repository URL or local path |
| `--ref` | `build` | `HEAD` | revision to pin |
| `--allow-network` | `build` | `false` | permit cloning remote git URLs |
| `--workspace` | all | `.codexploit` | workspace directory |
| `--db` | all except `build`'s default | `<workspace>/codexploit.db` | SQLite store to query |
| `--snapshot` | all except `build` | — (required) | snapshot id |
| `--symbol` | `callers`, `callees`, `slice`, `unresolved` | — | symbol id or qualified name |
| `--from`, `--to` | `paths` | — (required) | source and sink symbols |
| `--max-paths` | `paths` | `5` | maximum distinct paths to return |
| `--module` | `symbols` | — | module id or module path |
| `--kind` | `symbols` | — | comma-separated kinds (`function`, `method`, `type`, `interface`, `const`, `var`, `package`) |
| `--name` | `symbols` | — | substring match on the symbol name |
| `--qualified-name` | `symbols` | — | exact qualified name |
| `--file`, `--start-line`, `--end-line` | `slice` | — | file window instead of a symbol |
| `--include` | `slice` | `declaration` | `declaration`, `callers`, `calls` or `neighbors` |
| `--max-lines` | `slice` | service default (60) | lines per section |
| `--depth` | `callers`, `callees`, `paths` | service default | traversal / path depth |
| `--max-nodes` | traversal commands | service default | node budget |
| `--timeout-ms` | traversal commands | service default | accepted by the flag set; the service budget applies |
| `--limit`, `--offset` | list commands | `50`, `0` | paging |
| `--json` | all | `false` | print the full document |

Query budgets, `truncated` semantics and the meaning of every resolution class
are documented in [`docs/scg.md`](docs/scg.md) and
[`docs/api.md`](docs/api.md).

### Attack surface (ASG)

```bash
# snapshot + manifest + SCG + attack surface in one command
bin/cli asg build --source /path/to/repo --workspace .codexploit

# the route table: what is reachable from outside, and what guards it
bin/cli asg entrypoints --snapshot snap-0123456789abcdef0123456789abcdef
bin/cli asg summary     --snapshot snap-… --json
bin/cli asg nodes       --snapshot snap-… --kind SensitiveOperation
bin/cli asg nodes       --snapshot snap-… --kind SecurityControl
bin/cli asg node        --snapshot snap-… --node asgn-0123456789abcdef0123456789abcdef
bin/cli asg edges       --snapshot snap-… --kind REACHES
```

`asg entrypoints` prints one row per entry point: method and path (or the
registration kind, for gRPC, message consumers and CLI flags), the framework and
handler, the trust boundary, the controls that guard it — with the number wired
in as middleware separated from the number merely reachable — and the reachable
sensitive operations.

`asg build` needs an SCG and says so if one is missing: run
`bin/cli scg build` first, or use `asg build`, which produces the whole chain.
What every node and edge means, which rules produced them, and what the ASG
deliberately does not claim are in [`docs/asg.md`](docs/asg.md).

### Managing snapshots

```bash
bin/cli snapshots list --workspace .codexploit
bin/cli snapshots remove --id snap-0123456789abcdef0123456789abcdef --workspace .codexploit
```

`snapshots list` prints one line per snapshot (id, VCS, short revision, file
count); `--json` prints the ids as a document. `remove` unfreezes the tree and
then deletes the snapshot directory.

## Server

```bash
# authentication is mandatory: configure at least one token
bin/server --addr :8080 --workspace .codexploit --db .codexploit/codexploit.db \
  --api-token ci:writer:$(openssl rand -hex 16) \
  --api-token ops:admin:sha256:<hex digest>

# tokens may also come from the environment (semicolon separated)
CODEXPLOIT_API_TOKENS='ci:writer:...;ops:admin:sha256:...' bin/server

# local development only: anonymous callers get writer, never admin
bin/server --insecure-anonymous
```

Without tokens and without `--insecure-anonymous` the server refuses to start.
Clients present the secret as `Authorization: Bearer <secret>` (or `X-API-Key`).
A missing or wrong secret returns `401`; a valid token without the required
capability returns `403`. Roles are `reader`, `writer` and `admin`; secrets must
be at least 16 characters, may be given pre-hashed as `sha256:<hex digest>`, and
may themselves contain `:`.

| Flag | Default | Meaning |
|---|---|---|
| `--addr` | `:8080` | listen address |
| `--workspace` | `.codexploit` | workspace directory for snapshots |
| `--db` | `<workspace>/codexploit.db` | SQLite file; `memory` uses an in-process store |
| `--api-token` | — | `name:role:secret`, repeatable; role is `reader`, `writer` or `admin` |
| `--allow-network` | `false` | permit cloning remote git URLs |
| `--git` | `git` | git executable |
| `--insecure-anonymous` | `false` | serve without authentication (local development only) |
| `--idempotency-ttl` | `24h` | how long a stored write response may be replayed |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |

Environment: `CODEXPLOIT_API_TOKENS` (used when no `--api-token` flag is given).

```bash
# create or reuse a project for a repository
curl -s -X POST localhost:8080/api/projects \
  -H 'Authorization: Bearer <secret>' -H 'Content-Type: application/json' \
  -d '{"source":"/path/to/repo"}'

# freeze a snapshot, analyse it and build the graph (retry-safe with a key)
curl -s -X POST localhost:8080/api/projects/<project-id>/snapshots \
  -H 'Authorization: Bearer <secret>' -H 'Idempotency-Key: run-1' \
  -H 'Content-Type: application/json' -d '{"ref":"v1.2.3","build_graph":true}'

# read the manifest and query the graph
curl -s localhost:8080/api/snapshots/<snapshot-id>/manifest -H 'Authorization: Bearer <secret>'
curl -s 'localhost:8080/api/snapshots/<snapshot-id>/symbols?name=Save&limit=20' \
  -H 'Authorization: Bearer <secret>'
```

`GET /healthz` needs no credential. The full endpoint list, status codes and
error codes are in [`docs/api.md`](docs/api.md).

## MCP server

`bin/mcp` serves the graph service over the Model Context Protocol on stdio, for
agents that must not be handed a shell or a free-form query language:

```bash
bin/mcp --workspace .codexploit --db .codexploit/codexploit.db
```

It exposes **nine read-only tools** (`graph_summary`, `list_modules`,
`list_symbols`, `get_symbol`, `get_callers`, `get_callees`, `find_call_paths`,
`get_code_slice`, `list_unresolved_calls`). Every tool is scoped to one
`snapshot_id`, is bounded by the graph service's budgets and returns the
service's provenance block unchanged. `--transport stdio` is the only supported
transport (the default); the process never opens a listening socket. Because
authority comes from running the binary, there is no token. Flags:
`--workspace`, `--db`, `--transport`, `--log-level`. Tool arguments and error
codes: [`docs/mcp-tools.md`](docs/mcp-tools.md).

## Documentation index

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | pipeline, package responsibilities, storage schema, layering rules, configuration wiring |
| [`docs/contracts.md`](docs/contracts.md) | every invariant the code enforces, with the file that enforces it |
| [`docs/scg.md`](docs/scg.md) | Source Code Graph: nodes, edges, ids, resolution classes, query budgets, coverage, limits |
| [`docs/asg.md`](docs/asg.md) | Attack Surface Graph: node and edge kinds, rule tables, evidence model, reachability, limits |
| [`docs/api.md`](docs/api.md) | REST interface reference |
| [`docs/mcp-tools.md`](docs/mcp-tools.md) | MCP tool catalogue |
| [`docs/testing.md`](docs/testing.md) | how to run the suite and what CI does |
| [`docs/codexploit_design.md`](docs/codexploit_design.md) | upstream design specification |
| [`docs/codexploit_implementation_guide.md`](docs/codexploit_implementation_guide.md) | upstream implementation guide |

## Safety notes

- Codexploit never runs code from an audited repository, and never reaches the
  network for a source unless `--allow-network` was passed deliberately.
- Snapshots, manifests and stored graph documents are immutable evidence:
  nothing is rewritten in place, and a conflicting write is an error.
- An answer that is incomplete says so in its own result.

The guarantees behind these statements, and the limits that come with them, are
specified in [`docs/contracts.md`](docs/contracts.md) and
[`docs/scg.md`](docs/scg.md).
