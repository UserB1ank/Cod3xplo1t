# Testing Codexploit

How to run the suite, what CI runs on which platform, and the rules a test in
this repository must respect. The suite is the enforcement point for
[`contracts.md`](contracts.md): an invariant that is not covered by a test is a
comment, not a contract.

## Commands

| Command | What it runs |
|---|---|
| `make test` | `go test ./... -count=1 -shuffle=on -race -timeout 240s` — identical to CI |
| `make test-stress` | the same suite with `-count=3`, for filesystem and lifecycle races the race detector cannot see |
| `make vet` | `go vet ./...` |
| `make fmt` | `go fmt ./...` |
| `make tidy` | `go mod tidy` |
| `make build` | builds `bin/cli`, `bin/server`, `bin/mcp` |

Run a single package or test while iterating:

```bash
go test ./internal/scg/ -run TestBuilder -count=1
go test ./internal/repository/ -run TestSnapshotID -v
```

Two environment details matter:

- **`-shuffle=on` is not optional in CI.** Tests must pass in any order, so none
  of them may depend on another test's side effects or on a fixed execution
  sequence.
- **`make test-stress` is the filesystem/lifecycle net.** The race detector sees
  memory races, not "two snapshots of the same repository interleaved their temp
  directories" or "a frozen tree was removed while a reader held it". Run it
  locally before pushing when a change touches the workspace, the store or the
  freeze/unfreeze path.

## What CI does

`.github/workflows/test.yml` runs on every push to `main` and every pull request,
on a matrix of `ubuntu-latest`, `macos-latest` and `windows-latest`
(`fail-fast: false`, so one platform's failure does not hide another's). Per
runner:

1. check out the repository and install Go using the version in `go.mod`
   (`go-version-file`, module cache enabled);
2. **ubuntu only**: `gofmt -l .` must produce no output (formatting is a gate,
   checked once, not three times);
3. `go vet ./...`;
4. `go test ./... -count=1 -shuffle=on -race -timeout 240s`.

Nothing in CI reaches the network beyond the checkout and the Go module cache.
Reproduce any failure locally with the same command `make test` runs; do not
"fix" a platform difference by skipping the test.

## Rules every test must respect

- **No network.** Git fixtures are created locally; remote sources are rejected
  by policy (`ErrNetworkDisabled`) rather than contacted. The SQL store runs
  against a temporary SQLite file. A test that needs the network cannot run in
  CI.
- **`t.TempDir()` is the default.** Never hardcode a shared absolute path:
  runners are fresh, and tests may run in parallel or shuffled. Windows path
  separators and drive letters are part of the matrix.
- **Purge snapshots through the manager.** A frozen tree is read-only
  (`0444`/`0555`), so `os.RemoveAll` on it fails on every supported platform.
  Use `Manager.Remove` (which unfreezes first) or, for temporary directories the
  test owns, `t.TempDir()` cleanup *before* freezing.
- **Race-clean under `-race`.** Anything shared between goroutines —
  `Manager`'s per-repository locks, the graph result cache, idempotency claims —
  must be exercised through its public API, not bypassed.
- **Assume concurrency and dirty state.** Another test or process may be using
  the same machine; do not depend on an empty workspace, on process-wide state,
  or on a `Manager` singleton.
- **Determinism is testable.** Prefer asserting on documents and ids over
  timestamps; where a timestamp is unavoidable, compare the fields that carry
  meaning (for example the analysis id, as `cmd/cli/scg.go` does with
  `manifestStored`).
- **Failure must be visible.** A test for coverage accounting should assert the
  stated limitation, not just the counter: the point of the contract is that an
  incomplete result says so.

## Tests inside a sandbox that cannot write the default Go caches

Sandboxed runs (including agent workspaces) may not be able to write `GOPATH`,
the default module cache or the default build cache. This workspace keeps both
inside the repository, under the git-ignored `.cache/` directory
(`.cache/gomod` for modules, `.cache/gobuild` for build artifacts). Prefix any
command:

```bash
GOMODCACHE="$PWD/.cache/gomod" \
GOCACHE="$PWD/.cache/gobuild" \
GOFLAGS=-mod=mod \
make test

# or a single package
GOMODCACHE="$PWD/.cache/gomod" GOCACHE="$PWD/.cache/gobuild" GOFLAGS=-mod=mod \
  go vet ./internal/repository
```

`GOFLAGS=-mod=mod` is what lets the toolchain resolve and update the module graph
without trying to write a read-only `go.sum`. The cache is ordinary scratch
space: it is git-ignored, safe to delete at any time, and only needed when the
default caches are unavailable. Normal development uses the standard Go caches
and no prefix.

## Where the tests live

| Package | Test focus |
|---|---|
| `internal/repository` | id formulas (`id_test.go`), limits and ignore matching (`limits_test.go`), git hardening, dirty state, submodules (`git_test.go`), create/load/list/remove lifecycle (`manager_test.go`) |
| `internal/analysis` | detector output, confidence classes, coverage accounting, manifest determinism (`analysis_test.go`) |
| `internal/scg` | discovery, ids, resolution classes, budgets, determinism (`builder_test.go`) |
| `internal/graph` | bounded traversal, truncation vs depth, slices, cache behaviour (`service_test.go`) |
| `internal/storage` | store contract, graph persistence and rebuild atomicity, idempotency claim/complete/release (`store_test.go`, `graph_test.go`, `idempotency_test.go`) |
| `internal/api` | capability table and authentication (`auth_test.go`), routing, status codes, idempotency, ETag/If-Match (`server_test.go`) |
| `internal/mcp` | tool surface, argument validation, error codes, provenance block (`server_test.go`) |
| `internal/app` | wiring, migrations, memory vs file store (`app_test.go`) |
| `cmd/cli`, `cmd/server` | flag parsing, human output, authentication construction (`main_test.go`, `scg_test.go`) |

## Testing the path engine (P4)

The AuditPath engine is tested without a database and without a graph service:

- `internal/path/fake_test.go` holds an in-memory `Store` and readers built from a
  fixture attack surface. The fake enforces the same invariants the real stores
  must hold — a transition and its event together, lease ownership, optimistic
  concurrency, append-only score snapshots — so the contract is exercised in both
  places.
- Time is injected (`Engine.Now`, `Service.Now`). A test that depends on the wall
  clock is a test that fails at midnight on a slow runner.
- Determinism is asserted by generating twice and comparing the serialised
  document, and by planning the same queue twice and comparing the pick order.
- Scoring is asserted against the documented formula, not against stored numbers:
  the test recomputes `R`, `C`, `U` and `P` from the features and compares. A
  changed coefficient must therefore fail a test, not slip through a golden file.
- The storage backends are covered separately with the same table-driven style as
  the graph and ASG stores (`fullStores(t)`, memory and sqlite, always `-race`), so
  both paths must behave identically.
