# Project and task workbench

Codexploit provides a code vulnerability hunting workbench. The product hierarchy
is project → task. A project owns repository snapshots, source and attack-surface
graphs, and the accumulated finding library. A task owns its goal, seed selection,
path queue, Agent runs and report. The UI focuses on discovery and evidence;
there is no remediation or fix-retest workflow.

## Knowledge and task boundaries

Named tasks reuse the existing audit engine. Task metadata is stored on the audit
row: `name`, `objective`, `scope` and `paused`. Existing CLI audits appear as
unnamed tasks in their project's list. Task ids are audit ids; creating two tasks
with identical settings still creates independent queues. An `Idempotency-Key`
replays the original creation rather than creating another task.

The project has one logical knowledge graph with snapshot-specific versions.
Creating a task reads its selected snapshot's existing SCG and ASG. It never
rebuilds or copies them. Updating code creates a snapshot; existing tasks retain
their original baseline. Indexing a new version is currently a full build, not
incremental analysis.

Scope entries are repository-relative file/directory prefixes. They select paths
whose entry or sink occurs in those files. Prefixes match whole path components;
calls may leave the selected directories. This is seed selection, not a filesystem
or execution authorization boundary. The task objective is included in each
generated path's goals and therefore in the Agent task.

The Agent receives up to 20 prior findings from other tasks on the **same
snapshot**, with source task ids, evidence references and explicit conclusion
states. Knowledge from another code version remains visible in the project
library, but is not automatically treated as applicable to the current code.

Pausing a task prevents new path claims atomically in both stores and is honored
by the resident scheduler. A call already in progress may finish. Resuming
re-enables claims. Path controls remain available separately.

## Findings and severity

The three grades are `high`, `medium`, and `low`. Legacy `critical` maps to high,
`moderate` maps to medium, and informational maps to low. Unknown or missing
assessments remain visibly ungraded until a writer assesses them. A security
goal is never used as a severity value.

Grade and conclusion are independent. Conclusions remain candidate, confirmed,
refuted, inconclusive and blocked. Project grade counts include only confirmed
findings. Task priority is the engine's 0–100 scheduling score, not severity.

The project library groups findings only when snapshot, canonical path signature,
normalized title and conclusion match. It retains all source task/finding ids.
Different versions or conflicting conclusions remain separate. The highest
assessed grade is displayed for a grouped finding. Aggregation is capped at
10,000 source records and returns `truncated: true` if reached; counts then refer
to the scanned subset. Pages are served after grouping and filtering.

Writers can assess an individual finding's grade. `If-Match` is required, the
update changes only severity, and stale writers receive 412. Later verification
writes preserve the assessed grade and keep the original evidence.

## Build and run

```bash
make build
export CODEXPLOIT_API_TOKENS="local:admin:$(openssl rand -hex 24)"
bin/server --workspace .codexploit
```

Configure a known token in the shell for API-only access. For account/password
login, start with `--web-auth` and a runtime workspace outside the source tree.
Docker enables account login by default. `make build` installs locked frontend packages, checks
TypeScript, builds assets and compiles them with `-tags embedui` into `bin/server`.
The runtime needs no Node.js or separate web server. CLI and MCP binaries retain
their existing behavior. Git and CA certificates are needed for remote sources.

`make build-backend` builds API-only binaries. Without `embedui`, the root page
returns 503 with build instructions while API routes remain available.

For local development, run the API and Vite in separate terminals:

```bash
go run ./cmd/server --addr 127.0.0.1:8080 --insecure-anonymous
npm --prefix web run dev
```

`CODEXPLOIT_API_URL` optionally changes Vite's API proxy target (default
`http://127.0.0.1:8080`). Development anonymity must be explicitly enabled on the
API; a normal server requires configured credentials. API tokens stay in page
memory, and are never stored in localStorage or URLs. Account login uses an
HttpOnly session cookie instead.

## Docker deployment

```bash
docker compose up -d --build
```

Open `http://localhost:18080`. On first startup, create an administrator account
in the application, then sign in with its username and password. There is no
default username/password. Account names allow 3–64 letters, digits, underscores
and hyphens; passwords require 12–128 characters. After initialization, setup
is disabled and every workspace API request requires a valid login session or
an explicitly configured API token. Finish first-run setup locally before
making the service reachable through a network proxy.

The server stores only a random salt and PBKDF2-HMAC-SHA256 password hash with
600,000 iterations in `/data/auth/account.json`, with owner-only permissions.
This follows the [OWASP PBKDF2 guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).
The session cookie is HttpOnly and SameSite=Strict, lives at most 12 hours, and
can be revoked with **退出登录**. Sessions are invalidated on server restart;
the account remains available. Browser-origin mutation checks protect cookie
authentication, and login attempts are limited to five per minute per peer IP.
Remote-address headers are not trusted for rate limiting. If a reverse proxy
terminates HTTPS, set `X-Forwarded-Proto: https` so login sets a Secure cookie.
Never expose the HTTP port directly outside a trusted local environment.

`CODEXPLOIT_PORT` optionally changes the host port. Compose binds to loopback
by default and enables `--web-auth`, the native LLM adapter and resident
scheduler. No environment variables or credential files are required on the
host. Explicit `--api-token` / `CODEXPLOIT_API_TOKENS` configuration remains
available for CLI clients and custom multi-role deployments.

### Configure the LLM in the application

1. Sign in and open **模型设置**, available to administrators even before any
   project exists.
2. Choose **Chat Completions** for an OpenAI-compatible service, or **Responses**
   for a provider/model that uses that API. Enter the API root URL, including
   its version path, such as `https://api.openai.com/v1`. The adapter appends
   `/chat/completions` or `/responses` automatically.
3. Enter the model ID and API Key. An unauthenticated local model can leave the
   key empty. Configure a 5–600 second per-request timeout and 256–32768 token
   output limit. These apply in addition to the orchestrator's run budgets.
4. Click **测试连接**. This makes a small model request and tests function calling
   without transmitting repository content; it may incur a small provider charge.
   Testing a draft does not save it.
5. Enable LLM discovery and click **保存配置**. New runs use the saved settings;
   active runs retain their original configuration. Disabling the model stops
   new claims. Unconfigured/disabled models do not consume queued attempts.

Settings apply to the whole installation; project knowledge remains isolated.
The server encrypts configuration using AES-256-GCM in `/data/settings/llm.enc`.
The installation encryption key is `/data/settings/settings.key`. Both files
are owner-only and belong in the data volume, never in a repository or image.
Back up both together. Encryption protects accidental plaintext disclosure; an
operator with full access to the volume also has the decryption key.
The API returns only `api_key_configured`, never the saved key. Browser input
stays in memory and is cleared after saving. Changing the Base URL requires
re-entering or explicitly clearing the key to avoid sending an old credential
to a new service. Settings writes require `If-Match` to prevent stale overwrites.
Provider error bodies and redirects are never forwarded to the browser.

For a host-local model from Docker Desktop, use
`http://host.docker.internal:<model-port>/v1` rather than localhost. Compose
also provides the host-gateway mapping on Linux; the model must listen on an
interface reachable from the container. Use HTTPS when accessing the workbench
across a network through a reverse proxy.

The adapter follows the official [function calling protocol](https://developers.openai.com/api/docs/guides/function-calling).
Only the existing read-only graph tools are exposed to the model. Source
snapshots, tool allowlists, tool budgets, token budgets and evidence validation
remain controlled by the Go orchestrator. It records structured conclusions and
tool exchanges, not hidden model reasoning. A model cannot assert a confirmed
finding by itself.

For remote Git repositories, explicitly enable network access:

```bash
export CODEXPLOIT_ALLOW_NETWORK=true
docker compose up -d
```

For a local repository, mount it read-only:

```bash
export CODEXPLOIT_REPO_DIR=/absolute/path/to/repository
docker compose -f compose.yaml -f compose.local.yaml up -d --build
```

Enter `/repos/source` as the repository path in the UI. The directory and its
files must be readable by the runtime user. The container runs as uid/gid 10001,
with a read-only root, a temporary `/tmp`, no added capabilities, a persistent
`/data` volume, an HTTP healthcheck and graceful termination.

Choose **本地文件夹 · 读取当前文件** when creating a project to capture the current
folder, including uncommitted changes. The project **代码源** page supports
several local folders, captures a real snapshot with SCG/ASG, shows coverage,
and opens task creation with that snapshot selected. Task creation can filter
snapshots by source. Updating a folder and capturing again preserves old tasks'
snapshot bindings. The existing Git project entry retains its earlier behavior.

For several folders, mount a parent directory read-only at `/repos` using a Compose
override, then register each child (for example `/repos/service` and `/repos/library`).
The supplied `compose.local.yaml` mounts only one directory at `/repos/source`.
A non-container server can set `--local-source-root` to a controlled directory;
the browser still uses logical `/repos/...` paths relative to that root. This
setting is server-side only and does not expose a filesystem browser.

Source definitions currently start at version 1 and are read-only. **更新快照与图谱**
captures changed content; it does not edit the definition. Source records and
task bindings use the existing persistent SQLite database. PostgreSQL and
external artifact storage remain separate implementation work.

### Git credentials

The same **代码源** page accepts **Git 仓库**. Supply a credential-free HTTPS/SSH
URL and a branch, tag or commit. Snapshot detail displays the requested ref and
resolved commit. Private credentials are deployment-owned references; the UI
accepts only their IDs, and LLM settings remain configured in the application.

Enable `--allow-network` (or `CODEXPLOIT_ALLOW_NETWORK=true` in Compose). For a
private repository, mount a secret document read-only and append
`--git-credential-file repository-access=/run/secrets/repository-access` to the
server command. The application runtime user must be able to read it. Keep the
document outside the repository. Its structure for HTTPS is:

```json
{"origin":"https://forge.example.invalid","project_ids":["PROJECT_ID"],"authorization":"<Basic or Bearer authorization value>"}
```

The origin must exactly match scheme/host/port; project IDs are an explicit
allowlist. A new project can be created before configuring its private credential
and adding a source on its **代码源** page. Failed initial capture retains the
project and source so it can be retried after correcting deployment access.

For SSH, use the same `origin` and `project_ids`, omit `authorization`, and provide
`ssh_user`, `ssh_identity_file` and `ssh_known_hosts_file` (absolute container paths).
Mount the key and known_hosts read-only outside the image. SSH uses batch mode,
strict host checking and only this identity; it does not fall back to the local
user's agent or SSH configuration. Encrypted interactive keys are unsupported.
The image includes the OpenSSH client. A custom HTTPS trust bundle can be mounted
and selected with `--git-ca-file /run/secrets/repository-ca.crt`.

Credential references are validated again on each capture so revocation or
rotation takes effect without modifying the immutable source definition. Neither
the authorization value nor private-key contents belong in Compose, source URLs,
source definitions or logs. The page distinguishes unavailable credentials,
denied access, network policy, missing commits and transport failures.

The image includes the server, the HTTP model adapter, Git and CA certificates.
External CLI agents and evidence-verification executables are deployment-specific
and are **not automatically supplied**. Configure `--agent-runtime cli
--agent-command ...` or `--verify-executor ...` using a Compose command override
or a deployment-specific image. Evidence verification stays disabled until an
executor is configured; LLM conclusions are hypotheses, never automatic
confirmation. See [Agent runtime](agent-runtime.md),
[verification](verification.md) and [scheduling](scheduling.md) for the adapter
protocol and execution contract. The UI displays unavailable capabilities and
does not replace execution with demo results.

To upgrade, keep the same Compose project/volume and run
`docker compose up -d --build`. Schema migrations run on startup. To back up,
stop the service and back up the entire data volume, including SQLite and the
snapshot trees, account database in `auth` and the entire `settings` directory, before
restarting. Do not use `docker compose down -v` when
retaining project data. Frozen source trees should be removed via snapshot
lifecycle commands rather than manual filesystem deletion.

## New API surface

| Method and path | Capability | Result |
|---|---|---|
| `GET /api/me` | reader | identity and available execution capabilities |
| `GET /api/settings/llm` | admin | redacted model configuration and ETag |
| `PUT /api/settings/llm` | admin | validate and persist encrypted configuration, requires If-Match |
| `POST /api/settings/llm/test` | admin | test an unsaved draft using the same If-Match and credential rules |
| `GET /api/projects/{id}/tasks` | reader | project task page (`limit`, `offset`) |
| `POST /api/projects/{id}/tasks` | writer | create independent task using an owned snapshot |
| `GET /api/tasks/{id}` | reader | task and ETag |
| `POST /api/tasks/{id}/pause` or `/resume` | writer | change scheduling; body `{}`, requires If-Match |
| `GET /api/projects/{id}/findings` | reader | grouped findings and confirmed grade counts |
| `GET /api/knowledge/findings/{id}` | reader | evidence detail and ETag, including when execution is disabled |
| `PATCH /api/findings/{id}/severity` | writer | set grade with If-Match |

Task creation accepts `name`, `objective`, `snapshot_id`, optional `scope`,
`budget` and `limits`. The snapshot must belong to the project and have an ASG.
Omitting the snapshot selects the newest project snapshot. Workbench requests
have bounded budgets (at most 2,000 paths and 16 concurrent leases).

### Task organization

The formal project task table has **当前任务 / 已归档** tabs, project categories,
pinning, archive/restore and existing pause/resume controls. Search, state/category
filters and pages are fetched from the server. Task state and progress use current
path records; unfinished Agent/verification runs also prevent archiving. The
table refreshes every five seconds while visible and not editing categories.

Archive only after pausing scheduling and waiting for active paths and unfinished
runs to settle. Archived tasks retain their snapshot, graph, paths, findings and
evidence. Restoring leaves scheduling paused; resume it explicitly. Categories
are shared within the project (up to 32 names, 1–30 characters each); remove task
assignments before deleting an in-use category. Changing a name can be performed
by adding the new category, reassigning tasks and removing the old unused name.

All task organization writes use the displayed task's ETag. A stale edit returns
412 and refreshes the table rather than silently replacing another client's
changes. Category management captures its own ETag when opened and uses the same
CAS rule. Reader access can filter and inspect data but cannot mutate it.

| Method and path | Capability / behavior |
|---|---|
| `PATCH /api/projects/{id}/tasks/{taskID}` | writer; optional `pinned`, `category`, `archived`; at least one property and `If-Match` required |
| `GET /api/projects/{id}/task-categories` | reader; category array, version and ETag |
| `PUT /api/projects/{id}/task-categories` | writer; `{categories:[...]}` and `If-Match`; rejects deletion of assigned categories |

`GET /api/projects/{id}/tasks` additionally accepts `q` (up to 200 characters),
`state`, `category`, `archived`, `sort=organized`, `limit` and `offset`. Omit
`category` for all categories or pass an empty value for uncategorized tasks.
`state` is one of `QUEUED`, `RUNNING`, `PAUSED`, `CONCLUDED`, `BLOCKED`, `FAILED`,
`EMPTY`, `ARCHIVED`. Organization sorting is pinned first, then newest creation,
then audit ID for deterministic ties. Filters apply before counting and paging.
Unchanged data gives stable pages; after an edit the page is refreshed and an
out-of-range page is clamped. Lists without these filters keep their earlier
behavior, including archived tasks, for existing clients.

Task list/detail adds `pinned`, `category`, `archived`, `etag`, `can_archive` and
`archive_block_reason`. ETags/version describe editable task metadata; live path
counts may change without changing that version. Archive eligibility is a read
hint; the write rechecks actual activity under the store lock/transaction. New
Agent/verification runs are refused for archived tasks. Missing versions return
428, stale edits 412, an in-use category 409 `category_in_use`, and an invalid
archive 409 `task_not_idle`. A task outside the project path returns 404.

SQLite migration 0014 preserves existing IDs and defaults tasks to unpinned,
uncategorized and unarchived. These additive endpoints extend the existing task
service; they do not claim the target workflow-based `/api/v1/tasks` contract.

Project findings accept `severity`, `status`, `task_id`, `limit` and `offset`.
Counts are confirmed findings before display filters. The project predicate is
applied in storage, including for legacy audit rows. Existing snapshot, audit,
path, run, hypothesis, verification and report endpoints are unchanged.

Static application files are public, while API data and mutations keep their
capability checks. Unknown API routes never receive HTML. Missing assets return
404, HTML is revalidated, and hashed assets use immutable caching. Production
assets use a same-origin content security policy and load no third-party fonts
or scripts.

## Snapshot artifacts

The formal **产物与证据** page lists the fixed snapshot's source-file inventory
and source tar with canonical scope, producer, size and SHA-256. Open it from the
project navigation, a source snapshot's details, or a task's fixed input tab.
Verify, bounded JSON preview and authenticated downloads report real errors.
The browser checks downloaded size and digest before saving. Existing retained
snapshots can explicitly register inputs; new source captures register them.
See [the artifact interface and recovery contract](artifacts.md) for routes,
limits, local volume layout and the external storage extension point.

## Shared knowledge graph

The formal **共享知识图谱** page reads pinned knowledge views instead of the
legacy per-snapshot endpoints. Pick a code version, then a layer: 源码图谱 lists
real symbols with their code position, 攻击面 lists entry points, sensitive
operations and controls, and 审计路径 lists the paths of every task that shares
that snapshot and layer version. Rows are keyboard selectable (arrow keys move,
Enter opens); the drawer shows the code slice, callers and provenance — the
plugin, version, config digest, sharing tasks and the source artifact the fact
was derived from.

The page states its coverage (parsed files, unparsed files, skipped symbols),
the number of sharing tasks and any budget truncation. A layer that was never
built is shown as 未构建, a missing capability as 不可用, a snapshot without a
graph as 尚未构建, and a rebuilt layer surfaces `view_superseded` with a
“重新固定版本” action instead of silently switching to the new build. See
[the fixed-view contract](knowledge.md) for routes, pins and limits.

## Validation

The formal **插件中心** page provides the real versioned catalog and builtin Go
parser. Administrators can register schema-validated manifests; uninstalled
external entries remain unavailable. Writers select a fixed source snapshot and
plugin version, validate configuration/budgets, start/cancel calls and inspect
persistent coverage and outputs. AST/fact artifacts use the existing preview and
download page. See [Plugin interfaces](plugins.md) for the complete contract.

The same formal page now runs builtin security-semantics and candidate-path
analysis. Select a completed parser invocation for semantics, then a completed
semantic invocation for paths. Candidate details show severity hints, call
reachability versus hypotheses, ordered steps, canonical IDs, raw evidence and
coverage limitations. These observations cannot change existing verdicts. See
[Builtin analysis](builtin-analysis.md) for formats and limits.

```bash
make test-web
npm --prefix web run build
make test
make test-stress
make lint
```

CI keeps the three-OS Go matrix and adds a Node 22 frontend test/build job plus
an embedded-server build. Store tests cover both memory and SQLite, including
task isolation, paused claims, path labels, project filtering, and concurrent
grade updates.
