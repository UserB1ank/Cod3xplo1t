## Security & Privacy

禁止在项目中出现以下敏感信息和敏感文件：

- 本机 hostname、本地用户名称
- 真实密钥、API keys、tokens、passwords
- 邮箱地址、手机号等个人信息
- .env 文件、私钥文件（PEM、SSH key 等）
- 禁止出现 `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` 相关字样
- 只有在人工同意后才能push和commit。在多次commit后，人工要求push再进行push，绝对不要主动push。

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues via `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Project docs live under `docs/` (`docs/mcp-tools.md`, `docs/api.md`, `docs/architecture.md`, `docs/design/`).

### Releases

Use the release PR process in `docs/releasing.md` before tagging. Give the PR
a `release/vX.Y.Z` head branch or `release: vX.Y.Z` title, run
`make prepare-release RELEASE_VERSION=vX.Y.Z`, and review the generated
changelog and `server.json` changes. CI checks both files before merge.

### Tests run in CI on three OSes

Whenever you write or modify a test, remember it must pass in
`.github/workflows/test.yml` — ubuntu, macos and windows, via
`go test ./... -count=1 -shuffle=on -race -timeout 240s` (identical to
`make test`). For races the detector cannot see — filesystem and lifecycle
races — run `make test-stress` locally before pushing. Assume concurrency, a
fresh runner, and dirty state from other tests or processes. Never hardcode a
shared absolute path; `t.TempDir()` is the default. See
`docs/agents/testing.md`.

Static analysis is a gate too: the `lint` job runs `make lint` (gofmt over the
files `git ls-files` returns, `go vet`, and Staticcheck at the version pinned in
the Makefile) on ubuntu. Run `make lint` before pushing — a new Staticcheck
finding, including unused code, fails CI.
