# Codexploit Pi worker

One fixed-version worker process per agent run. It embeds
`@earendil-works/pi-agent-core` and `@earendil-works/pi-ai` and speaks the
worker protocol v1 over JSONL on stdin/stdout (`docs/agent-runtime.md`).

It owns no authority:

- every provider request waits for a host permit;
- every tool is a proxy to the host, which validates the schema, injects the
  task's scope and returns the budget receipt;
- every answer is proposed to the host for validation;
- no built-in filesystem, shell, edit, extension, session or model catalog is
  loaded. The model endpoint and credentials arrive in the private `init` frame
  and live only in memory.

Build and test:

```sh
make pi-worker
```

The build is pinned by `package-lock.json`. Node 22.19 or newer is required. The
runtime image copies `dist` and production dependencies and runs as the
non-root application user. This worker is trusted deployment code, not a
sandbox: see the containerization notes in `docs/agent-runtime.md`.

Deploy it with `--agent-runtime=pi --pi-worker=/app/pi-worker/dist/main.js`, or
with `CODEXPLOIT_AGENT_RUNTIME=pi` in the Compose deployments.
