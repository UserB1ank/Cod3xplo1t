# Third-party notices

The worker is pinned by `package-lock.json`. Direct runtime dependencies:

| Package | Version | License |
|---|---|---|
| `@earendil-works/pi-agent-core` | 1.3.0 | MIT |
| `@earendil-works/pi-ai` | 1.3.0 | MIT |
| `typebox` | 1.3.27 | MIT |

Transitive dependencies are locked by the lockfile with their integrity
digests. The Pi packages are upstream releases, not a fork; the worker imports
only `pi-agent-core` and `pi-ai`, never `pi-coding-agent`, its CLI, built-in
tools, extensions or session store.
