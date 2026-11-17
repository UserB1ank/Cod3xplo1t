# Current capability matrix

Date: 2026-11-17. This matrix describes the current refactor baseline, not every
historical feature description. It does not claim that the target autonomous
audit loop is complete.

## Baseline

| Item | Fixed value |
|---|---|
| Branch / committed baseline | `dev` at `a7989cc`; unrelated worktree WIP is preserved |
| Local toolchain observed | Go 1.27.0, Docker 29.8.2, Docker Compose 5.5.0 |
| CI toolchain | Go from `go.mod`; Node 22.19 for Pi worker; Node 22 for Web |
| Primary target stack | Go application, Grafana 8.3.0 / 8.3.1 |
| Fixed R0/R1 target pair | [Grafana CVE-2021-43798](../benchmarks/r0/grafana-cve-2021-43798/README.md) |
| Oracle | vulnerable returns `/etc/passwd` through a plugin asset URL; safe returns HTTP 404 |
| Verification environment | local Docker, read-only root filesystem, dropped capabilities, loopback-only ports |

Grafana is an open-source Go application. The canonical pair uses the real
CVE-2021-43798 affected release 8.3.0 and fixed release 8.3.1, with source tags,
source commits, official multi-architecture image digests and a response-body
oracle fixed in `dataset.json`. This program remains the default refactor sample
unless an explicit replacement decision is made.

## Capability

| Capability | State on this base | Evidence / limit |
|---|---|---|
| Read-only source input and immutable snapshots | Usable | Existing source import, snapshot, artifact and PostgreSQL paths remain the maintained storage profile |
| Go/Grafana static analysis | Limited | Existing Go frontend and graph capabilities are usable, but the complete Grafana investigation and runtime loop is not yet wired |
| Java/Spring static graph | Secondary compatibility | Existing Joern capability remains available; large-source runs can remain PARTIAL and must report coverage gaps |
| Source search and direct source reads | Usable independently | Must remain available when graph creation fails or is partial |
| Existing finding / evidence ledger and reports | Limited but usable | Historical findings and reports remain readable; they are not yet linked through one audit-root job identity |
| Main Agent conversation and project MCP tools | Experimental for this target | Existing supervisor sessions/tools are real, but the complete investigation-to-verification loop is not connected |
| Real child Agent work | Limited | Existing path/batch workers exist, but not as the R1 unified parent/child work protocol |
| Direction messages, global/child control and crash takeover | Partial / disconnected | Owner/epoch and lease mechanisms exist in separate execution domains; unified audit semantics remain R2 |
| Dynamic verification implementation | Experimental / not on the main line | Historical verification is API-only; R0 only fixes a real Docker target and oracle |
| Candidate detection metrics | Corrected in report v2 | TP/FN/FP/TN, abstention, execution failure and non-binary labels are separate |
| Dynamic verification metrics | Schema ready, no new evidence | `verification_status` is separate; R0 has no real verifier-generated samples |
| Historical benchmark numbers | Historical only | Version 1 metric defect is documented; raw samples are unavailable, so no new percentages are asserted |
| CI on active development branch | Locally equivalent checks pass; remote run not yet observed | Workflow push branches now include `main` and `dev`; before this slice only `main` was configured and the repository Actions API reported zero workflow runs |

## Baseline checks

Checks run on 2026-11-17 against the current worktree:

| Check | Result |
|---|---|
| R0 affected packages with `-race -shuffle` | 21 tests passed in 4 packages |
| Full Go suite `go test ./... -count=1 -shuffle=on -race -timeout 240s` | 1,506 tests passed in 58 packages |
| `make test-stress` | passed with the full suite repeated three times |
| `make test-postgres` | storage and API PostgreSQL acceptance passed |
| `make lint` | `go vet` and pinned Staticcheck passed |
| `make check-contracts` | v1 and v2 contract packages passed |
| Frontend | 78 tests, TypeScript check and production build passed; Vite retained a chunk-size warning |
| Docker target oracle | Grafana 8.3.0 returned HTTP 200 with `root:x:0:0`; 8.3.1 returned HTTP 404 without the marker |
| Remote `dev` CI | not run because this turn is prohibited from pushing; local commands match the workflow |

These are engineering-baseline results. They do not establish candidate quality,
dynamic-confirmation quality, or completion of the R1 autonomous-audit loop.

## R0 verification rule

R0 is a measurement baseline, not evidence that the full product works. Scripted
models, synthetic corpora, real models, PostgreSQL and Docker targets must remain
separately labelled. No dynamic confirmation or candidate-quality number may be
quoted until it is backed by retained raw samples and the corresponding real
execution or model record.
