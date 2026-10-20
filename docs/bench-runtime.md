# Runtime comparison benchmark

`cmd/bench-runtime` turns finished-run samples into a machine-readable comparison
of `llm` and `pi`. It is the evidence a maintainer reviews before deciding whether
Pi should become the default; **it never changes the default itself**. The scripted
golden set (`make bench-agent`) stays a contract regression; it is not quality
evidence.

## What counts as evidence

A sample is one finished run of one labeled task on one runtime. The aggregator
refuses to infer from missing data:

- a sample without `usage_source=reported` and a positive token total is
  **unavailable**; its tokens are not zero and it never wins on cost;
- fewer samples than `expected_runs` are **missing**, and the verdict becomes
  `insufficient_evidence`;
- scripted samples live in the `fixture` section and are never compared with the
  real `real` section;
- cost per confirmed finding is reported only when a verifier confirmed findings;
  otherwise it is N/A.

Verdicts are `real_run_pending` (no real samples), `insufficient_evidence` (fewer
than 20 available samples per runtime, any unavailable sample or any missing run)
and `comparable` (raw numbers only — choosing a winner remains a human decision).

## Sample input

```json
{
  "dataset": "labeled-set-v1",
  "expected_runs": 60,
  "runtimes": ["llm", "pi"],
  "fixture": [],
  "real": [
    {
      "runtime": "pi", "task_id": "task-...", "group": "seeded",
      "label": "vulnerable", "predicted": "candidate",
      "status": "SUCCEEDED", "stop_reason": "completed",
      "usage_source": "reported", "input_tokens": 1200, "output_tokens": 180,
      "model_requests": 2, "tool_calls": 1, "repairs": 0,
      "novelty": [2], "elapsed_ms": 8400,
      "evidence_items": 3, "valid_evidence": 3,
      "confirmed_findings": 1,
      "obligations_total": 4, "obligations_closed": 4
    }
  ]
}
```

`label` is `vulnerable`, `safe`, `undecidable` or `edge`; `predicted` is
`candidate`, `refuted` or `inconclusive`. Recall and the false-positive rate use
those labels. `confirmed_findings` is only for a real verifier's confirmed
findings.

## Running

```sh
# Fixture/contract report only: the real section is reported as pending.
make bench-runtime BENCH_ARGS="--samples samples.json --out bench-report.json --markdown bench-report.md"

# Include real-model samples only with an explicit opt-in.
make bench-runtime BENCH_ARGS="--samples samples.json --allow-real --out bench-report.json --markdown bench-report.md"
```

The command writes the JSON report and an optional Markdown summary. It does not
call a provider itself: the operator's evaluation run produces the samples (one
per task/runtime/repetition, at least 20 labeled tasks per group, three repetitions
per task and runtime, fixed seeds when the provider supports them), so the
official run needs operator credentials and an approved budget.

## Current status

The harness and its unavailable/failed semantics are in place and tested. No
real-model evaluation has been run in this environment (no operator credentials
were supplied), so the report is `real_run_pending` and the default runtime stays
`llm`. Pi remains selectable per task. When the real run is approved, produce the
samples, run the command, review recall / false positives / obligations /
unavailable counts and the raw cost, then decide whether to change the default in
a separate change. Existing runs keep the runtime they pinned.

## Running a real evaluation

Two commands produce the samples and the report:

```sh
# 1. Write a fixed, seeded corpus: 20 tasks per group (seeded, safe,
#    undecidable, edge), with the ground-truth label in the dataset.
go run ./cmd/bench-corpus --out /tmp/bench-corpus --per-group 20

# 2. Run the corpus through the deployment. --allow-real is the explicit
#    opt-in; the deployment needs the model configured in its encrypted
#    settings and a writer/admin API token.
go run ./cmd/bench-eval \
  --base http://127.0.0.1:18085 --token "$CODEXPLOIT_API_TOKEN" \
  --dataset /tmp/bench-corpus/dataset.json \
  --runs 3 --allow-real --out /tmp/bench-samples.json

# 3. Aggregate the samples into the machine-readable and Markdown report.
go run ./cmd/bench-runtime --samples /tmp/bench-samples.json --allow-real \
  --out /tmp/bench-report.json --markdown /tmp/bench-report.md
```

`expected_runs` in the samples file is **per runtime** (tasks × repetitions).
The corpus must be mounted into the deployment container at the path the
dataset's `source` fields use (default `/corpus`).

`--per-group N` selects the first N tasks of each group, `--concurrency 4`
evaluates several samples in parallel and rewrites the samples file after every
completed sample (an interrupted run keeps its progress), and
`--grant-tokens N` raises each task's audit ceiling before its run (a multi-path
task otherwise pauses at the default 60k). `bench-eval` pauses each new task and
runs exactly one path through `POST /api/paths/{id}/runs`, so the resident
scheduler cannot spend budget on the other paths and each sample is one task, one
path, one run. `bench-eval` creates one
project and one snapshot per task, then one task per runtime and repetition; it
waits for the first terminal run of that runtime and records the run's metrics
and answer. A task whose paths finish without a run of the runtime is recorded
as failed, not as a zero-cost success.

The corpus is seeded and synthetic. Its ground truth is known by construction,
which makes the recall and false-positive numbers reproducible, but it is not a
substitute for a curated real-world set; the report's verdict stays
`insufficient_evidence` until a runtime reaches 20 available samples with no
unavailable sample or missing run. The cost fields remain N/A while the
verification executor is unsupported (no verifier-confirmed finding).
