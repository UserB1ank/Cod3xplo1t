# Runtime comparison report — seeded corpus

Maintainer decision (2026-10-20): the deployment default runtime was switched to `pi`; `llm` remains available for per-task selection and as the `CODEXPLOIT_AGENT_RUNTIME=llm` fallback. Existing runs keep their pinned runtime.

Provider: `deepseek-chat` at `https://api.deepseek.com`.  Corpus: `seeded-go-v1` (80 synthetic tasks, 20 per group; one path per task; 3 repetitions per runtime; 480 real runs total).  Verification is disabled in this deployment, so confirmed findings and cost per confirmed finding are N/A.


- dataset: seeded-go-v1
- expected runs per runtime: 240
- generated: 2026-10-20T02:36:58Z

## Real models

| runtime | samples | available | unavailable | missing | success | recall | FP | tokens p50/p95 | requests | calls | repairs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| llm | 240 | 240 | 0 | 0 | 0.98 | 0.90 | 0.71 | 13399/40282 | 856 | 710 | 85 |
| pi | 240 | 240 | 0 | 0 | 0.97 | 0.92 | 0.65 | 2624/5709 | 694 | 529 | 56 |

## Notes

- numbers are raw per-runtime measurements; choosing a default runtime is a human decision
