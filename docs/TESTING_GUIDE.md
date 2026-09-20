# Testing guide

## Automated tests

```bash
cd backend
pytest -m "not integration"      # 123 unit tests, ~2 s, no services or LLM (this is what CI runs)
pytest -m integration            # 15 tests: full stack + Ollama, ~25 min
```

- **Unit:** parsers, one sample per ATT&CK rule (+ negatives), detection accuracy on the labeled cases (no LLM),
  real-format samples from the public datasets, input limits, prompt injection, IOC extraction, the LLM-dependent
  code paths with a fake model (retries, fallbacks, timeouts, the reflection loop).
- **Integration:** synthetic fixtures and three real public captures (Splunk attack_data) through all six agents
  with the real model. The real-capture tests skip if the data cache is missing.

## Evaluation scripts (real model / real data)

| Script | What it measures |
|---|---|
| `scripts/eval_detection_metrics.py --mode rules\|llm [--enrich]` | Precision/recall on the 25 labeled fixture cases |
| `scripts/eval_holdout_generalization.py [cases.json]` | Held-out sets in other formats (v1: default, v2: `data/holdout_v2_cases.json`) |
| `scripts/eval_public_datasets.py [--llm]` | Public attack data: per-rule (Splunk) and per-tactic (EVTX) detection; `--llm` adds the LLM on small samples |
| `scripts/eval_false_positives.py [--mixed] [--llm]` | Generated benign noise: false-alarm rate; `--mixed` blends real attack captures into it; `--llm` runs the LLM on benign batches |

Public datasets are downloaded on first run into the git-ignored `backend/data/public/`. They are attack-only, so
they measure recall, not false positives.

## Data

Synthetic and hand-written: `backend/data/labeled_incidents.json` (20 cases), `backend/tests/fixtures/test_logs.json`
(5 scenarios), `holdout_generalization_cases.json` (10), `holdout_v2_cases.json` (8), and the UI demo scenarios in
`frontend/src/lib/api.ts`. Real: the public datasets above.

## Manual checks

```bash
curl localhost:8000/api/health/basic          # liveness
curl localhost:8000/api/health/deep           # runs every agent (30-60 s)
./test_all_features.sh                        # API end-to-end (backend must be running)
```

UI: **Ingest -> Demo Mode** runs one of six scenarios (brute force, PowerShell, RDP lateral movement, ransomware,
cloud IAM abuse, port scan) with live agent progress. `GET /api/debug/validate-incident/{id}` checks an incident
against expected criteria; `GET /api/debug/last-analysis/{id}` shows each agent's duration and output.

## Troubleshooting

- **Analysis stays "queued":** the worker isn't running or can't reach Redis (`docker compose logs worker`).
- **No MITRE tags / "Unknown Technique":** run `docker compose exec backend python scripts/load_mitre.py`.
- **Embedding errors:** Ollama isn't running or `nomic-embed-text` isn't pulled.
- **Slow runs:** each analysis takes 2-3 minutes on a local model; the LLM calls dominate.
