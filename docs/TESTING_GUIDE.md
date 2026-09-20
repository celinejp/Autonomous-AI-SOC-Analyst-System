# Testing guide

## Automated tests

```bash
cd backend
pytest -m "not integration"      # 175 unit tests, ~3 s, no services or LLM (CI runs these)
pytest -m integration            # 10 tests, full stack + Ollama, ~17 min
```

| File | Covers |
|---|---|
| `test_ingest_parsers.py`, `test_cloud_parsers.py`, `test_public_formats.py` | Log parsers: sshd, Windows text/XML/blocks/JSON, Sysmon, CEF, Zeek, DNS, email, cloud; benign look-alikes staying quiet |
| `test_attack_rules.py` | One sample per ATT&CK rule, negative cases, no unsupported pattern types |
| `test_agent_accuracy.py` | Detection accuracy on the 25 labeled cases through the real pipeline (no LLM) |
| `test_agents_fake_llm.py` | LLM-dependent paths with a fake model: retries, fallbacks, timeouts, outages, the reflection loop |
| `test_agent_parsing.py`, `test_threat_intel.py`, `test_ioc_extraction.py`, `test_alert_filtering.py`, `test_log_summary.py` | Critic/Planner/Analyst parsing, technique grounding, IOC rules, alert filtering, LLM prompt summaries |
| `test_prompt_injection.py`, `test_input_limits.py` | Prompt-injection defences, upload limits |
| `test_api.py`, `test_job_queue.py`, `test_worker.py`, `test_embedding_service.py`, `test_llm_factory.py` | HTTP API and Demo Mode stream, Redis queue, worker, embeddings, provider selection (Redis, DB and workflow faked) |
| `test_system_health.py` (integration) | Real services: full workflow on a brute-force scenario, detection on the five fixture scenarios, three real public captures through all six agents, and a full-stack run (API -> Redis queue -> worker -> LLM -> Postgres/pgvector -> semantic search) |

The real-capture tests skip if the data cache is missing; the full-stack test skips if the backend isn't running.

## Evaluation scripts

| Script | Measures |
|---|---|
| `scripts/eval_detection_metrics.py --mode rules\|llm [--enrich]` | Precision/recall on the 25 labeled fixture cases |
| `scripts/eval_holdout_generalization.py [cases.json]` | Held-out sets in other formats (default v1; v2: `data/holdout_v2_cases.json`) |
| `scripts/eval_public_datasets.py [--llm]` | Per-rule (Splunk) and per-tactic (EVTX) detection on real attack data; `--llm` adds the LLM on small samples |
| `scripts/eval_false_positives.py [--mixed] [--llm]` | False-alarm rate on generated benign activity; `--mixed` blends in real attack captures; `--llm` runs the LLM |

Public datasets are downloaded on first run into the git-ignored `backend/data/public/`. They are attack-only, so
they measure recall, not false positives.

## Data

- Real: Splunk attack_data and EVTX-ATTACK-SAMPLES (public).
- Generated: seeded benign Windows activity (`scripts/eval_false_positives.py`).
- Hand-written: `backend/data/labeled_incidents.json` (20 cases), `backend/tests/fixtures/test_logs.json`
  (5 scenarios), `holdout_generalization_cases.json` (10), `holdout_v2_cases.json` (8), and the UI demo scenarios in
  `frontend/src/lib/api.ts`.

## Manual checks

```bash
curl localhost:8000/api/health/basic     # liveness
curl localhost:8000/api/health/deep      # runs every agent
./test_all_features.sh                   # API end-to-end (backend running)
```

UI: **Ingest -> Demo Mode** runs one of six scenarios with live agent progress. `GET /api/debug/last-analysis/{id}`
shows each agent's duration and output; `GET /api/debug/validate-incident/{id}` checks an incident against expected
criteria.

## Troubleshooting

- **Analysis stays "queued":** the worker isn't running or can't reach Redis (`docker compose logs worker`).
- **No MITRE tags / "Unknown Technique":** `docker compose exec backend python scripts/load_mitre.py`.
- **Embedding errors:** Ollama isn't running or `nomic-embed-text` isn't pulled.
