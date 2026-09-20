# Autonomous AI SOC Analyst System

Upload security logs and six LangGraph agents detect threats, map them to MITRE ATT&CK, write an incident report
with IOCs, and draft a response plan split by team. It only advises; nothing is executed automatically. Runs locally
with a free Ollama model.

## How it works

```
logs -> Ingest -> Detection -> Threat Intel -> Analyst -> Critic -+-> Response Planner
                                                  ^______________|  (re-analyze if confidence < 0.7, max 3 rounds)
```

| Agent | Job |
|---|---|
| Ingest | Parses raw logs into one schema (code only, no LLM) |
| Detection | 24 ATT&CK rules + ~15 keyword signatures + LLM; removes duplicates and routine activity |
| Threat Intel | Adds ATT&CK context; LLM-named technique IDs are kept only if a vector search over the MITRE catalogue agrees |
| Analyst | Incident report: summary, timeline, root cause, IOCs |
| Critic | Reviews the report and scores confidence |
| Response Planner | Actions tagged by team (SOC, Network, Endpoint, IAM, Legal, PR, Management) |

Every LLM call has a timeout, and each agent falls back to a deterministic result if the LLM fails.

**Stack:** FastAPI, LangGraph, Next.js 15, PostgreSQL + pgvector (incident embeddings), Qdrant (MITRE technique
embeddings), Redis (Streams job queue, cache, status), SSE, Docker Compose (6 services). LLM: Ollama (`llama3.1`),
or OpenAI / Groq / Anthropic via `LLM_PROVIDER`.

**Log formats:** syslog/sshd, Windows Security and Sysmon (event XML, multi-line blocks, JSON), CEF, Zeek conn.log,
DNS, email-gateway lines, Office 365 audit JSON, AWS CloudTrail, Azure, GCP. Logs are pasted or uploaded (max 5 MB,
5000 lines).

## Quick start

Needs Docker and [Ollama](https://ollama.ai) (`ollama pull llama3.1`, `ollama pull nomic-embed-text`).

```bash
cp .env.example .env
./start.sh                                                  # start services, initialise the DB
docker compose exec backend python scripts/load_mitre.py    # load the MITRE catalogue (once)
```

UI http://localhost:3000, API docs http://localhost:8000/docs, stop with `./stop.sh`. Try **Ingest -> Demo Mode**
or upload/paste logs.

## API

`POST /api/ingest/analyze|upload` (queued analysis) - `POST /api/v1/incidents/stream` (Demo Mode, SSE) -
`GET /api/incidents`, `/{id}`, `/{id}/status` - `PUT /api/incidents/{id}/status` -
`PATCH /api/incidents/{id}/response-plan/actions/{action_id}` - `GET /api/metrics/soc-kpis|attack-coverage` -
`POST /api/v1/incidents/search/semantic`, `GET /api/v1/mitre/search` - `GET /api/health/basic|deep`.

## Testing

```bash
cd backend
pytest -m "not integration and not db"   # 177 unit tests, ~4 s, no services (CI runs these)
pytest -m db                             # 6 tests, real Postgres + pgvector (CI runs these)
pytest -m integration                    # 10 tests, full stack + Ollama
python scripts/eval_public_datasets.py [--llm]      # real public attack data
python scripts/eval_false_positives.py [--mixed]    # generated benign noise
```

Test data: real attack captures from [Splunk attack_data](https://github.com/splunk/attack_data) and
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (downloaded on demand, git-ignored);
seeded generated benign Windows activity; and hand-written labeled cases. Details in `docs/TESTING_GUIDE.md`.

### Results (llama3.1 via Ollama)

| Test | Result |
|---|---|
| Rules on real Splunk attack_data captures | 24 of 24 rules fire |
| Rules on 249 real EVTX-ATTACK-SAMPLES files | alert on 92 (37%); the 24 rules cover a small part of ATT&CK |
| False positives on 100 generated benign batches (15,000 events) | alert in 1% of batches, 0.1 per 1000 events |
| 20 real attack captures blended into benign noise | target rule fires in 20 of 20 |
| LLM naming the right technique on 24 real captures | 2 (llama3.1) / 4 (gpt-oss-120b cloud) |
| Labeled synthetic fixtures (25 cases) | F1 1.0; technique precision / recall 0.944 / 0.548 |
| Held-out synthetic sets (v1 / v2) | F1 0.933 / 1.0 |
| End-to-end latency | 115-201 s per analysis (LLM-bound) |

The rules do the detecting; the LLM contributes the report, timeline and response plan. The public data is
attack-only (it measures recall), the benign noise and the labeled cases are synthetic, and no production logs were
used, so treat the numbers as indicative.

## Limitations

- No login (local use only) and no TLS.
- The LLM sees up to 100 lines verbatim (statistics plus a sample for larger batches); the rules see every line.
- llama3.1 sometimes returns malformed JSON (~5% of reports use the fallback) and is sensitive to prompt wording.
- Prompt-injection handling (sanitising, delimiting, detection) is heuristic.
- IOCs have no private-IP filter or enrichment.

More: `STACK_AND_IMPLEMENTATION.md`, `MITRE_ATTACK_EXPLAINED.md`, `docs/TESTING_GUIDE.md`.
