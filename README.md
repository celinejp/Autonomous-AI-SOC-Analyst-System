# Autonomous AI SOC Analyst System

A personal project: upload security logs and a chain of six LangGraph agents detects threats, maps them to
MITRE ATT&CK, writes an incident report with IOCs, and drafts a response plan split by team. It only advises;
nothing is executed automatically. Runs locally with a free Ollama model.

## How it works

```
logs -> Ingest -> Detection -> Threat Intel -> Analyst -> Critic -+-> Response Planner
                                                  ^______________|  (re-analyze if confidence < 0.7, max 3 rounds)
```

| Agent | Job |
|---|---|
| Ingest | Parses raw logs into one schema (code only, no LLM) |
| Detection | 24 ATT&CK rules + ~15 keyword signatures + LLM judgment; filters duplicates and routine activity |
| Threat Intel | Adds ATT&CK technique context; LLM-named technique IDs are kept only if a vector search over the MITRE catalogue agrees |
| Analyst | Incident report: summary, timeline, root cause, IOCs |
| Critic | Reviews the report and scores confidence |
| Response Planner | Actions tagged by team (SOC, Network, Endpoint, IAM, Legal, PR, Management) |

Every LLM call has a timeout and each agent degrades gracefully (rules-only detection, deterministic report, ...).

**Stack:** FastAPI, LangGraph, Next.js 15, PostgreSQL + pgvector (incident embeddings), Qdrant (MITRE technique
embeddings), Redis (job queue on Streams, cache, status), SSE for live progress, Docker Compose (6 services).
LLM providers: Ollama (default, `llama3.1`), OpenAI, Groq, Anthropic.

**Two ways to run an analysis:** upload/analyze is queued on Redis and processed by the `worker` container (the UI
polls); Demo Mode runs inline and streams progress over SSE.

**Log formats:** syslog/sshd, Windows Security and Sysmon (event XML, multi-line event blocks, JSON), CEF, Zeek
conn.log, DNS resolver lines, email-gateway lines, Office 365 audit JSON, AWS CloudTrail, Azure, GCP. Logs are
pasted or uploaded; nothing connects to a live source. Limits: 5 MB, 5000 lines, 8192 characters per line.

## Quick start

Needs Docker and [Ollama](https://ollama.ai) (`ollama pull llama3.1` and `ollama pull nomic-embed-text`).

```bash
cp .env.example .env
./start.sh                       # starts services, initialises the DB
docker compose exec backend python scripts/load_mitre.py   # load ~700 MITRE techniques (once)
```

UI http://localhost:3000 - API docs http://localhost:8000/docs. Stop with `./stop.sh`.
Try **Ingest -> Demo Mode**, or upload a log file / paste lines.

## Main API endpoints

`POST /api/ingest/analyze` and `/upload` (queue an analysis) - `POST /api/v1/incidents/stream` (Demo Mode, SSE) -
`GET /api/incidents`, `/{id}`, `/{id}/status` - `PUT /api/incidents/{id}/status` (incl. false positive) -
`PATCH /api/incidents/{id}/response-plan/actions/{action_id}` - `GET /api/metrics/soc-kpis`, `/attack-coverage` -
`POST /api/v1/incidents/search/semantic`, `GET /api/v1/mitre/search` - `GET /api/health/basic|deep`.

## Testing and data

- **Unit tests (123, ~2 s, no services):** `cd backend && pytest -m "not integration"`. They cover the parsers,
  reachability of all 24 rules, real-pipeline detection accuracy (no LLM), the LLM-dependent code paths with a fake
  model (retries, fallbacks, timeouts, the reflection loop), input limits, prompt-injection handling and IOC
  extraction. CI runs these.
- **Integration tests (15):** need the full stack and Ollama (~25 min); synthetic fixtures plus three real public
  captures through all six agents. `pytest tests/test_system_health.py -m integration`.
- **Evaluation scripts** (real model / real data): `scripts/eval_detection_metrics.py`,
  `scripts/eval_holdout_generalization.py`, `scripts/eval_public_datasets.py`, `scripts/eval_false_positives.py`.

### Test data

1. **Public attack datasets (real telemetry).** `scripts/eval_public_datasets.py` downloads them into the
   git-ignored `backend/data/public/` and runs the detection layer (rules only, no LLM):
   - [Splunk attack_data](https://github.com/splunk/attack_data) - real Atomic Red Team captures, one folder per
     ATT&CK technique ID.
   - [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - real Windows/Sysmon events
     labeled by ATT&CK tactic.
2. **Generated benign noise** (`scripts/eval_false_positives.py`, seeded): realistic ordinary Windows activity incl. look-alikes
   (admin `net user`, `curl` to an internal API, control-panel `rundll32`, updater services and Run keys). Used to
   measure false positives, alone and mixed with the real attack captures.
3. **Synthetic, hand-written by the author:** 25 labeled fixture cases, two held-out sets (10 + 8 cases in other
   formats), one sample per rule, and the UI demo scenarios.

### Results (20 Sep 2026, llama3.1 via Ollama)

| Test | Result |
|---|---|
| **Splunk attack_data**, rules only, up to 4 real captures per ATT&CK technique | **24 of 24 rules fire on real logs** (4 of 24 before the parser and rule fixes this data revealed) |
| Same, with the LLM on 24 small real captures | rules + LLM alert on 21 of 24; the LLM itself named the right technique family on only 2 |
| **EVTX-ATTACK-SAMPLES**, rules only, 249 real sample files across 8 tactics | Alert on 92 (37%), modest because 24 rules cover a small slice of ATT&CK |
| **False positives**, rules, 100 generated benign batches (15,000 events, incl. look-alikes) | Alert in 1% of batches, 0.1 alerts per 1000 events (**was 100% of batches / 29.7 per 1000 before tightening five rules**) |
| **Recall in noise**: 20 real attack captures blended into 300 benign events | Target rule still fires in 20 of 20 |
| LLM on real data, llama3.1 / gpt-oss-120b (cloud) | On 24 small real captures the LLM itself named the right technique family in 2 / 4; on 20 real attacks the rules missed it raised an alert on 7 / 10 (technique not checked) |
| LLM on 12 benign batches, llama3.1 / gpt-oss-120b (cloud) | 0 / 1 batches with an LLM-only alert |
| Fixtures, 25 synthetic cases (LLM) | F1 1.0; 0 false positives; technique precision / recall 0.944 / 0.548 |
| Held-out v1 / v2, synthetic (LLM) | F1 0.933 / 1.0, identical over 3 runs each |
| Latency, end to end | 115-201 s per analysis on local llama3.1 (LLM-bound) |

How to read this: on real logs the deterministic rules do the work and the LLM adds little (even the much larger
cloud model names the technique family in only 4 of 24), so detection quality depends on the rules; the LLM's value
is the report, timeline and response plan. The public data is attack-only, so false positives are measured on the
generated benign noise, which is synthetic and written by the author, so it is a sanity check, not production noise. The synthetic sets
were written next to the rules, so 1.0 there is close to self-grading. Splunk/EVTX labels are per file, not per
event. Six rules that public data couldn't exercise (port scan, beaconing, DNS tunnelling, ransomware, phishing
links, cloud upload) were replaced with techniques it does contain; ransomware, port scans, C2 and DNS tunnelling are
still caught by the keyword signatures and the LLM. Reproduce: `python scripts/eval_public_datasets.py [--llm]`.

## Notes

- **No login:** it is a personal, local project. Do not expose it to an untrusted network.
- **Prompt injection:** log text is sanitised, wrapped in untrusted-data markers, and instruction-like phrases
  become their own alert. It reduces the risk; it is not proof against a determined attacker.
- **LLM limits:** llama3.1 sometimes returns malformed JSON (~5% of analyst runs use the fallback report) and is
  sensitive to prompt wording, so critical rules are enforced in code. The LLM sees up to 100 lines verbatim
  (statistics plus a sample for larger batches); the rules see every line.
- **Not done:** TLS, IOC enrichment (VirusTotal etc.), private-IP filtering for IOCs, PDF export (incidents can be
  downloaded as JSON), deployment, load testing.

## Project layout

```
backend/app/{agents,detection,orchestrator,api/routes,services,database,core,tools,workers}
backend/{scripts,data,tests}      frontend/src/{app,components,hooks,lib}
docker-compose.yml  start.sh  stop.sh  .github/workflows/ci.yml
```

More: `STACK_AND_IMPLEMENTATION.md` (what is wired to what), `MITRE_ATTACK_EXPLAINED.md` (the 24 rules),
`docs/TESTING_GUIDE.md`.
