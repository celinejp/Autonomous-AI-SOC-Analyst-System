# Stack

## Components

| Layer | Technology | Role |
|---|---|---|
| Frontend | Next.js 15 (App Router), React 18, TypeScript, Tailwind/shadcn, TanStack Query, Recharts | UI; live progress via `fetch` + ReadableStream (SSE) |
| API | FastAPI | REST + SSE, OpenAPI docs at `/docs` |
| Orchestration | LangGraph | 6-node graph with one Critic -> Analyst loop; no checkpointer |
| LLM | Ollama (default `llama3.1`), OpenAI, Groq, Anthropic | one factory, `LLM_PROVIDER` / `LLM_MODEL`; every call has a timeout |
| Postgres + pgvector | incidents, alerts, reports, response plans, agent logs; incident embeddings | source of truth; incident search and similar-incident tool |
| Qdrant | ~700 MITRE technique embeddings | technique grounding and technique search only |
| Redis | Streams job queue, incident status, response cache, locks, rate limit | |
| Worker | `python -m app.workers.analysis_worker` | consumes the queue; retries 3x then dead-letter stream |
| Docker Compose | postgres, redis, qdrant, backend, worker, frontend | Ollama runs on the host; restart `worker` after agent code changes |

## Request paths

- **Upload / analyze:** `POST /api/ingest/*` creates an incident and queues a job -> worker runs the graph, saves
  the incident, queues an embedding job -> UI polls `GET /api/incidents/{id}/status`.
- **Demo Mode:** `POST /api/v1/incidents/stream` runs the graph as a background task and streams agent events over
  SSE; the incident is saved even if the browser disconnects.

## UI pages and their endpoints

| Page | Uses |
|---|---|
| Dashboard `/` | `/api/dashboard/stats`, `/api/metrics/soc-kpis` |
| Ingest `/ingest` | `/api/ingest/analyze`, `/api/v1/incidents/stream`, `/api/synthetic/generate` |
| Incidents `/incidents`, `/incident/[id]` | `/api/incidents` (list, detail, status, response-plan actions), JSON download |
| Search `/search` | `/api/v1/incidents/search/semantic`, `/api/v1/mitre/search` |
| Insights `/insights` | `/api/metrics/*`, dashboard stats |
| Health `/health` | `/api/health/basic`, `/api/health/deep` |
| Debug `/debug` | `/api/debug/*`, `/api/v1/validate/*`, `/api/v1/performance/metrics` |
