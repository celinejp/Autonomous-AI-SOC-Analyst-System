# Stack, Implementation & Connectivity

Overview of the **tech stack and each component’s role**, what is **implemented**, and **how connected** everything is (end-to-end vs backend-only).

---

## 1. Tech stack and roles

### Frontend
| Layer | Technology | Role |
|-------|------------|------|
| **App** | Next.js 15 (App Router) | Routing, SSR/CSR, layout |
| **UI** | React 18, TypeScript, Tailwind, shadcn/ui | Pages, components, styling |
| **Data** | TanStack Query (React Query v5) | Server state, caching, mutations |
| **Charts** | Recharts | Dashboards, severity/custom charts |
| **Real-time** | Fetch + ReadableStream (SSE) | Demo mode live agent stream |

**Role:** User interface for SOC analysts: ingest logs, run demos, view incidents, dashboard, insights, health, settings, debug, synthetic log generation.

---

### Backend API
| Layer | Technology | Role |
|-------|------------|------|
| **Framework** | FastAPI | REST + SSE, async, OpenAPI docs |
| **Routers** | 16 route modules | Health, incidents, ingest, stream, dashboard, metrics, organization, debug, synthetic, analysis, SIEM, response, semantic search, validation, performance |

**Role:** HTTP API and streaming; orchestrates agents, DB, cache, and external services.

---

### AI / orchestration
| Layer | Technology | Role |
|-------|------------|------|
| **Orchestration** | LangGraph | Multi-agent state machine, reflection loop (critic → re-analyze) |
| **Agents** | 6 agents (Ingest, Detection, Threat Intel, Analyst, Critic, Response Planner) | Parse logs, detect threats, enrich with ATT&CK, write report, critique, produce response plan |
| **LLM** | Multi-provider (Ollama, OpenAI, Groq, Anthropic) | Agent prompts and tool use |
| **Tools** | LangChain tools | IP lookup, MITRE search, file/domain intel (demo data) |

**Role:** End-to-end analysis pipeline from raw logs to incident report and response plan.

---

### Data & infrastructure
| Layer | Technology | Role |
|-------|------------|------|
| **Primary DB** | PostgreSQL + pgvector | Incidents, alerts, reports, response plans, org profile, agent logs, log entries |
| **Cache** | Redis | Incident status during analysis, API response cache |
| **Vector DB** | Qdrant | Semantic search, threat intel (when used) |
| **Migrations** | SQL scripts under `backend/scripts/migrations/` | Schema for incidents, reports, response_plans, organization_profile, etc. |

**Role:** Persistence, caching, and vector search for the pipeline and UI.

---

### DevOps / run
| Layer | Technology | Role |
|-------|------------|------|
| **Containers** | Docker Compose | PostgreSQL, Redis, Qdrant, backend (frontend optional) |
| **Scripts** | `start.sh`, `stop.sh`, `init_db` | One-command start/stop and DB init |

**Role:** Run full stack locally or in a lab.

---

## 2. What is implemented

### Fully implemented (backend + frontend + wired)

| Area | Backend | Frontend | Connection |
|------|---------|----------|------------|
| **Log ingestion** | `/api/ingest/analyze`, `/api/ingest/upload` | Ingest page (paste/upload, Analyze) | Full: UI → API → background workflow → DB → incident |
| **Demo mode** | `POST /api/v1/incidents/stream` (SSE) | Ingest → Demo tab, Run Demo, stream viewer, redirect | Full: UI → stream → save incident → redirect |
| **Incidents** | CRUD + filters + `GET/PUT /incidents/:id/status`, `PATCH .../response-plan/actions/:id` | List, detail, filters, Mark Contained/Closed, response plan “Start Action” | Full: all actions call API and refresh data |
| **Dashboard** | `/api/dashboard/stats` | Home: cards, top MITRE, quick links | Full |
| **Metrics** | `/api/metrics/soc-kpis`, `/api/metrics/attack-coverage` | Home + Insights: SOC KPIs, ATT&CK coverage | Full |
| **Health** | `/api/health/basic`, `/api/health/deep` | Health page, Refresh / Deep Check | Full |
| **Organization** | `GET/PUT /api/organization/profile` + DB persistence | Settings page: load/save profile | Full |
| **Debug** | `GET /api/debug/last-analysis/:id`, `GET /api/debug/agent-traces` | Debug page: last analysis by incident, recent traces | Full |
| **Synthetic** | `POST /api/synthetic/generate` | Ingest → “Generate synthetic” → fill textarea | Full |

### Also wired (UI added)

| Area | Backend | Frontend | Connection |
|------|---------|----------|------------|
| **Search** | Semantic + MITRE search APIs | Search page: semantic incident search, MITRE technique search | Full |
| **Integrations** | `/api/siem/...` (Splunk/ELK ingest & export) | Integrations page: ingest tab, export tab | Full |
| **Response actions** | `/api/response/block-ip`, disable-account, execution-log | Incident detail: Block IP, Disable account, Load execution log | Full |
| **Validation** | Validation router (metrics, validate, aggregate) | Debug page: Validation card (incident metrics + aggregate) | Full |
| **Performance** | Performance routes (Redis/metrics) | Debug page: Performance card | Full |

### Backend-only (optional / internal)

| Area | Backend | Notes |
|------|---------|-------|
| **Analysis (alternate)** | `/api/analysis/stream`, etc. | Demo uses `/api/v1/incidents/stream` instead |

### Implemented in pipeline (used by ingest/demo, not directly by UI)

- **LangGraph workflow** (all 6 agents)
- **ATT&CK rules** (detection agent)
- **Cloud log parsers** (AWS/Azure/GCP formats in ingest agent)
- **IncidentService** (save from state to PostgreSQL)
- **Redis** status during background analysis and stream

---

## 3. Connectivity overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│ FRONTEND (Next.js 15, React, TanStack Query)                             │
│   Pages: / (Dashboard), /ingest, /incidents, /incident/[id], /search,   │
│          /integrations, /insights, /health, /settings, /debug           │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ HTTP + SSE (NEXT_PUBLIC_API_URL → backend)
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ BACKEND API (FastAPI)                                                    │
│   Connected to UI: health, incidents, ingest, stream (v1), dashboard,   │
│                    metrics, organization, debug, synthetic, search,    │
│                    integrations (SIEM), response actions, validation,  │
│                    performance. Optional: analysis (alternate stream).  │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ PostgreSQL    │     │ Redis           │     │ LangGraph        │
│ (incidents,   │     │ (status, cache) │     │ (6 agents,       │
│  reports,     │     │                 │     │  workflow)      │
│  org profile) │     │                 │     │       │         │
└───────────────┘     └─────────────────┘     └─────────┬─────────┘
                                                      │
                                                      ▼
                                              ┌───────────────┐
                                              │ LLM (Ollama/  │
                                              │ OpenAI/Groq/  │
                                              │ Anthropic)    │
                                              └───────────────┘
                                                      │
                                              ┌───────┴───────┐
                                              ▼               ▼
                                        Qdrant (optional)   Tools
                                        (semantic search)  (IP, MITRE, file/domain)
```

---

## 4. Connection length summary

| Connection | Length | Notes |
|------------|--------|--------|
| **UI ↔ Incidents** | End-to-end | List, detail, filters, status update, response-plan action update |
| **UI ↔ Ingest** | End-to-end | Upload/paste → analyze; demo → stream → incident |
| **UI ↔ Dashboard/Metrics** | End-to-end | Stats, SOC KPIs, ATT&CK coverage |
| **UI ↔ Health** | End-to-end | Basic + deep checks |
| **UI ↔ Settings** | End-to-end | Org profile load/save, persisted in DB when table exists |
| **UI ↔ Debug** | End-to-end | Last analysis by incident, agent traces |
| **UI ↔ Synthetic** | End-to-end | Generate logs → fill textarea |
| **Backend ↔ PostgreSQL** | Full | Incidents, reports, plans, org profile, agent logs, log entries |
| **Backend ↔ Redis** | Full | Analysis status, API cache |
| **Backend ↔ LangGraph** | Full | Ingest and stream routes run full workflow |
| **Backend ↔ LLM** | Full | All agents use configured provider |
| **Backend ↔ Qdrant** | Optional | Used by semantic/search tools when configured |
| **UI ↔ Search** | End-to-end | Semantic incident search, MITRE technique search |
| **UI ↔ Integrations (SIEM)** | End-to-end | Ingest (Splunk/ELK), Export |
| **UI ↔ Response actions** | End-to-end | Block IP, disable account, execution log (incident page) |
| **UI ↔ Validation / Performance** | End-to-end | Debug page cards |

---

## 5. What is left (optional / future)

- **Fine-tuned student model** – Synthetic pipeline uses teacher model; set `STUDENT_MODEL_NAME` (and provider if needed) when a distilled model is available.
- **E2E tests** – `test_all_features.sh` and `backend/scripts/test_all_features.py` cover health, ingest, incidents, dashboard, metrics, debug; expand as needed.

Everything required for the main analyst flow is **implemented and connected** end-to-end.
