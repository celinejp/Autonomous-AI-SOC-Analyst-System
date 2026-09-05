# Autonomous AI SOC Analyst System

A production-ready, multi-agent Security Operations Center (SOC) analyst system powered by AI. This system demonstrates advanced agentic reasoning capabilities for cybersecurity threat detection and response using cutting-edge 2025 technologies.

## Overview

This system autonomously analyzes security logs, detects threats, enriches findings with threat intelligence, performs deep analysis, and generates actionable response plans. It features a multi-agent architecture orchestrated by LangGraph, with reflection loops for self-correction and continuous improvement.

### Key Features

- **6 Specialized AI Agents**: Each with distinct roles (Ingest, Detection, Threat Intel, Analyst, Response Planner, Critic)
- **LangGraph Orchestration**: State machine with conditional routing and reflection loops
- **Real-time Processing**: Server-Sent Events (SSE) for live agent execution streaming
- **MITRE ATT&CK Integration**: 24+ attack techniques mapped with detection rules
- **Multi-Cloud Log Support**: AWS CloudTrail, Azure Monitor, GCP Audit Logs
- **Enhanced SOC Features**: Structured IOCs, regulatory impact, role-based response plans
- **SOC KPI Metrics**: MTTD, MTTR, MTTC, false positive rate, alert reduction
- **Modern Tech Stack**: FastAPI + Next.js 15 + LangGraph + Multi-LLM support
- **Production-Ready**: Docker containerization, proper error handling, structured logging
- **Advanced UI**: shadcn/ui components, Recharts visualizations, Attack Graph visualization

## Architecture

### Agent Workflow

```
┌─────────────┐
│ Ingest Agent│  Parse & normalize security logs (30+ fields, multi-format)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│Detection    │  AI + Rule-based detection (24+ ATT&CK techniques)
│Agent        │  Generate alerts with severity
└──────┬──────┘
       │
       ▼
┌─────────────┐
│Threat Intel │  MITRE ATT&CK mapping, IP reputation, similarity search
│Agent        │  Threat intelligence enrichment
└──────┬──────┘
       │
       ▼
┌─────────────┐
│Analyst Agent│  Deep analysis, root cause, IOCs, regulatory impact
│             │  SOC-aligned incident reports
└──────┬──────┘
       │
       ▼
┌─────────────┐
│Critic Agent │  Quality review, confidence assessment
│             │  Evidence corroboration
└──────┬──────┘
       │
       ├─► Low confidence? ──┐
       │                     │
       │                     ▼
       │              [Reflection Loop]
       │                     │
       └──► High confidence ─┘
                    │
                    ▼
        ┌───────────────────┐
        │ Response Planner  │  Role-based actions, IOC blocklists
        │ Agent             │  Team assignments, approval workflows
        └───────────────────┘
```

### Technology Stack

#### Backend (Python 3.12+)
- **Framework**: FastAPI (async/await, high performance)
- **AI/LLM**: Multi-provider support (Ollama, OpenAI, Groq, Anthropic)
- **Orchestration**: LangGraph (state machine with reflection loops)
- **Tools**: LangChain (IP lookup, MITRE search, file/domain intel)
- **Vector DB**: Qdrant (semantic search, threat intelligence)
- **Primary DB**: PostgreSQL with pgvector (structured data, incidents)
- **Cache**: Redis (session, rate limiting, API caching)
- **ML**: Statistical anomaly detection

#### Frontend (Next.js 15)
- **Framework**: Next.js 15 (App Router, React 18)
- **Language**: TypeScript
- **UI**: Tailwind CSS + shadcn/ui components
- **State**: TanStack Query (React Query v5)
- **Real-time**: Server-Sent Events (SSE)
- **Charts**: Recharts
- **Visualizations**: Canvas-based Attack Graph

## Quick Start

### Prerequisites

- Docker and Docker Compose
- **LLM Provider** (choose one):
  - **Ollama** (FREE, recommended) - [Install Ollama](https://ollama.ai/) and run `ollama pull llama3.1`
  - **Groq** (FREE tier) - [Get API key](https://console.groq.com/)
  - **OpenAI** (FREE tier available) - [Get API key](https://platform.openai.com/)
  - **Anthropic** (paid) - [Get API key](https://console.anthropic.com/)
- (Optional) AbuseIPDB API key for IP reputation lookups

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/celinejp/Autonomous-AI-SOC-Analyst-System.git
   cd Autonomous-AI-SOC-Analyst-System
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env  # Create .env file if needed
   # Edit .env and configure your LLM provider
   # For free setup with Ollama:
   # LLM_PROVIDER=ollama
   # LLM_MODEL=llama3.1
   # OLLAMA_BASE_URL=http://localhost:11434
   ```

3. **Start all services**

   **Option 1: Using start script (Recommended)**
   ```bash
   chmod +x start.sh stop.sh
   ./start.sh
   ```
   
   The start script will:
   - Check Docker and Ollama are running
   - Start PostgreSQL, Redis, Qdrant, and Backend API
   - Wait for services to be healthy
   - Initialize database automatically
   - Prompt you to start frontend (Docker or locally)
   
   **Option 2: Using Docker Compose**
   ```bash
   docker-compose up -d postgres redis qdrant backend
   # Wait for backend to be healthy, then init DB:
   docker-compose exec -T backend sh -c "PYTHONPATH=/app python scripts/init_db.py"
   # Run pgvector migration if needed (for semantic search):
   docker-compose exec -T postgres psql -U soc_user -d soc_db -f - < backend/scripts/migrations/001_add_pgvector.sql
   ```
   
   This starts:
   - PostgreSQL (port 5433)
   - Redis (port 6379)
   - Qdrant (port 6333)
   - Backend API (port 8000)
   - Frontend (port 3000) - if started with Docker

4. **Start Frontend** (if not started with Docker)
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

5. **Load MITRE ATT&CK data** (optional)
   ```bash
   docker-compose exec backend python scripts/load_mitre.py
   ```

6. **Access the application**
   - Frontend: http://localhost:3000
   - API Docs: http://localhost:8000/docs
   - Health Check: http://localhost:8000/api/health/basic

**To stop all services:**
```bash
./stop.sh
# or
docker-compose down
```

## Usage Guide

### 1. Upload Security Logs

Navigate to `/ingest` and either:
- Drag and drop a log file (.log, .txt, .json)
- Paste logs directly
- Use Demo Mode for pre-configured test scenarios

**Supported formats:**
- JSON logs
- Syslog format
- CEF (Common Event Format)
- Windows Event Logs
- **AWS CloudTrail** (format parser)
- **Azure Monitor** (format parser)
- **GCP Audit Logs** (format parser)

### 2. Monitor Real-time Analysis

The system will automatically:
1. Parse logs (Ingest Agent)
2. Detect threats (Detection Agent) - 24+ ATT&CK techniques
3. Enrich with threat intel (Threat Intel Agent)
4. Perform deep analysis (Analyst Agent)
5. Review quality (Critic Agent - with reflection loop if needed)
6. Generate response plan (Response Planner Agent)

You can watch agent execution in real-time via SSE streaming.

### 3. Review Incident Details

Navigate to `/incidents` to see all incidents, or click on a specific incident to see:
- Complete analysis report (executive summary, technical findings, IOCs)
- Attack Graph visualization
- Agent reasoning chain
- MITRE ATT&CK technique mappings (24 techniques covered)
- Evidence and timeline
- Actionable response plan with team assignments (update action status)
- Response actions: Block IP, Disable account, execution log

### 4. Search, Integrations, Health & Debug

- **Search** (`/search`): Semantic incident search and MITRE ATT&CK technique search.
- **Integrations** (`/integrations`): SIEM ingest (Splunk/ELK) and export.
- **Health** (`/health`): Basic and deep health checks (API, DB, Redis, Qdrant, agents).
- **Settings** (`/settings`): Organization profile (industry, regulations, crown jewels).
- **Debug** (`/debug`): Last analysis by incident, agent traces, validation metrics, performance.

### 5. View Insights & Metrics

Navigate to `/insights` for:
- Severity distribution charts
- Top MITRE techniques
- False positive rates
- Agent performance metrics
- SOC KPIs (MTTD, MTTR, MTTC, alert reduction)

## 🔧 API Endpoints

### Core Endpoints
- `GET /api/incidents` - List incidents (with filters, pagination)
- `GET /api/incidents/{id}` - Get incident details
- `POST /api/ingest/upload` - Upload log file
- `POST /api/ingest/analyze` - Analyze logs (JSON array)
- `GET /api/health/basic` - Basic health check
- `GET /api/health/deep` - Deep health check (tests all agents)

### SOC Enhancement Endpoints
- `GET /api/metrics/soc-kpis` - SOC KPI metrics (MTTD, MTTR, etc.)
- `GET /api/metrics/attack-coverage` - MITRE ATT&CK coverage (24 techniques)
- `GET /api/organization/profile` - Organization profile

### Advanced Endpoints
- `POST /api/v1/incidents/stream` - Demo mode: stream agent execution (SSE)
- `POST /api/synthetic/generate` - Generate synthetic logs
- `GET /api/debug/last-analysis/{incident_id}` - Debug agent execution for an incident
- `GET /api/debug/agent-traces` - Recent agent traces
- `POST /api/v1/incidents/search/semantic` - Semantic incident search
- `GET /api/v1/mitre/search` - MITRE technique search
- `POST /api/siem/splunk/ingest`, `POST /api/siem/elk/ingest` - SIEM ingest
- `GET /api/response/execution-log` - Response action execution log
- `GET /api/v1/performance/metrics` - Performance/Redis metrics
- `GET /api/v1/validate/aggregate` - Validation aggregate

Full API docs available at `/docs` when running.

## System Capabilities

### Detection Rules (24+ ATT&CK Techniques)

The Detection Agent identifies:
- **Initial Access**: Phishing (T1566.001, T1566.002)
- **Credential Access**: Brute Force (T1110.001), Password Spraying (T1110.003), LSASS Memory (T1003.001)
- **Execution**: PowerShell (T1059.001), Command Shell (T1059.003)
- **Persistence**: Registry Run Keys (T1547.001), Scheduled Tasks (T1053.005), Create Account (T1136.001)
- **Privilege Escalation**: Bypass UAC (T1548.002)
- **Defense Evasion**: Clear Event Logs (T1070.001), Disable Tools (T1562.001)
- **Discovery**: Account Discovery (T1087.001), Network Service Discovery (T1046)
- **Lateral Movement**: RDP (T1021.001), SMB (T1021.002)
- **Exfiltration**: Alternative Protocol (T1048.003), Cloud Storage (T1567.002)
- **Command and Control**: Web Protocols (T1071.001), DNS (T1071.004)
- **Impact**: Data Encrypted (T1486), Inhibit System Recovery (T1490)

### Enhanced Log Processing (30+ Fields)

- Process information (name, PID, parent process, command line)
- File information (hashes MD5/SHA256, paths, registry keys)
- Network information (protocol, bytes, packets, duration)
- DNS, HTTP, Email fields
- Geographic and ASN intelligence
- Cloud-specific fields (AWS region/account, Azure tenant, GCP project)

### SOC Features

- **Structured Incident Reports**: Executive summary, IOCs, regulatory impact, detection gaps
- **Role-Based Response Plans**: Team assignments (SOC, Network, Endpoint, Legal, etc.)
- **IOC Blocklists**: Firewall IP blocks, DNS sinkhole, EDR hash blocks
- **SOC Metrics**: MTTD, MTTR, MTTC, false positive rate, alert reduction
- **Organization Profiles**: Business context, critical assets, escalation matrix

### ML Anomaly Detection

- Baseline establishment from historical logs
- Statistical anomaly detection (Z-score based)
- Brute force pattern detection
- Unusual IP/action detection
- Per-log anomaly scoring

## Testing the System

### Quick Health Check

```bash
# Basic health check (fast, cached for 30s)
curl http://localhost:8000/api/health/basic

# Deep health check (tests all agents - takes 30-60s)
curl http://localhost:8000/api/health/deep

# Test workflow with sample logs
curl -X POST http://localhost:8000/api/health/test-workflow \
  -H "Content-Type: application/json" \
  -d '{"logs": ["2024-01-15 10:30:00 AUTH FAILED user=admin src=192.168.1.100"]}'
```

### Demo Mode (Frontend)

1. Navigate to http://localhost:3000/ingest
2. Click "Demo Mode" tab
3. Click "Run Test" on any scenario:
   - Brute Force SSH
   - SQL Injection
   - Port Scan
   - Data Exfiltration
   - Normal Traffic
4. View PASS/FAIL validation results

### Automated Test Suite

```bash
# E2E tests (backend must be running at http://localhost:8000)
./test_all_features.sh

# Or run the Python test script
cd backend && PYTHONPATH=. python scripts/test_all_features.py

# Pytest integration tests
cd backend
pytest tests/test_system_health.py -v -m integration
pytest tests/test_system_health.py --timeout=120 -v
```

### Detection Accuracy

Real numbers from `backend/scripts/eval_detection_metrics.py`, run against the live
Docker stack (ingest → detection → threat intel enrichment) and the 25 labeled
cases in `backend/data/labeled_incidents.json` + `backend/tests/fixtures/test_logs.json`
(2026-08-30, `--mode llm --enrich`, full end-to-end pipeline):

| Metric | Value |
|---|---|
| Alert-level accuracy / precision / recall / F1 | 1.0 / 1.0 / 1.0 / 1.0 |
| MITRE technique recall | 0.548 |
| MITRE technique precision | 0.944 |
| MITRE technique F1 | 0.693 |

**Caveat on the alert-level numbers:** the labeled fixtures were written to match the
detection rules' exact keyword expectations, so a perfect 1.0 here is close to
self-grading rather than proof the system generalizes to real-world log variety - treat
it as a regression check, not an accuracy claim. The MITRE technique numbers are more
informative: they were a real bug (raw score reached **0.24 precision** before the fix -
alerts were tagged with irrelevant techniques like `T1486`/`T1566` off unfiltered
semantic search and ungrounded LLM tool calls) and the fix (score threshold tuned to
0.65, plus grounding every tagged technique against an actual similarity hit) nearly
quadrupled precision while holding recall at the no-enrichment baseline.

Reproduce with:
```bash
cd backend
python scripts/eval_detection_metrics.py --mode llm --enrich
```

## Security Considerations

- API keys stored in environment variables
- Input validation via Pydantic models
- SQL injection protection via SQLAlchemy ORM
- CORS configured for specific origins
- Error handling with secure error messages

## Project Structure

```
Autonomous-AI-SOC-Analyst-System/
├── backend/
│   ├── app/
│   │   ├── agents/          # 6 AI agents
│   │   ├── tools/           # LangChain tools (IP lookup, MITRE, file/domain intel)
│   │   ├── orchestrator/    # LangGraph workflow
│   │   ├── api/routes/      # FastAPI endpoints (health, incidents, ingest, stream, dashboard, metrics, organization, debug, synthetic, SIEM, response, semantic search, validation, performance)
│   │   ├── models/          # Pydantic models (incident, log_entry, organization, etc.)
│   │   ├── database/        # DB connections & models
│   │   ├── detection/       # ATT&CK-native detection rules (24 techniques)
│   │   ├── services/        # Business logic (ML, Response, Metrics, Synthetic Data)
│   │   └── core/            # Config, logging, LLM factory
│   ├── scripts/             # Data generation, DB init, migrations
│   └── tests/               # Test suite with fixtures
├── frontend/
│   └── src/
│       ├── app/             # Next.js pages (dashboard, ingest, incidents, incident/[id], search, integrations, insights, health, settings, debug)
│       ├── components/     # UI components (charts, DemoStreamViewer, ResponsePlanViewer, Navigation, etc.)
│       ├── lib/             # API client, utilities
│       └── types/           # TypeScript definitions
├── docker-compose.yml
├── start.sh                 # Start all services script
├── stop.sh                  # Stop all services script
├── test_all_features.sh     # E2E API test script
├── IMPLEMENTATION_STATUS.md # Implementation and API ↔ UI reference
├── STACK_AND_IMPLEMENTATION.md # Stack, connectivity, and what's wired
└── README.md
```
