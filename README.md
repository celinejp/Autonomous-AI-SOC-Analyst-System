# Autonomous AI SOC Analyst System

A production-ready, multi-agent Security Operations Center (SOC) analyst system powered by AI. This system demonstrates advanced agentic reasoning capabilities for cybersecurity threat detection and response using cutting-edge 2025 technologies.

## 🎯 Overview

This system autonomously analyzes security logs, detects threats, enriches findings with threat intelligence, performs deep analysis, and generates actionable response plans. It features a multi-agent architecture orchestrated by LangGraph, with reflection loops for self-correction and continuous improvement.

### Key Features

- **6 Specialized AI Agents**: Each with distinct roles (Ingest, Detection, Threat Intel, Analyst, Response Planner, Critic)
- **LangGraph Orchestration**: State machine with conditional routing and reflection loops
- **Real-time Processing**: Server-Sent Events (SSE) for live agent execution streaming
- **MITRE ATT&CK Integration**: Threat intelligence mapping to known attack techniques
- **Modern Tech Stack**: FastAPI + Next.js 15 + LangGraph + Claude API + Qdrant + PostgreSQL
- **Production-Ready**: Docker containerization, proper error handling, structured logging

## 🏗️ Architecture

### Agent Workflow

```
┌─────────────┐
│ Ingest Agent│  Parse & normalize security logs
└──────┬──────┘
       │
       ▼
┌─────────────┐
│Detection    │  Identify suspicious patterns
│Agent        │  Generate alerts with severity
└──────┬──────┘
       │
       ▼
┌─────────────┐
│Threat Intel │  MITRE ATT&CK mapping
│Agent        │  Threat intelligence enrichment
└──────┬──────┘
       │
       ▼
┌─────────────┐
│Analyst Agent│  Deep analysis & reasoning
│             │  Root cause analysis
└──────┬──────┘
       │
       ▼
┌─────────────┐
│Critic Agent │  Quality review
│             │  Confidence assessment
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
        │ Response Planner  │  Actionable mitigation steps
        │ Agent             │
        └───────────────────┘
```

### Technology Stack

#### Backend
- **Framework**: FastAPI (async/await, high performance)
- **Language**: Python 3.12+
- **AI/LLM**: 
  - Anthropic Claude API (claude-sonnet-4-20250514)
  - LangGraph for agent orchestration
  - LangChain for tool integration
- **Vector Database**: Qdrant (for semantic search)
- **Primary Database**: PostgreSQL with pgvector extension
- **Caching**: Redis
- **Logging**: structlog (structured logging)

#### Frontend
- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS v4
- **State Management**: Zustand + TanStack Query
- **Real-time**: Server-Sent Events (SSE)
- **Charts**: Recharts

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Anthropic API key ([Get one here](https://console.anthropic.com/))
- (Optional) AbuseIPDB API key for IP reputation lookups

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Autonomous-AI-SOC-Analyst-System
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env and add your ANTHROPIC_API_KEY
   ```

3. **Start all services**
   ```bash
   docker-compose up -d
   ```

   This starts:
   - PostgreSQL (port 5432)
   - Redis (port 6379)
   - Qdrant (port 6333)
   - Backend API (port 8000)
   - Frontend (port 3000)

4. **Access the application**
   - Frontend: http://localhost:3000
   - API Docs: http://localhost:8000/docs

### Generate Sample Data

```bash
cd backend
python scripts/generate_sample_data.py
```

This generates 5 realistic attack scenarios:
- Brute Force SSH Attack
- Phishing → Data Exfiltration
- Ransomware Execution Chain
- Insider Threat
- False Positive (legitimate activity)

## 📖 Usage Guide

### 1. Upload Security Logs

Navigate to `/ingest` and either:
- Drag and drop a log file (.log, .txt, .json)
- Or upload via file picker

Supported formats:
- JSON logs
- Syslog format
- CEF (Common Event Format)
- Windows Event Logs

### 2. Monitor Real-time Analysis

The system will:
1. Parse logs (Ingest Agent)
2. Detect threats (Detection Agent)
3. Enrich with threat intel (Threat Intel Agent)
4. Perform deep analysis (Analyst Agent)
5. Review quality (Critic Agent - with reflection loop if needed)
6. Generate response plan (Response Planner Agent)

You can watch agent execution in real-time via SSE streaming.

### 3. Review Incident Details

Navigate to `/incidents` to see all incidents, or click on a specific incident to see:
- Complete analysis report
- Agent reasoning chain
- MITRE ATT&CK technique mappings
- Evidence and timeline
- Actionable response plan

### 4. View Insights

Navigate to `/insights` for:
- Severity distribution
- Top MITRE techniques
- False positive rates
- Agent performance metrics

## 🔧 Configuration

### Environment Variables

```env
# Required
ANTHROPIC_API_KEY=your_api_key_here

# Database
DATABASE_URL=postgresql://soc_user:soc_password@localhost:5432/soc_db

# Redis
REDIS_URL=redis://localhost:6379

# Qdrant
QDRANT_URL=http://localhost:6333

# Optional
ABUSEIPDB_API_KEY=your_key_for_ip_lookup
```

### Agent Configuration

Agents are configured in `backend/app/agents/`. Each agent has:
- System prompt for role definition
- Access to LangChain tools
- Integration with Claude API

## 🛠️ Development

### Backend Development

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend Development

```bash
cd frontend
npm install
npm run dev
```

### Running Tests

```bash
cd backend
pytest
```

## 📊 System Capabilities

### Detection Rules

The Detection Agent identifies:
- **Brute Force**: Multiple failed logins from same IP
- **Port Scanning**: Connections to many different ports
- **Data Exfiltration**: Large outbound transfers
- **Lateral Movement**: Unusual access patterns
- **Anomalous DNS**: DGA domains, C2 communication
- **Privilege Escalation**: Unusual privilege changes

### MITRE ATT&CK Coverage

Pre-configured techniques:
- T1078 (Valid Accounts)
- T1059 (Command and Scripting Interpreter)
- T1110 (Brute Force)
- T1566 (Phishing)
- T1486 (Data Encrypted for Impact)
- And more...

### Agent Tools

Agents can autonomously use:
- `query_logs`: Search historical logs
- `lookup_ip`: Get IP reputation (AbuseIPDB)
- `get_mitre_technique`: Fetch ATT&CK details
- `search_mitre_techniques`: Semantic search
- `search_similar_incidents`: Find similar past cases

## 🎓 Learning Resources

### Key Concepts Demonstrated

1. **Multi-Agent Systems**: Coordination between specialized agents
2. **LangGraph**: State machine orchestration with conditional routing
3. **Reflection Loops**: Self-correction and quality improvement
4. **RAG (Retrieval Augmented Generation)**: Threat intelligence retrieval
5. **Function Calling**: Autonomous tool usage by agents
6. **Real-time Streaming**: SSE for live updates

### Architecture Patterns

- **Event-Driven**: Agents communicate via state updates
- **Observer Pattern**: Frontend subscribes to agent events
- **Strategy Pattern**: Different detection strategies per agent
- **Template Method**: Base agent class with shared functionality

## 📝 API Documentation

### Endpoints

- `GET /api/health` - Health check
- `GET /api/incidents` - List incidents (with filters)
- `GET /api/incidents/{id}` - Get incident details
- `POST /api/ingest/upload` - Upload log file
- `POST /api/ingest/analyze` - Analyze logs (JSON)
- `POST /api/analysis/stream` - Stream analysis (SSE)

Full API docs available at `/docs` when running.

## 🔒 Security Considerations

- API keys stored in environment variables
- Input validation via Pydantic models
- SQL injection protection via SQLAlchemy ORM
- CORS configured for specific origins
- Rate limiting recommended for production

## 🚧 Roadmap

- [ ] Full PostgreSQL persistence (currently in-memory)
- [ ] Complete MITRE ATT&CK technique database
- [ ] Advanced visualization (attack graphs, timelines)
- [ ] Machine learning-based anomaly detection
- [ ] Integration with SIEM systems (Splunk, ELK)
- [ ] Automated response actions (firewall rules, account blocking)

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is for educational and portfolio purposes.

## 🙏 Acknowledgments

- Anthropic for Claude API
- LangChain team for LangGraph
- MITRE for ATT&CK framework

## 📧 Contact

For questions or feedback, please open an issue on GitHub.

---

**Built with ❤️ to demonstrate modern AI engineering capabilities in cybersecurity.**
