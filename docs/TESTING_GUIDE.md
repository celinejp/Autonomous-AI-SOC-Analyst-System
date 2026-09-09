# Testing Guide: What Input Goes Where

This guide explains how to test the AI SOC Analyst system comprehensively, including what inputs to use in each interface.

## Table of Contents

1. [Quick Start Testing](#quick-start-testing)
2. [Demo Mode (Frontend)](#demo-mode-frontend)
3. [API Direct Testing](#api-direct-testing)
4. [Test Fixtures](#test-fixtures)
5. [Automated Testing](#automated-testing)
6. [Debugging Failed Tests](#debugging-failed-tests)

---

## Quick Start Testing

### 1. Health Checks

**Verify all services are running:**

```bash
# Basic health check
curl http://localhost:8000/api/health/basic

# Deep health check (tests all agents)
curl http://localhost:8000/api/health/deep
```

### 2. External Test Script

**Run the external test script:**

```bash
./scripts/external_test.sh
```

This script automatically:
- Checks all services are healthy
- Submits a test log (brute force attack)
- Waits for analysis to complete
- Validates the results

### 3. Automated Python Tests

**Run comprehensive test suite:**

```bash
# From project root
python backend/scripts/test_all_features.py

# Or via Docker
docker-compose exec backend python scripts/test_all_features.py
```

---

## Demo Mode (Frontend)

**Location:** http://localhost:3000/ingest → Click "Demo Mode" tab

### How It Works

1. Select a test scenario from the dropdown (6 scenarios, defined in
   `frontend/src/app/ingest/page.tsx`'s `DEMO_SCENARIOS`)
2. Click "Run Demo Scenario"
3. System automatically:
   - Streams synthetic logs for the scenario and runs the workflow inline in the
     `backend` container (not queued to the `worker`)
   - Renders live agent-by-agent progress over SSE
   - Redirects to the resulting incident on completion

### Test Scenarios

The 6 scenarios currently available in the Demo Mode dropdown:

1. **Brute Force (T1110)** - SSH brute force attack with multiple failed login attempts
2. **PowerShell Execution (T1059.001)** - Suspicious PowerShell commands and encoded scripts
3. **RDP Lateral Movement (T1021.001)** - Lateral movement via Remote Desktop Protocol
4. **Ransomware (T1486)** - File encryption and ransomware indicators
5. **Cloud IAM Abuse** - AWS IAM privilege escalation and backdoor creation
6. **Port Scan (T1046)** - Network reconnaissance port scanning activity

There is no "Normal Traffic" or "SQL Injection" scenario in Demo Mode - those exist
only as `backend/tests/fixtures/` files exercised by `test_all_features.py`, not as
Demo Mode options (see [Test Fixtures](#test-fixtures) below).

### What Gets Validated

Demo Mode itself does not display a PASS/FAIL verdict - it streams progress and redirects
to the resulting incident. To check a run's incident against expected criteria, call
`/api/debug/validate-incident/{id}` afterward (see below), which checks:
- ✅ **severity_match:** Actual severity meets minimum expected
- ✅ **has_mitre_techniques / correct_technique:** Expected techniques are identified
- ✅ **has_alerts / meets_min_alerts:** Minimum number of alerts generated
- ✅ **has_report:** Incident report was generated
- ✅ **has_response_plan:** Response plan was generated

---

## API Direct Testing

### 1. Log Ingestion

**Endpoint:** `POST /api/ingest/analyze`

**Input Format:** Array of log strings

```bash
curl -X POST http://localhost:8000/api/ingest/analyze \
  -H "Content-Type: application/json" \
  -d '[
    "Jan 15 10:00:00 sshd[1234]: Failed password for admin from 203.0.113.45",
    "Jan 15 10:00:01 sshd[1235]: Failed password for root from 203.0.113.45"
  ]'
```

**Response:**
```json
{
  "incident_id": "uuid-here",
  "status": "queued",
  "estimated_duration_seconds": 45,
  "message": "Analysis queued on Redis Streams worker.",
  "logs_processed": 2
}
```
The analysis itself runs in the separate `worker` container, which consumes the queued
job from Redis Streams - it is not processed inline by the request that queued it.

### 2. Check Analysis Status

**Endpoint:** `GET /api/incidents/{incident_id}/status`

```bash
curl http://localhost:8000/api/incidents/{incident_id}/status
```

**Response:**
```json
{
  "status": "completed",
  "progress_percent": 100,
  "current_agent": null,
  "eta_seconds": null
}
```

### 3. Get Incident Report

**Endpoint:** `GET /api/incidents/{incident_id}`

```bash
curl http://localhost:8000/api/incidents/{incident_id}
```

### 4. Validate Detection

**Endpoint:** `GET /api/debug/validate-incident/{incident_id}`

```bash
curl "http://localhost:8000/api/debug/validate-incident/{incident_id}?expected_severity=high&expected_mitre_techniques=T1110&expected_min_alerts=1"
```

**Response:**
```json
{
  "passed": true,
  "checks": {
    "severity_match": true,
    "meets_min_alerts": true,
    "correct_technique": true,
    "has_alerts": true,
    "has_mitre_techniques": true,
    "has_report": true,
    "has_response_plan": true
  },
  "actual": {
    "severity": "high",
    "mitre_techniques": ["T1110"],
    "alerts_count": 1
  }
}
```

### 5. Debug Agent Execution

**Endpoint:** `GET /api/debug/last-analysis/{incident_id}`

```bash
curl http://localhost:8000/api/debug/last-analysis/{incident_id}
```

**Response:** (one entry per agent, keyed by `agent_name`; no top-level "status" per agent -
absence of an entry means that agent didn't run)
```json
{
  "incident_id": "uuid",
  "workflow_trace": {
    "ingest": {"duration_ms": 450, "timestamp": "...", "tools_used": [], "reasoning": "...", "output": {}},
    "detection": {"duration_ms": 3200, "timestamp": "...", "tools_used": [], "reasoning": "...", "output": {}},
    "threat_intel": {"duration_ms": 2800, "timestamp": "...", "tools_used": ["mitre_search"], "reasoning": "...", "output": {}},
    "analyst": {"duration_ms": 5100, "timestamp": "...", "tools_used": [], "reasoning": "...", "output": {}},
    "critic": {"duration_ms": 1900, "timestamp": "...", "tools_used": [], "reasoning": "...", "output": {}},
    "response_planner": {"duration_ms": 2300, "timestamp": "...", "tools_used": [], "reasoning": "...", "output": {}}
  },
  "final_output": {
    "severity": "high",
    "mitre_techniques": ["T1110"],
    "alerts_count": 1,
    "confidence_score": 0.9,
    "has_report": true,
    "has_response_plan": true,
    "reason_for_failure": null
  },
  "overall_status": "new",
  "analysis_timestamp": "..."
}
```

---

## Test Fixtures

### Location

All test fixtures are in: `backend/tests/fixtures/`

### Available Fixtures

1. **`brute_force_ssh.json`**
   - 50+ failed SSH login attempts + 1 success
   - Expected: High severity, T1110.001

2. **`sql_injection.json`**
   - Multiple SQL injection patterns with sqlmap user agent
   - Expected: High severity, T1190

3. **`port_scan.json`**
   - 25+ connection attempts to different ports
   - Expected: Medium severity, T1046

4. **`data_exfiltration.json`**
   - Large outbound data transfers
   - Expected: High severity, T1041

5. **`normal_traffic.json`**
   - Benign web traffic
   - Expected: Low severity, no alerts

6. **`test_logs.json`**
   - Different structure from the 5 above: `{"scenarios": [...]}`, a list of 5 named
     cases (brute force, and others), each with its own `expected_severity` /
     `expected_techniques` / `logs`
   - Used by `backend/tests/test_system_health.py` (pytest) and
     `backend/scripts/eval_detection_metrics.py`, not by `test_all_features.py`
   - Deliberately excluded from the synthetic-data fixture loader
     (`backend/app/api/routes/synthetic_data.py`)

### Fixture Structure

```json
{
  "source": "auth_logs",
  "log_type": "authentication",
  "description": "Description of the test scenario",
  "logs": [
    "log entry 1",
    "log entry 2"
  ],
  "expected_detection": {
    "should_alert": true,
    "min_severity": "high",
    "mitre_techniques": ["T1110.001"],
    "attack_type": "credential_access",
    "min_alerts": 1,
    "reasoning": "Why this should be detected"
  }
}
```

### Using Fixtures

**Via Python script:**
```python
import json

with open("backend/tests/fixtures/brute_force_ssh.json") as f:
    test_data = json.load(f)

# Submit logs
response = requests.post(
    "http://localhost:8000/api/ingest/analyze",
    json=test_data["logs"]
)
```

**Via curl:**
```bash
LOGS=$(cat backend/tests/fixtures/brute_force_ssh.json | jq -c '.logs')

curl -X POST http://localhost:8000/api/ingest/analyze \
  -H "Content-Type: application/json" \
  -d "$LOGS"
```

---

## Automated Testing

### Comprehensive Test Suite

**Run all tests:**
```bash
python backend/scripts/test_all_features.py
```

**What it tests:**
1. ✅ Health Checks (DB, Redis, Qdrant, API)
2. ✅ Agent Execution (all 6 agents run successfully)
3. ✅ Detection Accuracy (validates against fixtures)
4. ✅ API Endpoints (all endpoints respond correctly)
5. ✅ Performance (dashboard load < 3s, analysis < 90s)

### Pytest Integration Tests

**Run pytest tests:**
```bash
docker-compose exec backend pytest tests/test_system_health.py -v
```

**Test coverage:**
- Agent functionality
- Detection accuracy for each attack type
- False positive rate
- End-to-end workflow completion

---

## Debugging Failed Tests

### 1. Check Agent Execution

If a test fails, use the debug endpoint to see what happened:

```bash
INCIDENT_ID="your-incident-id"
curl http://localhost:8000/api/debug/last-analysis/$INCIDENT_ID | jq
```

Look for:
- Which agents failed
- Error messages
- Duration of each agent
- Input/output counts

### 2. Check LLM Responses

If detection is failing, the issue might be:
- LLM not understanding the log format
- Prompt engineering needs improvement
- MITRE ATT&CK data not loaded in Qdrant

**Verify MITRE data (semantic search over the loaded techniques):**
```bash
curl "http://localhost:8000/api/v1/mitre/search?q=brute+force+password+guessing&limit=5" | jq
```

### 3. Check Log Parsing

If logs aren't being parsed correctly:
- Verify log format matches expected schema
- Check ingest agent output in debug trace
- Look for parsing errors in agent execution log

### 4. Validate Expected vs Actual

Use the validation endpoint to see exact mismatches:

```bash
curl "http://localhost:8000/api/debug/validate-incident/$INCIDENT_ID?expected_severity=high&expected_mitre_techniques=T1110"
```

This shows:
- Which checks passed/failed
- Actual vs expected values
- Detailed comparison

---

## Common Issues & Solutions

### Issue: Demo Mode stream errors out or never completes

Demo Mode itself has no PASS/FAIL verdict (see [above](#what-gets-validated)) - a failed
run surfaces as an `error` stream status with a message, or a stream that never reaches
completion.

**Causes:**
1. Analysis not completing (timeout)
2. LLM not detecting patterns correctly
3. MITRE techniques not matching expectations
4. Backend error mid-stream (check the browser console / network tab for the SSE response)

**Solutions:**
1. Check the debug endpoint to see agent execution for the resulting incident (if one was created)
2. Verify MITRE ATT&CK data is loaded
3. Review LLM prompts in detection agent
4. Use `/api/debug/validate-incident/{id}` afterward to check the incident against expected criteria

### Issue: Tests timeout after 90 seconds

**Causes:**
1. LLM (Ollama) is slow
2. Too many logs being processed
3. Network latency

**Solutions:**
1. Ensure Ollama is running: `ollama serve`
2. Reduce log volume in fixtures
3. Check Ollama model size (use smaller model)

### Issue: Incorrect MITRE technique mapping

**Causes:**
1. MITRE ATT&CK data not loaded
2. LLM not understanding attack patterns
3. Technique IDs don't match expected

**Solutions:**
1. Load MITRE data: `docker-compose exec backend python scripts/load_mitre.py`
2. Review threat intel agent prompts
3. Check technique IDs in fixtures match loaded data

---

## Best Practices

1. **Start with health checks** - Verify all services are running
2. **Use test fixtures** - They have expected detection criteria
3. **Check debug output** - Always inspect agent execution when tests fail
4. **Validate incrementally** - Test one scenario at a time
5. **Review LLM responses** - Check if agents are understanding patterns correctly

---

## Next Steps

- Review `backend/app/agents/` to understand agent logic
- Check `backend/tests/fixtures/` for example test scenarios
- Use `backend/scripts/test_all_features.py` for automated validation
- Consult `README.md` for setup instructions

