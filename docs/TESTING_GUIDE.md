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

1. Select a test scenario (Brute Force, SQL Injection, Port Scan, Normal Traffic)
2. Click "Run Test"
3. System automatically:
   - Submits logs for analysis
   - Waits for completion (up to 90 seconds)
   - Validates against expected criteria
   - Shows PASS/FAIL status

### Test Scenarios

#### 1. Brute Force Attack
- **Expected:** High severity, T1110.001 (Brute Force)
- **What it tests:** Detection of repeated failed login attempts

#### 2. SQL Injection Attempt
- **Expected:** High severity, T1190 (Exploit Public-Facing Application)
- **What it tests:** Detection of SQL injection patterns

#### 3. Port Scan
- **Expected:** Medium severity, T1046 (Network Service Scanning)
- **What it tests:** Detection of reconnaissance activity

#### 4. Normal Traffic
- **Expected:** Low severity, no alerts
- **What it tests:** False positive rate (should NOT alert)

### What Gets Validated

Each test checks:
- ✅ **Severity Match:** Actual severity meets minimum expected
- ✅ **MITRE Mapping:** Expected techniques are identified
- ✅ **Alert Generation:** Minimum number of alerts generated
- ✅ **Timeline Exists:** Incident report includes timeline
- ✅ **Recommendations:** Response plan includes actions

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
  "status": "analyzing",
  "estimated_duration_seconds": 45,
  "logs_processed": 2
}
```

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
curl "http://localhost:8000/api/debug/validate-incident/{incident_id}?expected_severity=high&expected_mitre_techniques=T1110.001&expected_min_alerts=1"
```

**Response:**
```json
{
  "passed": true,
  "checks": {
    "severity_match": true,
    "has_mitre_techniques": true,
    "correct_technique": true,
    "timeline_exists": true,
    "has_recommendations": true,
    "meets_min_alerts": true
  },
  "actual": {
    "severity": "high",
    "mitre_techniques": ["T1110.001"],
    "alerts_count": 1
  }
}
```

### 5. Debug Agent Execution

**Endpoint:** `GET /api/debug/last-analysis/{incident_id}`

```bash
curl http://localhost:8000/api/debug/last-analysis/{incident_id}
```

**Response:**
```json
{
  "incident_id": "uuid",
  "workflow_trace": {
    "ingest": {"status": "completed", "duration_ms": 450},
    "detect": {"status": "completed", "duration_ms": 3200},
    "enrich": {"status": "completed", "duration_ms": 2800},
    "analyze": {"status": "completed", "duration_ms": 5100},
    "critique": {"status": "completed", "duration_ms": 1900},
    "plan_response": {"status": "completed", "duration_ms": 2300}
  },
  "final_output": {
    "severity": "high",
    "mitre_techniques": ["T1110.001"],
    "alerts_count": 1
  }
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

**Verify MITRE data:**
```bash
curl http://localhost:8000/api/mitre/techniques | jq '.[] | select(.technique_id == "T1110.001")'
```

### 3. Check Log Parsing

If logs aren't being parsed correctly:
- Verify log format matches expected schema
- Check ingest agent output in debug trace
- Look for parsing errors in agent execution log

### 4. Validate Expected vs Actual

Use the validation endpoint to see exact mismatches:

```bash
curl "http://localhost:8000/api/debug/validate-incident/$INCIDENT_ID?expected_severity=high&expected_mitre_techniques=T1110.001"
```

This shows:
- Which checks passed/failed
- Actual vs expected values
- Detailed comparison

---

## Common Issues & Solutions

### Issue: Demo Mode shows all tests as FAIL

**Causes:**
1. Analysis not completing (timeout)
2. LLM not detecting patterns correctly
3. MITRE techniques not matching
4. Severity threshold too high

**Solutions:**
1. Check debug endpoint to see agent execution
2. Verify MITRE ATT&CK data is loaded
3. Review LLM prompts in detection agent
4. Adjust expected severity if needed

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
- Use `scripts/test_all_features.py` for automated validation
- Consult `README.md` for setup instructions

