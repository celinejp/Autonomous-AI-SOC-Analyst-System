# Comprehensive Testing Guide - What Input Goes Where

## 🎯 Quick Overview

This guide explains **exactly** what to input where and where to check outputs for all features, including the new **Synthetic Data / Model Distillation** feature.

---

## 📍 WHERE TO TEST EACH FEATURE

### 1. **Demo Mode (Frontend UI)** ⭐ Easiest Way to Test

**Location:** http://localhost:3000/ingest → Click "Demo Mode" tab

**What It Does:**
- Pre-configured test scenarios
- One-click testing
- Automatic validation
- Shows PASS/FAIL with detailed checks

**How to Use:**
1. Open http://localhost:3000/ingest
2. Click "Demo Mode" tab
3. Click "Run Test" on any scenario
4. Wait 30-90 seconds for analysis
5. View PASS/FAIL badge and detailed validation results

**Expected Results:**

| Scenario | Expected Result | Key Checks |
|----------|----------------|------------|
| Brute Force | ✅ PASS | High severity, T1110.001 detected |
| SQL Injection | ✅ PASS | High severity, T1190 detected |
| Port Scan | ✅ PASS | Medium severity, T1046 detected |
| Normal Traffic | ✅ PASS | Low severity, 0 alerts (no false positives) |

**If It Shows FAIL:**
- Click the "View Incident" link (👁️ icon) to see what was detected
- Check the detailed validation checks below the test name
- Use the debug endpoint to see agent execution: `/api/debug/last-analysis/{incident_id}`

---

### 2. **Log Ingestion (Frontend UI)**

**Location:** http://localhost:3000/ingest

**What to Input:**
- Paste raw log lines (one per line)
- Or upload a log file
- Examples:
  ```
  Jan 15 10:00:00 sshd[1234]: Failed password for admin from 203.0.113.45
  Jan 15 10:00:01 sshd[1235]: Failed password for root from 203.0.113.45
  Jan 15 10:00:02 sshd[1236]: Failed password for user1 from 203.0.113.45
  ```

**Where to Check Output:**
1. You'll be redirected to: `/incident/{incident_id}`
2. View incident details, alerts, MITRE techniques, response plan
3. See agent execution timeline

---

### 3. **API Direct Testing (curl/Postman)**

**Endpoint:** `POST http://localhost:8000/api/ingest/analyze`

**Input Format:**
```json
[
  "Jan 15 10:00:00 sshd[1234]: Failed password for admin from 203.0.113.45",
  "Jan 15 10:00:01 sshd[1235]: Failed password for root from 203.0.113.45"
]
```

**Check Output:**
```bash
# Get incident ID from response
INCIDENT_ID="..."

# Check status
curl http://localhost:8000/api/incidents/$INCIDENT_ID/status

# Get full incident
curl http://localhost:8000/api/incidents/$INCIDENT_ID | jq
```

---

### 4. **Synthetic Data Generation** ⭐ NEW FEATURE

**Location:** API endpoint `/api/synthetic/generate-single`

**What It Does (Step 1 - Teacher Model):**
- Uses LLM to analyze logs and generate perfect incident reports
- Creates high-quality training data for model distillation

**How to Test:**

**Option A: Generate Single Synthetic Incident**
```bash
curl -X POST http://localhost:8000/api/synthetic/generate-single \
  -H "Content-Type: application/json" \
  -d '[
    "Jan 15 10:00:00 sshd[1234]: Failed password for admin from 203.0.113.45",
    "Jan 15 10:00:01 sshd[1235]: Failed password for root from 203.0.113.45"
  ]' | jq
```

**Check Output:**
- Returns formatted training sample with `instruction`, `input`, `output`
- Output includes: severity, MITRE techniques, alerts, recommendations

**Option B: Generate Dataset from Fixtures** ⭐ Easiest
```bash
curl -X POST http://localhost:8000/api/synthetic/generate-from-fixtures \
  -H "Content-Type: application/json" \
  -d '{"num_samples_per_scenario": 5}'
```

**Check Output:**
- Creates `backend/data/synthetic/fixture_dataset_*.json`
- Contains multiple training samples in Alpaca format

**Option C: Generate Custom Dataset**
```bash
curl -X POST http://localhost:8000/api/synthetic/generate-dataset \
  -H "Content-Type: application/json" \
  -d '{
    "scenarios": [
      {
        "name": "Brute Force Attack",
        "logs": [
          "Jan 15 10:00:00 sshd[1234]: Failed password for admin from 203.0.113.45"
        ]
      }
    ],
    "num_samples_per_scenario": 10,
    "format_type": "alpaca"
  }' | jq
```

**Where Files Are Saved:**
- `backend/data/synthetic/training_dataset_*.json`
- View with: `cat backend/data/synthetic/*.json | jq`

---

### 5. **Model Comparison** ⭐ NEW FEATURE

**Location:** API endpoint `/api/synthetic/compare-models`

**What It Does (Step 4 - Benchmark):**
- Compares Teacher vs Student model performance
- Shows: accuracy, speed, cost, F1 score

**How to Test:**
```bash
curl -X POST http://localhost:8000/api/synthetic/compare-models \
  -H "Content-Type: application/json" \
  -d '[
    "Jan 15 10:00:00 sshd[1234]: Failed password for admin from 203.0.113.45",
    "Jan 15 10:00:01 sshd[1235]: Failed password for root from 203.0.113.45"
  ]' | jq
```

**Check Output:**
```json
{
  "teacher_model": {
    "duration_seconds": 45.2,
    "severity": "high",
    "mitre_techniques": ["T1110"]
  },
  "student_model": {
    "duration_seconds": 8.1,
    "severity": "high",
    "mitre_techniques": ["T1110"]
  },
  "comparison": {
    "speedup": 5.6,
    "mitre_accuracy": 0.92
  }
}
```

---

### 6. **Health Checks**

**Basic Health:**
```bash
curl http://localhost:8000/api/health/basic | jq
```

**Deep Health (Tests All Agents):**
```bash
curl http://localhost:8000/api/health/deep | jq
```

**Check Output:**
- Status of DB, Redis, Qdrant, Ollama
- Agent execution times
- Overall system health

---

### 7. **Debug Endpoints** (For Troubleshooting)

**Agent Execution Trace:**
```bash
curl http://localhost:8000/api/debug/last-analysis/{incident_id} | jq
```

**Validate Detection:**
```bash
curl "http://localhost:8000/api/debug/validate-incident/{incident_id}?expected_severity=high&expected_mitre_techniques=T1110.001&expected_min_alerts=1" | jq
```

**Check Output:**
- See which agents ran successfully
- View detailed execution logs
- See validation checks (severity, MITRE, alerts)

---

## 🔄 TESTING WORKFLOW

### Complete End-to-End Test:

1. **Start Services:**
   ```bash
   docker-compose up -d
   ollama serve  # In another terminal
   ```

2. **Check Health:**
   ```bash
   curl http://localhost:8000/api/health/basic
   ```

3. **Test Demo Mode:**
   - Open: http://localhost:3000/ingest
   - Click "Demo Mode" tab
   - Click "Run Test" on "Brute Force Attack"
   - Wait for PASS/FAIL result

4. **View Incident:**
   - Click the 👁️ icon to view detailed incident
   - Check: severity, MITRE techniques, alerts, timeline

5. **Generate Synthetic Data:**
   ```bash
   curl -X POST http://localhost:8000/api/synthetic/generate-from-fixtures \
     -H "Content-Type: application/json" \
     -d '{"num_samples_per_scenario": 2}'
   ```

6. **Check Generated Dataset:**
   ```bash
   ls -lh backend/data/synthetic/
   cat backend/data/synthetic/*.json | jq '.[0]'
   ```

---

## 🐛 WHY DEMO MODE MIGHT SHOW FAIL

### Common Causes:

1. **LLM Not Detecting Patterns**
   - **Fix:** Check Ollama is running: `ollama serve`
   - **Check:** Verify model loaded: `ollama list`
   - **Debug:** Use `/api/debug/last-analysis/{incident_id}` to see LLM responses

2. **Severity Mismatch**
   - **Fix:** Validation is lenient now - passes if severity >= expected
   - **Check:** View actual severity in incident details

3. **MITRE Techniques Not Mapped**
   - **Fix:** Ensure MITRE data loaded: `docker-compose exec backend python scripts/load_mitre.py`
   - **Check:** Verify techniques exist: `curl http://localhost:8000/api/mitre/techniques | jq '.[] | select(.technique_id == "T1110")'`

4. **No Alerts Generated**
   - **Fix:** Check detection agent output in debug trace
   - **Possible:** LLM timeout or pattern not recognized
   - **Debug:** Check `/api/debug/last-analysis/{incident_id}` for detection agent errors

5. **Analysis Timeout**
   - **Fix:** Increase timeout in Demo Mode (currently 120 seconds)
   - **Check:** Verify Ollama response time

---

## ✅ VALIDATION CRITERIA (What Makes a Test PASS)

### For Attack Scenarios (Brute Force, SQL Injection, Port Scan):

✅ **PASS if:**
- Severity >= expected (e.g., high severity for brute force)
- At least one expected MITRE technique is found
- Minimum number of alerts generated
- Core checks pass (severity, alerts, MITRE)

⚠️ **Warnings (but still PASS):**
- Timeline might be empty (optional)
- Response plan might be empty (optional)

### For Normal/Benign Traffic:

✅ **PASS if:**
- Severity is low
- 0 alerts generated
- No MITRE techniques found

---

## 🧪 COMPREHENSIVE TEST SCRIPT

Run all tests automatically:

```bash
# Run comprehensive test suite
python backend/scripts/test_all_features.py

# Or use external test script
./scripts/external_test.sh
```

---

## 📊 SYNTHETIC DATA / MODEL DISTILLATION WORKFLOW

### Step 1: Generate Training Data (Teacher Model)

```bash
# Generate from fixtures (easiest)
curl -X POST http://localhost:8000/api/synthetic/generate-from-fixtures \
  -H "Content-Type: application/json" \
  -d '{"num_samples_per_scenario": 5}'
```

**Output Location:** `backend/data/synthetic/fixture_dataset_*.json`

**Format:**
```json
[
  {
    "instruction": "Analyze these security logs...",
    "input": "[log entries]",
    "output": "{\"severity\": \"high\", \"mitre_techniques\": [\"T1110\"]...}"
  }
]
```

### Step 2: View Dataset Stats

```bash
curl http://localhost:8000/api/synthetic/dataset-stats | jq
```

### Step 3: Use for Fine-Tuning (Step 3 - Student Model)

**Note:** Fine-tuning requires additional infrastructure (GPU, training scripts).
The generated dataset is ready to use with:
- Unsloth (LoRA fine-tuning)
- HuggingFace Transformers
- Axolotl

**Training Command (Example):**
```bash
# Placeholder - actual training requires GPU setup
# unsloth --model llama-3.1-8b \
#   --dataset backend/data/synthetic/fixture_dataset_*.json \
#   --output_dir ./models/soc-llama
```

### Step 4: Compare Models

```bash
curl -X POST http://localhost:8000/api/synthetic/compare-models \
  -H "Content-Type: application/json" \
  -d '["test log entry"]' | jq
```

---

## 🎯 QUICK TEST CHECKLIST

- [ ] Health check passes: `curl http://localhost:8000/api/health/basic`
- [ ] Demo Mode works: http://localhost:3000/ingest → Demo Mode → Run Test
- [ ] Incident details visible: Click 👁️ icon after test
- [ ] Synthetic data generation: `/api/synthetic/generate-from-fixtures`
- [ ] Dataset created: `ls backend/data/synthetic/`
- [ ] Model comparison: `/api/synthetic/compare-models`

---

## 📝 UNDERSTANDING OUTPUTS

### Incident JSON Structure:
```json
{
  "id": "uuid",
  "severity": "high",
  "alerts": [
    {
      "title": "Brute force attack detected",
      "severity": "high",
      "mitre_techniques": ["T1110"]
    }
  ],
  "mitre_techniques": [
    {
      "technique_id": "T1110",
      "name": "Brute Force",
      "tactic": "Credential Access"
    }
  ],
  "report": {
    "executive_summary": "...",
    "technical_findings": "...",
    "timeline": [...],
    "root_cause": "..."
  },
  "response_plan": {
    "containment_actions": [...]
  }
}
```

### Validation Response:
```json
{
  "passed": true,
  "checks": {
    "severity_match": true,
    "meets_min_alerts": true,
    "correct_technique": true
  },
  "actual": {
    "severity": "high",
    "mitre_techniques": ["T1110.001"],
    "alerts_count": 1
  }
}
```

---

## 🔗 ALL ENDPOINTS SUMMARY

| Feature | Endpoint | Method | Input | Output Location |
|---------|----------|--------|-------|----------------|
| Log Ingestion | `/api/ingest/analyze` | POST | Logs array | Incident ID in response |
| Demo Mode | Frontend UI | Click | Pre-configured | UI shows PASS/FAIL |
| Incident Details | `/api/incidents/{id}` | GET | Incident ID | JSON response |
| Synthetic Data | `/api/synthetic/generate-single` | POST | Logs array | JSON response |
| Dataset Generation | `/api/synthetic/generate-from-fixtures` | POST | Config | `backend/data/synthetic/*.json` |
| Model Comparison | `/api/synthetic/compare-models` | POST | Logs array | JSON comparison |
| Health Check | `/api/health/basic` | GET | None | JSON status |
| Debug Trace | `/api/debug/last-analysis/{id}` | GET | Incident ID | JSON trace |
| Validation | `/api/debug/validate-incident/{id}` | GET | Query params | JSON validation |

---

## ✨ NEXT STEPS

1. **Test Demo Mode** - Start here for easiest testing
2. **Check Debug Output** - If tests fail, use debug endpoints
3. **Generate Synthetic Data** - Test the distillation feature
4. **View Generated Datasets** - Check training data quality
5. **Compare Models** - Benchmark performance

For issues, check:
- Backend logs: `docker-compose logs backend | tail -50`
- Frontend console: Open browser DevTools
- Debug endpoint: `/api/debug/last-analysis/{incident_id}`

