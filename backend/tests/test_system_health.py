"""Integration tests: real LLM (Ollama) and, for the real captures, the public dataset cache.

Run with the stack up and Ollama running:  pytest tests/test_system_health.py -m integration
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.agents.detection_agent import detection_agent  # noqa: E402
from app.agents.ingest_agent import ingest_agent  # noqa: E402
from app.orchestrator.langgraph_workflow import run_workflow_with_events  # noqa: E402

FIXTURES = json.load(open(Path(__file__).parent / "fixtures" / "test_logs.json"))["scenarios"]
SCENARIOS = {s["name"]: s for s in FIXTURES}
PUBLIC = Path(__file__).parent.parent / "data" / "public" / "splunk" / "datasets" / "attack_techniques"

pytestmark = pytest.mark.integration

ALL_AGENTS = {"ingest", "detect", "enrich", "analyze", "critique", "plan_response"}


async def run_full_workflow(raw_logs, incident_id):
    """Run the whole graph; returns (final_state, agents_that_started)."""
    final_state, started = None, set()
    async for event in run_workflow_with_events(raw_logs, incident_id):
        if event["type"] == "agent_start":
            started.add(event["agent"])
        elif event["type"] == "complete":
            final_state = event["data"]
        elif event["type"] == "error":
            pytest.fail(f"workflow error: {event.get('error')}")
    assert final_state, "workflow did not complete"
    return final_state, started


@pytest.mark.asyncio
@pytest.mark.timeout(900)
async def test_full_workflow_on_a_brute_force_scenario():
    """All six agents run and produce alerts, a report with IOCs and a response plan grouped by team."""
    state, started = await run_full_workflow(SCENARIOS["brute_force_attack"]["logs"], "it-brute-force")

    assert started == ALL_AGENTS
    alerts = state["alerts"]
    assert alerts and any(a["severity"] in ("high", "critical") for a in alerts)
    assert any(t.startswith("T1110") for a in alerts for t in a.get("mitre_techniques", []))

    report = state["incident_report"]
    assert report["executive_summary"] and report["root_cause"]
    ips = [i["value"] for i in (report.get("indicators_of_compromise") or {}).get("ip_addresses", [])]
    assert ips, "expected the attacking IP as an IOC"

    plan = state["response_plan"]
    assert plan["actions_by_team"], "response plan is not grouped by team"


@pytest.mark.asyncio
@pytest.mark.timeout(300)
@pytest.mark.parametrize("scenario,expect_alert", [
    ("brute_force_attack", True), ("sql_injection_attempt", True), ("ddos_pattern", True),
    ("lateral_movement", True), ("normal_traffic", False),
])
async def test_detection_on_scenarios(scenario, expect_alert):
    """Detection (LLM + rules) flags each attack scenario and stays quiet on normal traffic."""
    state = {"raw_logs": SCENARIOS[scenario]["logs"], "logs": [], "alerts": [], "agent_execution_log": []}
    state = await detection_agent(await ingest_agent(state))
    assert bool(state["alerts"]) == expect_alert, [a.title for a in state["alerts"]]


REAL_CAPTURES = [
    ("T1070.001", "windows_event_log_cleared/windows-security.log"),
    ("T1543.003", "atomic_red_team/remcom_windows-system.log"),
    ("T1047", "lateral_movement/wmi_remote_process_powershell.log"),
]


@pytest.mark.asyncio
@pytest.mark.timeout(900)
@pytest.mark.parametrize("technique,relative", REAL_CAPTURES)
async def test_real_public_capture_end_to_end(technique, relative):
    """A real attack capture (Splunk attack_data) goes through all six agents and is detected.
    Needs the cache: run `python scripts/eval_public_datasets.py --splunk-only` once."""
    from scripts.eval_public_datasets import split_events

    path = PUBLIC / technique / relative
    if not path.exists():
        pytest.skip("public dataset cache missing (run scripts/eval_public_datasets.py --splunk-only)")

    state, _ = await run_full_workflow(split_events(path.read_text(errors="ignore"))[:300], f"it-real-{technique}")

    techniques = {t for a in state["alerts"] for t in a.get("mitre_techniques", [])}
    assert any(t.split(".")[0] == technique.split(".")[0] for t in techniques), f"{technique} not detected: {techniques}"
    assert state["incident_report"] and state["response_plan"]


# ---- The real stack: API -> Redis queue -> worker -> LangGraph + Ollama -> Postgres/pgvector -----------
API = "http://localhost:8000/api"


def _api_up() -> bool:
    import httpx
    try:
        return httpx.get(f"{API}/health/basic", timeout=5).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.mark.timeout(900)
def test_full_stack_submit_analyze_save_and_search():
    """Submit logs to the running API and follow the incident through the real queue, worker, LLM and
    databases: it is saved with alerts, a report with IOCs and a response plan, its embedding is stored
    (pgvector) and semantic search finds it. Needs `docker compose up` and Ollama."""
    import time

    import httpx

    if not _api_up():
        pytest.skip("backend API is not running on localhost:8000")

    logs = [f"Jan 15 10:30:0{i} host sshd[1]: Failed password for root from 203.0.113.9 port 22" for i in range(6)]
    client = httpx.Client(base_url=API, timeout=30)
    submitted = client.post("/ingest/analyze", json=logs)
    assert submitted.status_code == 200 and submitted.json()["status"] == "queued"
    incident_id = submitted.json()["incident_id"]

    try:
        deadline = time.time() + 600
        status = {}
        while time.time() < deadline:
            status = client.get(f"/incidents/{incident_id}/status").json()
            if status["status"] in ("completed", "failed"):
                break
            time.sleep(5)
        assert status["status"] == "completed", status

        incident = client.get(f"/incidents/{incident_id}").json()
        assert incident["severity"].lower() in ("high", "critical")
        assert any(t.startswith("T1110") for a in incident["alerts"] for t in a["mitre_techniques"])
        report = incident["report"]
        assert report["executive_summary"] and report["root_cause"]
        assert "203.0.113.9" in [i["value"] for i in report["indicators_of_compromise"]["ip_addresses"]]
        assert incident["response_plan"]["actions_by_team"]

        found = []
        deadline = time.time() + 180  # the embedding job runs after the save
        while time.time() < deadline and incident_id not in found:
            time.sleep(5)
            try:  # the first embedding after an LLM run waits for Ollama to swap models
                hits = client.post("/v1/incidents/search/semantic", json={"query": "ssh brute force failed logins", "limit": 20}, timeout=120).json()
            except httpx.ReadTimeout:
                continue
            found = [r["id"] for r in hits["results"]]
        assert incident_id in found, "incident embedding was not stored / searchable"
    finally:
        client.delete(f"/incidents/{incident_id}")
