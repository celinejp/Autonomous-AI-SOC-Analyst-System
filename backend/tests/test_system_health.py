"""Comprehensive system health and integration tests."""

import pytest
import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.orchestrator.langgraph_workflow import run_workflow_with_events


# Test fixtures
FIXTURES_DIR = Path(__file__).parent / "fixtures"
TEST_LOGS_PATH = FIXTURES_DIR / "test_logs.json"


def load_test_scenarios() -> List[Dict[str, Any]]:
    """Load test scenarios from fixtures."""
    with open(TEST_LOGS_PATH) as f:
        data = json.load(f)
    return data.get("scenarios", [])


def load_fixture(scenario_name: str) -> Dict[str, Any]:
    """Load a specific test scenario."""
    scenarios = load_test_scenarios()
    return next((s for s in scenarios if s["name"] == scenario_name), None)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_all_agents_functional():
    """Verify all 6 agents execute successfully."""
    scenario = load_fixture("brute_force_attack")
    assert scenario, "Test scenario not found"
    
    agents_seen = set()
    
    async for event in run_workflow_with_events(scenario["logs"], "test-all-agents"):
        if event.get("type") == "agent_start":
            agents_seen.add(event.get("agent"))
        elif event.get("type") == "complete":
            break
        elif event.get("type") == "error":
            pytest.fail(f"Workflow error: {event.get('error')}")
    
    # Verify all agents executed
    expected_agents = {"ingest", "detect", "enrich", "analyze", "critique", "plan_response"}
    assert agents_seen == expected_agents, f"Missing agents: {expected_agents - agents_seen}"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_detection_accuracy_brute_force():
    """Verify detection agent catches brute force attacks."""
    scenario = load_fixture("brute_force_attack")
    assert scenario, "Test scenario not found"
    
    final_state = None
    
    async for event in run_workflow_with_events(scenario["logs"], "test-brute-force"):
        if event.get("type") == "complete":
            final_state = event.get("data")
            break
        elif event.get("type") == "error":
            pytest.fail(f"Workflow error: {event.get('error')}")
    
    assert final_state, "Workflow did not complete"
    
    # Check alerts were generated
    alerts = final_state.get("alerts", [])
    assert len(alerts) > 0, "No alerts generated for brute force attack"
    
    # Check severity
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    max_severity = max(
        (severity_map.get(a.get("severity", "low"), 1) for a in alerts),
        default=1
    )
    assert max_severity >= 3, f"Expected high severity, got {max_severity}"
    
    # Check MITRE techniques
    techniques = final_state.get("mitre_techniques", [])
    technique_ids = [
        t.get("technique_id", t) if isinstance(t, dict) else str(t)
        for t in techniques
    ]
    assert any("T1110" in tid or "T1078" in tid for tid in technique_ids), \
        f"Expected T1110 or T1078, got {technique_ids}"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_detection_accuracy_sql_injection():
    """Verify detection agent catches SQL injection attempts."""
    scenario = load_fixture("sql_injection_attempt")
    assert scenario, "Test scenario not found"
    
    final_state = None
    
    async for event in run_workflow_with_events(scenario["logs"], "test-sql-injection"):
        if event.get("type") == "complete":
            final_state = event.get("data")
            break
    
    assert final_state, "Workflow did not complete"
    
    alerts = final_state.get("alerts", [])
    assert len(alerts) > 0, "No alerts generated for SQL injection"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_detection_accuracy_ddos():
    """Verify detection agent catches DDoS patterns."""
    scenario = load_fixture("ddos_pattern")
    assert scenario, "Test scenario not found"
    
    final_state = None
    
    async for event in run_workflow_with_events(scenario["logs"], "test-ddos"):
        if event.get("type") == "complete":
            final_state = event.get("data")
            break
    
    assert final_state, "Workflow did not complete"
    
    alerts = final_state.get("alerts", [])
    assert len(alerts) > 0, "No alerts generated for DDoS pattern"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_false_positive_rate():
    """Verify benign logs don't trigger false alerts."""
    scenario = load_fixture("normal_traffic")
    assert scenario, "Test scenario not found"
    
    final_state = None
    
    async for event in run_workflow_with_events(scenario["logs"], "test-normal"):
        if event.get("type") == "complete":
            final_state = event.get("data")
            break
    
    assert final_state, "Workflow did not complete"
    
    # Benign traffic should have low or no alerts
    alerts = final_state.get("alerts", [])
    
    # If alerts exist, they should be low severity
    if alerts:
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_severity = max(
            (severity_map.get(a.get("severity", "low"), 1) for a in alerts),
            default=1
        )
        assert max_severity <= 2, f"Expected low/medium severity for benign traffic, got {max_severity}"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_workflow_completes_successfully():
    """Verify workflow completes without errors."""
    scenario = load_fixture("brute_force_attack")
    
    completed = False
    error_occurred = False
    
    async for event in run_workflow_with_events(scenario["logs"], "test-complete"):
        if event.get("type") == "complete":
            completed = True
            break
        elif event.get("type") == "error":
            error_occurred = True
            pytest.fail(f"Workflow error: {event.get('error')}")
    
    assert completed, "Workflow did not complete"
    assert not error_occurred, "Workflow encountered an error"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_ingest_agent_parses_logs():
    """Verify ingest agent correctly parses log entries."""
    logs = [
        "2024-01-15 10:30:00 AUTH FAILED user=admin src=192.168.1.100",
        "2024-01-15 10:30:01 HTTP REQUEST src=10.0.0.1 dst=example.com",
    ]
    
    from app.agents.ingest_agent import ingest_agent
    from app.models.agent_state import AgentState
    
    state: AgentState = {
        "logs": [],
        "raw_logs": logs,
        "alerts": [],
        "threat_intel": {},
        "incident_report": None,
        "response_plan": None,
        "confidence": 0.0,
        "iteration": 0,
        "needs_revision": False,
        "critique_feedback": None,
        "messages": [],
        "agent_execution_log": [],
        "incident_id": "test-ingest",
    }
    
    result = await ingest_agent(state)
    
    assert "logs" in result
    assert len(result["logs"]) > 0, "Ingest agent did not parse logs"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_detection_agent_generates_alerts():
    """Verify detection agent generates alerts from parsed logs."""
    from app.agents.detection_agent import detection_agent
    from app.models.agent_state import AgentState
    from app.models.log_entry import LogEntry
    from datetime import datetime
    
    logs = [
        LogEntry(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            destination_ip="10.0.0.50",
            action="AUTH FAILED",
            status="failed",
            log_source="auth",
            raw_log="AUTH FAILED user=admin",
        )
    ]
    
    state: AgentState = {
        "logs": logs,
        "raw_logs": [],
        "alerts": [],
        "threat_intel": {},
        "incident_report": None,
        "response_plan": None,
        "confidence": 0.0,
        "iteration": 0,
        "needs_revision": False,
        "critique_feedback": None,
        "messages": [],
        "agent_execution_log": [],
        "incident_id": "test-detect",
    }
    
    result = await detection_agent(state)
    
    assert "alerts" in result
    assert len(result["alerts"]) > 0, "Detection agent did not generate alerts"


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.timeout(120)
async def test_all_scenarios_complete():
    """Run all test scenarios and verify they complete."""
    scenarios = load_test_scenarios()
    
    results = []
    for scenario in scenarios:
        try:
            completed = False
            async for event in run_workflow_with_events(
                scenario["logs"], 
                f"test-{scenario['name']}"
            ):
                if event.get("type") == "complete":
                    completed = True
                    break
                elif event.get("type") == "error":
                    results.append({
                        "scenario": scenario["name"],
                        "status": "fail",
                        "error": event.get("error")
                    })
                    break
            
            if completed:
                results.append({
                    "scenario": scenario["name"],
                    "status": "pass"
                })
        except Exception as e:
            results.append({
                "scenario": scenario["name"],
                "status": "fail",
                "error": str(e)
            })
    
    # Verify all scenarios passed
    failed = [r for r in results if r["status"] == "fail"]
    if failed:
        pytest.fail(f"Scenarios failed: {failed}")
    
    assert len(results) == len(scenarios), "Not all scenarios were tested"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_workflow_timeout_handling():
    """Verify workflow handles timeouts gracefully."""
    # Use very large log set that might timeout
    large_logs = [f"2024-01-15 10:00:{i:02d} LOG ENTRY {i}" for i in range(100)]
    
    try:
        async for event in asyncio.wait_for(
            run_workflow_with_events(large_logs, "test-timeout"),
            timeout=90.0
        ):
            if event.get("type") == "error":
                # Errors are acceptable for timeout tests
                break
            elif event.get("type") == "complete":
                break
    except asyncio.TimeoutError:
        # Timeout is expected for this test
        pass


@pytest.mark.asyncio
@pytest.mark.integration
async def test_incident_report_generation():
    """Verify analyst agent generates incident reports."""
    scenario = load_fixture("brute_force_attack")
    
    final_state = None
    async for event in run_workflow_with_events(scenario["logs"], "test-report"):
        if event.get("type") == "complete":
            final_state = event.get("data")
            break
    
    assert final_state, "Workflow did not complete"
    
    # Check that incident report exists
    report = final_state.get("incident_report")
    assert report is not None, "Incident report was not generated"
    
    # Check required fields
    if isinstance(report, dict):
        assert "executive_summary" in report or report.get("executive_summary")
        assert "technical_findings" in report or report.get("technical_findings")
        assert "root_cause" in report or report.get("root_cause")
    else:
        # Pydantic model
        assert hasattr(report, "executive_summary")
        assert hasattr(report, "technical_findings")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_response_plan_generation():
    """Verify response planner generates actionable plans."""
    scenario = load_fixture("brute_force_attack")
    
    final_state = None
    async for event in run_workflow_with_events(scenario["logs"], "test-plan"):
        if event.get("type") == "complete":
            final_state = event.get("data")
            break
    
    assert final_state, "Workflow did not complete"
    
    plan = final_state.get("response_plan")
    assert plan is not None, "Response plan was not generated"
    
    # Check that plan has actions
    if isinstance(plan, dict):
        has_actions = (
            len(plan.get("containment_actions", [])) > 0 or
            len(plan.get("investigation_steps", [])) > 0 or
            len(plan.get("remediation_actions", [])) > 0
        )
        assert has_actions, "Response plan has no actionable items"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "integration"])

