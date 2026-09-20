"""Filtering of LLM alerts that the logs do not support."""

import asyncio
from datetime import datetime

from app.agents.detection_agent import _filter_alerts
from app.agents.ingest_agent import ingest_agent
from app.models.incident import Alert, Severity


def parse(lines):
    return asyncio.run(ingest_agent({"raw_logs": lines, "logs": [], "alerts": [], "agent_execution_log": []}))["logs"]


def llm_brute_force_alert():
    return Alert(timestamp=datetime.utcnow(), severity=Severity.HIGH, title="Brute force attack",
                 description="d", detection_rule="LLM-detected pattern", mitre_techniques=["T1110"])


def test_typo_then_success_is_not_reported_as_brute_force():
    logs = parse(["Sep 1 09:00:00 h sshd[3]: Failed password for mkim from 10.0.4.12 port 1",
                  "Sep 1 09:00:09 h sshd[3]: Failed password for mkim from 10.0.4.12 port 2",
                  "Sep 1 09:00:21 h sshd[3]: Accepted password for mkim from 10.0.4.12 port 3"])
    assert _filter_alerts([llm_brute_force_alert()], logs) == []


def test_real_burst_keeps_the_llm_alert():
    logs = parse([f"Sep 1 09:00:0{i} h sshd[3]: Failed password for root from 203.0.113.9 port {i}" for i in range(5)])
    assert len(_filter_alerts([llm_brute_force_alert()], logs)) == 1


def test_highest_severity_uses_severity_not_alphabetical_or_enum_order():
    from app.models.incident import highest_severity
    assert highest_severity([Severity.MEDIUM, Severity.CRITICAL, Severity.LOW]) == Severity.CRITICAL
    assert highest_severity([Severity.LOW, Severity.MEDIUM]) == Severity.MEDIUM
    assert highest_severity([]) == Severity.LOW


def test_fallback_plan_contains_containment_when_any_alert_is_high_or_critical():
    from app.agents.response_planner import _fallback_plan
    alerts = [Alert(timestamp=datetime.utcnow(), severity=s, title="a", description="d", detection_rule="r")
              for s in (Severity.MEDIUM, Severity.CRITICAL, Severity.LOW)]
    assert _fallback_plan(alerts).containment_actions
