"""IOC extraction: deterministic from log fields; LLM additions must be grounded."""

import asyncio
from datetime import datetime

from app.agents.analyst_agent import _build_ioc_collection
from app.agents.ingest_agent import ingest_agent
from app.models.incident import Alert, Severity


def _fixture():
    lines = [f"Jan 15 10:30:0{i} h sshd[1]: Failed password for root from 203.0.113.9 port 22" for i in range(4)]
    logs = asyncio.run(ingest_agent({"raw_logs": lines, "logs": [], "alerts": [], "agent_execution_log": []}))["logs"]
    alert = Alert(timestamp=datetime.utcnow(), severity=Severity.HIGH, title="Brute force from 203.0.113.9",
                  description="4 failed logins", detection_rule="multiple_failed_logins",
                  related_logs=["0", "1", "2", "3"], mitre_techniques=["T1110"])
    return [alert], logs


def test_ip_comes_from_parsed_fields_and_is_deduplicated():
    alerts, logs = _fixture()
    ips = [i.value for i in _build_ioc_collection(alerts, logs, None).ip_addresses]
    assert ips == ["203.0.113.9"]


def test_llm_ioc_copied_from_prompt_example_is_dropped():
    alerts, logs = _fixture()
    llm = [{"value": "203.0.113.55", "type": "ip", "confidence": "high", "recommended_action": "block"}]
    ips = [i.value for i in _build_ioc_collection(alerts, logs, llm).ip_addresses]
    assert "203.0.113.55" not in ips


def test_llm_ioc_present_in_alert_text_is_kept():
    alerts, logs = _fixture()
    alerts[0].description += " beacon to evil-c2.example.net observed"
    llm = [{"value": "evil-c2.example.net", "type": "domain", "confidence": "medium", "recommended_action": "block"}]
    assert "evil-c2.example.net" in [d.value for d in _build_ioc_collection(alerts, logs, llm).domains]


def test_parser_placeholder_unknown_is_not_an_ioc():
    lines = ["Sysmon EventID=11 FileCreate: TargetFilename=C:\\x\\a.docx.locked24 Image=C:\\x\\i.exe"]
    logs = asyncio.run(ingest_agent({"raw_logs": lines, "logs": [], "alerts": [], "agent_execution_log": []}))["logs"]
    alert = Alert(timestamp=datetime.utcnow(), severity=Severity.CRITICAL, title="Ransomware", description="d",
                  detection_rule="rule:ransomware", related_logs=["0"], mitre_techniques=["T1486"])
    coll = _build_ioc_collection([alert], logs, None)
    assert coll is None or "unknown" not in [i.value for i in coll.ip_addresses]
