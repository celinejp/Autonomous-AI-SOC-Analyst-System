"""Detection Agent - Analyzes logs for suspicious patterns."""

from datetime import datetime
from typing import Any, Dict, List
from collections import Counter

from app.core.llm_factory import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base import BaseAgent
from app.core.config import settings
from app.models.agent_state import AgentState
from app.models.incident import Alert, Severity
from app.models.log_entry import LogEntry

SYSTEM_PROMPT = """You are a security detection agent. Your role is to analyze normalized security logs and identify suspicious patterns that indicate potential security threats.

You should detect:
1. Brute force attempts (multiple failed logins from same IP)
2. Port scanning behavior (multiple connections to different ports)
3. Data exfiltration (large outbound data transfers)
4. Lateral movement indicators (unusual access patterns)
5. Anomalous DNS queries (DGA domains, C2 communication patterns)
6. Privilege escalation attempts (unusual privilege changes)

For each detected pattern, create an alert with:
- severity (critical/high/medium/low)
- title
- description
- detection_rule
- evidence (relevant log entries)
- related_logs (log IDs)

Output a JSON array of alerts."""


async def detection_agent(state: AgentState) -> AgentState:
    """Analyze logs for suspicious patterns."""
    logs = state.get("logs", [])
    if not logs:
        state["alerts"] = []
        return state

    # Use LLM for pattern detection
    llm = get_llm(temperature=0.1)

    # Prepare log summary for LLM
    log_summary = _create_log_summary(logs)
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"Analyze these logs for suspicious patterns:\n\n{log_summary}\n\nOutput JSON array of alerts."),
    ]

    response = await llm.ainvoke(messages)
    content = response.content

    # Parse alerts from LLM response
    alerts = _parse_alerts_from_response(content, logs)
    
    # Also run ATT&CK-based detection rules
    from app.detection.attack_rules import evaluate_attack_rules
    attack_alerts = evaluate_attack_rules(logs)
    
    # Convert ATT&CK alerts to Alert objects
    for attack_alert in attack_alerts:
        alerts.append(Alert(
            timestamp=datetime.utcnow(),
            severity=Severity(attack_alert["severity"]),
            title=f"{attack_alert['name']} - {attack_alert['technique_id']}",
            description=f"Detected {attack_alert['tactic']} technique: {attack_alert['name']}",
            detection_rule=f"ATT&CK Rule: {attack_alert['technique_id']}",
            related_logs=attack_alert.get("matched_logs", []),
            mitre_techniques=[attack_alert["technique_id"]],
            evidence=[{"rule": attack_alert["technique_id"], "confidence": attack_alert.get("confidence", 0.75)}],
        ))
    
    # Also run rule-based detection as fallback
    rule_based_alerts = _rule_based_detection(logs)
    alerts.extend(rule_based_alerts)

    state["alerts"] = alerts
    state["agent_execution_log"].append({
        "agent_name": "detection",
        "timestamp": datetime.utcnow().isoformat(),
        "logs_analyzed": len(logs),
        "alerts_generated": len(alerts),
    })

    return state


def _create_log_summary(logs: List[LogEntry]) -> str:
    """Create a summary of logs for LLM analysis."""
    summary_lines = []
    for i, log in enumerate(logs[:100]):  # Limit to first 100 for token efficiency
        summary_lines.append(
            f"{i}: [{log.timestamp}] {log.log_source.value} | "
            f"src={log.source_ip} dst={log.destination_ip}:{log.destination_port} | "
            f"user={log.user} | action={log.action} | status={log.status}"
        )
    return "\n".join(summary_lines)


def _parse_alerts_from_response(content: str, logs: List[LogEntry]) -> List[Alert]:
    """Parse alerts from LLM response."""
    import json
    import re
    
    alerts = []
    
    # Try to extract JSON from response
    json_match = re.search(r'\[.*\]', content, re.DOTALL)
    if json_match:
        try:
            alerts_data = json.loads(json_match.group())
            for alert_data in alerts_data:
                alert = Alert(
                    timestamp=datetime.utcnow(),
                    severity=Severity(alert_data.get("severity", "medium")),
                    title=alert_data.get("title", "Suspicious activity detected"),
                    description=alert_data.get("description", ""),
                    detection_rule=alert_data.get("detection_rule", "LLM-detected pattern"),
                    evidence=alert_data.get("evidence", []),
                    related_logs=[str(i) for i in alert_data.get("related_log_indices", [])],
                    mitre_techniques=alert_data.get("mitre_techniques", []),
                )
                alerts.append(alert)
        except Exception:
            pass
    
    # If parsing fails, create a generic alert
    if not alerts and "suspicious" in content.lower() or "attack" in content.lower():
        alerts.append(Alert(
            timestamp=datetime.utcnow(),
            severity=Severity.MEDIUM,
            title="Suspicious activity detected",
            description=content[:500],
            detection_rule="LLM-detected pattern",
            related_logs=[str(i) for i in range(min(10, len(logs)))],
        ))
    
    return alerts


def _rule_based_detection(logs: List[LogEntry]) -> List[Alert]:
    """Rule-based detection as fallback."""
    alerts = []
    
    # Brute force detection
    failed_logins_by_ip = Counter()
    for log in logs:
        if log.log_source.value == "auth" and log.action in ["login_attempt", "login_failed"] and log.status == "failure":
            failed_logins_by_ip[log.source_ip] += 1
    
    for ip, count in failed_logins_by_ip.items():
        if count >= 5:
            severity = Severity.CRITICAL if count >= 20 else Severity.HIGH
            related_logs = [str(i) for i, log in enumerate(logs) if log.source_ip == ip and "login" in log.action.lower()]
            
            alerts.append(Alert(
                timestamp=datetime.utcnow(),
                severity=severity,
                title=f"Brute force attack detected from {ip}",
                description=f"Detected {count} failed login attempts from {ip}",
                detection_rule="multiple_failed_logins",
                related_logs=related_logs[:20],
                mitre_techniques=["T1110"],
            ))
    
    # Port scanning detection
    ports_by_ip = {}
    for log in logs:
        if log.destination_port:
            if log.source_ip not in ports_by_ip:
                ports_by_ip[log.source_ip] = set()
            ports_by_ip[log.source_ip].add(log.destination_port)
    
    for ip, ports in ports_by_ip.items():
        if len(ports) >= 10:
            related_logs = [str(i) for i, log in enumerate(logs) if log.source_ip == ip and log.destination_port]
            
            alerts.append(Alert(
                timestamp=datetime.utcnow(),
                severity=Severity.HIGH,
                title=f"Port scanning detected from {ip}",
                description=f"Detected connections to {len(ports)} different ports from {ip}",
                detection_rule="port_scanning",
                related_logs=related_logs[:20],
            ))
    
    return alerts

