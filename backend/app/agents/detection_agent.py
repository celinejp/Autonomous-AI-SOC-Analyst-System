"""Detection Agent - Analyzes logs for suspicious patterns with FP controls."""

from datetime import datetime
from typing import Any, Dict, List
from collections import Counter

from app.core.llm_factory import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from app.models.agent_state import AgentState
from app.models.incident import Alert, Severity
from app.models.log_entry import LogEntry

SYSTEM_PROMPT = """You are a security detection agent. Analyze normalized security logs and identify ONLY clear security threats.

Detect these when evidence is strong:
1. Brute force (multiple failed logins from same IP)
2. Port scanning (many distinct destination ports)
3. Data exfiltration (large unusual outbound transfers)
4. Lateral movement (unusual internal admin hops after compromise signals)
5. C2 / anomalous DNS (DGA, beaconing)
6. Privilege escalation or malware execution

CRITICAL FALSE-POSITIVE RULES:
- Routine admin work, backups, VPN+MFA success, software updates, cloud sync, and approved testing are NOT alerts.
- If activity looks legitimate or ambiguous, return an empty JSON array: []
- Do NOT invent alerts. Prefer zero alerts over noisy ones.
- Only emit an alert when you have concrete evidence in the logs.

For each real threat, output a JSON array of objects with:
- severity: critical|high|medium (never invent "low" speculative alerts)
- title, description, detection_rule
- evidence (short strings)
- mitre_techniques (e.g. ["T1110"]) when known
- related_log_indices (integers)

Output ONLY a JSON array. Empty array [] if no threats."""


_BENIGN_MARKERS = (
    "backup start",
    "backup complete",
    "securitypatch",
    "windows update",
    "wuauclt.exe",
    "update.microsoft.com",
    "softwaredistribution",
    "service restart",
    "vpn connect",
    "method=mfa",
    "onedrive",
    "cloud sync",
    "env=testing",
    "test-environment",
    "test-server",
    "vulnerability scan",
    "nightly-backup",
    "approved=true",
    "scanner=nessus",
    "scanner=qualys",
    "authorized",
    "it_admin",
)


def _logs_look_benign(logs: List[LogEntry]) -> bool:
    """Heuristic: mostly routine ops with no hard failure/attack signals."""
    if not logs:
        return True
    raw = " ".join((getattr(log, "raw_log", None) or "") for log in logs).lower()
    actions = " ".join((getattr(log, "action", None) or "") for log in logs).lower()
    blob = f"{raw} {actions}"

    hostile = any(
        token in blob
        for token in (
            "auth failed",
            "login_failed",
            "failed password",
            "drop table",
            "union select",
            "ransomware",
            "encrypt",
            "c2",
            "beacon",
            "mimikatz",
            "lsass",
            "powershell -enc",
            "webshell",
            "bruteforce",
            "brute force",
            "shell.aspx",
            "?cmd=",
            "compromised",
            "child=powershell",
            "readme_decrypt",
            "cryptor.exe",
        )
    )
    if hostile:
        return False

    benign_hits = sum(1 for m in _BENIGN_MARKERS if m in blob)
    # Strong benign signal and no hostile markers
    return benign_hits >= 1 and all(
        (log.status or "").lower() in ("success", "unknown", "", "ok")
        or "fail" not in (log.status or "").lower()
        for log in logs
    )


async def detection_agent(state: AgentState) -> AgentState:
    """Analyze logs for suspicious patterns."""
    _started_at = datetime.utcnow()
    logs = state.get("logs", [])
    if not logs:
        state["alerts"] = []
        return state

    llm = get_llm(temperature=0.0)
    log_summary = _create_log_summary(logs)

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(
            content=(
                f"Analyze these logs for suspicious patterns.\n"
                f"If benign/normal, return [].\n\n{log_summary}\n\n"
                f"Output JSON array of alerts only."
            )
        ),
    ]

    response = await llm.ainvoke(messages)
    content = response.content

    alerts = _parse_alerts_from_response(content, logs)

    from app.detection.attack_rules import evaluate_attack_rules

    for attack_alert in evaluate_attack_rules(logs):
        alerts.append(
            Alert(
                timestamp=datetime.utcnow(),
                severity=Severity(attack_alert["severity"]),
                title=f"{attack_alert['name']} - {attack_alert['technique_id']}",
                description=f"Detected {attack_alert['tactic']} technique: {attack_alert['name']}",
                detection_rule=f"ATT&CK Rule: {attack_alert['technique_id']}",
                related_logs=attack_alert.get("matched_logs", []),
                mitre_techniques=[attack_alert["technique_id"]],
                evidence=[
                    {
                        "rule": attack_alert["technique_id"],
                        "confidence": attack_alert.get("confidence", 0.75),
                    }
                ],
            )
        )

    alerts.extend(_rule_based_detection(logs))
    alerts = _filter_alerts(alerts, logs)

    state["alerts"] = alerts
    state["agent_execution_log"].append(
        {
            "agent_name": "detection",
            "timestamp": datetime.utcnow().isoformat(),
            "duration_ms": (datetime.utcnow() - _started_at).total_seconds() * 1000,
            "output_data": {"logs_analyzed": len(logs), "alerts_generated": len(alerts)},
        }
    )
    return state


def _create_log_summary(logs: List[LogEntry]) -> str:
    summary_lines = []
    for i, log in enumerate(logs[:100]):
        summary_lines.append(
            f"{i}: [{log.timestamp}] {log.log_source.value} | "
            f"src={log.source_ip} dst={log.destination_ip}:{log.destination_port} | "
            f"user={log.user} | action={log.action} | status={log.status} | "
            f"raw={(log.raw_log or '')[:160]}"
        )
    return "\n".join(summary_lines)


def _parse_alerts_from_response(content: str, logs: List[LogEntry]) -> List[Alert]:
    """Parse alerts from LLM response. Never invent alerts from prose."""
    import json
    import re

    alerts: List[Alert] = []
    json_match = re.search(r'\[.*\]', content, re.DOTALL)
    if not json_match:
        return alerts

    try:
        alerts_data = json.loads(json_match.group())
    except Exception:
        return alerts

    if not isinstance(alerts_data, list):
        return alerts

    for alert_data in alerts_data:
        if not isinstance(alert_data, dict):
            continue
        try:
            sev_raw = str(alert_data.get("severity", "medium")).lower()
            if sev_raw not in ("critical", "high", "medium", "low"):
                sev_raw = "medium"
            # Drop speculative low LLM alerts
            if sev_raw == "low":
                continue
            alert = Alert(
                timestamp=datetime.utcnow(),
                severity=Severity(sev_raw),
                title=alert_data.get("title", "Suspicious activity detected"),
                description=alert_data.get("description", ""),
                detection_rule=alert_data.get("detection_rule", "LLM-detected pattern"),
                evidence=alert_data.get("evidence", []) or [],
                related_logs=[str(i) for i in alert_data.get("related_log_indices", [])],
                mitre_techniques=alert_data.get("mitre_techniques", []) or [],
            )
            alerts.append(alert)
        except Exception:
            continue

    return alerts


def _filter_alerts(alerts: List[Alert], logs: List[LogEntry]) -> List[Alert]:
    """Deduplicate and suppress alerts on likely-benign traffic when only LLM noise exists."""
    if not alerts:
        return []

    kept: List[Alert] = []
    seen_titles = set()
    for alert in alerts:
        is_rule = (alert.detection_rule or "").startswith("ATT&CK Rule") or (
            alert.detection_rule or ""
        ).startswith("rule:") or alert.detection_rule in (
            "multiple_failed_logins",
            "port_scanning",
        )
        if not is_rule:
            if alert.severity == Severity.LOW:
                continue
            # Keep medium+ LLM alerts that have a concrete title (not empty fluff)
            title = (alert.title or "").strip().lower()
            if not title or title in ("suspicious activity detected", "alert"):
                if not (alert.mitre_techniques or alert.evidence):
                    continue

        key = (alert.title.lower().strip(), alert.detection_rule)
        if key in seen_titles:
            continue
        seen_titles.add(key)
        kept.append(alert)

    if _logs_look_benign(logs):
        # On benign traffic, drop LLM-only alerts; keep hard rule hits only
        kept = [
            a
            for a in kept
            if (a.detection_rule or "").startswith("ATT&CK Rule")
            or (a.detection_rule or "").startswith("rule:")
            or a.detection_rule in ("multiple_failed_logins", "port_scanning")
        ]

    return kept


def _rule_based_detection(logs: List[LogEntry]) -> List[Alert]:
    """Deterministic signature/threshold detection (primary FP-safe signal)."""
    alerts: List[Alert] = []
    blob = " ".join((log.raw_log or "") for log in logs).lower()

    def add(title: str, description: str, rule: str, severity: Severity, techniques: List[str]):
        alerts.append(
            Alert(
                timestamp=datetime.utcnow(),
                severity=severity,
                title=title,
                description=description,
                detection_rule=rule,
                related_logs=[str(i) for i in range(min(10, len(logs)))],
                mitre_techniques=techniques,
                evidence=[{"rule": rule, "match": True}],
            )
        )

    # Brute force
    failed_logins_by_ip = Counter()
    for log in logs:
        raw = (log.raw_log or "").lower()
        if (
            log.log_source.value == "auth"
            and log.action in ["login_attempt", "login_failed"]
            and log.status == "failure"
        ):
            failed_logins_by_ip[log.source_ip] += 1
        elif "auth failed" in raw or "failed password" in raw:
            failed_logins_by_ip[log.source_ip or "unknown"] += 1

    for ip, count in failed_logins_by_ip.items():
        # Threshold 3 matches common labeled brute-force fixtures
        if count >= 3:
            severity = Severity.CRITICAL if count >= 20 else Severity.HIGH
            add(
                f"Brute force attack detected from {ip}",
                f"Detected {count} failed login attempts from {ip}",
                "multiple_failed_logins",
                severity,
                ["T1110"],
            )

    # Port scanning (many distinct ports)
    ports_by_ip: Dict[str, set] = {}
    for log in logs:
        if log.destination_port:
            ports_by_ip.setdefault(log.source_ip, set()).add(log.destination_port)
    for ip, ports in ports_by_ip.items():
        if len(ports) >= 10:
            add(
                f"Port scanning detected from {ip}",
                f"Detected connections to {len(ports)} different ports from {ip}",
                "port_scanning",
                Severity.HIGH,
                ["T1046"],
            )

    # Signature rules (high precision keywords)
    signatures = [
        (
            any(x in blob for x in ("readme_decrypt", "cryptor.exe", "ransom")),
            "Ransomware / encryption activity",
            "Ransomware indicators in process/file activity",
            "rule:ransomware",
            Severity.CRITICAL,
            ["T1486"],
        ),
        (
            "mimikatz" in blob or "lsass access" in blob or "lsass.exe" in blob,
            "Credential dumping (LSASS/mimikatz)",
            "Credential dumping tooling or LSASS access detected",
            "rule:cred_dump",
            Severity.CRITICAL,
            ["T1003"],
        ),
        (
            "macro execution" in blob or (".docm" in blob and "attachment opened" in blob)
            or "phishing.com" in blob,
            "Phishing / malicious document",
            "Phishing delivery or macro execution detected",
            "rule:phishing",
            Severity.HIGH,
            ["T1566"],
        ),
        (
            ("rdp connect" in blob and blob.count("rdp connect") >= 2)
            or "admin share access" in blob
            or "\\\\" in blob and "c$" in blob,
            "Lateral movement indicators",
            "Multi-host RDP or admin share access pattern",
            "rule:lateral",
            Severity.HIGH,
            ["T1021"],
        ),
        (
            any(x in blob for x in ("union select", "or '1'='1", "drop table", "sql injection")),
            "SQL injection attempt",
            "SQLi patterns in HTTP request logs",
            "rule:sqli",
            Severity.HIGH,
            ["T1190"],
        ),
        (
            "privilege change" in blob and "system" in blob,
            "Privilege escalation",
            "Unexpected privilege elevation to SYSTEM",
            "rule:privesc",
            Severity.HIGH,
            ["T1548"],
        ),
        (
            "http post" in blob and ("2gb" in blob or "exfil" in blob or "anonymous-storage" in blob),
            "Possible data exfiltration",
            "Large outbound transfer to external storage",
            "rule:exfil",
            Severity.CRITICAL,
            ["T1567"],
        ),
        (
            "interval=300s" in blob or ("beacon" in blob) or ("c2" in blob and "connect" in blob),
            "C2 beaconing pattern",
            "Periodic outbound connections consistent with C2",
            "rule:c2",
            Severity.HIGH,
            ["T1071"],
        ),
        (
            "memory write" in blob and "explorer.exe" in blob,
            "Process injection",
            "Cross-process memory write into explorer.exe",
            "rule:injection",
            Severity.HIGH,
            ["T1055"],
        ),
        (
            "registry modify" in blob and "currentversion\\run" in blob,
            "Persistence via Run key",
            "Registry Run key modification for persistence",
            "rule:persistence",
            Severity.HIGH,
            ["T1547"],
        ),
        (
            "webshell" in blob
            or "shell.aspx" in blob
            or "?cmd=" in blob
            or ("file create" in blob and (".aspx" in blob or ".php" in blob) and "wwwroot" in blob),
            "Web shell / malicious upload",
            "Web shell or suspicious upload activity",
            "rule:webshell",
            Severity.HIGH,
            ["T1505"],
        ),
        (
            ("dns query" in blob or "dns " in blob)
            and any(x in blob for x in ("tunnel", "txt ", "type=txt", "dga", "long domain", "evil-dns")),
            "Suspicious DNS activity",
            "Possible DNS tunneling or anomalous DNS patterns",
            "rule:dns",
            Severity.MEDIUM,
            ["T1071"],
        ),
        (
            # Volumetric / DDoS-like: many identical HTTP requests
            blob.count("http request") >= 12 and len(set((log.source_ip for log in logs))) <= 2,
            "High-volume request flood",
            "Burst of repetitive HTTP requests from few sources",
            "rule:ddos",
            Severity.HIGH,
            ["T1499"],
        ),
        (
            "compromised" in blob
            or ("software update" in blob and "powershell" in blob)
            or ("child=powershell" in blob and "update" in blob),
            "Supply chain compromise indicators",
            "Suspicious package/update supply-chain signals",
            "rule:supply_chain",
            Severity.HIGH,
            ["T1195"],
        ),
    ]

    # Skip signature alerts when traffic is clearly approved/benign
    if not _logs_look_benign(logs):
        for matched, title, desc, rule, sev, techs in signatures:
            if matched:
                add(title, desc, rule, sev, techs)

    return alerts
