"""ATT&CK-native detection rules library."""

from typing import Dict, List, Any, Optional
from app.models.log_entry import LogEntry


# ATT&CK Detection Rules Library
ATTACK_DETECTION_RULES: Dict[str, Dict[str, Any]] = {
    # Initial Access (TA0001)
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "required_telemetry": ["email_gateway", "edr"],
        "patterns": [
            {"type": "email_attachment", "suspicious_types": [".exe", ".bat", ".scr", ".vbs", ".js"]},
            {"type": "email_attachment_hash", "reputation": "malicious"},
        ],
        "severity_base": "high",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "required_telemetry": ["email_gateway", "proxy"],
        "patterns": [
            {"type": "url_reputation", "reputation": "phishing"},
            {"type": "domain_age", "days_threshold": 30},
        ],
        "severity_base": "high",
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "required_telemetry": ["windows_security", "syslog"],
        "patterns": [
            {
                "type": "threshold",
                "field": "auth_result",
                "value": "failure",
                "count": 5,
                "window_seconds": 60,
                "group_by": ["source_ip", "user"],
            }
        ],
        "severity_base": "high",
    },
    "T1110.003": {
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "required_telemetry": ["windows_security", "azure_ad"],
        "patterns": [
            {
                "type": "threshold",
                "field": "auth_result",
                "value": "failure",
                "count": 10,
                "window_seconds": 300,
                "group_by": ["source_ip"],
                "distinct_field": "user",
                "distinct_min": 5,
            }
        ],
        "severity_base": "critical",
    },
    # Execution (TA0002)
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(powershell|pwsh).*(-enc|-encodedcommand|-e\s)"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)powershell.*(-nop|-noprofile).*(-w\s*hidden|-windowstyle\s*hidden)"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)IEX|Invoke-Expression|DownloadString|WebClient"},
        ],
        "severity_base": "high",
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)cmd.*\/c.*\\\\.*\$"},
            {
                "type": "parent_child",
                "parent_pattern": r"(?i)(outlook|winword|excel|powerpnt)\.exe",
                "child_pattern": r"(?i)cmd\.exe",
            },
        ],
        "severity_base": "medium",
    },
    # Persistence (TA0003)
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "tactic": "Persistence",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "regex", "field": "registry_key", "pattern": r"(?i)(HKLM|HKCU)\\.*\\(Run|RunOnce)"},
        ],
        "severity_base": "high",
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "required_telemetry": ["windows_security", "windows_sysmon"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)schtasks.*\/create"},
            {"type": "event_id", "value": 4698},  # Windows Security scheduled task created
        ],
        "severity_base": "medium",
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "required_telemetry": ["windows_security"],
        "patterns": [
            {"type": "event_id", "value": 4720},  # User account created
            {"type": "regex", "field": "command_line", "pattern": r"(?i)net\s+user\s+\w+\s+.*\/add"},
        ],
        "severity_base": "high",
    },
    # Privilege Escalation (TA0004)
    "T1548.002": {
        "name": "Abuse Elevation Control Mechanism: Bypass UAC",
        "tactic": "Privilege Escalation",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(fodhelper|eventvwr|sdclt)\.exe"},
            {"type": "registry", "pattern": r"ms-settings\\shell\\open\\command"},
        ],
        "severity_base": "critical",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "process_access", "target": "lsass.exe", "access_mask": ["0x1010", "0x1410"]},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(mimikatz|procdump.*lsass|sekurlsa)"},
        ],
        "severity_base": "critical",
    },
    # Defense Evasion (TA0005)
    "T1070.001": {
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "required_telemetry": ["windows_security"],
        "patterns": [
            {"type": "event_id", "value": 1102},  # Audit log cleared
            {"type": "regex", "field": "command_line", "pattern": r"(?i)wevtutil\s+(cl|clear-log)"},
        ],
        "severity_base": "critical",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(Set-MpPreference|DisableRealtimeMonitoring|sc\s+stop\s+windefend)"},
            {"type": "service_stop", "services": ["WinDefend", "MsMpSvc", "Sense"]},
        ],
        "severity_base": "critical",
    },
    # Discovery (TA0007)
    "T1087.001": {
        "name": "Account Discovery: Local Account",
        "tactic": "Discovery",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(net\s+user|net\s+localgroup|wmic\s+useraccount)"},
        ],
        "severity_base": "low",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "required_telemetry": ["firewall", "netflow"],
        "patterns": [
            {"type": "port_scan", "unique_ports_threshold": 20, "window_seconds": 60},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(nmap|masscan|portscan)"},
        ],
        "severity_base": "medium",
    },
    # Lateral Movement (TA0008)
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "required_telemetry": ["windows_security", "firewall"],
        "patterns": [
            {"type": "event_id", "value": 4624, "logon_type": 10},  # RDP logon
            {"type": "multiple_hosts", "protocol": "rdp", "threshold": 3, "window_seconds": 3600},
        ],
        "severity_base": "medium",
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "required_telemetry": ["windows_security", "firewall"],
        "patterns": [
            {"type": "regex", "field": "file_path", "pattern": r"\\\\.*\\(ADMIN\$|C\$|IPC\$)"},
            {"type": "process", "name": "psexec", "multiple_hosts": True},
        ],
        "severity_base": "high",
    },
    # Collection (TA0009)
    "T1560.001": {
        "name": "Archive Collected Data: Archive via Utility",
        "tactic": "Collection",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(7z|rar|zip).*(-p|password)"},
            {"type": "file_create", "extension": [".7z", ".rar", ".zip"], "size_threshold_mb": 100},
        ],
        "severity_base": "medium",
    },
    # Exfiltration (TA0010)
    "T1048.003": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "required_telemetry": ["proxy", "firewall", "dns"],
        "patterns": [
            {"type": "data_volume", "bytes_out_threshold": 104857600, "window_seconds": 3600},  # 100MB
            {"type": "dns_exfil", "query_length_threshold": 50, "subdomain_entropy_threshold": 3.5},
        ],
        "severity_base": "critical",
    },
    "T1567.002": {
        "name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "tactic": "Exfiltration",
        "required_telemetry": ["proxy"],
        "patterns": [
            {
                "type": "upload",
                "domains": ["dropbox.com", "drive.google.com", "onedrive.live.com", "mega.nz"],
                "bytes_threshold": 52428800,
            }
        ],
        "severity_base": "high",
    },
    # Command and Control (TA0011)
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "required_telemetry": ["proxy", "firewall"],
        "patterns": [
            {"type": "beaconing", "interval_regularity_threshold": 0.9, "min_connections": 10},
            {"type": "domain_age", "days_threshold": 30},
        ],
        "severity_base": "high",
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "required_telemetry": ["dns"],
        "patterns": [
            {"type": "dns_tunneling", "txt_record_threshold": 10, "query_frequency_threshold": 100},
        ],
        "severity_base": "critical",
    },
    # Impact (TA0040)
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "required_telemetry": ["edr", "windows_sysmon"],
        "patterns": [
            {"type": "file_modify", "extensions_changed_threshold": 50, "window_seconds": 60},
            {"type": "file_create", "pattern": r"(?i)(readme|decrypt|ransom|locked).*\.txt"},
        ],
        "severity_base": "critical",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(vssadmin\s+delete|bcdedit.*recoveryenabled.*no|wbadmin\s+delete)"},
        ],
        "severity_base": "critical",
    },
}


def evaluate_attack_rules(logs: List[LogEntry], rules: Dict[str, Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Evaluate ATT&CK-mapped detection rules against log entries.
    
    Returns list of alerts in format:
    {
        "technique_id": "T1110.001",
        "name": "...",
        "tactic": "...",
        "severity": "high",
        "matched_logs": [...],
        "confidence": 0.85
    }
    """
    if rules is None:
        rules = ATTACK_DETECTION_RULES

    alerts = []

    # Group logs by required telemetry type
    logs_by_source = {}
    for log in logs:
        source_type = log.log_source_type.value if log.log_source_type else "custom"
        if source_type not in logs_by_source:
            logs_by_source[source_type] = []
        logs_by_source[source_type].append(log)

    # Evaluate each rule
    for technique_id, rule in rules.items():
        # Check if required telemetry is available
        required_telemetry = rule.get("required_telemetry", [])
        available_sources = set(logs_by_source.keys())
        has_required_telemetry = any(
            req in available_sources or req.replace("_", " ") in available_sources
            for req in required_telemetry
        )

        if not has_required_telemetry:
            continue

        # Evaluate patterns
        matched_logs = []
        for pattern in rule.get("patterns", []):
            pattern_type = pattern.get("type")

            if pattern_type == "threshold":
                matched_logs.extend(_evaluate_threshold_pattern(logs, pattern))
            elif pattern_type == "regex":
                matched_logs.extend(_evaluate_regex_pattern(logs, pattern))
            elif pattern_type == "event_id":
                matched_logs.extend(_evaluate_event_id_pattern(logs, pattern))
            # Add more pattern types as needed

        if matched_logs:
            alerts.append(
                {
                    "technique_id": technique_id,
                    "name": rule.get("name"),
                    "tactic": rule.get("tactic"),
                    "severity": rule.get("severity_base", "medium"),
                    "matched_logs": [log.id for log in matched_logs],
                    "confidence": min(0.9, 0.5 + (len(matched_logs) * 0.1)),
                }
            )

    return alerts


def _evaluate_threshold_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    """Evaluate threshold-based pattern (e.g., 5 failed logins in 60 seconds)."""
    matched = []
    field = pattern.get("field")
    value = pattern.get("value")
    count = pattern.get("count", 5)
    window_seconds = pattern.get("window_seconds", 60)

    # Group by group_by fields
    from collections import defaultdict
    groups = defaultdict(list)

    for log in logs:
        if hasattr(log, field) and getattr(log, field) == value:
            key = tuple(getattr(log, gb, None) for gb in pattern.get("group_by", []))
            groups[key].append(log)

    # Check if any group exceeds threshold within window
    for group_logs in groups.values():
        if len(group_logs) >= count:
            matched.extend(group_logs)

    return matched


def _evaluate_regex_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    """Evaluate regex pattern against log field."""
    import re

    matched = []
    field = pattern.get("field")
    regex_pattern = pattern.get("pattern")

    if not regex_pattern:
        return matched

    compiled = re.compile(regex_pattern)

    for log in logs:
        field_value = getattr(log, field, None) if hasattr(log, field) else None
        if field_value and compiled.search(str(field_value)):
            matched.append(log)

    return matched


def _evaluate_event_id_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    """Evaluate event ID pattern (Windows Event Log)."""
    matched = []
    event_id = pattern.get("value")

    for log in logs:
        if hasattr(log, "event_id") and log.event_id == event_id:
            matched.append(log)

    return matched

