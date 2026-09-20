"""ATT&CK-native detection rules library."""

import ipaddress
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from app.core.logging import get_logger
from app.models.log_entry import LogEntry

logger = get_logger(__name__)


# ATT&CK Detection Rules Library
ATTACK_DETECTION_RULES: Dict[str, Dict[str, Any]] = {
    # Initial Access (TA0001)
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "required_telemetry": ["email_gateway", "edr"],
        "patterns": [
            {"type": "email_attachment", "suspicious_types": [".exe", ".bat", ".scr", ".vbs", ".js", ".docm", ".xlsm", ".pptm", ".iso", ".lnk"]},
            # A verdict the mail gateway / sandbox already wrote into the log line
            # (e.g. attachment_verdict=malicious_macro). No external lookup is done here.
            {"type": "email_attachment_hash", "reputation": "malicious"},
            # Endpoint evidence that an opened attachment executed: an Office app spawning a shell/script host.
            {"type": "parent_child", "parent_pattern": r"(?i)(winword|excel|powerpnt|outlook|msaccess)\.exe",
             "child_pattern": r"(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|msdt)\.exe"},
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
            {"type": "registry", "pattern": r"(?i)\\CurrentVersion\\(Run|RunOnce|RunServices)(Ex)?\\|\\Winlogon\\(Userinit|Shell)\b",
             "details_pattern": r"(?i)\\Temp\\|\\ProgramData\\|\\Users\\Public\\|powershell|cmd(\.exe)?\s|wscript|cscript|mshta|rundll32|regsvr32|https?://|\.(bat|vbs|js|ps1|hta)\b"},
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
            {"type": "regex", "field": "command_line", "pattern": r"(?i)net1?\s+(user|localgroup)\s+.*/add"},
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
            {"type": "registry", "pattern": r"(?i)[\\_]Classes\\(ms-settings|mscfile|exefile|Folder)\\shell\\open\\command"},
        ],
        "severity_base": "critical",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "process_access", "target": "lsass.exe", "access_mask": ["0x1010", "0x1410"]},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(mimikatz|sekurlsa|(procdump|createdump|dump)\S*\s.*lsass|lsass\S*\.dmp|comsvcs(\.dll)?[,\s]+#?(minidump|24)|rundll32.*comsvcs)"},
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
            {"type": "event_id", "value": 104, "provider": "eventlog"},  # System/Application log cleared
            {"type": "regex", "field": "command_line", "pattern": r"(?i)wevtutil\s+(cl|clear-log)"},
        ],
        "severity_base": "critical",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)((Set|Add)-MpPreference|DisableRealtimeMonitoring|sc(\.exe)?\s+(stop|config)\s+windefend|netsh\s+advfirewall\s+set\s+\S+\s+state\s+off)"},
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
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(net1?\s+(user|localgroup|group)|wmic\s+useraccount)", "min_count": 3, "window_seconds": 600},
        ],
        "severity_base": "low",
    },
    # Lateral Movement (TA0008)
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "required_telemetry": ["windows_security", "firewall"],
        "patterns": [
            {"type": "event_id", "value": 4624, "logon_type": 10},  # RDP logon
            {"type": "regex", "field": "command_line", "pattern": r"(?i)mstsc(\.exe)?\"?\s+.*?/v:"},  # RDP client launched
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
            {"type": "regex", "field": "command_line", "pattern": r"\\\\[^\s\\]+\\(ADMIN\$|C\$|IPC\$)"},
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
            {"type": "dns_exfil", "query_length_threshold": 50, "subdomain_entropy_threshold": 3.5, "min_queries": 3},
            # nslookup carrying encoded data; WebDAV upload via davclnt.dll
            {"type": "regex", "field": "command_line", "pattern": r"(?i)nslookup(\.exe)?\s+(-\S+\s+)*[A-Za-z0-9+/=_-]{16,}\b"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)davclnt\.dll,\s*DavSetCookie"},
        ],
        "severity_base": "critical",
    },
    # Command and Control (TA0011)
    # Impact (TA0040)
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "required_telemetry": ["windows_sysmon", "edr"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(vssadmin(\.exe)?\s+delete|wmic.*shadowcopy.*delete|Win32_ShadowCopy.*Delete|bcdedit.*recoveryenabled.*no|wbadmin\s+delete)"},
        ],
        "severity_base": "critical",
    },
    # Techniques below were added after testing on public attack data (Splunk attack_data).
    "T1218.011": {
        "name": "System Binary Proxy Execution: Rundll32",
        "tactic": "Defense Evasion",
        "required_telemetry": ["windows_sysmon", "windows_security"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)rundll32(\.exe)?\"?\s+(javascript:|vbscript:|\\\\)"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)rundll32(\.exe)?\"?\s+\S*\\(temp|appdata|programdata|users\\public)\\"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)rundll32(\.exe)?\"?\s+[^\s,]+\.(?!dll\b)[a-z0-9]{1,5}\s*,"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)rundll32(\.exe)?\"?\s+\S+,\s*#\d+"},  # export called by ordinal
        ],
        "severity_base": "medium",
    },
    "T1218.005": {
        "name": "System Binary Proxy Execution: Mshta",
        "tactic": "Defense Evasion",
        "required_telemetry": ["windows_sysmon", "windows_security"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)mshta(\.exe)?\"?\s+(.*(https?://|javascript:|vbscript:)|\S+\.hta)"},
        ],
        "severity_base": "high",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "required_telemetry": ["windows_sysmon", "windows_security"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)certutil(\.exe)?\"?\s+.*-(urlcache|verifyctl)"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)bitsadmin(\.exe)?\"?\s+.*/transfer|Start-BitsTransfer"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)\b(curl|wget)(\.exe)?\"?\s+(?=.*https?://)(?=.*(-o\s|-O\b|--output|>\s*\S))"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(Invoke-WebRequest|\biwr\b)(?=.*-OutFile)"},
        ],
        "severity_base": "medium",
    },
    "T1543.003": {
        "name": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence",
        "required_telemetry": ["windows_system", "windows_security"],
        "patterns": [
            # A new service whose binary is in a user-writable path, runs a shell, or is a remote share (events 7045 / 4697)
            {"type": "regex", "field": "command_line", "event_ids": [7045, 4697], "pattern": r"(?i)(\\(temp|appdata|programdata|users\\public)\\|%comspec%|\bcmd(\.exe)?\s+/c|powershell|\\\\[^\s\\]+\\|\\admin\$|psexesvc|remcom)"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)\bsc(\.exe)?\s+create\b|New-Service\b"},
        ],
        "severity_base": "high",
    },
    "T1003.002": {
        "name": "OS Credential Dumping: Security Account Manager",
        "tactic": "Credential Access",
        "required_telemetry": ["windows_sysmon", "windows_security"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)reg(\.exe)?\"?\s+save\s+\S*\b(sam|system|security)\b"},
            {"type": "regex", "field": "command_line", "pattern": r"(?i)(esentutl|ntdsutil|vssadmin)\S*\s.*\b(sam|ntds)\b|\\config\\sam\b"},
        ],
        "severity_base": "critical",
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "required_telemetry": ["windows_sysmon", "windows_security"],
        "patterns": [
            {"type": "regex", "field": "command_line", "pattern": r"(?i)wmic(\.exe)?\"?\s+.*(process\s+call\s+create|/node:)|Invoke-(Cim|Wmi)Method|Win32_Process.*Create"},
        ],
        "severity_base": "medium",
    },
}


# --------------------------------------------------------------------------------------
# Rule evaluation
#
# Every pattern "type" used in ATTACK_DETECTION_RULES needs an evaluator here (tests/test_attack_rules.py
# checks this). `required_telemetry` is documentation only: evaluators read concrete LogEntry fields and
# find nothing when a field is absent.
# --------------------------------------------------------------------------------------

_EPOCH = datetime(1970, 1, 1)


def _ts(log: LogEntry):
    return log.timestamp or _EPOCH


def _meta(log: LogEntry, key: str, default: Any = None) -> Any:
    return (log.metadata or {}).get(key, default)


def _dest_host(log: LogEntry) -> Optional[str]:
    return log.destination_ip or _meta(log, "dhost") or _meta(log, "dest_host") or _meta(log, "host")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _windows(ordered: List[LogEntry], window: timedelta):
    """Yield each sliding time window (as a list) over logs already sorted by time."""
    start = 0
    for end in range(len(ordered)):
        while _ts(ordered[end]) - _ts(ordered[start]) > window:
            start += 1
        yield ordered[start:end + 1]


def _evaluate_threshold_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    """N matching events inside a time window, grouped by fields (e.g. 5 failed logins
    from one IP+user in 60 s). Optional distinct_field/distinct_min turns it into
    password-spraying logic (many different users from one source)."""
    matched: List[LogEntry] = []
    field = pattern.get("field")
    value = pattern.get("value")
    count = pattern.get("count", 5)
    window = timedelta(seconds=pattern.get("window_seconds", 60))
    distinct_field = pattern.get("distinct_field")
    distinct_min = pattern.get("distinct_min", 0)

    groups: Dict[tuple, List[LogEntry]] = defaultdict(list)
    for log in logs:
        if getattr(log, field, None) == value:
            key = tuple(getattr(log, gb, None) for gb in pattern.get("group_by", []))
            groups[key].append(log)

    for group_logs in groups.values():
        ordered = sorted(group_logs, key=_ts)
        for win in _windows(ordered, window):
            if len(win) < count:
                continue
            if distinct_field:
                distinct = {getattr(l, distinct_field, None) for l in win} - {None}
                if len(distinct) < distinct_min:
                    continue
            matched.extend(ordered)
            break
    return matched


def _evaluate_regex_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    compiled = re.compile(pattern["pattern"]) if pattern.get("pattern") else None
    field = pattern.get("field")
    if not compiled:
        return []
    event_ids = pattern.get("event_ids")  # optionally restrict the pattern to specific Windows event IDs
    out = [log for log in logs
           if (not event_ids or log.event_id in event_ids)
           and getattr(log, field, None) and compiled.search(str(getattr(log, field)))]
    min_count = pattern.get("min_count", 1)
    if min_count > 1:  # e.g. one `net user` is routine admin work; several discovery commands together are not
        window = timedelta(seconds=pattern.get("window_seconds", 600))
        for win in _windows(sorted(out, key=_ts), window):
            if len(win) >= min_count:
                return out
        return []
    return out


def _evaluate_event_id_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    event_id = pattern.get("value")
    logon_type = pattern.get("logon_type")
    out = []
    for log in logs:
        if log.event_id != event_id:
            continue
        if logon_type is not None and _meta(log, "logon_type") != logon_type:
            continue
        provider = pattern.get("provider")
        if provider and provider not in str(_meta(log, "provider", "")).lower():
            continue
        out.append(log)
    return out


def _evaluate_parent_child_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    parent_re = re.compile(pattern["parent_pattern"])
    child_re = re.compile(pattern["child_pattern"])
    return [
        l for l in logs
        if l.parent_process_name and parent_re.search(l.parent_process_name)
        and (child_re.search(l.process_name or "") or child_re.search(l.command_line or ""))
    ]


def _evaluate_process_access_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    """Sysmon event 10 style: some process opens `target` with a suspicious access mask."""
    target = pattern["target"].lower()
    masks = {m.lower() for m in pattern.get("access_mask", [])}
    out = []
    for log in logs:
        raw = (log.raw_log or "").lower()
        tgt = str(_meta(log, "TargetImage") or "").lower()
        if not (target in tgt or re.search(r"targetimage\W+\S*" + re.escape(target), raw)):
            continue
        granted = str(_meta(log, "GrantedAccess") or "").lower()
        if not granted:
            m = re.search(r"grantedaccess\W+(0x[0-9a-f]+)", raw)
            granted = m.group(1) if m else ""
        if not masks or granted in masks:
            out.append(log)
    return out


def _evaluate_registry_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    """Registry key matches; if the pattern has `details_pattern` and the event carries the written
    value, the value must match too (an updater's Run key pointing into Program Files is routine)."""
    compiled = re.compile(pattern["pattern"])
    details_re = re.compile(pattern["details_pattern"]) if pattern.get("details_pattern") else None
    out = []
    for log in logs:
        if not (compiled.search(log.registry_key or "") or compiled.search(log.raw_log or "")):
            continue
        details = _meta(log, "Details")
        if details_re and details and not details_re.search(str(details)):
            continue
        out.append(log)
    return out


def _evaluate_service_stop_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    names = "|".join(re.escape(s) for s in pattern.get("services", []))
    compiled = re.compile(rf"(?i)(sc(\.exe)?\s+(stop|config)|net\s+stop|Stop-Service)\s+[\"']?({names})")
    return [l for l in logs if compiled.search(l.command_line or "") or compiled.search(l.raw_log or "")]


def _is_rdp(log: LogEntry) -> bool:
    return (
        log.destination_port == 3389
        or _meta(log, "logon_type") == 10
        or bool(re.search(r"(?i)\brdp\b|remote\s?desktop|RemoteInteractive|mstsc", log.raw_log or ""))
    )


def _evaluate_multiple_hosts_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    """One source reaching several different hosts over a protocol inside a window."""
    if pattern.get("protocol") != "rdp":
        return []
    threshold = pattern.get("threshold", 3)
    window = timedelta(seconds=pattern.get("window_seconds", 3600))
    by_src: Dict[str, List[LogEntry]] = defaultdict(list)
    for log in logs:
        if _is_rdp(log) and _dest_host(log):
            by_src[log.source_ip].append(log)
    matched: List[LogEntry] = []
    for ls in by_src.values():
        ordered = sorted(ls, key=_ts)
        for win in _windows(ordered, window):
            if len({_dest_host(l) for l in win}) >= threshold:
                matched.extend(ordered)
                break
    return matched


def _evaluate_process_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    """A named tool (e.g. psexec) used against more than one host."""
    name = pattern["name"].lower()
    hits = [
        l for l in logs
        if name in (l.process_name or "").lower() or name in (l.command_line or "").lower()
        or name in (l.raw_log or "").lower()
    ]
    if pattern.get("multiple_hosts") and len({_dest_host(l) for l in hits} - {None}) < 2:
        return []
    return hits


def _is_internal(ip: Optional[str]) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _evaluate_data_volume_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    """Large outbound volume from one source. Transfers to a private/internal destination
    (backups, file servers) are not exfiltration and are skipped when the destination is known."""
    threshold = pattern.get("bytes_out_threshold", 104857600)
    by_src: Dict[str, List[LogEntry]] = defaultdict(list)
    for log in logs:
        if log.bytes_out and not _is_internal(log.destination_ip):
            by_src[log.source_ip].append(log)
    matched: List[LogEntry] = []
    for ls in by_src.values():
        if sum(l.bytes_out for l in ls) >= threshold:
            matched.extend(ls)
    return matched


def _long_random_queries(logs: List[LogEntry], length: int, entropy: float, min_queries: int) -> List[LogEntry]:
    """DNS queries whose left-most label is long and random-looking, repeated against one
    parent domain - the shape of DNS tunnelling / exfiltration."""
    by_domain: Dict[str, List[LogEntry]] = defaultdict(list)
    for log in logs:
        q = (log.dns_query or "").rstrip(".")
        parts = q.split(".")
        if len(parts) < 2:
            continue
        label = parts[0]
        if len(label) >= length and _entropy(label) >= entropy:
            by_domain[".".join(parts[-2:])].append(log)
    matched: List[LogEntry] = []
    for ls in by_domain.values():
        if len(ls) >= min_queries:
            matched.extend(ls)
    return matched


def _evaluate_dns_exfil_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    # query_length_threshold is the whole query length; use it as a per-label floor / 2.
    return _long_random_queries(
        logs, max(20, pattern.get("query_length_threshold", 50) // 2),
        pattern.get("subdomain_entropy_threshold", 3.5), pattern.get("min_queries", 3),
    )


def _evaluate_email_attachment_pattern(logs: List[LogEntry], pattern: Dict[str, Any]) -> List[LogEntry]:
    suspicious = tuple(pattern.get("suspicious_types", []))
    return [
        l for l in logs
        if any(name.lower().endswith(suspicious) for name in (l.attachment_names or []))
    ]


def _evaluate_verdict_pattern(logs: List[LogEntry], pattern: Dict[str, Any], keys: str) -> List[LogEntry]:
    """Match a verdict/reputation value that the log source itself reported."""
    word = pattern.get("reputation", "malicious")
    compiled = re.compile(rf"(?i)\b(?:{keys})\w*[=:]\s*\"?[\w-]*{re.escape(word)}")
    return [l for l in logs if compiled.search(l.raw_log or "")]


_EVALUATORS: Dict[str, Callable[[List[LogEntry], Dict[str, Any]], List[LogEntry]]] = {
    "threshold": _evaluate_threshold_pattern,
    "regex": _evaluate_regex_pattern,
    "event_id": _evaluate_event_id_pattern,
    "parent_child": _evaluate_parent_child_pattern,
    "process_access": _evaluate_process_access_pattern,
    "registry": _evaluate_registry_pattern,
    "service_stop": _evaluate_service_stop_pattern,
    "multiple_hosts": _evaluate_multiple_hosts_pattern,
    "process": _evaluate_process_pattern,
    "data_volume": _evaluate_data_volume_pattern,
    "dns_exfil": _evaluate_dns_exfil_pattern,
    "email_attachment": _evaluate_email_attachment_pattern,
    "email_attachment_hash": lambda logs, p: _evaluate_verdict_pattern(logs, p, "attachment_verdict|verdict|av_result"),
}

SUPPORTED_PATTERN_TYPES = frozenset(_EVALUATORS)


def evaluate_attack_rules(logs: List[LogEntry], rules: Dict[str, Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Evaluate the ATT&CK-mapped rules against parsed log entries.

    Returns one dict per technique that matched:
    {"technique_id", "name", "tactic", "severity", "matched_logs" (positions in `logs`),
     "confidence"}
    """
    if rules is None:
        rules = ATTACK_DETECTION_RULES

    # LogEntry.id is never populated during ingest - reference matched logs by their
    # position in `logs`, like every other alert path in detection_agent.py.
    positions = {id(log): i for i, log in enumerate(logs)}
    alerts: List[Dict[str, Any]] = []

    for technique_id, rule in rules.items():
        matched: Dict[int, LogEntry] = {}
        for pattern in rule.get("patterns", []):
            evaluator = _EVALUATORS.get(pattern.get("type"))
            if evaluator is None:
                logger.warning("attack_rules: unsupported pattern type %r in %s", pattern.get("type"), technique_id)
                continue
            for log in evaluator(logs, pattern):
                matched[positions[id(log)]] = log
        if matched:
            alerts.append({
                "technique_id": technique_id,
                "name": rule.get("name"),
                "tactic": rule.get("tactic"),
                "severity": rule.get("severity_base", "medium"),
                "matched_logs": [str(i) for i in sorted(matched)],
                "confidence": min(0.9, 0.5 + (len(matched) * 0.1)),
            })
    return alerts
