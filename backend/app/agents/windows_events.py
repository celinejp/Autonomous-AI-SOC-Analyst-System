"""Parsers for real Windows / Sysmon / PowerShell events.

Two shapes are handled: the Windows event XML (`<Event xmlns=...>` - what `wevtutil`, Splunk's
XmlWinEventLog and the public attack datasets contain) and flat JSON events with EventID/Channel
keys (what winlogbeat / NXLog export). Both are reduced to the same field dict and turned into a
LogEntry, so the ATT&CK rules read the same fields regardless of how the event arrived.
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, Optional

from app.core.time_utils import parse_iso_timestamp_naive
from app.models.log_entry import LogEntry, LogSource, LogSourceType

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")

_SYSMON_ACTIONS = {
    1: "process_create", 3: "network_connect", 7: "image_load", 8: "create_remote_thread",
    10: "process_access", 11: "file_create", 12: "registry_event", 13: "registry_event",
    14: "registry_event", 15: "file_stream", 17: "pipe_event", 18: "pipe_event", 22: "dns_query",
}
_SECURITY_ACTIONS = {
    4624: "login_success", 4625: "login_failed", 4688: "process_create", 4698: "scheduled_task_created",
    4720: "account_created", 1102: "audit_log_cleared", 4697: "service_installed", 7045: "service_installed",
}
_EMPTY = {"", "-", "(null)", "null"}


def _clean(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in _EMPTY else text


def _timestamp(value: Optional[str]) -> datetime:
    if value:
        try:
            return parse_iso_timestamp_naive(_FRACTION_RE.sub(r"\1", value.replace(" ", "T", 1)))
        except ValueError:
            pass
    return datetime.utcnow()


def parse_event_xml(raw: str) -> Optional[Dict[str, Any]]:
    """`<Event>` XML -> flat dict (EventID, Provider, Channel, Computer, SystemTime + EventData names)."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    system = root.find(f"{_NS}System")
    if system is None:
        return None
    fields: Dict[str, Any] = {}
    provider = system.find(f"{_NS}Provider")
    fields["Provider"] = provider.get("Name") if provider is not None else None
    for tag in ("EventID", "Channel", "Computer"):
        el = system.find(f"{_NS}{tag}")
        fields[tag] = el.text if el is not None else None
    created = system.find(f"{_NS}TimeCreated")
    fields["SystemTime"] = created.get("SystemTime") if created is not None else None
    data = root.find(f"{_NS}EventData")
    if data is not None:
        for item in data.findall(f"{_NS}Data"):
            if item.get("Name"):
                fields[item.get("Name")] = item.text
    return fields


def entry_from_fields(fields: Dict[str, Any], raw: str) -> Optional[LogEntry]:
    """Build a LogEntry from a flat Windows event dict."""
    try:
        event_id = int(str(fields.get("EventID")).strip())
    except (TypeError, ValueError):
        return None
    provider = str(fields.get("Provider") or fields.get("ProviderName") or "")
    channel = str(fields.get("Channel") or "")
    get = lambda k: _clean(fields.get(k))  # noqa: E731

    is_sysmon = "sysmon" in provider.lower() or "sysmon" in channel.lower()
    is_powershell = "powershell" in provider.lower() or "powershell" in channel.lower()
    is_security = "security" in provider.lower() or channel.lower() == "security"

    source_type = (LogSourceType.WINDOWS_SYSMON if is_sysmon
                   else LogSourceType.WINDOWS_SECURITY if is_security else LogSourceType.EDR)
    source = LogSource.AUTH if event_id in (4624, 4625) else LogSource.SYSTEM
    action = _SYSMON_ACTIONS.get(event_id, "sysmon_event") if is_sysmon else _SECURITY_ACTIONS.get(event_id, "windows_event")
    status = "failure" if event_id == 4625 else "success"

    image = get("Image") or get("NewProcessName") or get("SourceImage") or get("Application")
    command_line = get("CommandLine")
    if is_powershell and event_id in (4103, 4104):
        # Script-block logging: the "command line" is the script text itself.
        command_line = get("ScriptBlockText") or get("Payload") or command_line
        image = image or "powershell.exe"
        action = "powershell_script_block"
    if event_id in (4698, 4702):
        command_line = command_line or get("TaskContent") or get("TaskContentNew")
    if event_id in (7045, 4697):  # new service: the service binary is what matters
        command_line = command_line or get("ImagePath") or get("ServiceFileName")

    logon_type = get("LogonType")
    metadata: Dict[str, Any] = {k: v for k, v in fields.items() if k in
                                ("SourceImage", "TargetImage", "GrantedAccess", "CallTrace", "Hashes", "TaskName", "Details")}
    metadata["provider"] = provider
    if logon_type and logon_type.isdigit():
        metadata["logon_type"] = int(logon_type)

    source_ip = get("SourceIp") or get("IpAddress") or get("SourceAddress") or "unknown"
    return LogEntry(
        timestamp=_timestamp(fields.get("SystemTime") or fields.get("UtcTime")),
        source_ip=source_ip,
        destination_ip=get("DestinationIp") or get("DestAddress"),
        destination_port=int(get("DestinationPort") or get("DestPort")) if (get("DestinationPort") or get("DestPort") or "").isdigit() else None,
        user=get("TargetUserName") or get("SubjectUserName") or get("User"),
        action=action,
        status=status,
        log_source=source,
        log_source_type=source_type,
        event_id=event_id,
        process_name=image,
        parent_process_name=get("ParentImage") or get("ParentProcessName"),
        command_line=command_line,
        file_path=get("TargetFilename"),
        registry_key=get("TargetObject"),
        dns_query=get("QueryName"),
        auth_result="failure" if event_id == 4625 else ("success" if event_id == 4624 else None),
        metadata=metadata,
        raw_log=raw,
    )


def parse_windows_event_xml(raw: str) -> Optional[LogEntry]:
    fields = parse_event_xml(raw)
    return entry_from_fields(fields, raw) if fields else None


def looks_like_windows_json(log_data: Dict[str, Any]) -> bool:
    return "EventID" in log_data and any(k in log_data for k in ("Channel", "ProviderName", "Provider"))


# ---- Splunk / Event Viewer style text blocks: "LogName=... EventCode=... Message=..." -------------
_TEXT_HEADER_RE = re.compile(r"^\s*(\d{2})/(\d{2})/(\d{4}) (\d{2}):(\d{2}):(\d{2}) ([AP]M)")
TEXT_EVENT_START_RE = re.compile(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M\s*$")


def _text_field(raw: str, label: str, last: bool = False) -> Optional[str]:
    hits = re.findall(rf"^\s*{re.escape(label)}:[ \t]*(.*?)\s*$", raw, re.MULTILINE)
    hits = [h for h in hits if h not in _EMPTY]
    if not hits:
        return None
    return hits[-1] if last else hits[0]


def looks_like_text_event(raw: str) -> bool:
    return "LogName=" in raw and "EventCode=" in raw


def parse_windows_text_event(raw: str) -> Optional[LogEntry]:
    """One multi-line Windows event block (Splunk WinEventLog / Event Viewer text) -> LogEntry."""
    code = re.search(r"^EventCode=(\d+)", raw, re.MULTILINE)
    log_name = re.search(r"^LogName=(.+)$", raw, re.MULTILINE)
    if not code:
        return None
    m = _TEXT_HEADER_RE.match(raw)
    ts = None
    if m:
        mo, d, y, hh, mi, ss, ap = m.groups()
        hour = int(hh) % 12 + (12 if ap == "PM" else 0)
        ts = f"{y}-{mo}-{d}T{hour:02d}:{mi}:{ss}"
    event_id = int(code.group(1))
    channel = (log_name.group(1) if log_name else "").strip()
    fields: Dict[str, Any] = {
        "EventID": event_id, "Channel": channel, "Provider": channel, "SystemTime": ts,
        "LogonType": _text_field(raw, "Logon Type"),
        "SourceImage": None,
    }
    fields["IpAddress"] = _text_field(raw, "Source Network Address")
    if event_id in (4624, 4625, 4720, 4738):  # the *last* "Account Name" is the account acted on
        fields["TargetUserName"] = _text_field(raw, "Account Name", last=True)
    else:
        fields["SubjectUserName"] = _text_field(raw, "Account Name")
    fields["NewProcessName"] = _text_field(raw, "New Process Name")
    fields["ParentProcessName"] = _text_field(raw, "Creator Process Name")
    fields["CommandLine"] = _text_field(raw, "Process Command Line")
    fields["TaskName"] = _text_field(raw, "Task Name")
    if event_id in (4698, 4702):
        fields["TaskContent"] = raw.split("Task Content:", 1)[-1].strip() if "Task Content:" in raw else None
    if "powershell" in channel.lower() and event_id in (4103, 4104):
        body = raw.split("Message=", 1)[-1]
        body = re.sub(r"^Creating Scriptblock text \(\d+ of \d+\):\s*", "", body.strip())
        fields["ScriptBlockText"] = body.split("ScriptBlock ID:")[0].strip()
    fields["Provider"] = "Microsoft-Windows-Security-Auditing" if channel.lower() == "security" else channel
    return entry_from_fields(fields, raw)
