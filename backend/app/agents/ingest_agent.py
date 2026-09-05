"""Ingest Agent - Parses and normalizes security logs."""

import json
import re
from datetime import datetime
from typing import Any, Dict, List

from app.agents.base import BaseAgent
from app.models.agent_state import AgentState
from app.models.log_entry import LogEntry, LogFormat, LogSource, LogSourceType

SYSTEM_PROMPT = """You are a security log ingestion agent. Your role is to parse and normalize security logs from various sources into a unified schema.

You receive raw log entries and must extract:
- timestamp
- source_ip
- destination_ip (if present)
- destination_port (if present)
- user (if present)
- action (what happened - e.g., "login_attempt", "dns_query", "http_request")
- status (success, failure, etc.)
- log_source (dns, auth, http, system)

Output a JSON array of normalized log entries. Be precise and extract all available information."""


async def ingest_agent(state: AgentState) -> AgentState:
    """Parse and normalize raw logs."""
    _started_at = datetime.utcnow()
    raw_logs = state.get("raw_logs", [])
    if not raw_logs:
        state["logs"] = []
        return state

    normalized_logs = []
    
    for raw_log in raw_logs:
        try:
            # Try JSON first
            try:
                log_data = json.loads(raw_log)
                
                # Check for cloud log formats
                if "eventSource" in log_data or "eventName" in log_data:
                    log_entry = parse_cloudtrail_log(log_data)
                elif "callerIpAddress" in log_data or "operationName" in log_data:
                    log_entry = parse_azure_activity_log(log_data)
                elif "protoPayload" in log_data or "methodName" in log_data:
                    log_entry = parse_gcp_audit_log(log_data)
                else:
                    log_entry = _parse_json_log(log_data, raw_log)
            except json.JSONDecodeError:
                # Try syslog format
                log_entry = _parse_syslog_log(raw_log)
            
            if log_entry:
                normalized_logs.append(log_entry)
        except Exception as e:
            # Skip malformed logs but log the error
            continue

    state["logs"] = normalized_logs
    state["agent_execution_log"].append({
        "agent_name": "ingest",
        "timestamp": datetime.utcnow().isoformat(),
        "duration_ms": (datetime.utcnow() - _started_at).total_seconds() * 1000,
        "output_data": {"input_count": len(raw_logs), "output_count": len(normalized_logs)},
    })
    
    return state


def _parse_json_log(log_data: Dict[str, Any], raw_log: str) -> LogEntry:
    """Parse JSON formatted log."""
    # Extract timestamp
    timestamp_str = log_data.get("timestamp") or log_data.get("time") or log_data.get("@timestamp")
    if isinstance(timestamp_str, str):
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    else:
        timestamp = datetime.utcnow()
    
    # Determine log source
    source = LogSource.SYSTEM
    if "dns" in raw_log.lower() or "query" in raw_log.lower():
        source = LogSource.DNS
    elif "auth" in raw_log.lower() or "login" in raw_log.lower() or "ssh" in raw_log.lower():
        source = LogSource.AUTH
    elif "http" in raw_log.lower() or "request" in raw_log.lower():
        source = LogSource.HTTP
    
    # Detect cloud log types
    log_source_type = None
    if "eventSource" in log_data or "eventName" in log_data or "awsRegion" in log_data:
        log_source_type = LogSourceType.CLOUD_TRAIL
    elif "callerIpAddress" in log_data or "operationName" in log_data or "resourceId" in log_data:
        log_source_type = LogSourceType.AZURE_MONITOR
    elif "protoPayload" in log_data or "methodName" in log_data:
        log_source_type = LogSourceType.GCP_LOGGING
    
    return LogEntry(
        timestamp=timestamp,
        source_ip=log_data.get("source_ip") or log_data.get("src_ip") or log_data.get("ip") or log_data.get("sourceIPAddress") or log_data.get("callerIpAddress") or "unknown",
        destination_ip=log_data.get("destination_ip") or log_data.get("dest_ip") or log_data.get("dst_ip"),
        destination_port=log_data.get("destination_port") or log_data.get("dest_port") or log_data.get("port"),
        user=log_data.get("user") or log_data.get("username") or log_data.get("user_name") or log_data.get("userIdentity", {}).get("userName") if isinstance(log_data.get("userIdentity"), dict) else None,
        action=log_data.get("action") or log_data.get("event") or log_data.get("type") or log_data.get("eventName") or log_data.get("operationName", {}).get("value") if isinstance(log_data.get("operationName"), dict) else "unknown",
        status=log_data.get("status") or log_data.get("result") or ("success" if not log_data.get("errorCode") else "failure") or "unknown",
        log_source=source,
        log_source_type=log_source_type,
        raw_log=raw_log,
        metadata=log_data,
        # Cloud-specific fields
        aws_region=log_data.get("awsRegion"),
        aws_account=log_data.get("accountId"),
        azure_tenant=log_data.get("tenantId"),
        gcp_project=log_data.get("resource", {}).get("labels", {}).get("project_id") if isinstance(log_data.get("resource"), dict) else None,
        resource=log_data.get("resourceId") or log_data.get("resourceName") or log_data.get("resourceArn"),
        user_agent=log_data.get("userAgent"),
        http_method=log_data.get("httpMethod") or log_data.get("requestParameters", {}).get("httpMethod") if isinstance(log_data.get("requestParameters"), dict) else None,
        http_path=log_data.get("path") or log_data.get("requestParameters", {}).get("path") if isinstance(log_data.get("requestParameters"), dict) else None,
        command_line=log_data.get("commandLine"),
        process_name=log_data.get("processName") or log_data.get("Image"),
        file_path=log_data.get("filePath") or log_data.get("TargetFilename"),
        registry_key=log_data.get("registryKey") or log_data.get("TargetObject"),
    )


def parse_cloudtrail_log(log_entry: dict) -> LogEntry:
    """Parse AWS CloudTrail log format."""
    timestamp_str = log_entry.get("eventTime")
    if timestamp_str:
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    else:
        timestamp = datetime.utcnow()
    
    source = LogSource.SYSTEM
    if "s3" in log_entry.get("eventSource", "").lower() or "lambda" in log_entry.get("eventSource", "").lower():
        source = LogSource.HTTP
    
    user_identity = log_entry.get("userIdentity", {})
    
    return LogEntry(
        timestamp=timestamp,
        source_ip=log_entry.get("sourceIPAddress", "unknown"),
        user=user_identity.get("userName") or user_identity.get("arn"),
        action=log_entry.get("eventName", "unknown"),
        resource=log_entry.get("requestParameters", {}).get("resourceArn") if isinstance(log_entry.get("requestParameters"), dict) else None,
        status="success" if not log_entry.get("errorCode") else "failure",
        log_source=source,
        log_source_type=LogSourceType.CLOUD_TRAIL,
        raw_log=json.dumps(log_entry),
        aws_region=log_entry.get("awsRegion"),
        aws_account=log_entry.get("recipientAccountId") or log_entry.get("accountId"),
        user_agent=log_entry.get("userAgent"),
        http_method=log_entry.get("requestParameters", {}).get("httpMethod") if isinstance(log_entry.get("requestParameters"), dict) else None,
        metadata=log_entry,
    )


def parse_azure_activity_log(log_entry: dict) -> LogEntry:
    """Parse Azure Activity Log format."""
    timestamp_str = log_entry.get("time")
    if timestamp_str:
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    else:
        timestamp = datetime.utcnow()
    
    operation_name = log_entry.get("operationName", {})
    if isinstance(operation_name, dict):
        action = operation_name.get("value", "unknown")
    else:
        action = str(operation_name)
    
    return LogEntry(
        timestamp=timestamp,
        source_ip=log_entry.get("callerIpAddress", "unknown"),
        user=log_entry.get("caller"),
        action=action,
        resource=log_entry.get("resourceId"),
        status=log_entry.get("status", {}).get("value", "unknown") if isinstance(log_entry.get("status"), dict) else "unknown",
        log_source=LogSource.SYSTEM,
        log_source_type=LogSourceType.AZURE_MONITOR,
        raw_log=json.dumps(log_entry),
        azure_tenant=log_entry.get("tenantId"),
        metadata=log_entry,
    )


def parse_gcp_audit_log(log_entry: dict) -> LogEntry:
    """Parse GCP Audit Log format."""
    timestamp_str = log_entry.get("timestamp")
    if timestamp_str:
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    else:
        timestamp = datetime.utcnow()
    
    proto_payload = log_entry.get("protoPayload", {})
    request_metadata = proto_payload.get("requestMetadata", {})
    auth_info = proto_payload.get("authenticationInfo", {})
    
    return LogEntry(
        timestamp=timestamp,
        source_ip=request_metadata.get("callerIp", "unknown"),
        user=auth_info.get("principalEmail"),
        action=proto_payload.get("methodName", "unknown"),
        resource=proto_payload.get("resourceName"),
        status="success" if proto_payload.get("status", {}).get("code") == 0 else "failure",
        log_source=LogSource.SYSTEM,
        log_source_type=LogSourceType.GCP_LOGGING,
        raw_log=json.dumps(log_entry),
        gcp_project=log_entry.get("resource", {}).get("labels", {}).get("project_id") if isinstance(log_entry.get("resource"), dict) else None,
        user_agent=request_metadata.get("callerSuppliedUserAgent"),
        metadata=log_entry,
    )


_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

_CEF_HEADER_RE = re.compile(
    r'CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|'
    r'(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extension>.*)$'
)
_CEF_KV_RE = re.compile(r'(\w+)=([^=]*?)(?=\s+\w+=|$)')

_WINDOWS_MARKER_RE = re.compile(r'Security-Auditing|Event\s?ID[:=]?\s*\d{3,5}', re.IGNORECASE)
_WINDOWS_EVENT_ID_RE = re.compile(r'Event\s?ID[:=]?\s*(?P<id>\d{3,5})', re.IGNORECASE)
_WINDOWS_ACCOUNT_RE = re.compile(r'Account Name:\s*(?P<user>[^\s,;]+)', re.IGNORECASE)
_WINDOWS_SRC_IP_RE = re.compile(r'Source Network Address:\s*(?P<ip>[\d.]+)', re.IGNORECASE)

_SSH_FAILED_RE = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?',
    re.IGNORECASE,
)
_SSH_ACCEPTED_RE = re.compile(
    r'Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?',
    re.IGNORECASE,
)
_SSH_INVALID_USER_RE = re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)', re.IGNORECASE)

# Substring (not word-bounded) so compound tokens like "AUTH_FAIL" or "auth_failure" still match.
_FAILURE_TOKEN_RE = re.compile(r'fail|invalid|denied|incorrect|unsuccessful|reject|error', re.IGNORECASE)


def _parse_syslog_log(raw_log: str) -> LogEntry:
    """Parse a raw (non-JSON) log line, dispatching to a format-specific structured
    parser instead of a single flat keyword scan. Real log fleets mix sshd-style
    syslog, Windows Security Event exports, and CEF-formatted appliance logs, and a
    keyword scan tuned for one format silently misclassifies the others (e.g. a
    Windows/CEF "AUTH_FAIL" token doesn't contain the substring "failed")."""
    if "CEF:" in raw_log:
        return _parse_cef_log(raw_log)
    if _WINDOWS_MARKER_RE.search(raw_log):
        return _parse_windows_event_log(raw_log)
    return _parse_generic_syslog_log(raw_log)


def _parse_generic_syslog_log(raw_log: str) -> LogEntry:
    """Parse standard syslog-style lines (e.g. sshd auth logs)."""
    timestamp = datetime.utcnow()

    source = LogSource.SYSTEM
    action = "log_event"
    status = "unknown"
    user = None
    source_ip = None
    destination_port = None

    is_auth_line = "sshd" in raw_log.lower() or "ssh" in raw_log.lower() or "login" in raw_log.lower()

    if is_auth_line:
        source = LogSource.AUTH
        match = _SSH_FAILED_RE.search(raw_log) or _SSH_INVALID_USER_RE.search(raw_log)
        accepted_match = _SSH_ACCEPTED_RE.search(raw_log)
        if accepted_match:
            action = "login_success"
            status = "success"
            user = accepted_match.group("user")
            source_ip = accepted_match.group("ip")
            port = accepted_match.groupdict().get("port")
            destination_port = int(port) if port else None
        elif match:
            action = "login_failed"
            status = "failure"
            user = match.group("user")
            source_ip = match.group("ip")
            port = match.groupdict().get("port")
            destination_port = int(port) if port else None
        else:
            action = "login_attempt"
            status = "failure" if _FAILURE_TOKEN_RE.search(raw_log) else "success"
    elif "dns" in raw_log.lower():
        source = LogSource.DNS
        action = "dns_query"
        status = "failure" if _FAILURE_TOKEN_RE.search(raw_log) else "success"
    elif "http" in raw_log.lower() or "GET" in raw_log or "POST" in raw_log:
        source = LogSource.HTTP
        action = "http_request"
        status = "failure" if _FAILURE_TOKEN_RE.search(raw_log) else "success"
    else:
        status = "failure" if _FAILURE_TOKEN_RE.search(raw_log) else "success"

    if not source_ip:
        ips = _IP_RE.findall(raw_log)
        source_ip = ips[0] if ips else "unknown"
        destination_ip = ips[1] if len(ips) > 1 else None
    else:
        ips = _IP_RE.findall(raw_log)
        destination_ip = next((ip for ip in ips if ip != source_ip), None)

    return LogEntry(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        user=user,
        log_source=source,
        log_source_type=LogSourceType.SYSLOG,
        action=action,
        status=status,
        raw_log=raw_log,
    )


def _parse_windows_event_log(raw_log: str) -> LogEntry:
    """Parse a Windows Security Event log line (4624/4625-style auth events)."""
    timestamp = datetime.utcnow()

    event_id_match = _WINDOWS_EVENT_ID_RE.search(raw_log)
    event_id = int(event_id_match.group("id")) if event_id_match else None

    lowered = raw_log.lower()
    if event_id == 4625 or "failed to log on" in lowered:
        action = "login_failed"
        status = "failure"
    elif event_id == 4624 or "successfully logged on" in lowered:
        action = "login_success"
        status = "success"
    else:
        action = "windows_security_event"
        status = "failure" if _FAILURE_TOKEN_RE.search(raw_log) else "success"

    user_match = _WINDOWS_ACCOUNT_RE.search(raw_log)
    user = user_match.group("user") if user_match else None

    ip_match = _WINDOWS_SRC_IP_RE.search(raw_log)
    if ip_match:
        source_ip = ip_match.group("ip")
    else:
        ips = _IP_RE.findall(raw_log)
        source_ip = ips[0] if ips else "unknown"

    return LogEntry(
        timestamp=timestamp,
        source_ip=source_ip,
        user=user,
        event_id=event_id,
        log_source=LogSource.AUTH,
        log_source_type=LogSourceType.WINDOWS_SECURITY,
        action=action,
        status=status,
        raw_log=raw_log,
    )


def _parse_cef_log(raw_log: str) -> LogEntry:
    """Parse a CEF (Common Event Format) log line."""
    timestamp = datetime.utcnow()

    header_match = _CEF_HEADER_RE.search(raw_log)
    extension: Dict[str, str] = {}
    name = ""
    if header_match:
        name = header_match.group("name") or ""
        extension = dict(_CEF_KV_RE.findall(header_match.group("extension")))

    outcome = (extension.get("outcome") or extension.get("act") or "").lower()
    if outcome in ("failure", "fail", "denied", "blocked", "reject"):
        status = "failure"
    elif outcome in ("success", "allow", "allowed", "accept"):
        status = "success"
    else:
        status = "failure" if _FAILURE_TOKEN_RE.search(raw_log) else "success"

    action = extension.get("act") or name.strip().lower().replace(" ", "_") or "cef_event"

    source_ip = extension.get("src")
    if not source_ip:
        ips = _IP_RE.findall(raw_log)
        source_ip = ips[0] if ips else "unknown"

    dpt = extension.get("dpt")

    return LogEntry(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=extension.get("dst"),
        destination_port=int(dpt) if dpt and dpt.isdigit() else None,
        user=extension.get("duser") or extension.get("suser"),
        log_source=LogSource.AUTH if "login" in name.lower() or "auth" in name.lower() else LogSource.SYSTEM,
        log_source_type=LogSourceType.FIREWALL,
        action=action,
        status=status,
        raw_log=raw_log,
    )

