"""Ingest Agent - Parses and normalizes security logs."""

import json
import re
from datetime import datetime
from typing import Any, Dict, List

from app.agents.base import BaseAgent
from app.models.agent_state import AgentState
from app.models.log_entry import LogEntry, LogFormat, LogSource

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
        "input_count": len(raw_logs),
        "output_count": len(normalized_logs),
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
    
    return LogEntry(
        timestamp=timestamp,
        source_ip=log_data.get("source_ip") or log_data.get("src_ip") or log_data.get("ip") or "unknown",
        destination_ip=log_data.get("destination_ip") or log_data.get("dest_ip") or log_data.get("dst_ip"),
        destination_port=log_data.get("destination_port") or log_data.get("dest_port") or log_data.get("port"),
        user=log_data.get("user") or log_data.get("username") or log_data.get("user_name"),
        action=log_data.get("action") or log_data.get("event") or log_data.get("type") or "unknown",
        status=log_data.get("status") or log_data.get("result") or "unknown",
        log_source=source,
        raw_log=raw_log,
        metadata=log_data,
    )


def _parse_syslog_log(raw_log: str) -> LogEntry:
    """Parse syslog format log."""
    # Simple syslog parser - extract IPs, timestamps, etc.
    # Format: timestamp hostname program: message
    timestamp = datetime.utcnow()
    
    # Try to extract IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, raw_log)
    source_ip = ips[0] if ips else "unknown"
    destination_ip = ips[1] if len(ips) > 1 else None
    
    # Determine source and action
    source = LogSource.SYSTEM
    action = "log_event"
    
    if "ssh" in raw_log.lower() or "login" in raw_log.lower():
        source = LogSource.AUTH
        action = "login_attempt"
        if "failed" in raw_log.lower() or "error" in raw_log.lower():
            action = "login_failed"
    elif "dns" in raw_log.lower():
        source = LogSource.DNS
        action = "dns_query"
    elif "http" in raw_log.lower() or "GET" in raw_log or "POST" in raw_log:
        source = LogSource.HTTP
        action = "http_request"
    
    # Extract status
    status = "success"
    if "failed" in raw_log.lower() or "error" in raw_log.lower() or "denied" in raw_log.lower():
        status = "failure"
    
    return LogEntry(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        log_source=source,
        action=action,
        status=status,
        raw_log=raw_log,
    )

