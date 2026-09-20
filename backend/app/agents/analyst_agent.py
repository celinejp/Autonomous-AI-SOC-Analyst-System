"""Analyst Agent - Primary reasoning engine that synthesizes information."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.llm_factory import ainvoke_llm, get_llm
from app.core.logging import get_logger
from app.core.text_safety import UNTRUSTED_DATA_NOTICE, sanitize_untrusted, wrap_untrusted
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from app.models.agent_state import AgentState
from app.models.incident import IncidentReport, IOCCollection, IOCEntry
from app.tools.similarity_search import search_similar_incidents

logger = get_logger(__name__)


class _ReportParseError(Exception):
    """Raised when the LLM's response can't be parsed as the expected JSON report -
    distinct from a legitimate empty/minimal report, so callers know to retry."""

SYSTEM_PROMPT = """You are a Tier 2 SOC Analyst performing deep investigation.

""" + UNTRUSTED_DATA_NOTICE + """

Return ONLY valid JSON with this exact schema:
{
  "executive_summary": "2-3 sentences, business impact focus, no jargon, includes severity/urgency",
  "technical_findings": "attack timeline, MITRE ATT&CK techniques observed (with IDs), and scope assessment",
  "timeline": [{"timestamp": "2026-08-30T10:15:00", "event": "what happened", "severity": "low|medium|high|critical"}],
  "affected_assets": ["<actual hostnames/IPs taken from the alerts above>"],
  "root_cause": "initial access vector, vulnerabilities/misconfigurations exploited, contributing factors",
  "impact_assessment": "business/data impact and regulatory considerations",
  "confidence_score": 0.0,
  "reasoning_process": ["step-by-step reasoning that led to the above conclusions"],
  "detection_gaps": ["missing telemetry or logging that limited this investigation"],
  "lessons_learned": ["security controls that failed or were absent, process improvements needed"],
  "indicators_of_compromise": [{"value": "<a real IP/domain/hash/URL/email address from the alerts above - never invent one>", "type": "ip|domain|url|hash|email", "confidence": "low|medium|high", "recommended_action": "block|monitor|investigate"}]
}

confidence_score MUST be a number between 0.0 and 1.0.
Be concise and actionable. Prioritize findings by business impact.
For indicators_of_compromise, only list values that actually appear in the ALERTS
section above - if none are worth flagging beyond what's already obvious from the alert
source IPs, return an empty list rather than guessing.
Use tools first if you need more context, then answer with the JSON object only - no markdown, no prose outside the JSON."""


async def analyst_agent(state: AgentState) -> AgentState:
    """Perform deep analysis and create incident report."""
    _started_at = datetime.utcnow()
    alerts = state.get("alerts", [])
    logs = state.get("logs", [])
    threat_intel = state.get("threat_intel", {})
    critique_feedback = state.get("critique_feedback")
    
    if not alerts:
        state["incident_report"] = None
        return state

    tools_by_name = {"search_similar_incidents": search_similar_incidents}
    llm = get_llm(temperature=0.2).bind_tools([search_similar_incidents])

    # Prepare analysis context
    alerts_summary = "\n".join([
        f"Alert {i+1}: [{a.severity.value}] {sanitize_untrusted(a.title, 200)}\n  {sanitize_untrusted(a.description, 500)}\n  MITRE: {', '.join(a.mitre_techniques)}"
        for i, a in enumerate(alerts)
    ])
    
    threat_intel_summary = f"MITRE Techniques: {len(threat_intel.get('mitre_techniques', []))} identified"
    
    analysis_prompt = f"""Analyze these security alerts and create a comprehensive incident report:

ALERTS:
{wrap_untrusted(alerts_summary)}

THREAT INTELLIGENCE:
{threat_intel_summary}

{"CRITIQUE FEEDBACK (revise based on this):\n" + sanitize_untrusted(str(critique_feedback), 1500) if critique_feedback else ""}

Perform deep analysis considering:
1. How do these alerts relate to each other?
2. What is the attack chain/timeline?
3. What assets are affected?
4. What is the root cause?
5. What is the business impact?

Use tools to search for similar past incidents if helpful."""

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=analysis_prompt),
    ]

    try:
        response = await ainvoke_llm(llm, messages)
    except Exception as e:  # LLM down / timed out: still save a deterministic report
        logger.error("analyst_agent: LLM call failed, using fallback report: %s", e)
        state["incident_report"] = _fallback_report("", alerts, logs)
        state["agent_execution_log"].append({
            "agent_name": "analyst", "timestamp": datetime.utcnow().isoformat(),
            "duration_ms": (datetime.utcnow() - _started_at).total_seconds() * 1000,
            "output_data": {"llm_error": f"{type(e).__name__}: {e}"},
        })
        return state

    # If the model chose to call tools instead of answering directly, execute
    # them and give it a follow-up turn so we get actual report text back.
    tools_used = set()
    for _ in range(3):
        if not getattr(response, "tool_calls", None):
            break
        messages.append(response)
        for tool_call in response.tool_calls:
            tools_used.add(tool_call["name"])
            tool_fn = tools_by_name.get(tool_call["name"])
            try:
                result = tool_fn.invoke(tool_call["args"]) if tool_fn else f"Unknown tool: {tool_call['name']}"
            except Exception as e:
                result = f"Tool error: {e}"
            messages.append(ToolMessage(content=str(result), tool_call_id=tool_call["id"]))
        response = await ainvoke_llm(llm, messages)

    content = response.content

    # The LLM sometimes emits unparseable JSON; one retry, then a deterministic fallback report.
    try:
        incident_report = _parse_incident_report(content, alerts, logs)
    except _ReportParseError as e:
        logger.warning("analyst_agent: report JSON failed to parse, retrying once: %s", e)
        retry_response = await ainvoke_llm(llm, messages)
        try:
            incident_report = _parse_incident_report(retry_response.content, alerts, logs)
        except _ReportParseError as e2:
            logger.warning("analyst_agent: retry also failed to parse, using fallback report: %s", e2)
            incident_report = _fallback_report(retry_response.content, alerts, logs)

    state["incident_report"] = incident_report
    state["agent_execution_log"].append({
        "agent_name": "analyst",
        "timestamp": datetime.utcnow().isoformat(),
        "duration_ms": (datetime.utcnow() - _started_at).total_seconds() * 1000,
        "tools_used": sorted(tools_used),
        "output_data": {
            "alerts_analyzed": len(alerts),
            "confidence_score": incident_report.confidence_score if incident_report else 0.0,
            "reasoning_steps": len(incident_report.reasoning_process) if incident_report else 0,
        },
    })

    return state


def _parse_incident_report(content: str, alerts: List, logs: List) -> IncidentReport:
    """Parse incident report from LLM response, which is instructed to return JSON
    matching IncidentReport's field names. Falls back to a deterministic report
    built from the alerts/logs if the model didn't return valid JSON."""
    import json
    import re

    json_match = re.search(r'\{.*\}', content, re.DOTALL)
    if not json_match:
        raise _ReportParseError(f"no JSON object found in response: {content[:300]!r}")

    try:
        report_data = json.loads(json_match.group())
    except Exception as e:
        raise _ReportParseError(f"invalid JSON ({e}): {json_match.group()[:300]!r}") from e

    if not isinstance(report_data, dict):
        raise _ReportParseError(f"parsed JSON is not an object: {type(report_data).__name__}")

    # Valid JSON can still be garbage: the whole object dumped into one field. A long executive
    # summary containing other schema keys is the signal; treat it as a parse failure (retry).
    exec_summary_raw = report_data.get("executive_summary")
    if isinstance(exec_summary_raw, str) and (
        len(exec_summary_raw) > 800
        or '"technical_findings"' in exec_summary_raw
        or '"root_cause"' in exec_summary_raw
    ):
        raise _ReportParseError(
            f"executive_summary looks like a dumped/duplicated blob ({len(exec_summary_raw)} chars): {exec_summary_raw[:200]!r}"
        )

    confidence_score = float(report_data.get("confidence_score", 0.75) or 0.75)
    confidence_score = min(max(confidence_score, 0.0), 1.0)
    return IncidentReport(
        executive_summary=str(report_data.get("executive_summary") or content[:500]),
        technical_findings=str(report_data.get("technical_findings") or content[:1000]),
        timeline=report_data.get("timeline") or _default_timeline(alerts),
        affected_assets=report_data.get("affected_assets") or _default_affected_assets(alerts, logs),
        root_cause=str(report_data.get("root_cause") or "Analysis in progress"),
        impact_assessment=str(report_data.get("impact_assessment") or "Assessment pending"),
        confidence_score=confidence_score,
        reasoning_process=report_data.get("reasoning_process") or [content[:200]],
        detection_gaps=_parse_detection_gaps(report_data.get("detection_gaps")),
        lessons_learned=[str(x) for x in (report_data.get("lessons_learned") or [])],
        indicators_of_compromise=_build_ioc_collection(alerts, logs, report_data.get("indicators_of_compromise")),
    )


_IOC_TYPE_TO_BUCKET = {
    "ip": "ip_addresses",
    "domain": "domains",
    "url": "urls",
    "hash": "file_hashes",
    "email": "email_addresses",
}
_VALID_IOC_ACTIONS = {"block", "monitor", "investigate"}
_VALID_IOC_CONFIDENCE = {"low", "medium", "high"}


def _severity_to_ioc_action(severity: Any) -> str:
    """Map an alert's severity to a default IOC recommended_action - a reasonable
    heuristic tied to a real signal already on the alert, not an arbitrary default."""
    value = severity.value if hasattr(severity, "value") else str(severity)
    if value in ("critical", "high"):
        return "block"
    if value == "medium":
        return "investigate"
    return "monitor"


def _extract_known_iocs(alerts: List, logs: List) -> Dict[str, List[IOCEntry]]:
    """Deterministically pull IOCs straight from the structured LogEntry fields tied
    to each alert (source/destination IP, file hashes, DNS queries, email addresses).
    Unlike the LLM-identified IOCs the prompt also asks for, these can't be omitted
    by a non-deterministic model or hallucinated: if the raw log has a source_ip,
    it's a real, observed IOC. This is what keeps indicators_of_compromise reliably
    populated instead of depending entirely on the LLM choosing to fill in a nested
    JSON array correctly every time."""
    buckets: Dict[str, Dict[str, IOCEntry]] = {b: {} for b in _IOC_TYPE_TO_BUCKET.values()}

    def add(bucket: str, value: Optional[str], techniques: List[str], action: str):
        if not value or value.strip().lower() in ("unknown", "none", "-"):
            return  # parser placeholder, not an observed indicator
        existing = buckets[bucket].get(value)
        if existing:
            for t in techniques:
                if t not in existing.related_techniques:
                    existing.related_techniques.append(t)
            return
        ioc_type = next(k for k, v in _IOC_TYPE_TO_BUCKET.items() if v == bucket)
        buckets[bucket][value] = IOCEntry(
            value=value,
            type=ioc_type,
            related_techniques=list(techniques),
            confidence="high",  # directly observed in raw log data, not inferred
            recommended_action=action,
        )

    for alert in alerts:
        action = _severity_to_ioc_action(alert.severity)
        for log_idx in alert.related_logs:
            try:
                log = logs[int(log_idx)]
            except (ValueError, IndexError, TypeError):
                continue
            add("ip_addresses", log.source_ip, alert.mitre_techniques, action)
            add("ip_addresses", log.destination_ip, alert.mitre_techniques, action)
            add("file_hashes", log.file_hash_sha256, alert.mitre_techniques, action)
            add("file_hashes", log.file_hash_md5, alert.mitre_techniques, action)
            if log.dns_query:
                add("domains", log.dns_query.rstrip("."), alert.mitre_techniques, action)
            add("email_addresses", log.email_sender, alert.mitre_techniques, action)
            for recipient in (log.email_recipients or []):
                add("email_addresses", recipient, alert.mitre_techniques, action)

    return {bucket: list(entries.values()) for bucket, entries in buckets.items()}


def _observed_text(alerts: List, logs: List) -> str:
    """Everything the LLM was legitimately allowed to draw an IOC from: the raw log lines and
    the alert text. An IOC value that appears in none of it was invented."""
    parts = [getattr(log, "raw_log", "") or "" for log in logs]
    for a in alerts:
        parts.append(f"{a.title} {a.description}")
        parts.extend(str(e) for e in (a.evidence or []))
    return "\n".join(parts).lower()


def _merge_llm_iocs(buckets: Dict[str, List[IOCEntry]], items: Any, observed: str = "") -> None:
    """Merge the LLM's own identified IOCs (which may add judgment that
    pure log extraction can't) into the deterministic
    buckets above, skipping anything malformed or already present rather than
    failing the whole report over one bad entry."""
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        ioc_type = str(item.get("type") or "").strip().lower()
        bucket = _IOC_TYPE_TO_BUCKET.get(ioc_type)
        if not value or not bucket:
            continue
        if any(existing.value == value for existing in buckets[bucket]):
            continue
        if value.lower() not in observed:
            logger.info("analyst_agent: dropping LLM IOC not present in logs/alerts", value=value)
            continue
        confidence = item.get("confidence")
        if confidence not in _VALID_IOC_CONFIDENCE:
            confidence = "medium"
        action = item.get("recommended_action")
        if action not in _VALID_IOC_ACTIONS:
            action = "investigate"
        try:
            buckets[bucket].append(IOCEntry(
                value=value, type=ioc_type, confidence=confidence, recommended_action=action,
            ))
        except Exception:
            continue


def _build_ioc_collection(alerts: List, logs: List, llm_items: Any) -> Optional[IOCCollection]:
    buckets = _extract_known_iocs(alerts, logs)
    _merge_llm_iocs(buckets, llm_items, _observed_text(alerts, logs))
    if not any(buckets.values()):
        return None
    return IOCCollection(**buckets)


def _default_timeline(alerts: List) -> List[Dict[str, Any]]:
    return [
        {
            "timestamp": alert.timestamp.isoformat(),
            "event": alert.title,
            "severity": alert.severity.value,
        }
        for alert in alerts[:10]
    ]


def _default_affected_assets(alerts: List, logs: List) -> List[str]:
    affected_assets = set()
    for alert in alerts:
        for log_idx in alert.related_logs[:5]:
            try:
                log = logs[int(log_idx)]
                affected_assets.add(log.source_ip)
                if log.destination_ip:
                    affected_assets.add(log.destination_ip)
            except (ValueError, IndexError):
                pass
    return list(affected_assets)


def _parse_detection_gaps(items: Any) -> List:
    from app.models.incident import DetectionGap

    if not isinstance(items, list):
        return []
    gaps = []
    for item in items:
        if isinstance(item, str):
            gaps.append(DetectionGap(description=item))
        elif isinstance(item, dict) and item.get("description"):
            try:
                gaps.append(DetectionGap(**item))
            except Exception:
                gaps.append(DetectionGap(description=str(item.get("description"))))
    return gaps


def _fallback_report(content: str, alerts: List, logs: List) -> IncidentReport:
    """Deterministic report built from alerts/logs when the model returned no valid JSON."""
    sections = content.split("\n\n")
    executive_summary = sections[0] if sections else content[:500]
    technical_findings = "\n\n".join(sections[1:3]) if len(sections) > 1 else content[:1000]

    return IncidentReport(
        executive_summary=executive_summary,
        technical_findings=technical_findings,
        timeline=_default_timeline(alerts),
        affected_assets=_default_affected_assets(alerts, logs),
        root_cause="Analysis in progress",
        impact_assessment="Assessment pending",
        confidence_score=0.75,
        reasoning_process=[s[:200] for s in sections[:5]],
        indicators_of_compromise=_build_ioc_collection(alerts, logs, None),
    )

