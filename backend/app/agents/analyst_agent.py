"""Analyst Agent - Primary reasoning engine that synthesizes information."""

from datetime import datetime
from typing import Any, Dict, List

from app.core.llm_factory import get_llm
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from app.agents.base import BaseAgent
from app.core.config import settings
from app.models.agent_state import AgentState
from app.models.incident import IncidentReport, Severity
from app.tools.similarity_search import search_similar_incidents
from app.tools.ip_lookup import lookup_ip

SYSTEM_PROMPT = """You are a Tier 2 SOC Analyst performing deep investigation.

Return ONLY valid JSON with this exact schema:
{
  "executive_summary": "2-3 sentences, business impact focus, no jargon, includes severity/urgency",
  "technical_findings": "attack timeline, MITRE ATT&CK techniques observed (with IDs), and scope assessment",
  "timeline": [{"timestamp": "2026-08-30T10:15:00", "event": "what happened", "severity": "low|medium|high|critical"}],
  "affected_assets": ["<actual hostnames/IPs from the alerts above, e.g. 203.0.113.55>"],
  "root_cause": "initial access vector, vulnerabilities/misconfigurations exploited, contributing factors",
  "impact_assessment": "business/data impact, indicators of compromise, and regulatory considerations",
  "confidence_score": 0.0,
  "reasoning_process": ["step-by-step reasoning that led to the above conclusions"],
  "detection_gaps": ["missing telemetry or logging that limited this investigation"],
  "lessons_learned": ["security controls that failed or were absent, process improvements needed"]
}

confidence_score MUST be a number between 0.0 and 1.0.
Be concise and actionable. Prioritize findings by business impact.
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

    tools_by_name = {"search_similar_incidents": search_similar_incidents, "lookup_ip": lookup_ip}
    llm = get_llm(temperature=0.2).bind_tools([search_similar_incidents, lookup_ip])

    # Prepare analysis context
    alerts_summary = "\n".join([
        f"Alert {i+1}: [{a.severity.value}] {a.title}\n  {a.description}\n  MITRE: {', '.join(a.mitre_techniques)}"
        for i, a in enumerate(alerts)
    ])
    
    threat_intel_summary = f"MITRE Techniques: {len(threat_intel.get('mitre_techniques', []))} identified"
    
    # Check IPs for reputation
    source_ips = set()
    for alert in alerts:
        for log_idx in alert.related_logs[:5]:  # Check first few logs
            try:
                log = logs[int(log_idx)]
                source_ips.add(log.source_ip)
            except (ValueError, IndexError):
                pass
    
    ip_reputations = {}
    for ip in list(source_ips)[:5]:  # Limit to 5 IPs
        try:
            ip_reputations[ip] = lookup_ip(ip)
        except Exception:
            pass
    
    analysis_prompt = f"""Analyze these security alerts and create a comprehensive incident report:

ALERTS:
{alerts_summary}

THREAT INTELLIGENCE:
{threat_intel_summary}

IP REPUTATION:
{chr(10).join(f"{ip}: {rep[:200]}" for ip, rep in ip_reputations.items())}

{"CRITIQUE FEEDBACK (revise based on this):" + critique_feedback if critique_feedback else ""}

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

    response = await llm.ainvoke(messages)

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
        response = await llm.ainvoke(messages)

    content = response.content

    # Parse incident report from response
    incident_report = _parse_incident_report(content, alerts, logs)
    
    # Update highest severity
    max_severity = max((a.severity for a in alerts), key=lambda s: Severity.__members__.get(s.value, 0))

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
    if json_match:
        try:
            report_data = json.loads(json_match.group())
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
            )
        except Exception:
            pass

    return _fallback_report(content, alerts, logs)


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
    )

