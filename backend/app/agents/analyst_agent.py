"""Analyst Agent - Primary reasoning engine that synthesizes information."""

from datetime import datetime
from typing import Any, Dict, List

from app.core.llm_factory import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base import BaseAgent
from app.core.config import settings
from app.models.agent_state import AgentState
from app.models.incident import IncidentReport, Severity
from app.tools.similarity_search import search_similar_incidents
from app.tools.ip_lookup import lookup_ip

SYSTEM_PROMPT = """You are a Tier 2 SOC Analyst performing deep investigation.

Your analysis MUST include these sections:

## Executive Summary
- 2-3 sentences maximum
- Business impact focus, no technical jargon
- Severity and recommended urgency

## Technical Analysis
### Attack Timeline
- Chronological sequence of attacker actions
- Include timestamps, systems, and users involved

### MITRE ATT&CK Mapping
- List all identified techniques with IDs (e.g., T1110.001)
- Explain how each technique was observed

### Root Cause Analysis
- Initial access vector
- Vulnerabilities or misconfigurations exploited
- Contributing factors

### Scope Assessment
- All confirmed affected systems
- Potential lateral movement paths
- Data at risk (classification and volume)

## Indicators of Compromise
Format as structured list:
- IP addresses with reputation and recommended action
- Domains with context
- File hashes with malware family if known
- Email addresses if relevant

## Confidence Assessment
- Overall confidence (0-100%)
- Detection confidence
- Scope confidence
- What evidence is missing that would increase confidence

## Regulatory Considerations
- Applicable regulations based on data types involved
- Notification requirements and deadlines
- Recommended legal/compliance actions

## Detection Gaps
- What telemetry was missing
- What additional logging would help
- Proposed detection rules (in pseudocode or natural language)

## Lessons Learned
- What security controls failed or were absent
- Process improvements needed
- Training recommendations

Be concise and actionable. Prioritize findings by business impact."""


async def analyst_agent(state: AgentState) -> AgentState:
    """Perform deep analysis and create incident report."""
    alerts = state.get("alerts", [])
    logs = state.get("logs", [])
    threat_intel = state.get("threat_intel", {})
    critique_feedback = state.get("critique_feedback")
    
    if not alerts:
        state["incident_report"] = None
        return state

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
    content = response.content

    # Parse incident report from response
    incident_report = _parse_incident_report(content, alerts, logs)
    
    # Update highest severity
    max_severity = max((a.severity for a in alerts), key=lambda s: Severity.__members__.get(s.value, 0))

    state["incident_report"] = incident_report
    state["agent_execution_log"].append({
        "agent_name": "analyst",
        "timestamp": datetime.utcnow().isoformat(),
        "alerts_analyzed": len(alerts),
        "confidence_score": incident_report.confidence_score if incident_report else 0.0,
        "reasoning_steps": len(incident_report.reasoning_process) if incident_report else 0,
    })

    return state


def _parse_incident_report(content: str, alerts: List, logs: List) -> IncidentReport:
    """Parse incident report from LLM response."""
    import json
    import re
    
    # Try to extract JSON from response
    json_match = re.search(r'\{.*\}', content, re.DOTALL)
    if json_match:
        try:
            report_data = json.loads(json_match.group())
            return IncidentReport(
                executive_summary=report_data.get("executive_summary", content[:500]),
                technical_findings=report_data.get("technical_findings", content[:1000]),
                timeline=report_data.get("timeline", []),
                affected_assets=report_data.get("affected_assets", []),
                root_cause=report_data.get("root_cause", "Analysis in progress"),
                impact_assessment=report_data.get("impact_assessment", "Assessment pending"),
                confidence_score=float(report_data.get("confidence_score", 0.75)),
                reasoning_process=report_data.get("reasoning_process", [content[:200]]),
            )
        except Exception:
            pass
    
    # Fallback: create report from content
    sections = content.split("\n\n")
    executive_summary = sections[0] if sections else content[:500]
    technical_findings = "\n\n".join(sections[1:3]) if len(sections) > 1 else content[:1000]
    
    # Extract timeline from content
    timeline = []
    for i, alert in enumerate(alerts[:10]):
        timeline.append({
            "timestamp": alert.timestamp.isoformat(),
            "event": alert.title,
            "severity": alert.severity.value,
        })
    
    # Extract affected assets (IPs from alerts)
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
    
    return IncidentReport(
        executive_summary=executive_summary,
        technical_findings=technical_findings,
        timeline=timeline,
        affected_assets=list(affected_assets),
        root_cause=content.split("Root cause:")[1].split("\n")[0] if "Root cause:" in content else "Analysis in progress",
        impact_assessment=content.split("Impact:")[1].split("\n")[0] if "Impact:" in content else "Assessment pending",
        confidence_score=0.75,
        reasoning_process=[s[:200] for s in sections[:5]],
    )

