"""Response Planner Agent - Creates actionable response plans."""

from datetime import datetime
from typing import Any, Dict, List

from app.core.llm_factory import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base import BaseAgent
from app.core.config import settings
from app.models.agent_state import AgentState
from app.models.incident import ResponsePlan, ResponseAction, Severity

SYSTEM_PROMPT = """You are a cybersecurity response planner agent. Your role is to create detailed, actionable response plans based on incident analysis.

For each incident, create prioritized response actions in these categories:

1. CONTAINMENT ACTIONS (immediate):
   - Block malicious IPs
   - Disable compromised accounts
   - Isolate affected systems
   - Quarantine malicious files

2. INVESTIGATION STEPS (high priority):
   - Collect forensic artifacts
   - Review related logs
   - Check other systems for indicators
   - Analyze network traffic

3. REMEDIATION ACTIONS (medium priority):
   - Patch vulnerable systems
   - Update firewall rules
   - Rotate credentials
   - Update detection rules

4. LONG-TERM IMPROVEMENTS (low priority):
   - Security awareness training
   - System hardening
   - Process improvements
   - Policy updates

Each action should be specific, actionable, and prioritized. Consider business impact when recommending actions."""


async def response_planner_agent(state: AgentState) -> AgentState:
    """Create response plan based on incident analysis."""
    incident_report = state.get("incident_report")
    alerts = state.get("alerts", [])
    
    if not incident_report:
        state["response_plan"] = None
        return state

    llm = get_llm(temperature=0.1)

    # Prepare context
    report_summary = f"""
Executive Summary: {incident_report.executive_summary}
Root Cause: {incident_report.root_cause}
Affected Assets: {', '.join(incident_report.affected_assets)}
Impact: {incident_report.impact_assessment}

Top Alerts:
{chr(10).join(f"- [{a.severity.value}] {a.title}" for a in alerts[:5])}
"""

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"Create a detailed response plan for this incident:\n\n{report_summary}\n\nOutput structured response actions."),
    ]

    response = await llm.ainvoke(messages)
    content = response.content

    # Parse response plan
    response_plan = _parse_response_plan(content, alerts, incident_report)
    
    state["response_plan"] = response_plan
    state["agent_execution_log"].append({
        "agent_name": "response_planner",
        "timestamp": datetime.utcnow().isoformat(),
        "containment_actions": len(response_plan.containment_actions),
        "investigation_steps": len(response_plan.investigation_steps),
        "remediation_actions": len(response_plan.remediation_actions),
    })

    return state


def _parse_response_plan(content: str, alerts: List, report) -> ResponsePlan:
    """Parse response plan from LLM response."""
    import json
    import re
    
    # Try to extract JSON
    json_match = re.search(r'\{.*\}', content, re.DOTALL)
    if json_match:
        try:
            plan_data = json.loads(json_match.group())
            return ResponsePlan(
                containment_actions=[ResponseAction(**a) for a in plan_data.get("containment_actions", [])],
                investigation_steps=[ResponseAction(**a) for a in plan_data.get("investigation_steps", [])],
                remediation_actions=[ResponseAction(**a) for a in plan_data.get("remediation_actions", [])],
                long_term_improvements=[ResponseAction(**a) for a in plan_data.get("long_term_improvements", [])],
            )
        except Exception:
            pass
    
    # Fallback: create plan from content and alerts
    containment_actions = []
    investigation_steps = []
    remediation_actions = []
    long_term_improvements = []
    
    # Extract source IPs for containment
    source_ips = set()
    for alert in alerts:
        for log_idx in alert.related_logs[:3]:
            try:
                log_idx_int = int(log_idx)
                # Would need access to logs here - for now create generic actions
            except (ValueError, IndexError):
                pass
    
    # Generate default containment actions based on alerts
    if alerts:
        max_severity = max(a.severity for a in alerts)
        if max_severity in [Severity.CRITICAL, Severity.HIGH]:
            containment_actions.append(ResponseAction(
                priority="immediate",
                action="Block source IPs",
                description="Block all source IPs associated with malicious activity",
                status="pending",
            ))
            containment_actions.append(ResponseAction(
                priority="immediate",
                action="Disable affected accounts",
                description="Temporarily disable user accounts involved in suspicious activity",
                status="pending",
            ))
    
    # Generate investigation steps
    investigation_steps.append(ResponseAction(
        priority="high",
        action="Review full log timeline",
        description="Analyze complete timeline of events leading to incident",
        status="pending",
    ))
    investigation_steps.append(ResponseAction(
        priority="high",
        action="Check for lateral movement",
        description="Investigate if attacker moved to other systems",
        status="pending",
    ))
    
    # Generate remediation
    remediation_actions.append(ResponseAction(
        priority="medium",
        action="Update detection rules",
        description="Refine detection rules based on this incident",
        status="pending",
    ))
    
    # Generate improvements
    long_term_improvements.append(ResponseAction(
        priority="low",
        action="Security awareness training",
        description="Provide training on recognizing similar threats",
        status="pending",
    ))
    
    return ResponsePlan(
        containment_actions=containment_actions,
        investigation_steps=investigation_steps,
        remediation_actions=remediation_actions,
        long_term_improvements=long_term_improvements,
    )

