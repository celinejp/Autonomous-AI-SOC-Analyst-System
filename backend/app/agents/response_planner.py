"""Response Planner Agent - Creates actionable response plans."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.llm_factory import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from app.models.agent_state import AgentState
from app.models.incident import ResponsePlan, ResponseAction, Severity

SYSTEM_PROMPT = """You are a cybersecurity response planner. Create actionable response plans.

Return ONLY valid JSON with this exact schema:
{
  "containment_actions": [Action],
  "investigation_steps": [Action],
  "remediation_actions": [Action],
  "long_term_improvements": [Action]
}

Each Action MUST include ALL of:
- priority: immediate|high|medium|low|short_term|long_term
- action_type: block_ip|disable_account|isolate_host|collect_forensics|review_logs|patch_system|update_rules|training|other
- action: short title
- description: what to do
- target: host/user/ip/system name or "unknown"
- assigned_team: SOC|Network|Endpoint|IAM|Legal|PR|Management
- status: pending

If the incident has no clear threat / no alerts, return empty lists for all categories."""


async def response_planner_agent(state: AgentState) -> AgentState:
    """Create response plan based on incident analysis."""
    _started_at = datetime.utcnow()
    incident_report = state.get("incident_report")
    alerts = state.get("alerts", [])
    incident_id = state.get("incident_id") or ""

    if not incident_report:
        state["response_plan"] = _empty_plan(incident_id)
        return state

    # No alerts → minimal / empty plan (avoid inventing response for noise)
    if not alerts:
        state["response_plan"] = _empty_plan(incident_id)
        state["agent_execution_log"].append(
            {
                "agent_name": "response_planner",
                "timestamp": datetime.utcnow().isoformat(),
                "duration_ms": (datetime.utcnow() - _started_at).total_seconds() * 1000,
                "reasoning": "skipped: no alerts",
                "output_data": {"containment_actions": 0, "investigation_steps": 0, "remediation_actions": 0},
            }
        )
        return state

    llm = get_llm(temperature=0.1)

    exec_summary = _attr(incident_report, "executive_summary", "")
    root_cause = _attr(incident_report, "root_cause", "")
    assets = _attr(incident_report, "affected_assets", []) or []
    if isinstance(assets, str):
        assets = [assets]
    impact = _attr(incident_report, "impact_assessment", "")

    report_summary = f"""
Executive Summary: {exec_summary}
Root Cause: {root_cause}
Affected Assets: {', '.join(str(a) for a in assets)}
Impact: {impact}

Top Alerts:
{chr(10).join(f"- [{_severity_val(a)}] {_attr(a, 'title', '')}" for a in alerts[:5])}
"""

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(
            content=f"Create a response plan as JSON only:\n\n{report_summary}"
        ),
    ]

    try:
        response = await llm.ainvoke(messages)
        content = response.content
        response_plan = _parse_response_plan(content, alerts, incident_report)
    except Exception:
        response_plan = _fallback_plan(alerts)

    response_plan.actions_by_team = _group_actions_by_team(response_plan)
    response_plan.incident_id = incident_id
    response_plan.generated_at = datetime.utcnow()

    state["response_plan"] = response_plan
    state["agent_execution_log"].append(
        {
            "agent_name": "response_planner",
            "timestamp": datetime.utcnow().isoformat(),
            "duration_ms": (datetime.utcnow() - _started_at).total_seconds() * 1000,
            "output_data": {
                "containment_actions": len(response_plan.containment_actions),
                "investigation_steps": len(response_plan.investigation_steps),
                "remediation_actions": len(response_plan.remediation_actions),
            },
        }
    )
    return state


def _attr(obj: Any, key: str, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _severity_val(alert: Any) -> str:
    sev = _attr(alert, "severity", "medium")
    return sev.value if hasattr(sev, "value") else str(sev)


def _group_actions_by_team(plan: ResponsePlan) -> Dict[str, List[ResponseAction]]:
    """Group all response actions by their assigned_team for the team-specific view."""
    grouped: Dict[str, List[ResponseAction]] = {}
    all_actions = (
        plan.containment_actions
        + plan.investigation_steps
        + plan.remediation_actions
        + plan.long_term_improvements
    )
    for action in all_actions:
        grouped.setdefault(action.assigned_team, []).append(action)
    return grouped


def _empty_plan(incident_id: str = "") -> ResponsePlan:
    return ResponsePlan(
        incident_id=incident_id,
        generated_at=datetime.utcnow(),
        containment_actions=[],
        investigation_steps=[],
        remediation_actions=[],
        long_term_improvements=[],
    )


def _normalize_action(raw: Any, defaults: Optional[Dict[str, str]] = None) -> Optional[ResponseAction]:
    """Coerce LLM/partial dicts into a valid ResponseAction. Never raises."""
    defaults = defaults or {}
    if isinstance(raw, ResponseAction):
        return raw
    if not isinstance(raw, dict):
        return None

    priority = str(raw.get("priority") or defaults.get("priority") or "medium")
    action = str(raw.get("action") or raw.get("title") or defaults.get("action") or "Review finding")
    description = str(
        raw.get("description") or raw.get("details") or action
    )
    action_type = str(
        raw.get("action_type")
        or raw.get("type")
        or defaults.get("action_type")
        or "other"
    )
    target = str(raw.get("target") or raw.get("asset") or defaults.get("target") or "unknown")
    assigned_team = str(
        raw.get("assigned_team")
        or raw.get("team")
        or defaults.get("assigned_team")
        or "SOC"
    )
    status = str(raw.get("status") or "pending")

    try:
        return ResponseAction(
            priority=priority,
            action_type=action_type,
            action=action,
            description=description,
            target=target,
            assigned_team=assigned_team,
            status=status,
            requires_approval=bool(raw.get("requires_approval", False)),
            automated=bool(raw.get("automated", False)),
            automation_available=bool(raw.get("automation_available", False)),
            success_criteria=str(raw.get("success_criteria") or ""),
            verification_steps=list(raw.get("verification_steps") or []),
            depends_on=list(raw.get("depends_on") or []),
            manual_steps=list(raw.get("manual_steps") or []) or None,
        )
    except Exception:
        return None


def _parse_action_list(items: Any, defaults: Optional[Dict[str, str]] = None) -> List[ResponseAction]:
    if not isinstance(items, list):
        return []
    out: List[ResponseAction] = []
    for item in items:
        action = _normalize_action(item, defaults)
        if action:
            out.append(action)
    return out


def _parse_response_plan(content: str, alerts: List, report) -> ResponsePlan:
    """Parse response plan from LLM response with safe defaults."""
    import json
    import re

    json_match = re.search(r'\{.*\}', content, re.DOTALL)
    if json_match:
        try:
            plan_data = json.loads(json_match.group())
            plan = ResponsePlan(
                containment_actions=_parse_action_list(
                    plan_data.get("containment_actions", []),
                    {"priority": "immediate", "action_type": "block_ip", "assigned_team": "Network"},
                ),
                investigation_steps=_parse_action_list(
                    plan_data.get("investigation_steps", []),
                    {"priority": "high", "action_type": "review_logs", "assigned_team": "SOC"},
                ),
                remediation_actions=_parse_action_list(
                    plan_data.get("remediation_actions", []),
                    {"priority": "medium", "action_type": "patch_system", "assigned_team": "Endpoint"},
                ),
                long_term_improvements=_parse_action_list(
                    plan_data.get("long_term_improvements", []),
                    {"priority": "low", "action_type": "training", "assigned_team": "Management"},
                ),
            )
            if any(
                [
                    plan.containment_actions,
                    plan.investigation_steps,
                    plan.remediation_actions,
                    plan.long_term_improvements,
                ]
            ):
                return plan
        except Exception:
            pass

    return _fallback_plan(alerts)


def _fallback_plan(alerts: List) -> ResponsePlan:
    """Deterministic plan that always validates."""
    containment_actions: List[ResponseAction] = []
    investigation_steps: List[ResponseAction] = []
    remediation_actions: List[ResponseAction] = []
    long_term_improvements: List[ResponseAction] = []

    if alerts:
        severities = []
        for a in alerts:
            sev = _attr(a, "severity", Severity.LOW)
            if isinstance(sev, str):
                try:
                    sev = Severity(sev)
                except ValueError:
                    sev = Severity.LOW
            severities.append(sev)
        max_severity = max(severities) if severities else Severity.LOW

        if max_severity in (Severity.CRITICAL, Severity.HIGH):
            containment_actions.append(
                ResponseAction(
                    priority="immediate",
                    action_type="block_ip",
                    action="Block source IPs",
                    description="Block source IPs associated with malicious activity",
                    target="source_ips",
                    assigned_team="Network",
                    status="pending",
                )
            )
            containment_actions.append(
                ResponseAction(
                    priority="immediate",
                    action_type="disable_account",
                    action="Disable affected accounts",
                    description="Temporarily disable user accounts involved in suspicious activity",
                    target="affected_accounts",
                    assigned_team="IAM",
                    status="pending",
                )
            )

    investigation_steps.append(
        ResponseAction(
            priority="high",
            action_type="review_logs",
            action="Review full log timeline",
            description="Analyze complete timeline of events leading to incident",
            target="incident_logs",
            assigned_team="SOC",
            status="pending",
        )
    )
    investigation_steps.append(
        ResponseAction(
            priority="high",
            action_type="collect_forensics",
            action="Check for lateral movement",
            description="Investigate if attacker moved to other systems",
            target="internal_hosts",
            assigned_team="SOC",
            status="pending",
        )
    )
    remediation_actions.append(
        ResponseAction(
            priority="medium",
            action_type="update_rules",
            action="Update detection rules",
            description="Refine detection rules based on this incident",
            target="detection_rules",
            assigned_team="SOC",
            status="pending",
        )
    )
    long_term_improvements.append(
        ResponseAction(
            priority="low",
            action_type="training",
            action="Security awareness training",
            description="Provide training on recognizing similar threats",
            target="employees",
            assigned_team="Management",
            status="pending",
        )
    )

    return ResponsePlan(
        containment_actions=containment_actions,
        investigation_steps=investigation_steps,
        remediation_actions=remediation_actions,
        long_term_improvements=long_term_improvements,
    )
