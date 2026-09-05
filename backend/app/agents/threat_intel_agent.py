"""Threat Intel Agent - Retrieves MITRE ATT&CK and threat intelligence context."""

from datetime import datetime
from typing import Any, Dict, List

from app.core.llm_factory import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base import BaseAgent
from app.core.config import settings
from app.models.agent_state import AgentState
from app.tools.mitre_search import (
    MITRE_SCORE_THRESHOLD,
    get_mitre_technique,
    get_mitre_technique_raw,
    search_mitre_techniques,
    search_mitre_techniques_raw,
)

SYSTEM_PROMPT = """You are a threat intelligence agent. Your role is to enrich security alerts with MITRE ATT&CK framework context and threat intelligence.

For each alert, you should:
1. Identify relevant MITRE ATT&CK techniques and tactics
2. Retrieve detailed information about those techniques
3. Search for similar known attack patterns
4. Provide context about threat actors and TTPs (Tactics, Techniques, Procedures)

Use the available tools to:
- get_mitre_technique: Get details about specific MITRE techniques
- search_mitre_techniques: Search for techniques by description

Output a structured threat intelligence report with MITRE mappings."""


async def threat_intel_agent(state: AgentState) -> AgentState:
    """Enrich alerts with threat intelligence."""
    _started_at = datetime.utcnow()
    alerts = state.get("alerts", [])
    if not alerts:
        state["threat_intel"] = {}
        return state

    llm = get_llm(temperature=0.1).bind_tools([get_mitre_technique, search_mitre_techniques])

    threat_intel_data = {
        "mitre_techniques": [],
        "threat_actors": [],
        "attack_patterns": [],
        "iocs": [],
    }
    tools_used = set()

    # Analyze each alert for MITRE mappings
    for alert in alerts:
        # Prepare alert description for MITRE search
        alert_text = f"{alert.title} {alert.description} {' '.join(alert.detection_rule)}"
        
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Analyze this alert and identify relevant MITRE ATT&CK techniques:\n\n{alert_text}\n\nUse tools to retrieve detailed technique information."),
        ]

        response = await llm.ainvoke(messages)

        # Extract tool calls
        tool_calls = []
        if hasattr(response, "tool_calls"):
            tool_calls = response.tool_calls

        # Ground truth for this alert: technique IDs whose embedding similarity to the
        # alert text actually clears the threshold. get_mitre_technique is a detail-lookup
        # tool with no similarity score of its own, so the LLM can name any technique ID
        # it wants there -- only tag the alert with an ID if this grounding search (or an
        # explicit search_mitre_techniques call below) corroborates it above the threshold.
        grounded_ids = {
            str(hit["id"]).upper()
            for hit in search_mitre_techniques_raw(alert_text)
            if hit.get("id") and hit.get("score", 0) >= MITRE_SCORE_THRESHOLD
        }

        # Process tool calls and gather MITRE data
        mitre_ids = set()
        looked_up_ids = set()
        for tool_call in tool_calls:
            tools_used.add(tool_call["name"])
            if tool_call["name"] == "get_mitre_technique":
                technique_id = tool_call["args"].get("technique_id", "")
                if technique_id:
                    technique_id = technique_id.upper()
                    looked_up_ids.add(technique_id)
                    if technique_id in grounded_ids:
                        mitre_ids.add(technique_id)
            elif tool_call["name"] == "search_mitre_techniques":
                query = tool_call["args"].get("query", alert_text)
                limit = tool_call["args"].get("limit", 5)
                # Only keep technique IDs whose similarity score actually clears the
                # threshold, instead of regexing every T-number out of the raw result
                # string (which also matched IDs mentioned incidentally in descriptions).
                for hit in search_mitre_techniques_raw(query, limit=limit):
                    tid = hit.get("id")
                    score = hit.get("score", 0)
                    if tid and score >= MITRE_SCORE_THRESHOLD:
                        tid = str(tid).upper()
                        looked_up_ids.add(tid)
                        mitre_ids.add(tid)

        # Also check alert's existing MITRE techniques (from rule-based detection - trusted)
        mitre_ids.update(alert.mitre_techniques)
        looked_up_ids.update(alert.mitre_techniques)

        # Get detailed technique info for everything looked up, even ids that didn't clear
        # grounding (useful context for the analyst), but only tagged ids go on the alert.
        # Use the structured dict (not the LLM-formatted string get_mitre_technique
        # returns) - incident_service.save_incident_from_state expects "info" to be a
        # dict with name/tactic/description/detection_methods and silently skips it
        # otherwise, which meant no MITRETechniqueModel row was ever persisted.
        for tech_id in looked_up_ids:
            tech_info = get_mitre_technique_raw(tech_id)
            threat_intel_data["mitre_techniques"].append({
                "technique_id": tech_id,
                "info": tech_info,
                "tagged": tech_id in mitre_ids,
            })

        # Update alert with MITRE techniques
        alert.mitre_techniques = list(mitre_ids)

    state["threat_intel"] = threat_intel_data
    state["agent_execution_log"].append({
        "agent_name": "threat_intel",
        "timestamp": datetime.utcnow().isoformat(),
        "duration_ms": (datetime.utcnow() - _started_at).total_seconds() * 1000,
        "tools_used": sorted(tools_used),
        "output_data": {
            "alerts_enriched": len(alerts),
            "mitre_techniques_found": len(threat_intel_data["mitre_techniques"]),
        },
    })

    return state

