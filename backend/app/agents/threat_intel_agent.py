"""Threat Intel Agent - Retrieves MITRE ATT&CK and threat intelligence context."""

from datetime import datetime
from typing import Any, Dict, List

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base import BaseAgent
from app.core.config import settings
from app.models.agent_state import AgentState
from app.tools.mitre_search import get_mitre_technique, search_mitre_techniques

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
    alerts = state.get("alerts", [])
    if not alerts:
        state["threat_intel"] = {}
        return state

    llm = ChatAnthropic(
        model="claude-sonnet-4-20250514",
        temperature=0.1,
        anthropic_api_key=settings.anthropic_api_key,
    ).bind_tools([get_mitre_technique, search_mitre_techniques])

    threat_intel_data = {
        "mitre_techniques": [],
        "threat_actors": [],
        "attack_patterns": [],
        "iocs": [],
    }

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
        
        # Process tool calls and gather MITRE data
        mitre_ids = set()
        for tool_call in tool_calls:
            if tool_call["name"] == "get_mitre_technique":
                technique_id = tool_call["args"].get("technique_id", "")
                if technique_id:
                    mitre_ids.add(technique_id.upper())
            elif tool_call["name"] == "search_mitre_techniques":
                query = tool_call["args"].get("query", alert_text)
                # Extract technique IDs from search results
                search_result = search_mitre_techniques(query)
                # Parse technique IDs from result
                import re
                ids = re.findall(r'T\d{4}(?:\.\d{3})?', search_result)
                mitre_ids.update(ids)

        # Also check alert's existing MITRE techniques
        mitre_ids.update(alert.mitre_techniques)

        # Get detailed technique info
        for tech_id in mitre_ids:
            tech_info = get_mitre_technique(tech_id)
            threat_intel_data["mitre_techniques"].append({
                "technique_id": tech_id,
                "info": tech_info,
            })

        # Update alert with MITRE techniques
        alert.mitre_techniques = list(mitre_ids)

    state["threat_intel"] = threat_intel_data
    state["agent_execution_log"].append({
        "agent_name": "threat_intel",
        "timestamp": datetime.utcnow().isoformat(),
        "alerts_enriched": len(alerts),
        "mitre_techniques_found": len(threat_intel_data["mitre_techniques"]),
    })

    return state

