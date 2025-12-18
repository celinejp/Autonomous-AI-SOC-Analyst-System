"""Critic Agent - Reviews analysis for quality and correctness."""

from datetime import datetime
from typing import Any, Dict

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base import BaseAgent
from app.core.config import settings
from app.models.agent_state import AgentState

SYSTEM_PROMPT = """You are a critic agent that reviews security incident analysis for quality and correctness.

Your role is to:
1. Check for logical inconsistencies in the analysis
2. Validate that evidence supports conclusions
3. Identify potential false positives
4. Assess confidence levels appropriately
5. Challenge assumptions and conclusions
6. Identify gaps in reasoning or missing information

For each analysis, provide:
- confidence_score (0.0-1.0) - How confident is the analysis?
- needs_revision (true/false) - Does this need to be revised?
- feedback (string) - Specific feedback for improvement
- false_positive_likelihood (0.0-1.0) - Could this be a false positive?

Be thorough but fair. Flag issues that need correction, but don't be overly critical of valid analysis."""


async def critic_agent(state: AgentState) -> AgentState:
    """Review incident analysis and provide critique."""
    incident_report = state.get("incident_report")
    alerts = state.get("alerts", [])
    logs = state.get("logs", [])
    iteration = state.get("iteration", 0)
    
    # Skip critique if no report
    if not incident_report:
        state["confidence"] = 0.0
        state["needs_revision"] = False
        return state

    llm = ChatAnthropic(
        model="claude-sonnet-4-20250514",
        temperature=0.1,
        anthropic_api_key=settings.anthropic_api_key,
    )

    # Prepare critique context
    critique_context = f"""
INCIDENT REPORT:
Executive Summary: {incident_report.executive_summary}
Technical Findings: {incident_report.technical_findings[:500]}
Root Cause: {incident_report.root_cause}
Confidence Score: {incident_report.confidence_score}
Reasoning Steps: {len(incident_report.reasoning_process)}

ALERTS:
{chr(10).join(f"- [{a.severity.value}] {a.title}: {a.description[:100]}" for a in alerts[:5]))}

LOGS ANALYZED: {len(logs)}
"""

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"Review this incident analysis:\n\n{critique_context}\n\nProvide critical feedback."),
    ]

    response = await llm.ainvoke(messages)
    content = response.content

    # Parse critique from response
    critique_result = _parse_critique(content, incident_report)
    
    # Determine if revision is needed
    needs_revision = (
        critique_result["confidence"] < 0.7 or
        critique_result["false_positive_likelihood"] > 0.5 or
        critique_result["needs_revision"]
    )
    
    # Limit iterations to prevent infinite loops
    if iteration >= 3:
        needs_revision = False

    state["confidence"] = critique_result["confidence"]
    state["needs_revision"] = needs_revision
    state["critique_feedback"] = critique_result["feedback"]
    state["iteration"] = iteration + 1 if needs_revision else iteration
    
    state["agent_execution_log"].append({
        "agent_name": "critic",
        "timestamp": datetime.utcnow().isoformat(),
        "confidence_score": critique_result["confidence"],
        "needs_revision": needs_revision,
        "false_positive_likelihood": critique_result["false_positive_likelihood"],
        "iteration": state["iteration"],
    })

    return state


def _parse_critique(content: str, incident_report) -> Dict[str, Any]:
    """Parse critique from LLM response."""
    import json
    import re
    
    # Try to extract JSON
    json_match = re.search(r'\{.*\}', content, re.DOTALL)
    if json_match:
        try:
            critique_data = json.loads(json_match.group())
            return {
                "confidence": float(critique_data.get("confidence_score", incident_report.confidence_score)),
                "needs_revision": critique_data.get("needs_revision", False),
                "feedback": critique_data.get("feedback", content),
                "false_positive_likelihood": float(critique_data.get("false_positive_likelihood", 0.2)),
            }
        except Exception:
            pass
    
    # Fallback: parse from text
    confidence = incident_report.confidence_score
    needs_revision = False
    false_positive_likelihood = 0.2
    
    # Look for confidence indicators
    if "low confidence" in content.lower() or "uncertain" in content.lower():
        confidence = min(confidence, 0.6)
        needs_revision = True
    if "high confidence" in content.lower() or "confident" in content.lower():
        confidence = max(confidence, 0.8)
    
    # Look for false positive indicators
    if "false positive" in content.lower() or "legitimate" in content.lower():
        false_positive_likelihood = 0.6
        needs_revision = True
    
    # Look for inconsistency indicators
    if "inconsistent" in content.lower() or "contradict" in content.lower():
        needs_revision = True
    
    return {
        "confidence": confidence,
        "needs_revision": needs_revision,
        "feedback": content,
        "false_positive_likelihood": false_positive_likelihood,
    }

