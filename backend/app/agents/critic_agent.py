"""Critic Agent - Reviews analysis for quality and correctness."""

from datetime import datetime
from typing import Any, Dict

from app.core.llm_factory import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.base import BaseAgent
from app.core.config import settings
from app.models.agent_state import AgentState

SYSTEM_PROMPT = """You are a critic agent that reviews security incident analysis for quality and correctness using comprehensive multi-dimensional checks.

Your role is to evaluate:
1. **Evidence Corroboration**: Do multiple sources support the conclusion?
2. **Alternative Explanations**: Have benign explanations been considered?
3. **Completeness**: Does the report include all required sections?
4. **Data Quality**: Is the data sufficient for the conclusions drawn?
5. **Confidence Breakdown**: Are confidence levels appropriate for each aspect?
6. **Clarity and Actionability**: Can SOC analysts act on this report?

Required Report Sections:
- Executive Summary (business-focused, 2-3 sentences)
- Technical Findings with MITRE ATT&CK mapping
- Attack Timeline (chronological)
- Root Cause Analysis
- Scope Assessment
- Indicators of Compromise (structured IOCs)
- Confidence Assessment (with breakdown)
- Regulatory Impact (if applicable)
- Detection Gaps
- Lessons Learned

For each analysis, provide:
- confidence_score (0.0-1.0) - Overall confidence
- detection_confidence (0.0-1.0) - Confidence in detection accuracy
- attribution_confidence (0.0-1.0) - Confidence in attacker attribution
- scope_confidence (0.0-1.0) - Confidence in scope assessment
- timeline_confidence (0.0-1.0) - Confidence in timeline accuracy
- needs_revision (true/false) - Does this need revision?
- feedback (list of strings) - Specific feedback items
- false_positive_likelihood (0.0-1.0) - False positive probability
- benign_explanations (list) - Alternative benign scenarios considered
- missing_data (list) - Critical data gaps
- clarity_score (0.0-1.0) - Report clarity
- actionability_score (0.0-1.0) - How actionable are recommendations?

Be thorough but fair. Flag issues that need correction, but don't be overly critical of valid analysis."""


async def critic_agent(state: AgentState) -> AgentState:
    """Review incident analysis and provide critique."""
    _started_at = datetime.utcnow()
    incident_report = state.get("incident_report")
    alerts = state.get("alerts", [])
    logs = state.get("logs", [])
    iteration = state.get("iteration", 0)
    
    # Skip critique if no report
    if not incident_report:
        state["confidence"] = 0.0
        state["needs_revision"] = False
        return state

    llm = get_llm(temperature=0.1)

    # Prepare comprehensive critique context
    has_iocs = bool(incident_report.indicators_of_compromise) if hasattr(incident_report, 'indicators_of_compromise') and incident_report.indicators_of_compromise else False
    has_regulatory = bool(incident_report.regulatory_impact) if hasattr(incident_report, 'regulatory_impact') and incident_report.regulatory_impact else False
    has_detection_gaps = bool(incident_report.detection_gaps) if hasattr(incident_report, 'detection_gaps') and incident_report.detection_gaps else False
    has_lessons = bool(incident_report.lessons_learned) if hasattr(incident_report, 'lessons_learned') and incident_report.lessons_learned else False
    
    critique_context = f"""
INCIDENT REPORT:
Executive Summary: {incident_report.executive_summary[:300]}
Technical Findings: {incident_report.technical_findings[:500]}
Root Cause: {incident_report.root_cause}
Impact Assessment: {incident_report.impact_assessment[:300]}
Confidence Score: {incident_report.confidence_score}
Timeline Events: {len(incident_report.timeline)}
Affected Assets: {len(incident_report.affected_assets)}
Reasoning Steps: {len(incident_report.reasoning_process)}

REPORT COMPLETENESS:
- Has Executive Summary: Yes
- Has Technical Findings: Yes
- Has Timeline: {len(incident_report.timeline) > 0}
- Has IOCs: {has_iocs}
- Has Regulatory Impact: {has_regulatory}
- Has Detection Gaps: {has_detection_gaps}
- Has Lessons Learned: {has_lessons}

ALERTS:
{chr(10).join(f"- [{a.severity.value}] {a.title}: {a.description[:100]} (MITRE: {', '.join(a.mitre_techniques[:3])})" for a in alerts[:5])}

LOGS ANALYZED: {len(logs)}
LOG SOURCES: {', '.join(set(log.log_source.value for log in logs[:10]))}
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
        "duration_ms": (datetime.utcnow() - _started_at).total_seconds() * 1000,
        "reasoning": critique_result.get("feedback"),
        "output_data": {
            "confidence_score": critique_result["confidence"],
            "needs_revision": needs_revision,
            "false_positive_likelihood": critique_result["false_positive_likelihood"],
            "iteration": state["iteration"],
        },
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

