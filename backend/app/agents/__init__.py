"""SOC Analyst Agents."""

from app.agents.ingest_agent import ingest_agent
from app.agents.detection_agent import detection_agent
from app.agents.threat_intel_agent import threat_intel_agent
from app.agents.analyst_agent import analyst_agent
from app.agents.response_planner import response_planner_agent
from app.agents.critic_agent import critic_agent

__all__ = [
    "ingest_agent",
    "detection_agent",
    "threat_intel_agent",
    "analyst_agent",
    "response_planner_agent",
    "critic_agent",
]

