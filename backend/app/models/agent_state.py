"""LangGraph agent state model."""

from typing import Any, Dict, List, Optional, TypedDict

from langchain_core.messages import BaseMessage
from pydantic import BaseModel

from app.models.incident import Alert, IncidentReport, ResponsePlan
from app.models.log_entry import LogEntry


class AgentMessage(BaseModel):
    """Structured agent message for execution log."""

    agent_name: str
    timestamp: str
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    tools_used: List[str] = []
    reasoning: Optional[str] = None
    duration_ms: Optional[float] = None


class AgentState(TypedDict):
    """LangGraph state definition."""

    # Input
    logs: List[LogEntry]
    raw_logs: List[str]

    # Intermediate processing
    alerts: List[Alert]
    threat_intel: Dict[str, Any]
    incident_report: Optional[IncidentReport]
    response_plan: Optional[ResponsePlan]

    # Reflection loop
    confidence: float
    iteration: int
    needs_revision: bool
    critique_feedback: Optional[str]

    # Execution tracking
    messages: List[BaseMessage]
    agent_execution_log: List[Dict[str, Any]]
    incident_id: Optional[str]

