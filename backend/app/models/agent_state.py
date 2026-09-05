"""LangGraph agent state model."""

from typing import Any, Dict, List, Optional, TypedDict

from langchain_core.messages import BaseMessage
from pydantic import BaseModel

from app.models.incident import Alert, IncidentReport, ResponsePlan
from app.models.log_entry import LogEntry


class AgentMessage(BaseModel):
    """Structured agent message for execution log.

    Each agent populates duration_ms (wall-clock time), tools_used (LLM tool-call
    names, where the agent binds any), and output_data (small summary counters it
    already computes - e.g. alerts_generated, confidence_score). input_data is
    deliberately left empty by every agent: capturing the actual inputs (full log
    batches, prior agent outputs) would meaningfully bloat agent_execution_log's
    per-incident state/DB size for a debug-only feature, and the same information
    is already visible via the incident's own logs/alerts/report fields.
    """

    agent_name: str
    timestamp: str
    input_data: Dict[str, Any] = {}
    output_data: Dict[str, Any] = {}
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

