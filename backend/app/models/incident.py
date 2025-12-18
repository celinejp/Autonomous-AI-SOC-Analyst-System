"""Incident and alert models."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, Enum):
    """Incident status."""

    NEW = "new"
    IN_PROGRESS = "in_progress"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(BaseModel):
    """Security alert model."""

    id: Optional[str] = None
    timestamp: datetime
    severity: Severity
    title: str
    description: str
    detection_rule: str
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    related_logs: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class MITRETechnique(BaseModel):
    """MITRE ATT&CK technique reference."""

    technique_id: str
    name: str
    tactic: str
    description: str
    detection_methods: List[str] = Field(default_factory=list)


class ResponseAction(BaseModel):
    """Individual response action item."""

    priority: str  # immediate, high, medium, low
    action: str
    description: str
    status: str = "pending"


class ResponsePlan(BaseModel):
    """Incident response plan."""

    containment_actions: List[ResponseAction] = Field(default_factory=list)
    investigation_steps: List[ResponseAction] = Field(default_factory=list)
    remediation_actions: List[ResponseAction] = Field(default_factory=list)
    long_term_improvements: List[ResponseAction] = Field(default_factory=list)


class IncidentReport(BaseModel):
    """Complete incident analysis report."""

    executive_summary: str
    technical_findings: str
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    root_cause: str
    impact_assessment: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    reasoning_process: List[str] = Field(default_factory=list)


class Incident(BaseModel):
    """Complete incident model."""

    id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    status: IncidentStatus
    severity: Severity
    alerts: List[Alert] = Field(default_factory=list)
    threat_intel: Dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: List[MITRETechnique] = Field(default_factory=list)
    report: Optional[IncidentReport] = None
    response_plan: Optional[ResponsePlan] = None
    agent_execution_log: List[Dict[str, Any]] = Field(default_factory=list)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    false_positive_reason: Optional[str] = None

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }

