"""Incident and alert models."""

import uuid
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


SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def highest_severity(severities) -> "Severity":
    """The most severe of several severities (LOW if empty). Severity is a string enum, so plain
    max() would compare the words alphabetically and enum order lists CRITICAL first; use the rank."""
    return max(severities, key=SEVERITY_RANK.__getitem__, default=Severity.LOW)


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
    """Individual response action item with role assignment."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    priority: str  # immediate, short_term, long_term
    action_type: str  # block_ip, disable_account, isolate_host, etc.
    action: str
    description: str
    target: str
    status: str = "pending"
    
    # Role assignment
    assigned_team: str  # SOC, Network, Endpoint, IAM, Legal, PR, Management



class IOCEntry(BaseModel):
    """Indicator of Compromise entry."""

    value: str
    type: str  # ip, domain, url, hash, email
    related_techniques: List[str] = Field(default_factory=list)
    confidence: str = "medium"  # low, medium, high
    recommended_action: str  # block, monitor, investigate


class IOCCollection(BaseModel):
    """Collection of Indicators of Compromise."""

    ip_addresses: List[IOCEntry] = Field(default_factory=list)
    domains: List[IOCEntry] = Field(default_factory=list)
    urls: List[IOCEntry] = Field(default_factory=list)
    file_hashes: List[IOCEntry] = Field(default_factory=list)
    email_addresses: List[IOCEntry] = Field(default_factory=list)



class ResponsePlan(BaseModel):
    """Enhanced incident response plan with role-tagged actions."""

    incident_id: str = ""
    generated_at: Optional[datetime] = None
    
    containment_actions: List[ResponseAction] = Field(default_factory=list)
    investigation_steps: List[ResponseAction] = Field(default_factory=list)
    remediation_actions: List[ResponseAction] = Field(default_factory=list)
    long_term_improvements: List[ResponseAction] = Field(default_factory=list)
    
    # Team-specific views
    actions_by_team: Dict[str, List[ResponseAction]] = Field(default_factory=dict)
    






class DetectionGap(BaseModel):
    """Detection gap identification."""

    description: str
    affected_techniques: List[str] = Field(default_factory=list)
    recommended_telemetry: List[str] = Field(default_factory=list)
    priority: str = "medium"  # low, medium, high


class IncidentReport(BaseModel):
    """Enhanced complete incident analysis report."""

    # Existing fields (for backward compatibility)
    executive_summary: str = ""
    technical_findings: str = ""
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)  # Legacy string list
    root_cause: str = ""
    impact_assessment: str = ""
    confidence_score: float = Field(ge=0.0, le=1.0, default=0.0)
    reasoning_process: List[str] = Field(default_factory=list)
    
    # Structured IOCs
    indicators_of_compromise: Optional[IOCCollection] = None
    
    # Detection improvement suggestions
    detection_gaps: List[DetectionGap] = Field(default_factory=list)
    
    # Lessons learned
    lessons_learned: List[str] = Field(default_factory=list)


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

