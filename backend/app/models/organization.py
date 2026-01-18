"""Organization profile models for context-aware SOC analysis."""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime


class CriticalAsset(BaseModel):
    """Critical asset definition."""

    name: str
    type: str  # database, application, server, network_segment
    data_classification: str  # public, internal, confidential, restricted
    business_impact: str  # low, medium, high, critical
    rto_hours: int = Field(description="Recovery Time Objective")  # Recovery Time Objective
    rpo_hours: int = Field(description="Recovery Point Objective")  # Recovery Point Objective
    owner: str
    backup_available: bool = True


class NotificationContact(BaseModel):
    """Notification contact information."""

    role: str
    name: str
    email: str
    phone: Optional[str] = None
    notification_threshold: str = "high"  # low, medium, high, critical


class EscalationLevel(BaseModel):
    """Escalation level definition."""

    level: int
    trigger_severity: str
    trigger_time_hours: int
    contacts: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)


class EscalationMatrix(BaseModel):
    """Escalation matrix for incident response."""

    levels: List[EscalationLevel] = Field(default_factory=list)


class OrganizationProfile(BaseModel):
    """Organization profile for context-aware analysis."""

    name: str
    industry: str  # healthcare, finance, retail, technology, government, etc.

    # Regulatory environment
    applicable_regulations: List[str] = Field(
        default_factory=list, description="HIPAA, PCI-DSS, GDPR, SOX, etc."
    )
    data_residency_requirements: List[str] = Field(default_factory=list)

    # Critical assets
    crown_jewels: List[CriticalAsset] = Field(default_factory=list)

    # Risk parameters
    risk_appetite: str = "moderate"  # conservative, moderate, aggressive
    acceptable_downtime_hours: Dict[str, int] = Field(
        default_factory=dict, description="service -> hours"
    )

    # Response parameters
    incident_notification_contacts: List[NotificationContact] = Field(default_factory=list)
    escalation_matrix: Optional[EscalationMatrix] = None

    # Network context
    internal_ip_ranges: List[str] = Field(default_factory=list)
    trusted_domains: List[str] = Field(default_factory=list)
    approved_cloud_services: List[str] = Field(default_factory=list)

    # Metadata
    updated_at: Optional[datetime] = None

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }

