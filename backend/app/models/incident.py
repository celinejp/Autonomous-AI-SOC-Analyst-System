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
    requires_approval: bool = False
    approval_level: Optional[str] = None  # team_lead, manager, ciso
    
    # Execution details
    automated: bool = False
    automation_available: bool = False
    manual_steps: Optional[List[str]] = Field(default_factory=list)
    
    # Timing
    sla_hours: Optional[int] = None
    
    # Dependencies
    depends_on: List[str] = Field(default_factory=list)  # IDs of other actions
    
    # Verification
    success_criteria: str = ""
    verification_steps: List[str] = Field(default_factory=list)


class StakeholderNotification(BaseModel):
    """Stakeholder notification entry."""

    recipient_role: str  # CISO, Legal, PR, Business Owner, etc.
    notification_type: str  # immediate_alert, status_update, final_report
    content_summary: str
    delivery_method: str  # email, phone, ticket
    deadline_hours: Optional[int] = None


class IOCEntry(BaseModel):
    """Indicator of Compromise entry."""

    value: str
    type: str  # ip, domain, url, hash, email
    reputation: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
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


class EmailGatewayBlocks(BaseModel):
    """Email gateway block list."""

    sender_addresses: List[str] = Field(default_factory=list)
    sender_domains: List[str] = Field(default_factory=list)
    subject_patterns: List[str] = Field(default_factory=list)
    attachment_hashes: List[str] = Field(default_factory=list)


class IOCBlocklistUpdate(BaseModel):
    """IOC blocklist update instructions."""

    firewall_ip_blocks: List[str] = Field(default_factory=list)
    dns_sinkhole_domains: List[str] = Field(default_factory=list)
    proxy_url_blocks: List[str] = Field(default_factory=list)
    edr_hash_blocks: List[str] = Field(default_factory=list)
    email_gateway_blocks: EmailGatewayBlocks = Field(default_factory=lambda: EmailGatewayBlocks())


class ProposedDetectionRule(BaseModel):
    """Proposed detection rule for improvement."""

    name: str
    description: str
    attack_technique: str
    platform: str  # splunk, sentinel, elastic, sigma
    query: str  # SPL, KQL, or Sigma YAML
    severity: str
    false_positive_notes: str = ""


class ResponsePlan(BaseModel):
    """Enhanced incident response plan with role-tagged actions."""

    incident_id: str = ""
    generated_at: Optional[datetime] = None
    
    # Categorized actions by timing
    immediate_actions: List[ResponseAction] = Field(default_factory=list)  # < 1 hour
    short_term_actions: List[ResponseAction] = Field(default_factory=list)  # 1-24 hours
    long_term_actions: List[ResponseAction] = Field(default_factory=list)  # > 24 hours
    
    # Legacy compatibility
    containment_actions: List[ResponseAction] = Field(default_factory=list)
    investigation_steps: List[ResponseAction] = Field(default_factory=list)
    remediation_actions: List[ResponseAction] = Field(default_factory=list)
    long_term_improvements: List[ResponseAction] = Field(default_factory=list)
    
    # Team-specific views
    actions_by_team: Dict[str, List[ResponseAction]] = Field(default_factory=dict)
    
    # Communication plan
    stakeholder_notifications: List[StakeholderNotification] = Field(default_factory=list)
    
    # IOC deployment
    ioc_blocklist_updates: Optional[IOCBlocklistUpdate] = None
    
    # Detection improvements
    detection_rule_updates: List[ProposedDetectionRule] = Field(default_factory=list)


class ImpactedAsset(BaseModel):
    """Impacted asset with business context."""

    hostname: str
    ip_address: Optional[str] = None
    asset_type: str  # workstation, server, domain_controller, database, etc.
    business_service: Optional[str] = None  # billing-api, patient-records, etc.
    criticality: str  # low, medium, high, critical
    data_classification: Optional[str] = None  # public, internal, confidential, restricted
    owner: Optional[str] = None
    actions_taken: List[str] = Field(default_factory=list)


class DataCompletenessAssessment(BaseModel):
    """Data completeness assessment."""

    available_sources: List[str] = Field(default_factory=list)
    missing_sources: List[str] = Field(default_factory=list)
    coverage_score: float = Field(ge=0.0, le=1.0, default=0.0)
    gaps_impact: str = ""


class ConfidenceAssessment(BaseModel):
    """Confidence breakdown assessment."""

    overall_confidence: float = Field(ge=0.0, le=1.0)
    detection_confidence: float = Field(ge=0.0, le=1.0)
    attribution_confidence: float = Field(ge=0.0, le=1.0)
    scope_confidence: float = Field(ge=0.0, le=1.0)
    timeline_confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class RegulatoryImpact(BaseModel):
    """Regulatory impact assessment."""

    applicable_regulations: List[str] = Field(default_factory=list)  # GDPR, HIPAA, PCI-DSS, etc.
    data_categories_at_risk: List[str] = Field(default_factory=list)
    notification_required: bool = False
    notification_deadline_hours: Optional[int] = None
    recommended_actions: List[str] = Field(default_factory=list)


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
    
    # New structured sections
    impacted_assets: List[ImpactedAsset] = Field(default_factory=list)  # Structured asset list
    
    # Structured IOCs
    indicators_of_compromise: Optional[IOCCollection] = None
    
    # Data completeness assessment
    data_completeness: Optional[DataCompletenessAssessment] = None
    
    # Analysis confidence breakdown
    confidence_assessment: Optional[ConfidenceAssessment] = None
    
    # Regulatory implications
    regulatory_impact: Optional[RegulatoryImpact] = None
    
    # Detection improvement suggestions
    detection_gaps: List[DetectionGap] = Field(default_factory=list)
    proposed_detection_rules: List[ProposedDetectionRule] = Field(default_factory=list)
    
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

