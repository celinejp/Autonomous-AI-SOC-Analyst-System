"""SQLAlchemy database models."""

from datetime import datetime
from typing import Dict, Any
import json

from sqlalchemy import Column, String, DateTime, Float, Integer, Text, ForeignKey, JSON, Enum as SQLEnum, Boolean
from sqlalchemy.dialects.postgresql import UUID
from pgvector.sqlalchemy import Vector
from sqlalchemy.orm import relationship
import uuid

from app.database.postgres import Base
from app.models.incident import Severity, IncidentStatus


class IncidentModel(Base):
    """Incident database model."""

    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    status = Column(SQLEnum(IncidentStatus), nullable=False, default=IncidentStatus.NEW)
    severity = Column(SQLEnum(Severity), nullable=False)
    threat_intel = Column(JSON, default=dict)
    confidence_score = Column(Float, default=0.0, nullable=False)
    false_positive_reason = Column(Text, nullable=True)
    search_text = Column(Text, nullable=True)
    embedding = Column(Vector(768), nullable=True)

    # Relationships
    alerts = relationship("AlertModel", back_populates="incident", cascade="all, delete-orphan")
    mitre_techniques = relationship("MITRETechniqueModel", back_populates="incident", cascade="all, delete-orphan")
    report = relationship("IncidentReportModel", back_populates="incident", uselist=False, cascade="all, delete-orphan")
    response_plan = relationship("ResponsePlanModel", back_populates="incident", uselist=False, cascade="all, delete-orphan")
    agent_execution_log = relationship("AgentExecutionLogModel", back_populates="incident", cascade="all, delete-orphan")
    log_entries = relationship("LogEntryModel", back_populates="incident", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "status": self.status.value if self.status else None,
            "severity": self.severity.value if self.severity else None,
            "threat_intel": self.threat_intel or {},
            "confidence_score": self.confidence_score,
            "false_positive_reason": self.false_positive_reason,
        }


class AlertModel(Base):
    """Alert database model."""

    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(UUID(as_uuid=False), ForeignKey("incidents.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    detection_rule = Column(String(200), nullable=False)
    evidence = Column(JSON, default=list)
    related_logs = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)

    # Relationships
    incident = relationship("IncidentModel", back_populates="alerts")


class MITRETechniqueModel(Base):
    """MITRE ATT&CK technique database model."""

    __tablename__ = "mitre_techniques"

    id = Column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(UUID(as_uuid=False), ForeignKey("incidents.id"), nullable=False)
    technique_id = Column(String(50), nullable=False)
    name = Column(String(200), nullable=False)
    tactic = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    detection_methods = Column(JSON, default=list)

    # Relationships
    incident = relationship("IncidentModel", back_populates="mitre_techniques")


class IncidentReportModel(Base):
    """Incident report database model."""

    __tablename__ = "incident_reports"

    id = Column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(UUID(as_uuid=False), ForeignKey("incidents.id"), nullable=False, unique=True)
    executive_summary = Column(Text, nullable=False)
    technical_findings = Column(Text, nullable=False)
    timeline = Column(JSON, default=list)
    affected_assets = Column(JSON, default=list)
    root_cause = Column(Text, nullable=False)
    impact_assessment = Column(Text, nullable=False)
    confidence_score = Column(Float, default=0.0, nullable=False)
    reasoning_process = Column(JSON, default=list)
    embedding = Column(Vector(768), nullable=True)

    # Relationships
    incident = relationship("IncidentModel", back_populates="report")


class ResponsePlanModel(Base):
    """Response plan database model."""

    __tablename__ = "response_plans"

    id = Column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(UUID(as_uuid=False), ForeignKey("incidents.id"), nullable=False, unique=True)
    containment_actions = Column(JSON, default=list)
    investigation_steps = Column(JSON, default=list)
    remediation_actions = Column(JSON, default=list)
    long_term_improvements = Column(JSON, default=list)
    actions_by_team = Column(JSON, default=dict)

    # Relationships
    incident = relationship("IncidentModel", back_populates="response_plan")


class AgentExecutionLogModel(Base):
    """Agent execution log database model."""

    __tablename__ = "agent_execution_logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(UUID(as_uuid=False), ForeignKey("incidents.id"), nullable=False)
    agent_name = Column(String(100), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    input_data = Column(JSON, default=dict)
    output_data = Column(JSON, default=dict)
    tools_used = Column(JSON, default=list)
    reasoning = Column(Text, nullable=True)
    duration_ms = Column(Float, nullable=True)

    # Relationships
    incident = relationship("IncidentModel", back_populates="agent_execution_log")


class LogEntryModel(Base):
    """Log entry database model."""

    __tablename__ = "log_entries"

    id = Column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(UUID(as_uuid=False), ForeignKey("incidents.id"), nullable=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    destination_port = Column(Integer, nullable=True)
    user = Column(String(200), nullable=True)
    action = Column(String(200), nullable=False)
    status = Column(String(50), nullable=False)
    log_source = Column(String(50), nullable=False)
    raw_log = Column(Text, nullable=False)
    log_metadata = Column(JSON, default=dict)

    # Relationships
    incident = relationship("IncidentModel", back_populates="log_entries")

