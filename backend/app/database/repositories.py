"""Database repository pattern for data access."""

from typing import List, Optional
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database.models import (
    IncidentModel, AlertModel, MITRETechniqueModel, IncidentReportModel,
    ResponsePlanModel, AgentExecutionLogModel, LogEntryModel
)
from app.models.incident import Incident, Alert, MITRETechnique, IncidentReport, ResponsePlan, IncidentStatus, Severity
from app.models.log_entry import LogEntry


class IncidentRepository:
    """Repository for incident operations."""

    @staticmethod
    async def create(session: AsyncSession, incident_data: dict) -> IncidentModel:
        """Create a new incident."""
        incident = IncidentModel(**incident_data)
        session.add(incident)
        await session.commit()
        await session.refresh(incident)
        return incident

    @staticmethod
    async def get_by_id(session: AsyncSession, incident_id: str) -> Optional[IncidentModel]:
        """Get incident by ID with all relationships."""
        result = await session.execute(
            select(IncidentModel)
            .options(
                selectinload(IncidentModel.alerts),
                selectinload(IncidentModel.mitre_techniques),
                selectinload(IncidentModel.report),
                selectinload(IncidentModel.response_plan),
                selectinload(IncidentModel.agent_execution_log),
                selectinload(IncidentModel.log_entries),
            )
            .where(IncidentModel.id == incident_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def list(
        session: AsyncSession,
        status: Optional[IncidentStatus] = None,
        severity: Optional[Severity] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[IncidentModel]:
        """List incidents with filters."""
        query = select(IncidentModel).options(
            selectinload(IncidentModel.alerts),
            selectinload(IncidentModel.mitre_techniques),
        )

        conditions = []
        if status:
            conditions.append(IncidentModel.status == status)
        if severity:
            conditions.append(IncidentModel.severity == severity)

        if conditions:
            query = query.where(and_(*conditions))

        query = query.order_by(IncidentModel.created_at.desc()).limit(limit).offset(offset)

        result = await session.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def update(session: AsyncSession, incident_id: str, incident_data: dict) -> Optional[IncidentModel]:
        """Update an incident."""
        incident = await IncidentRepository.get_by_id(session, incident_id)
        if not incident:
            return None

        for key, value in incident_data.items():
            setattr(incident, key, value)

        incident.updated_at = datetime.utcnow()
        await session.commit()
        await session.refresh(incident)
        return incident

    @staticmethod
    async def delete(session: AsyncSession, incident_id: str) -> bool:
        """Delete an incident."""
        incident = await IncidentRepository.get_by_id(session, incident_id)
        if not incident:
            return False

        await session.delete(incident)
        await session.commit()
        return True

    @staticmethod
    async def model_to_pydantic(incident_model: IncidentModel) -> Incident:
        """Convert SQLAlchemy model to Pydantic model."""
        return Incident(
            id=incident_model.id,
            created_at=incident_model.created_at,
            updated_at=incident_model.updated_at,
            status=incident_model.status,
            severity=incident_model.severity,
            alerts=[
                Alert(
                    id=alert.id,
                    timestamp=alert.timestamp,
                    severity=alert.severity,
                    title=alert.title,
                    description=alert.description,
                    detection_rule=alert.detection_rule,
                    evidence=alert.evidence or [],
                    related_logs=alert.related_logs or [],
                    mitre_techniques=alert.mitre_techniques or [],
                )
                for alert in incident_model.alerts
            ],
            threat_intel=incident_model.threat_intel or {},
            mitre_techniques=[
                MITRETechnique(
                    technique_id=tech.technique_id,
                    name=tech.name,
                    tactic=tech.tactic,
                    description=tech.description or "",
                    detection_methods=tech.detection_methods or [],
                )
                for tech in incident_model.mitre_techniques
            ],
            report=IncidentReport(
                executive_summary=incident_model.report.executive_summary,
                technical_findings=incident_model.report.technical_findings,
                timeline=incident_model.report.timeline or [],
                affected_assets=incident_model.report.affected_assets or [],
                root_cause=incident_model.report.root_cause,
                impact_assessment=incident_model.report.impact_assessment,
                confidence_score=incident_model.report.confidence_score,
                reasoning_process=incident_model.report.reasoning_process or [],
            ) if incident_model.report else None,
            response_plan=ResponsePlan(
                containment_actions=incident_model.response_plan.containment_actions or [],
                investigation_steps=incident_model.response_plan.investigation_steps or [],
                remediation_actions=incident_model.response_plan.remediation_actions or [],
                long_term_improvements=incident_model.response_plan.long_term_improvements or [],
            ) if incident_model.response_plan else None,
            agent_execution_log=[
                {
                    "agent_name": log.agent_name,
                    "timestamp": log.timestamp.isoformat(),
                    "input_data": log.input_data or {},
                    "output_data": log.output_data or {},
                    "tools_used": log.tools_used or [],
                    "reasoning": log.reasoning,
                    "duration_ms": log.duration_ms,
                }
                for log in incident_model.agent_execution_log
            ],
            confidence_score=incident_model.confidence_score,
            false_positive_reason=incident_model.false_positive_reason,
        )


class LogEntryRepository:
    """Repository for log entry operations."""

    @staticmethod
    async def create_bulk(session: AsyncSession, log_entries: List[dict]) -> List[LogEntryModel]:
        """Create multiple log entries."""
        models = [LogEntryModel(**entry) for entry in log_entries]
        session.add_all(models)
        await session.commit()
        for model in models:
            await session.refresh(model)
        return models

    @staticmethod
    async def query(
        session: AsyncSession,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        user: Optional[str] = None,
        action: Optional[str] = None,
        time_range_hours: int = 24,
        limit: int = 100,
    ) -> List[LogEntryModel]:
        """Query log entries with filters."""
        query = select(LogEntryModel)

        conditions = []
        if source_ip:
            conditions.append(LogEntryModel.source_ip == source_ip)
        if destination_ip:
            conditions.append(LogEntryModel.destination_ip == destination_ip)
        if user:
            conditions.append(LogEntryModel.user == user)
        if action:
            conditions.append(LogEntryModel.action == action)

        if time_range_hours:
            time_threshold = datetime.utcnow() - timedelta(hours=time_range_hours)
            conditions.append(LogEntryModel.timestamp >= time_threshold)

        if conditions:
            query = query.where(and_(*conditions))

        query = query.order_by(LogEntryModel.timestamp.desc()).limit(limit)

        result = await session.execute(query)
        return list(result.scalars().all())

