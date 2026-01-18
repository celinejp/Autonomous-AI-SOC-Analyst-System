"""Service layer for incident operations."""

from typing import List, Optional
from datetime import datetime
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories import IncidentRepository, LogEntryRepository
from app.database.models import (
    AlertModel, MITRETechniqueModel, IncidentReportModel,
    ResponsePlanModel, AgentExecutionLogModel
)
from app.models.incident import Incident, IncidentStatus, Severity, Alert, IncidentReport, ResponsePlan
from app.models.log_entry import LogEntry


class IncidentService:
    """Service for incident business logic."""

    @staticmethod
    async def save_incident_from_state(session: AsyncSession, state: dict) -> str:
        """Save an incident from agent state."""
        incident_id = state.get("incident_id") or str(uuid.uuid4())

        # Extract data from state
        alerts = state.get("alerts", [])
        threat_intel = state.get("threat_intel", {})
        incident_report = state.get("incident_report")
        response_plan = state.get("response_plan")
        logs = state.get("logs", [])
        agent_execution_log = state.get("agent_execution_log", [])

        # Determine severity
        max_severity = Severity.LOW
        if alerts:
            max_severity = max((a.severity for a in alerts), key=lambda s: list(Severity).index(s))

        # Create incident
        incident_data = {
            "id": incident_id,
            "status": IncidentStatus.NEW,
            "severity": max_severity,
            "threat_intel": threat_intel,
            "confidence_score": state.get("confidence", 0.0),
        }

        # Check if incident exists
        existing = await IncidentRepository.get_by_id(session, incident_id)
        if existing:
            incident_model = await IncidentRepository.update(session, incident_id, incident_data)
        else:
            incident_model = await IncidentRepository.create(session, incident_data)

        # Save alerts
        for alert in alerts:
            alert_model = AlertModel(
                incident_id=incident_id,
                timestamp=alert.timestamp,
                severity=alert.severity,
                title=alert.title,
                description=alert.description,
                detection_rule=alert.detection_rule,
                evidence=alert.evidence,
                related_logs=alert.related_logs,
                mitre_techniques=alert.mitre_techniques,
            )
            session.add(alert_model)

        # Save MITRE techniques
        mitre_techniques = threat_intel.get("mitre_techniques", [])
        for tech_data in mitre_techniques:
            tech_info = tech_data.get("info", {}) if isinstance(tech_data, dict) else {}
            if isinstance(tech_info, str):
                # Parse if it's a string
                continue
            
            technique_id = tech_data.get("technique_id") or tech_info.get("id", "")
            if technique_id:
                mitre_model = MITRETechniqueModel(
                    incident_id=incident_id,
                    technique_id=technique_id,
                    name=tech_info.get("name", ""),
                    tactic=tech_info.get("tactic", ""),
                    description=tech_info.get("description", ""),
                    detection_methods=tech_info.get("detection_methods", []),
                )
                session.add(mitre_model)

        # Save report
        if incident_report:
            report_model = IncidentReportModel(
                incident_id=incident_id,
                executive_summary=incident_report.executive_summary,
                technical_findings=incident_report.technical_findings,
                timeline=incident_report.timeline,
                affected_assets=incident_report.affected_assets,
                root_cause=incident_report.root_cause,
                impact_assessment=incident_report.impact_assessment,
                confidence_score=incident_report.confidence_score,
                reasoning_process=incident_report.reasoning_process,
            )
            session.add(report_model)

        # Save response plan
        if response_plan:
            plan_model = ResponsePlanModel(
                incident_id=incident_id,
                containment_actions=[a.dict() for a in response_plan.containment_actions],
                investigation_steps=[a.dict() for a in response_plan.investigation_steps],
                remediation_actions=[a.dict() for a in response_plan.remediation_actions],
                long_term_improvements=[a.dict() for a in response_plan.long_term_improvements],
            )
            session.add(plan_model)

        # Save agent execution logs
        for log_entry in agent_execution_log:
            timestamp_str = log_entry.get("timestamp")
            if isinstance(timestamp_str, str):
                try:
                    log_timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    log_timestamp = datetime.utcnow()
            else:
                log_timestamp = datetime.utcnow()
            
            log_model = AgentExecutionLogModel(
                incident_id=incident_id,
                agent_name=log_entry.get("agent_name", ""),
                timestamp=log_timestamp,
                input_data=log_entry.get("input_data", {}),
                output_data=log_entry.get("output_data", {}),
                tools_used=log_entry.get("tools_used", []),
                reasoning=log_entry.get("reasoning"),
                duration_ms=log_entry.get("duration_ms"),
            )
            session.add(log_model)

        # Save log entries
        if logs:
            log_entries_data = [
                {
                    "incident_id": incident_id,
                    "timestamp": log.timestamp,
                    "source_ip": log.source_ip,
                    "destination_ip": log.destination_ip,
                    "destination_port": log.destination_port,
                    "user": log.user,
                    "action": log.action,
                    "status": log.status,
                    "log_source": log.log_source.value,
                    "raw_log": log.raw_log,
                    "metadata": log.metadata,
                }
                for log in logs
            ]
            await LogEntryRepository.create_bulk(session, log_entries_data)

        await session.commit()
        await session.refresh(incident_model)
        return incident_id

