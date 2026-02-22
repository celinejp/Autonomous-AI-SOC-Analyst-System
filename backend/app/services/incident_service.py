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

        # Normalize alerts to support both dict and model (e.g. from serialized stream state)
        def _severity(a):
            s = getattr(a, "severity", None) or (a.get("severity") if isinstance(a, dict) else None)
            return s if isinstance(s, Severity) else Severity(s) if s else Severity.LOW
        max_severity = Severity.LOW
        if alerts:
            severities = [_severity(a) for a in alerts]
            max_severity = max(severities, key=lambda s: list(Severity).index(s))

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

        # Save alerts (support dict or model)
        def _alert_attr(alert, key, default=None):
            if isinstance(alert, dict):
                return alert.get(key, default)
            return getattr(alert, key, default)
        for alert in alerts:
            ts = _alert_attr(alert, "timestamp")
            if hasattr(ts, "isoformat"):
                pass
            elif isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    ts = datetime.utcnow()
            else:
                ts = datetime.utcnow()
            sev = _alert_attr(alert, "severity")
            if isinstance(sev, str):
                try:
                    sev = Severity(sev)
                except ValueError:
                    sev = Severity.LOW
            alert_model = AlertModel(
                incident_id=incident_id,
                timestamp=ts,
                severity=sev,
                title=_alert_attr(alert, "title", ""),
                description=_alert_attr(alert, "description", ""),
                detection_rule=_alert_attr(alert, "detection_rule", ""),
                evidence=_alert_attr(alert, "evidence") or [],
                related_logs=_alert_attr(alert, "related_logs") or [],
                mitre_techniques=_alert_attr(alert, "mitre_techniques") or [],
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

        # Save report (support dict or model)
        def _report_attr(report, key, default=None):
            if report is None:
                return default
            if isinstance(report, dict):
                return report.get(key, default)
            return getattr(report, key, default)
        if incident_report:
            report_model = IncidentReportModel(
                incident_id=incident_id,
                executive_summary=_report_attr(incident_report, "executive_summary") or "",
                technical_findings=_report_attr(incident_report, "technical_findings") or "",
                timeline=_report_attr(incident_report, "timeline") or "",
                affected_assets=_report_attr(incident_report, "affected_assets") or "",
                root_cause=_report_attr(incident_report, "root_cause") or "",
                impact_assessment=_report_attr(incident_report, "impact_assessment") or "",
                confidence_score=float(_report_attr(incident_report, "confidence_score") or 0),
                reasoning_process=_report_attr(incident_report, "reasoning_process") or "",
            )
            session.add(report_model)

        # Save response plan (support dict or model)
        def _plan_list(plan, key):
            if not plan:
                return []
            val = plan.get(key, []) if isinstance(plan, dict) else getattr(plan, key, [])
            if not val:
                return []
            return [x.dict() if hasattr(x, "dict") else (x if isinstance(x, dict) else {}) for x in val]
        if response_plan:
            plan_model = ResponsePlanModel(
                incident_id=incident_id,
                containment_actions=_plan_list(response_plan, "containment_actions"),
                investigation_steps=_plan_list(response_plan, "investigation_steps"),
                remediation_actions=_plan_list(response_plan, "remediation_actions"),
                long_term_improvements=_plan_list(response_plan, "long_term_improvements"),
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

        # Save log entries (support dict or model)
        def _log_attr(log, key, default=None):
            if isinstance(log, dict):
                return log.get(key, default)
            return getattr(log, key, default)
        if logs:
            log_entries_data = []
            for log in logs:
                ls = _log_attr(log, "log_source")
                if hasattr(ls, "value"):
                    ls = ls.value
                elif isinstance(ls, str):
                    pass
                else:
                    ls = "unknown"
                log_entries_data.append({
                    "incident_id": incident_id,
                    "timestamp": _log_attr(log, "timestamp") or datetime.utcnow(),
                    "source_ip": _log_attr(log, "source_ip"),
                    "destination_ip": _log_attr(log, "destination_ip"),
                    "destination_port": _log_attr(log, "destination_port"),
                    "user": _log_attr(log, "user"),
                    "action": _log_attr(log, "action"),
                    "status": _log_attr(log, "status"),
                    "log_source": ls,
                    "raw_log": _log_attr(log, "raw_log"),
                    "metadata": _log_attr(log, "metadata") or {},
                })
            await LogEntryRepository.create_bulk(session, log_entries_data)

        await session.commit()
        await session.refresh(incident_model)
        return incident_id

