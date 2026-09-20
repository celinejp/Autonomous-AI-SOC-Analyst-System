"""SOC KPI metrics service."""

from datetime import datetime
from typing import Dict
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.database.models import IncidentModel, AlertModel, IncidentStatus
from app.core.logging import get_logger

logger = get_logger(__name__)


class SOCMetrics(BaseModel):
    """SOC KPI metrics model."""

    # Quality metrics
    false_positive_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    true_positive_rate: float = Field(default=0.0, ge=0.0, le=1.0)

    # Volume metrics
    alerts_received: int = 0
    alerts_closed: int = 0
    alerts_escalated: int = 0
    incidents_created: int = 0

    alert_reduction_ratio: float = Field(default=0.0, description="Alerts per incident")

    # Coverage metrics
    attack_technique_coverage: Dict[str, bool] = Field(
        default_factory=dict, description="Which ATT&CK techniques can we detect"
    )

    # Period
    period_start: datetime
    period_end: datetime


class MetricsService:
    """Service for calculating SOC KPI metrics."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def calculate_soc_metrics(
        self, start_time: datetime, end_time: datetime
    ) -> SOCMetrics:
        """
        Calculate SOC KPIs for the given time period.
        
        False positive rate: Incidents marked FALSE_POSITIVE / total incidents
        Alert reduction: Alerts / incidents
        """
        try:
            # Get incidents in period
            incidents_query = select(IncidentModel).where(
                and_(
                    IncidentModel.created_at >= start_time,
                    IncidentModel.created_at <= end_time,
                )
            )
            result = await self.db.execute(incidents_query)
            incidents = result.scalars().all()

            incidents_list = list(incidents)
            incidents_count = len(incidents_list)

            # Count false positives
            false_positive_count = 0
            true_positive_count = 0

            # Count alerts
            alerts_count = 0
            escalated_count = 0

            for incident in incidents_list:
                # Check if false positive
                if incident.status == IncidentStatus.FALSE_POSITIVE:
                    false_positive_count += 1
                else:
                    true_positive_count += 1

                # Get alerts for this incident
                alerts_query = select(AlertModel).where(AlertModel.incident_id == incident.id)
                alerts_result = await self.db.execute(alerts_query)
                incident_alerts = list(alerts_result.scalars().all())
                alerts_count += len(incident_alerts)

                # Check if escalated (status is investigating or in_progress for > 1 hour)
                if incident.status in [IncidentStatus.INVESTIGATING, IncidentStatus.IN_PROGRESS]:
                    if incident.updated_at and incident.created_at:
                        time_diff = (incident.updated_at - incident.created_at).total_seconds()
                        if time_diff > 3600:  # More than 1 hour
                            escalated_count += 1

            # Calculate rates
            total_incidents = false_positive_count + true_positive_count
            false_positive_rate = (
                false_positive_count / total_incidents if total_incidents > 0 else 0.0
            )
            true_positive_rate = (
                true_positive_count / total_incidents if total_incidents > 0 else 0.0
            )

            alert_reduction_ratio = alerts_count / incidents_count if incidents_count > 0 else 0.0

            # Get attack technique coverage
            attack_coverage = await self.get_attack_technique_coverage()

            return SOCMetrics(
                false_positive_rate=false_positive_rate,
                true_positive_rate=true_positive_rate,
                alerts_received=alerts_count,
                alerts_closed=incidents_count - len(
                    [i for i in incidents_list if i.status != IncidentStatus.RESOLVED]
                ),
                alerts_escalated=escalated_count,
                incidents_created=incidents_count,
                alert_reduction_ratio=alert_reduction_ratio,
                attack_technique_coverage=attack_coverage,
                period_start=start_time,
                period_end=end_time,
            )
        except Exception as e:
            logger.error(f"Failed to calculate SOC metrics: {e}")
            # Return empty metrics on error
            return SOCMetrics(
                period_start=start_time,
                period_end=end_time,
            )

    async def get_attack_technique_coverage(self) -> Dict[str, bool]:
        """Return which ATT&CK techniques have active detection rules."""
        from app.detection.attack_rules import ATTACK_DETECTION_RULES

        # Return dict of technique_id -> True for all implemented rules
        return {technique_id: True for technique_id in ATTACK_DETECTION_RULES.keys()}
