"""SOC KPI metrics API routes."""

from fastapi import APIRouter, Depends, Query
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.services.metrics_service import MetricsService
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/soc-kpis")
async def get_soc_kpis(
    hours: int = Query(24, description="Time period in hours"),
    db: AsyncSession = Depends(get_db),
):
    """Get SOC KPI metrics for the specified time period."""
    try:
        metrics_service = MetricsService(db)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        metrics = await metrics_service.calculate_soc_metrics(start_time, end_time)
        
        return {
            "status": "success",
            "metrics": metrics.model_dump(),
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "hours": hours,
            },
        }
    except Exception as e:
        logger.error(f"Failed to get SOC KPIs: {e}")
        raise


@router.get("/attack-coverage")
async def get_attack_coverage(
    db: AsyncSession = Depends(get_db),
):
    """Get ATT&CK technique detection coverage."""
    try:
        metrics_service = MetricsService(db)
        coverage = await metrics_service.get_attack_technique_coverage()
        
        total_techniques = len(coverage)
        covered_techniques = sum(1 for v in coverage.values() if v)
        coverage_percentage = (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0.0
        
        return {
            "status": "success",
            "coverage": coverage,
            "summary": {
                "total_techniques": total_techniques,
                "covered_techniques": covered_techniques,
                "coverage_percentage": round(coverage_percentage, 2),
            },
        }
    except Exception as e:
        logger.error(f"Failed to get attack coverage: {e}")
        raise


@router.get("/range")
async def get_metrics_range(
    start_time: datetime = Query(..., description="Start time (ISO format)"),
    end_time: datetime = Query(..., description="End time (ISO format)"),
    db: AsyncSession = Depends(get_db),
):
    """Get SOC KPI metrics for a custom time range."""
    try:
        if end_time < start_time:
            raise ValueError("End time must be after start time")
        
        metrics_service = MetricsService(db)
        metrics = await metrics_service.calculate_soc_metrics(start_time, end_time)
        
        return {
            "status": "success",
            "metrics": metrics.model_dump(),
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
            },
        }
    except Exception as e:
        logger.error(f"Failed to get metrics range: {e}")
        raise

