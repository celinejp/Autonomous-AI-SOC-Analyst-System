"""Validation endpoints for QA metrics."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.database.postgres import get_db
from app.database.redis_client import get_redis_client
from app.core.metrics import (
    IncidentMetrics,
    calculate_incident_metrics,
)
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/validate", tags=["validation"])

# Load ground truth data


class MetricsResponse(BaseModel):
    """Response with incident metrics."""
    incident_id: str
    metrics: IncidentMetrics


class AggregateResponse(BaseModel):
    """Response with aggregate metrics."""
    period: str
    total_incidents: int
    avg_accuracy: float
    avg_precision: float
    avg_recall: float
    avg_f1_score: float
    true_positive_rate: float
    false_positive_rate: float
    agent_performance: dict = {}
    metrics_source: str = "unevaluated"
    evaluated_at: Optional[str] = None


_RESULTS_DIR = Path(__file__).parent.parent.parent.parent / "tests" / "results"
# eval_detection_metrics.py names its output by --mode / --enrich; most complete run first.
REAL_METRICS_PATHS = [
    _RESULTS_DIR / "real_accuracy_report_llm_enrich.json",
    _RESULTS_DIR / "real_accuracy_report_llm.json",
    _RESULTS_DIR / "real_accuracy_report_enrich.json",
    _RESULTS_DIR / "real_accuracy_report.json",
]


def load_real_eval_metrics() -> Optional[dict]:
    """Load last measured detection metrics from eval script output (not hardcoded)."""
    for path in REAL_METRICS_PATHS:
        try:
            if not path.exists():
                continue
            with open(path) as f:
                data = json.load(f)
            # Combined report shape
            if "datasets" in data and "combined" in data["datasets"]:
                agg = data["datasets"]["combined"]
                return {
                    "total_incidents": agg.get("n", 0),
                    "avg_accuracy": agg.get("accuracy", 0),
                    "avg_precision": agg.get("precision", 0),
                    "avg_recall": agg.get("recall", 0),
                    "avg_f1_score": agg.get("f1", 0),
                    "true_positive_rate": agg.get("recall", 0),
                    "false_positive_rate": agg.get("false_positive_rate", 0),
                    "metrics_source": f"eval:{path.name}",
                    "evaluated_at": data.get("generated_at"),
                    "agent_performance": {},
                }
            # Flat aggregate shape from eval_detection_metrics.py
            if "aggregate" in data:
                agg = data["aggregate"]
                return {
                    "total_incidents": agg.get("n", 0),
                    "avg_accuracy": agg.get("accuracy", 0),
                    "avg_precision": agg.get("precision", 0),
                    "avg_recall": agg.get("recall", 0),
                    "avg_f1_score": agg.get("f1", 0),
                    "true_positive_rate": agg.get("detection_rate", agg.get("recall", 0)),
                    "false_positive_rate": agg.get("false_positive_rate", 0),
                    "metrics_source": f"eval:{path.name}:mode={data.get('mode', 'unknown')}",
                    "evaluated_at": data.get("generated_at"),
                    "agent_performance": {},
                }
        except Exception as e:
            logger.warning(f"Could not load real metrics from {path}: {e}")
    return None


@router.get("/incident/{incident_id}/metrics", response_model=MetricsResponse)
async def get_incident_metrics(
    incident_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Calculate quality metrics for a specific incident."""
    # Fetch incident from database
    sql = text("""
        SELECT i.*, 
               ir.executive_summary, ir.technical_findings, ir.root_cause,
               ir.affected_assets, ir.impact_assessment, ir.confidence_score as report_confidence
        FROM incidents i
        LEFT JOIN incident_reports ir ON ir.incident_id = i.id
        WHERE i.id = :incident_id
    """)
    result = await db.execute(sql, {"incident_id": incident_id})
    row = result.fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Fetch related data
    alerts_sql = text("SELECT * FROM alerts WHERE incident_id = :incident_id")
    alerts_result = await db.execute(alerts_sql, {"incident_id": incident_id})
    alerts = [dict(r._mapping) for r in alerts_result.fetchall()]
    
    techniques_sql = text("SELECT * FROM mitre_techniques WHERE incident_id = :incident_id")
    techniques_result = await db.execute(techniques_sql, {"incident_id": incident_id})
    techniques = [dict(r._mapping) for r in techniques_result.fetchall()]
    
    plan_sql = text("SELECT * FROM response_plans WHERE incident_id = :incident_id")
    plan_result = await db.execute(plan_sql, {"incident_id": incident_id})
    plan_row = plan_result.fetchone()
    
    # Build incident dict
    incident = {
        "incident_id": incident_id,
        "severity": str(row.severity) if row.severity else "medium",
        "confidence_score": row.confidence_score or 0.5,
        "alerts": alerts,
        "mitre_techniques": techniques,
        "incident_report": {
            "executive_summary": row.executive_summary if hasattr(row, 'executive_summary') else None,
            "technical_findings": row.technical_findings if hasattr(row, 'technical_findings') else None,
            "root_cause": row.root_cause if hasattr(row, 'root_cause') else None,
            "affected_assets": row.affected_assets if hasattr(row, 'affected_assets') else [],
            "impact_assessment": row.impact_assessment if hasattr(row, 'impact_assessment') else None,
        } if hasattr(row, 'executive_summary') and row.executive_summary else None,
        "response_plan": dict(plan_row._mapping) if plan_row else None,
    }
    
    metrics = calculate_incident_metrics(incident)
    
    return MetricsResponse(incident_id=incident_id, metrics=metrics)


@router.get("/aggregate", response_model=AggregateResponse)
async def get_aggregate_metrics(
    days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db)
):
    """Get aggregated detection metrics from the last real eval run (not hardcoded)."""
    redis = get_redis_client()
    cache_key = f"aggregate_metrics:{days}"

    try:
        cached = await redis.get(cache_key)
        if cached:
            return json.loads(cached)
    except Exception:
        pass

    real = load_real_eval_metrics()
    if real:
        response = AggregateResponse(
            period=f"Last measured eval ({days}d window label)",
            total_incidents=real["total_incidents"],
            avg_accuracy=real["avg_accuracy"],
            avg_precision=real["avg_precision"],
            avg_recall=real["avg_recall"],
            avg_f1_score=real["avg_f1_score"],
            true_positive_rate=real["true_positive_rate"],
            false_positive_rate=real["false_positive_rate"],
            agent_performance=real.get("agent_performance") or {},
            metrics_source=real["metrics_source"],
            evaluated_at=real.get("evaluated_at"),
        )
    else:
        # Honest empty state — never invent vanity metrics
        sql = text("""
            SELECT COUNT(*) AS n FROM incidents
            WHERE created_at >= :start AND created_at <= :end
        """)
        period_end = datetime.utcnow()
        period_start = period_end - timedelta(days=days)
        result = await db.execute(sql, {"start": period_start, "end": period_end})
        n = int(result.scalar() or 0)
        response = AggregateResponse(
            period=f"Last {days} days",
            total_incidents=n,
            avg_accuracy=0.0,
            avg_precision=0.0,
            avg_recall=0.0,
            avg_f1_score=0.0,
            true_positive_rate=0.0,
            false_positive_rate=0.0,
            agent_performance={},
            metrics_source="unevaluated",
            evaluated_at=None,
        )

    try:
        await redis.setex(cache_key, 300, response.model_dump_json())
    except Exception:
        pass

    return response
