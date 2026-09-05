"""Validation endpoints for QA metrics."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.database.postgres import get_db
from app.database.redis_client import get_redis_client
from app.core.metrics import (
    IncidentMetrics,
    ValidationResult,
    AggregateMetrics,
    calculate_incident_metrics,
    validate_against_ground_truth,
    calculate_aggregate_metrics,
)
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/validate", tags=["validation"])

# Load ground truth data
GROUND_TRUTH_PATH = Path(__file__).parent.parent.parent.parent / "data" / "labeled_incidents.json"


def load_ground_truth() -> dict:
    """Load labeled incidents from JSON file."""
    try:
        with open(GROUND_TRUTH_PATH) as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load ground truth: {e}")
        return {"incidents": []}


class MetricsResponse(BaseModel):
    """Response with incident metrics."""
    incident_id: str
    metrics: IncidentMetrics


class ValidationResponse(BaseModel):
    """Response with validation result."""
    incident_id: str
    ground_truth_id: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    mitre_accuracy: float
    confidence_score: float
    details: dict


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


REAL_METRICS_PATHS = [
    Path(__file__).parent.parent.parent / "tests" / "results" / "real_accuracy_report_llm.json",
    Path(__file__).parent.parent.parent / "tests" / "results" / "real_accuracy_report.json",
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


@router.post("/incident/{incident_id}", response_model=ValidationResponse)
async def validate_incident(
    incident_id: str,
    ground_truth_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Validate incident against ground truth dataset."""
    # Load ground truth
    gt_data = load_ground_truth()
    gt_incidents = gt_data.get("incidents", [])
    
    if not gt_incidents:
        raise HTTPException(status_code=500, detail="Ground truth data not available")
    
    # Find matching ground truth
    ground_truth = None
    if ground_truth_id:
        ground_truth = next((i for i in gt_incidents if i["id"] == ground_truth_id), None)
    
    if not ground_truth:
        raise HTTPException(status_code=400, detail="Ground truth ID required or not found")
    
    # Fetch incident
    sql = text("SELECT * FROM incidents WHERE id = :incident_id")
    result = await db.execute(sql, {"incident_id": incident_id})
    row = result.fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Build incident dict (simplified)
    alerts_sql = text("SELECT * FROM alerts WHERE incident_id = :incident_id")
    alerts = [dict(r._mapping) for r in (await db.execute(alerts_sql, {"incident_id": incident_id})).fetchall()]
    
    techniques_sql = text("SELECT technique_id FROM mitre_techniques WHERE incident_id = :incident_id")
    techniques = [r.technique_id for r in (await db.execute(techniques_sql, {"incident_id": incident_id})).fetchall()]
    
    incident = {
        "incident_id": incident_id,
        "severity": str(row.severity) if row.severity else "medium",
        "confidence_score": row.confidence_score or 0.5,
        "alerts": alerts,
        "mitre_techniques": [{"technique_id": t} for t in techniques],
    }
    
    validation = validate_against_ground_truth(incident, ground_truth)
    
    # Cache result
    try:
        redis = get_redis_client()
        cache_key = f"validation:{incident_id}:{ground_truth_id}"
        await redis.setex(cache_key, 3600, validation.model_dump_json())
    except Exception:
        pass
    
    return ValidationResponse(
        incident_id=incident_id,
        ground_truth_id=ground_truth_id,
        accuracy=validation.accuracy,
        precision=validation.precision,
        recall=validation.recall,
        f1_score=validation.f1_score,
        mitre_accuracy=validation.mitre_accuracy,
        confidence_score=validation.confidence_score,
        details=validation.details,
    )


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


@router.get("/ground-truth")
async def list_ground_truth():
    """List available ground truth incidents."""
    gt_data = load_ground_truth()
    incidents = gt_data.get("incidents", [])
    
    return {
        "total": len(incidents),
        "true_positives": sum(1 for i in incidents if i.get("is_true_positive")),
        "false_positives": sum(1 for i in incidents if not i.get("is_true_positive")),
        "incidents": [
            {
                "id": i["id"],
                "name": i["name"],
                "is_true_positive": i["is_true_positive"],
                "severity": i["severity"],
                "category": i["category"],
                "mitre_techniques": i["mitre_techniques"],
            }
            for i in incidents
        ]
    }


@router.post("/run-batch")
async def run_batch_validation(
    limit: int = Query(default=20, ge=1, le=100),
):
    """Run validation on batch of ground truth incidents (for testing)."""
    gt_data = load_ground_truth()
    incidents = gt_data.get("incidents", [])[:limit]
    
    results = []
    for gt in incidents:
        # Simulate validation (in production, would run through workflow)
        result = {
            "ground_truth_id": gt["id"],
            "name": gt["name"],
            "is_true_positive": gt["is_true_positive"],
            "expected_severity": gt["severity"],
            "expected_techniques": gt["mitre_techniques"],
            "status": "pending",
        }
        results.append(result)
    
    return {
        "batch_id": f"batch-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "total": len(results),
        "results": results,
    }

