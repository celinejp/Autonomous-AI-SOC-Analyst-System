"""Dashboard stats endpoint with caching."""

from fastapi import APIRouter, Response, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, func
from typing import Dict, Any
from datetime import datetime, timedelta

from app.database.postgres import get_db
from app.core.cache import cache_response
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["dashboard"])


@router.get("/stats")
@cache_response(ttl=60, key_prefix="dashboard:stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    response: Response = None,
) -> Dict[str, Any]:
    """Get dashboard statistics with 60-second cache."""
    if response:
        response.headers["Cache-Control"] = "public, max-age=60"
    
    try:
        # Get counts by severity
        severity_query = text("""
            SELECT severity, COUNT(*) as count
            FROM incidents
            GROUP BY severity
        """)
        severity_result = await db.execute(severity_query)
        # DB stores the SQLAlchemy Enum member name (e.g. "HIGH"), not the lowercase
        # Severity value the code below looks up - normalize so the .get() calls hit.
        severity_counts = {row.severity.lower(): row.count for row in severity_result}
        
        # Get counts by status
        status_query = text("""
            SELECT status, COUNT(*) as count
            FROM incidents
            GROUP BY status
        """)
        status_result = await db.execute(status_query)
        status_counts = {row.status: row.count for row in status_result}
        
        # Get total counts
        total_query = text("SELECT COUNT(*) as total FROM incidents")
        total_result = await db.execute(total_query)
        total_incidents = total_result.scalar() or 0
        
        # Get recent incidents (last 24h)
        recent_query = text("""
            SELECT COUNT(*) as count
            FROM incidents
            WHERE created_at >= NOW() - INTERVAL '24 hours'
        """)
        recent_result = await db.execute(recent_query)
        recent_count = recent_result.scalar() or 0
        
        # Get average confidence
        confidence_query = text("""
            SELECT AVG(confidence_score) as avg_confidence
            FROM incidents
            WHERE confidence_score > 0
        """)
        confidence_result = await db.execute(confidence_query)
        avg_confidence = float(confidence_result.scalar() or 0)

        # Top MITRE techniques (from mitre_techniques table)
        try:
            top_mitre_query = text("""
                SELECT technique_id, COUNT(*) as count
                FROM mitre_techniques
                GROUP BY technique_id
                ORDER BY count DESC
                LIMIT 10
            """)
            top_mitre_result = await db.execute(top_mitre_query)
            top_mitre_techniques = [
                {"technique_id": row.technique_id, "count": row.count}
                for row in top_mitre_result
            ]
        except Exception:
            top_mitre_techniques = []
        
        return {
            "total_incidents": total_incidents,
            "recent_24h": recent_count,
            "severity_counts": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
            },
            "status_counts": {
                status: count for status, count in status_counts.items()
            },
            "avg_confidence": round(avg_confidence, 2),
            "top_mitre_techniques": top_mitre_techniques,
            "cached_at": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        raise


@router.get("/timeline")
@cache_response(ttl=60, key_prefix="dashboard:timeline")
async def get_timeline_data(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
    response: Response = None,
) -> Dict[str, Any]:
    """Get timeline data for last N hours."""
    if response:
        response.headers["Cache-Control"] = "public, max-age=60"
    
    try:
        query = text("""
            SELECT 
                DATE_TRUNC('hour', created_at) as hour,
                COUNT(*) as count,
                severity
            FROM incidents
            WHERE created_at >= NOW() - INTERVAL ':hours hours'
            GROUP BY hour, severity
            ORDER BY hour ASC
        """)
        result = await db.execute(query, {"hours": hours})
        
        timeline = {}
        for row in result:
            hour_str = row.hour.isoformat() if row.hour else ""
            if hour_str not in timeline:
                timeline[hour_str] = {}
            timeline[hour_str][row.severity] = row.count
        
        return {
            "timeline": timeline,
            "hours": hours,
        }
    except Exception as e:
        logger.error(f"Timeline error: {e}")
        raise

