"""Log ingestion endpoints — enqueue analysis jobs onto Redis Streams."""

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from typing import List
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.core.job_queue import enqueue_analysis_job
from app.core.logging import get_logger
from app.models.incident import IncidentStatus, Severity

logger = get_logger(__name__)
router = APIRouter()

# Keep for status ETA estimates (worker also uses these)
AGENT_DURATIONS = {
    "ingest": 2,
    "detect": 8,
    "enrich": 5,
    "analyze": 15,
    "critique": 5,
    "plan_response": 10,
}
TOTAL_ESTIMATED_SECONDS = sum(AGENT_DURATIONS.values())


async def _create_and_enqueue(db: AsyncSession, raw_logs: List[str]) -> dict:
    incident_id = str(uuid.uuid4())
    try:
        from app.database.repositories import IncidentRepository

        await IncidentRepository.create(
            db,
            {
                "id": incident_id,
                "status": IncidentStatus.IN_PROGRESS,
                "severity": Severity.LOW,
                "confidence_score": 0.0,
            },
        )
        await db.commit()
    except Exception as e:
        logger.warning(f"Could not create initial incident record: {e}")

    await enqueue_analysis_job(incident_id, raw_logs)

    return {
        "incident_id": incident_id,
        "status": "queued",
        "estimated_duration_seconds": TOTAL_ESTIMATED_SECONDS,
        "message": "Analysis queued on Redis Streams worker.",
        "logs_processed": len(raw_logs),
    }


@router.post("/upload")
async def upload_logs(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload and enqueue log file for worker processing."""
    try:
        content = await file.read()
        raw_logs = content.decode("utf-8").strip().split("\n")
        raw_logs = [line for line in raw_logs if line.strip()]
        if not raw_logs:
            raise HTTPException(status_code=400, detail="No log entries found")
        return await _create_and_enqueue(db, raw_logs)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze")
async def analyze_logs(
    raw_logs: List[str],
    db: AsyncSession = Depends(get_db),
):
    """Enqueue logs for analysis via Redis Streams worker."""
    try:
        if not raw_logs:
            raise HTTPException(status_code=400, detail="No log entries provided")
        return await _create_and_enqueue(db, raw_logs)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
