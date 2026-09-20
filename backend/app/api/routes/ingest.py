"""Log ingestion endpoints — enqueue analysis jobs onto Redis Streams."""

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from typing import List
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.core.job_queue import enqueue_analysis_job
from app.core.config import settings
from app.core.logging import get_logger
from app.core.input_limits import validate_raw_logs
from app.models.incident import IncidentStatus, Severity

logger = get_logger(__name__)
router = APIRouter()

# Keep for status ETA estimates (worker also uses these)
# Rough per-agent seconds, averaged from 3 timed end-to-end runs with llama3.1 on the dev
# machine (Ollama, no GPU tuning). Only used for the progress ETA; real time varies with the
# model, the hardware and how many reflection rounds the Critic asks for.
AGENT_DURATIONS = {
    "ingest": 1,
    "detect": 15,
    "enrich": 8,
    "analyze": 30,
    "critique": 30,
    "plan_response": 32,
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
        # Read one byte past the limit so an oversized file is rejected without loading it all.
        content = await file.read(settings.max_upload_bytes + 1)
        if len(content) > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail=f"File too large (max {settings.max_upload_bytes} bytes)")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="File must be UTF-8 text")
        raw_logs = [line for line in text.strip().split("\n") if line.strip()]
        if not raw_logs:
            raise HTTPException(status_code=400, detail="No log entries found")
        return await _create_and_enqueue(db, validate_raw_logs(raw_logs))
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
        return await _create_and_enqueue(db, validate_raw_logs(raw_logs))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
