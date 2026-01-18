"""Log ingestion endpoints with background processing."""

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, BackgroundTasks
from fastapi.responses import StreamingResponse
from typing import List
import json
import asyncio
from datetime import datetime
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.database.redis_client import get_redis_client
from app.services.incident_service import IncidentService
from app.orchestrator.langgraph_workflow import run_workflow_with_events
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Agent order and estimated durations (seconds)
AGENT_DURATIONS = {
    "ingest": 2,
    "detect": 8,
    "enrich": 5,
    "analyze": 15,
    "critique": 5,
    "plan_response": 10,
}
TOTAL_ESTIMATED_SECONDS = sum(AGENT_DURATIONS.values())


async def process_logs_background(
    raw_logs: List[str],
    incident_id: str,
    db: AsyncSession
):
    """Background task to process logs through workflow."""
    redis = get_redis_client()
    
    try:
        # Initialize status
        if redis:
            status_key = f"incident_status:{incident_id}"
            redis.hset(status_key, mapping={
                "status": "analyzing",
                "progress_percent": "0",
                "current_agent": "ingest",
                "started_at": datetime.utcnow().isoformat(),
                "estimated_duration": str(TOTAL_ESTIMATED_SECONDS),
            })
            redis.expire(status_key, 3600)  # 1 hour TTL
        
        agents_completed = 0
        total_agents = len(AGENT_DURATIONS)
        
        # Run workflow with progress tracking
        async for event in run_workflow_with_events(raw_logs, incident_id):
            event_type = event.get("type")
            
            if event_type == "agent_start" and redis:
                agent = event.get("agent")
                agents_completed += 1
                progress = int((agents_completed / total_agents) * 100)
                
                redis.hset(status_key, mapping={
                    "current_agent": agent,
                    "progress_percent": str(progress),
                })
            
            elif event_type == "complete" and redis:
                final_state = event["data"]
                
                # Save to database
                try:
                    await IncidentService.save_incident_from_state(db, final_state)
                    redis.hset(status_key, mapping={
                        "status": "completed",
                        "progress_percent": "100",
                        "completed_at": datetime.utcnow().isoformat(),
                    })
                except Exception as e:
                    logger.error(f"Failed to save incident: {e}")
                    redis.hset(status_key, mapping={
                        "status": "failed",
                        "error": str(e),
                    })
        
    except Exception as e:
        logger.error(f"Background processing failed: {e}")
        if redis:
            status_key = f"incident_status:{incident_id}"
            redis.hset(status_key, mapping={
                "status": "failed",
                "error": str(e),
            })


@router.post("/upload")
async def upload_logs(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
):
    """Upload and process log file - returns immediately with status."""
    try:
        content = await file.read()
        raw_logs = content.decode("utf-8").strip().split("\n")
        raw_logs = [line for line in raw_logs if line.strip()]
        
        if not raw_logs:
            raise HTTPException(status_code=400, detail="No log entries found")
        
        incident_id = str(uuid.uuid4())
        
        # Create initial incident record with "analyzing" status
        try:
            from app.database.repositories import IncidentRepository
            incident_data = {
                "id": incident_id,
                "status": "analyzing",  # Custom status for in-progress
                "severity": "low",  # Placeholder
                "confidence_score": 0.0,
            }
            await IncidentRepository.create(db, incident_data)
            await db.commit()
        except Exception as e:
            logger.warning(f"Could not create initial incident record: {e}")
        
        # Start background processing
        if background_tasks:
            background_tasks.add_task(process_logs_background, raw_logs, incident_id, db)
        else:
            # Fallback: run in background using asyncio
            asyncio.create_task(process_logs_background(raw_logs, incident_id, db))
        
        return {
            "incident_id": incident_id,
            "status": "analyzing",
            "estimated_duration_seconds": TOTAL_ESTIMATED_SECONDS,
            "message": "Analysis started. You'll be redirected when complete.",
            "logs_processed": len(raw_logs),
        }
    except Exception as e:
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze")
async def analyze_logs(
    raw_logs: List[str],
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
):
    """Analyze logs provided as JSON array - returns immediately with status."""
    try:
        if not raw_logs or len(raw_logs) == 0:
            raise HTTPException(status_code=400, detail="No log entries provided")
        
        incident_id = str(uuid.uuid4())
        
        # Create initial incident record
        try:
            from app.database.repositories import IncidentRepository
            incident_data = {
                "id": incident_id,
                "status": "analyzing",
                "severity": "low",
                "confidence_score": 0.0,
            }
            await IncidentRepository.create(db, incident_data)
            await db.commit()
        except Exception as e:
            logger.warning(f"Could not create initial incident record: {e}")
        
        # Start background processing
        if background_tasks:
            background_tasks.add_task(process_logs_background, raw_logs, incident_id, db)
        else:
            asyncio.create_task(process_logs_background(raw_logs, incident_id, db))
        
        return {
            "incident_id": incident_id,
            "status": "analyzing",
            "estimated_duration_seconds": TOTAL_ESTIMATED_SECONDS,
            "message": "Analysis started. You'll be redirected when complete.",
            "logs_processed": len(raw_logs),
        }
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
