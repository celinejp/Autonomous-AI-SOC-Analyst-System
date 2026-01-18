"""Analysis streaming endpoints."""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from typing import List
import json

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.services.incident_service import IncidentService
from app.orchestrator.langgraph_workflow import run_workflow
import uuid

router = APIRouter()


@router.post("/stream")
async def stream_analysis(
    raw_logs: List[str],
    db: AsyncSession = Depends(get_db),
):
    """Stream agent execution in real-time using Server-Sent Events."""
    
    async def event_generator():
        incident_id = str(uuid.uuid4())
        final_state = None
        
        try:
            async for event in run_workflow(raw_logs, incident_id, stream=True):
                # Format as SSE
                data = json.dumps(event)
                yield f"data: {data}\n\n"
                
                if event["type"] == "complete":
                    final_state = event["data"]
            
            # Save incident to database after completion
            if final_state:
                try:
                    await IncidentService.save_incident_from_state(db, final_state)
                except Exception as db_error:
                    import logging
                    logging.error(f"Failed to save incident to database: {db_error}")
            
            yield f"data: {json.dumps({'type': 'end', 'incident_id': incident_id})}\n\n"
        except Exception as e:
            error_data = json.dumps({"type": "error", "error": str(e)})
            yield f"data: {error_data}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/stream/{incident_id}")
async def stream_analysis_by_id(
    incident_id: str,
    raw_logs: List[str],
    db: AsyncSession = Depends(get_db),
):
    """Stream analysis for a specific incident ID."""
    
    async def event_generator():
        final_state = None
        try:
            async for event in run_workflow(raw_logs, incident_id, stream=True):
                data = json.dumps(event)
                yield f"data: {data}\n\n"
                
                if event["type"] == "complete":
                    final_state = event["data"]
            
            # Save incident to database after completion
            if final_state:
                try:
                    await IncidentService.save_incident_from_state(db, final_state)
                except Exception as db_error:
                    import logging
                    logging.error(f"Failed to save incident to database: {db_error}")
            
            yield f"data: {json.dumps({'type': 'end', 'incident_id': incident_id})}\n\n"
        except Exception as e:
            error_data = json.dumps({"type": "error", "error": str(e)})
            yield f"data: {error_data}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
