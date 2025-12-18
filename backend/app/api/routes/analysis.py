"""Analysis streaming endpoints."""

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from typing import List
import json

from app.orchestrator.langgraph_workflow import run_workflow
import uuid

router = APIRouter()


@router.post("/stream")
async def stream_analysis(raw_logs: List[str]):
    """Stream agent execution in real-time using Server-Sent Events."""
    
    async def event_generator():
        incident_id = str(uuid.uuid4())
        
        try:
            async for event in run_workflow(raw_logs, incident_id, stream=True):
                # Format as SSE
                data = json.dumps(event)
                yield f"data: {data}\n\n"
            
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
async def stream_analysis_by_id(incident_id: str, raw_logs: List[str]):
    """Stream analysis for a specific incident ID."""
    
    async def event_generator():
        try:
            async for event in run_workflow(raw_logs, incident_id, stream=True):
                data = json.dumps(event)
                yield f"data: {data}\n\n"
            
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

