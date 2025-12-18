"""Log ingestion endpoints."""

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
from typing import List
import json

from app.orchestrator.langgraph_workflow import run_workflow
import uuid

router = APIRouter()


@router.post("/upload")
async def upload_logs(file: UploadFile = File(...)):
    """Upload and process log file."""
    try:
        content = await file.read()
        raw_logs = content.decode("utf-8").strip().split("\n")
        raw_logs = [line for line in raw_logs if line.strip()]
        
        incident_id = str(uuid.uuid4())
        
        # Process logs through workflow
        final_state = None
        async for event in run_workflow(raw_logs, incident_id, stream=False):
            if event["type"] == "complete":
                final_state = event["data"]
        
        if final_state is None:
            raise HTTPException(status_code=500, detail="Workflow execution failed")
        
        return {
            "incident_id": incident_id,
            "logs_processed": len(raw_logs),
            "alerts_generated": len(final_state.get("alerts", [])),
            "status": "processed",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze")
async def analyze_logs(raw_logs: List[str]):
    """Analyze logs provided as JSON array."""
    try:
        incident_id = str(uuid.uuid4())
        
        final_state = None
        async for event in run_workflow(raw_logs, incident_id, stream=False):
            if event["type"] == "complete":
                final_state = event["data"]
        
        if final_state is None:
            raise HTTPException(status_code=500, detail="Workflow execution failed")
        
        return {
            "incident_id": incident_id,
            "logs_processed": len(raw_logs),
            "alerts_generated": len(final_state.get("alerts", [])),
            "state": final_state,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

