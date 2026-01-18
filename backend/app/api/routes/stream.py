"""SSE streaming endpoint for real-time agent execution."""

import json
import asyncio
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, Optional
import uuid

from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.services.incident_service import IncidentService
from app.orchestrator.langgraph_workflow import run_workflow_with_events
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["streaming"])

# Agent display names and order
AGENT_INFO = {
    "ingest": {"name": "Ingest Agent", "order": 1, "description": "Parsing and normalizing logs"},
    "detect": {"name": "Detection Agent", "order": 2, "description": "Identifying suspicious patterns"},
    "enrich": {"name": "Threat Intel Agent", "order": 3, "description": "Enriching with MITRE ATT&CK"},
    "analyze": {"name": "Analyst Agent", "order": 4, "description": "Deep investigation and correlation"},
    "critique": {"name": "Critic Agent", "order": 5, "description": "Reviewing analysis quality"},
    "plan_response": {"name": "Response Planner", "order": 6, "description": "Creating response plan"},
}


class StreamRequest(BaseModel):
    """Request to start streaming analysis."""
    raw_logs: list[str] = Field(..., min_items=1, description="Raw log entries to analyze")
    incident_id: Optional[str] = Field(default=None, description="Optional incident ID")


def format_sse_event(event_type: str, data: Dict[str, Any]) -> str:
    """Format data as SSE event."""
    payload = {
        "event": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        **data
    }
    return f"data: {json.dumps(payload)}\n\n"


async def stream_workflow_events(
    raw_logs: list[str],
    incident_id: str,
    db: AsyncSession,
    request: Request,
) -> AsyncGenerator[str, None]:
    """Stream workflow events as SSE."""
    
    # Send initial connection event
    yield format_sse_event("connected", {
        "incident_id": incident_id,
        "agents": [
            {"id": k, **v, "status": "pending"} 
            for k, v in sorted(AGENT_INFO.items(), key=lambda x: x[1]["order"])
        ]
    })
    
    final_state = None
    current_agent = None
    agent_start_time = None
    
    try:
        async for event in run_workflow_with_events(raw_logs, incident_id):
            # Check for client disconnect
            if await request.is_disconnected():
                logger.info("Client disconnected", incident_id=incident_id)
                break
            
            event_type = event.get("type")
            
            if event_type == "agent_start":
                agent_id = event.get("agent")
                current_agent = agent_id
                agent_start_time = datetime.utcnow()
                
                agent_info = AGENT_INFO.get(agent_id, {"name": agent_id, "description": ""})
                yield format_sse_event("agent_start", {
                    "agent": agent_id,
                    "agent_name": agent_info["name"],
                    "description": agent_info["description"],
                })
            
            elif event_type == "agent_output":
                agent_id = event.get("agent")
                output_data = event.get("data", {})
                
                # Extract key metrics from output
                summary = extract_output_summary(agent_id, output_data)
                
                yield format_sse_event("agent_output", {
                    "agent": agent_id,
                    "data": summary,
                })
            
            elif event_type == "agent_complete":
                agent_id = event.get("agent")
                duration_ms = 0
                if agent_start_time:
                    duration_ms = (datetime.utcnow() - agent_start_time).total_seconds() * 1000
                
                yield format_sse_event("agent_complete", {
                    "agent": agent_id,
                    "duration_ms": round(duration_ms, 2),
                })
                current_agent = None
                agent_start_time = None
            
            elif event_type == "state_update":
                # Periodic state updates
                state_data = event.get("data", {})
                yield format_sse_event("state_update", {
                    "confidence": state_data.get("confidence", 0),
                    "iteration": state_data.get("iteration", 0),
                    "alerts_count": len(state_data.get("alerts", [])),
                    "logs_count": len(state_data.get("logs", [])),
                })
            
            elif event_type == "complete":
                final_state = event.get("data")
                
                # Extract final summary
                summary = {
                    "total_alerts": len(final_state.get("alerts", [])),
                    "total_logs": len(final_state.get("logs", [])),
                    "confidence": final_state.get("confidence", 0),
                    "iterations": final_state.get("iteration", 1),
                    "severity": extract_severity(final_state),
                }
                
                yield format_sse_event("workflow_complete", {
                    "incident_id": incident_id,
                    "summary": summary,
                })
            
            elif event_type == "error":
                yield format_sse_event("error", {
                    "message": event.get("error", "Unknown error"),
                    "agent": current_agent,
                })
        
        # Save to database
        if final_state:
            try:
                await IncidentService.save_incident_from_state(db, final_state)
                yield format_sse_event("saved", {"incident_id": incident_id})
            except Exception as e:
                logger.error("Failed to save incident", error=str(e))
                yield format_sse_event("save_error", {"message": str(e)})
        
        # Final end event
        yield format_sse_event("end", {"incident_id": incident_id})
        
    except asyncio.CancelledError:
        logger.info("Stream cancelled", incident_id=incident_id)
        yield format_sse_event("cancelled", {"incident_id": incident_id})
    except Exception as e:
        logger.error("Stream error", error=str(e), incident_id=incident_id)
        yield format_sse_event("error", {"message": str(e)})


def extract_output_summary(agent_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key information from agent output for streaming."""
    summary = {}
    
    if agent_id == "ingest":
        logs = data.get("logs", [])
        summary = {
            "logs_parsed": len(logs),
            "sources": list(set(log.get("log_source", "unknown") for log in logs[:10])),
        }
    elif agent_id == "detect":
        alerts = data.get("alerts", [])
        summary = {
            "alerts_generated": len(alerts),
            "severities": [a.get("severity", "unknown") for a in alerts[:5]],
        }
    elif agent_id == "threat_intel":
        techniques = data.get("mitre_techniques", [])
        summary = {
            "techniques_found": len(techniques) if isinstance(techniques, list) else 0,
            "threat_intel": bool(data.get("threat_intel")),
        }
    elif agent_id == "analyze":
        report = data.get("incident_report")
        if report:
            summary = {
                "has_report": True,
                "confidence": data.get("confidence", 0),
            }
    elif agent_id == "critique":
        summary = {
            "needs_revision": data.get("needs_revision", False),
            "iteration": data.get("iteration", 0),
        }
    elif agent_id == "plan_response":
        plan = data.get("response_plan")
        if plan:
            summary = {
                "containment_actions": len(plan.get("containment_actions", [])),
                "investigation_steps": len(plan.get("investigation_steps", [])),
            }
    
    return summary


def extract_severity(state: Dict[str, Any]) -> str:
    """Extract overall severity from final state."""
    alerts = state.get("alerts", [])
    if not alerts:
        return "low"
    
    severities = [a.get("severity", "low") for a in alerts]
    if "critical" in severities:
        return "critical"
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"


@router.post("/incidents/stream")
async def start_incident_stream(
    request_body: StreamRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Start streaming analysis of logs with real-time agent updates.
    
    Returns Server-Sent Events (SSE) stream with:
    - agent_start: When an agent begins processing
    - agent_output: Intermediate results from agent
    - agent_complete: When agent finishes with duration
    - workflow_complete: Final analysis results
    - error: If something goes wrong
    """
    incident_id = request_body.incident_id or str(uuid.uuid4())
    
    return StreamingResponse(
        stream_workflow_events(
            request_body.raw_logs,
            incident_id,
            db,
            request,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/incidents/{incident_id}/stream/status")
async def get_stream_status(incident_id: str):
    """Check if an incident stream is available."""
    return {
        "incident_id": incident_id,
        "streaming_available": True,
        "agents": list(AGENT_INFO.keys()),
    }

