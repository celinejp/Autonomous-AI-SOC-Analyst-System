"""SSE streaming endpoint for real-time agent execution."""

import json
import asyncio
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, Optional
import uuid

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.core.cache import invalidate_incident_caches
from app.database.postgres import AsyncSessionLocal
from app.services.incident_service import IncidentService
from app.orchestrator.langgraph_workflow import run_workflow_with_events
from app.core.logging import get_logger
from app.core.input_limits import validate_raw_logs

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


_background_runs: set = set()  # strong references so a run isn't garbage-collected mid-flight


async def _run_and_save(raw_logs: list[str], incident_id: str, queue: "asyncio.Queue") -> None:
    """Run the workflow and save the incident, independent of the browser connection.
    Events go into `queue` for the SSE generator; if the client has disconnected nobody reads
    them, but the run still finishes and the incident is still saved."""
    final_state = None
    try:
        async for event in run_workflow_with_events(raw_logs, incident_id):
            if event.get("type") == "complete":
                final_state = event.get("data")
            await queue.put(event)
        if final_state:
            try:
                async with AsyncSessionLocal() as db:
                    await IncidentService.save_incident_from_state(db, final_state)
                await invalidate_incident_caches()
                await queue.put({"type": "saved"})
            except Exception as e:
                logger.error("Failed to save incident", error=str(e), incident_id=incident_id)
                await queue.put({"type": "save_error", "error": str(e)})
    except Exception as e:
        logger.error("Stream workflow error", error=str(e), incident_id=incident_id)
        await queue.put({"type": "error", "error": str(e)})
    finally:
        await queue.put(None)


async def stream_workflow_events(raw_logs: list[str], incident_id: str) -> AsyncGenerator[str, None]:
    """Stream workflow events as SSE."""
    yield format_sse_event("connected", {
        "incident_id": incident_id,
        "agents": [
            {"id": k, **v, "status": "pending"}
            for k, v in sorted(AGENT_INFO.items(), key=lambda x: x[1]["order"])
        ]
    })

    queue: asyncio.Queue = asyncio.Queue()
    task = asyncio.create_task(_run_and_save(raw_logs, incident_id, queue))
    _background_runs.add(task)
    task.add_done_callback(_background_runs.discard)

    agent_start_time = None
    current_agent = None
    while True:
        event = await queue.get()
        if event is None:
            break
        event_type = event.get("type")

        if event_type == "agent_start":
            current_agent = event.get("agent")
            agent_start_time = datetime.utcnow()
            info = AGENT_INFO.get(current_agent, {"name": current_agent, "description": ""})
            yield format_sse_event("agent_start", {
                "agent": current_agent, "agent_name": info["name"], "description": info["description"],
            })
        elif event_type == "agent_output":
            agent_id = event.get("agent")
            yield format_sse_event("agent_output", {
                "agent": agent_id, "data": extract_output_summary(agent_id, event.get("data", {})),
            })
        elif event_type == "agent_complete":
            duration_ms = (datetime.utcnow() - agent_start_time).total_seconds() * 1000 if agent_start_time else 0
            yield format_sse_event("agent_complete", {"agent": event.get("agent"), "duration_ms": round(duration_ms, 2)})
            current_agent, agent_start_time = None, None
        elif event_type == "complete":
            final_state = event.get("data") or {}
            yield format_sse_event("workflow_complete", {
                "incident_id": incident_id,
                "summary": {
                    "total_alerts": len(final_state.get("alerts", [])),
                    "total_logs": len(final_state.get("logs", [])),
                    "confidence": final_state.get("confidence", 0),
                    "iterations": final_state.get("iteration", 1),
                    "severity": extract_severity(final_state),
                },
            })
        elif event_type == "saved":
            yield format_sse_event("saved", {"incident_id": incident_id})
        elif event_type == "save_error":
            yield format_sse_event("save_error", {"message": event.get("error")})
        elif event_type == "error":
            yield format_sse_event("error", {"message": event.get("error", "Unknown error"), "agent": current_agent})

    yield format_sse_event("end", {"incident_id": incident_id})


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
    validate_raw_logs(request_body.raw_logs)
    incident_id = request_body.incident_id or str(uuid.uuid4())
    
    return StreamingResponse(
        stream_workflow_events(request_body.raw_logs, incident_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
