"""Incident management endpoints."""

from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from datetime import datetime
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import Query, Response
from fastapi.responses import JSONResponse

from sqlalchemy import select
from app.database.postgres import get_db
from app.database.repositories import IncidentRepository
from app.database.models import ResponsePlanModel
from app.models.incident import Incident, IncidentStatus, Severity
from app.core.logging import get_logger
from app.core.cache import cache_response, cache_key
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

logger = get_logger(__name__)

# Estimated total duration for analysis
TOTAL_ESTIMATED_SECONDS = 45

router = APIRouter()


@router.get("", response_model=List[Incident])
@cache_response(ttl=30, key_prefix="incidents:list")
async def list_incidents(
    status: Optional[IncidentStatus] = Query(None),
    severity: Optional[Severity] = Query(None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    fields: Optional[str] = Query(None, description="Comma-separated field names to include"),
    db: AsyncSession = Depends(get_db),
    response: Response = None,
):
    """List incidents with pagination, filtering, and field selection."""
    # Set cache headers
    if response:
        response.headers["Cache-Control"] = "public, max-age=30"
    
    incident_models = await IncidentRepository.list(
        session=db,
        status=status,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    
    incidents = []
    for model in incident_models:
        try:
            incident = await IncidentRepository.model_to_pydantic(model)
            
            # Field filtering
            if fields:
                field_set = set(f.strip() for f in fields.split(","))
                # Use model_dump() for Pydantic v2 or dict() for v1
                incident_dict = incident.model_dump() if hasattr(incident, 'model_dump') else incident.dict()
                filtered = {k: v for k, v in incident_dict.items() if k in field_set}
                incidents.append(filtered)
            else:
                # Convert to dict for JSON serialization
                incident_dict = incident.model_dump() if hasattr(incident, 'model_dump') else incident.dict()
                incidents.append(incident_dict)
        except Exception as e:
            logger.error(f"Error converting incident model {model.id}: {e}")
            continue
    
    return incidents


@router.get("/{incident_id}", response_model=Incident)
@cache_response(ttl=60, key_prefix="incidents:detail")
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    response: Response = None,
):
    """Get incident by ID with caching."""
    if response:
        response.headers["Cache-Control"] = "public, max-age=60"
    
    incident_model = await IncidentRepository.get_by_id(db, incident_id)
    if not incident_model:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    incident = await IncidentRepository.model_to_pydantic(incident_model)
    # Convert to dict for JSON serialization
    return incident.model_dump() if hasattr(incident, 'model_dump') else incident.dict()


@router.post("", response_model=Incident)
async def create_incident(
    incident: Incident,
    db: AsyncSession = Depends(get_db),
):
    """Create a new incident."""
    if incident.id is None:
        incident.id = str(uuid.uuid4())
    
    incident_data = {
        "id": incident.id,
        "status": incident.status,
        "severity": incident.severity,
        "threat_intel": incident.threat_intel,
        "confidence_score": incident.confidence_score,
        "false_positive_reason": incident.false_positive_reason,
    }
    
    incident_model = await IncidentRepository.create(db, incident_data)
    from app.core.cache import invalidate_incident_caches
    await invalidate_incident_caches()
    return await IncidentRepository.model_to_pydantic(incident_model)


@router.put("/{incident_id}", response_model=Incident)
async def update_incident(
    incident_id: str,
    incident: Incident,
    db: AsyncSession = Depends(get_db),
):
    """Update an incident."""
    incident_data = {
        "status": incident.status,
        "severity": incident.severity,
        "threat_intel": incident.threat_intel,
        "confidence_score": incident.confidence_score,
        "false_positive_reason": incident.false_positive_reason,
    }
    
    incident_model = await IncidentRepository.update(db, incident_id, incident_data)
    if not incident_model:
        raise HTTPException(status_code=404, detail="Incident not found")

    from app.core.cache import invalidate_incident_caches
    await invalidate_incident_caches()
    return await IncidentRepository.model_to_pydantic(incident_model)


def _find_and_update_action_status(actions_list: list, action_id: str, status: str) -> bool:
    """Find action by id in a list of dicts and update status. Returns True if found."""
    for a in actions_list:
        if isinstance(a, dict) and a.get("id") == action_id:
            a["status"] = status
            return True
    return False


@router.patch("/{incident_id}/response-plan/actions/{action_id}")
async def update_response_plan_action_status(
    incident_id: str,
    action_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
):
    """Update a single response plan action's status (e.g. pending -> in_progress -> completed)."""
    status = body.get("status")
    if not status or status not in ("pending", "in_progress", "completed", "cancelled"):
        raise HTTPException(
            status_code=400,
            detail="status must be one of: pending, in_progress, completed, cancelled",
        )
    plan_model = await db.execute(
        select(ResponsePlanModel).where(ResponsePlanModel.incident_id == incident_id)
    )
    plan = plan_model.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Response plan not found")
    for attr in ("containment_actions", "investigation_steps", "remediation_actions", "long_term_improvements"):
        lst = list(getattr(plan, attr) or [])
        if _find_and_update_action_status(lst, action_id, status):
            setattr(plan, attr, lst)
            await db.commit()
            await db.refresh(plan)
            return {"ok": True, "action_id": action_id, "status": status}
    raise HTTPException(status_code=404, detail="Action not found in response plan")


@router.put("/{incident_id}/status", response_model=Incident)
async def update_incident_status(
    incident_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
):
    """Update only the status of an incident (e.g. contained, closed)."""
    status_value = body.get("status")
    if not status_value:
        raise HTTPException(status_code=400, detail="status is required")
    try:
        status_enum = IncidentStatus(status_value)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {[s.value for s in IncidentStatus]}",
        )
    incident_model = await IncidentRepository.get_by_id(db, incident_id)
    if not incident_model:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident_data = {"status": status_enum}
    updated = await IncidentRepository.update(db, incident_id, incident_data)
    from app.core.cache import invalidate_incident_caches
    await invalidate_incident_caches()
    return await IncidentRepository.model_to_pydantic(updated)


@router.delete("/{incident_id}")
async def delete_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete an incident."""
    success = await IncidentRepository.delete(db, incident_id)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")

    from app.core.cache import invalidate_incident_caches
    await invalidate_incident_caches()
    return {"message": "Incident deleted"}


class IncidentStatusResponse(BaseModel):
    """Status response for incident analysis progress."""
    status: str  # "queued" | "analyzing" | "completed" | "failed"
    progress_percent: int
    current_agent: Optional[str] = None
    eta_seconds: Optional[int] = None
    message: Optional[str] = None
    error: Optional[str] = None


@router.get("/{incident_id}/status", response_model=IncidentStatusResponse)
async def get_incident_status(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get current status of incident analysis (for polling)."""
    # Check Redis for live status
    from app.database.redis_client import hgetall

    status_key = f"incident_status:{incident_id}"
    
    try:
        status_data = await hgetall(status_key)
        if status_data:
            progress = int(status_data.get("progress_percent", "0") or 0)
            estimated_duration = int(
                status_data.get("estimated_duration", str(TOTAL_ESTIMATED_SECONDS)) or TOTAL_ESTIMATED_SECONDS
            )
            current_agent = status_data.get("current_agent") or None
            
            # Calculate ETA
            started_at_str = status_data.get("started_at")
            eta_seconds = None
            if started_at_str:
                try:
                    started_at = datetime.fromisoformat(started_at_str.replace("Z", "+00:00"))
                    elapsed = (datetime.utcnow() - started_at.replace(tzinfo=None)).total_seconds()
                    remaining = estimated_duration - elapsed
                    eta_seconds = max(0, int(remaining))
                except Exception:
                    pass
            
            return IncidentStatusResponse(
                status=status_data.get("status", "analyzing"),
                progress_percent=progress,
                current_agent=current_agent,
                eta_seconds=eta_seconds,
                message=status_data.get("message"),
                error=status_data.get("error"),
            )
    except Exception as e:
        logger.warning(f"Redis status check failed: {e}")
    
    # Fallback: check database
    try:
        incident_model = await IncidentRepository.get_by_id(db, incident_id)
        if incident_model:
            status = str(incident_model.status).lower()
            if status in ["new", "analyzing", "in_progress"]:
                return IncidentStatusResponse(
                    status="analyzing",
                    progress_percent=50,  # Unknown progress
                    current_agent=None,
                    eta_seconds=None,
                )
            elif status == "closed":
                return IncidentStatusResponse(
                    status="completed",
                    progress_percent=100,
                    current_agent=None,
                    eta_seconds=0,
                )
            else:
                return IncidentStatusResponse(
                    status="completed",
                    progress_percent=100,
                    current_agent=None,
                    eta_seconds=0,
                )
    except Exception:
        pass
    
    # Default: not found
    raise HTTPException(status_code=404, detail="Incident status not found")

