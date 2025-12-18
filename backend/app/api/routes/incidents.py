"""Incident management endpoints."""

from fastapi import APIRouter, HTTPException
from typing import List, Optional
from datetime import datetime
import uuid

from app.models.incident import Incident, IncidentStatus, Severity

router = APIRouter()

# In-memory storage for demo (replace with database in production)
incidents_db: dict[str, Incident] = {}


@router.get("", response_model=List[Incident])
async def list_incidents(
    status: Optional[IncidentStatus] = None,
    severity: Optional[Severity] = None,
    limit: int = 100,
):
    """List all incidents with optional filters."""
    incidents = list(incidents_db.values())
    
    if status:
        incidents = [i for i in incidents if i.status == status]
    if severity:
        incidents = [i for i in incidents if i.severity == severity]
    
    return incidents[:limit]


@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    """Get incident by ID."""
    if incident_id not in incidents_db:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incidents_db[incident_id]


@router.post("", response_model=Incident)
async def create_incident(incident: Incident):
    """Create a new incident."""
    if incident.id is None:
        incident.id = str(uuid.uuid4())
    incidents_db[incident.id] = incident
    return incident


@router.put("/{incident_id}", response_model=Incident)
async def update_incident(incident_id: str, incident: Incident):
    """Update an incident."""
    if incident_id not in incidents_db:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.id = incident_id
    incident.updated_at = datetime.utcnow()
    incidents_db[incident_id] = incident
    return incident


@router.delete("/{incident_id}")
async def delete_incident(incident_id: str):
    """Delete an incident."""
    if incident_id not in incidents_db:
        raise HTTPException(status_code=404, detail="Incident not found")
    del incidents_db[incident_id]
    return {"message": "Incident deleted"}

