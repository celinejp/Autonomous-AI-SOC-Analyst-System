"""SIEM integration endpoints."""

from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

from sqlalchemy.ext.asyncio import AsyncSession
from app.database.postgres import get_db
from app.database.repositories import LogEntryRepository, IncidentRepository

router = APIRouter()


class SplunkEvent(BaseModel):
    """Splunk event model."""

    time: str
    host: str
    source: str
    sourcetype: str
    event: Dict[str, Any]


class ELKEvent(BaseModel):
    """ELK/Elasticsearch event model."""

    timestamp: str
    source: str
    message: Dict[str, Any]
    fields: Optional[Dict[str, Any]] = None


@router.post("/splunk/ingest")
async def ingest_splunk_events(
    events: List[SplunkEvent],
    db: AsyncSession = Depends(get_db),
):
    """Ingest events from Splunk.
    
    Converts Splunk events to log entries and stores them.
    """
    try:
        log_entries_data = []
        for event in events:
            # Convert Splunk event to log entry format
            log_entry = {
                "timestamp": event.time,
                "source_ip": event.event.get("src_ip", "unknown"),
                "destination_ip": event.event.get("dst_ip"),
                "destination_port": event.event.get("dst_port"),
                "user": event.event.get("user"),
                "action": event.event.get("action", "log_event"),
                "status": event.event.get("status", "unknown"),
                "log_source": event.sourcetype.split(":")[0] if ":" in event.sourcetype else "system",
                "raw_log": str(event.event),
                "metadata": {
                    "splunk_host": event.host,
                    "splunk_source": event.source,
                    "splunk_sourcetype": event.sourcetype,
                },
            }
            log_entries_data.append(log_entry)
        
        # Save to database
        await LogEntryRepository.create_bulk(db, log_entries_data)
        
        return {
            "status": "success",
            "events_processed": len(events),
            "log_entries_created": len(log_entries_data),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elk/ingest")
async def ingest_elk_events(
    events: List[ELKEvent],
    db: AsyncSession = Depends(get_db),
):
    """Ingest events from ELK/Elasticsearch.
    
    Converts ELK events to log entries and stores them.
    """
    try:
        log_entries_data = []
        for event in events:
            # Convert ELK event to log entry format
            message = event.message if isinstance(event.message, dict) else {"message": event.message}
            
            log_entry = {
                "timestamp": event.timestamp,
                "source_ip": message.get("source_ip") or message.get("src_ip", "unknown"),
                "destination_ip": message.get("destination_ip") or message.get("dst_ip"),
                "destination_port": message.get("destination_port") or message.get("dst_port"),
                "user": message.get("user") or message.get("username"),
                "action": message.get("action") or message.get("event_type", "log_event"),
                "status": message.get("status") or message.get("result", "unknown"),
                "log_source": event.source,
                "raw_log": str(message),
                "metadata": {
                    "elk_source": event.source,
                    "elk_fields": event.fields or {},
                },
            }
            log_entries_data.append(log_entry)
        
        # Save to database
        await LogEntryRepository.create_bulk(db, log_entries_data)
        
        return {
            "status": "success",
            "events_processed": len(events),
            "log_entries_created": len(log_entries_data),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/splunk/export")
async def export_to_splunk(
    incident_id: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    """Export incidents/logs in Splunk-compatible format."""
    try:
        if incident_id:
            # Export specific incident
            incident = await IncidentRepository.get_by_id(db, incident_id)
            if not incident:
                raise HTTPException(status_code=404, detail="Incident not found")
            
            # Convert to Splunk format
            events = []
            for log in incident.log_entries:
                events.append({
                    "time": log.timestamp.isoformat(),
                    "host": "soc-analyst",
                    "source": log.log_source,
                    "sourcetype": f"soc:{log.log_source}",
                    "event": {
                        "incident_id": incident_id,
                        "source_ip": log.source_ip,
                        "destination_ip": log.destination_ip,
                        "action": log.action,
                        "status": log.status,
                    },
                })
            
            return {"events": events}
        else:
            # Export recent logs
            logs = await LogEntryRepository.query(db, limit=limit)
            events = []
            for log in logs:
                events.append({
                    "time": log.timestamp.isoformat(),
                    "host": "soc-analyst",
                    "source": log.log_source,
                    "sourcetype": f"soc:{log.log_source}",
                    "event": {
                        "source_ip": log.source_ip,
                        "destination_ip": log.destination_ip,
                        "action": log.action,
                        "status": log.status,
                    },
                })
            
            return {"events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elk/export")
async def export_to_elk(
    incident_id: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    """Export incidents/logs in ELK-compatible format."""
    try:
        if incident_id:
            incident = await IncidentRepository.get_by_id(db, incident_id)
            if not incident:
                raise HTTPException(status_code=404, detail="Incident not found")
            
            events = []
            for log in incident.log_entries:
                events.append({
                    "timestamp": log.timestamp.isoformat(),
                    "source": log.log_source,
                    "message": {
                        "incident_id": incident_id,
                        "source_ip": log.source_ip,
                        "destination_ip": log.destination_ip,
                        "action": log.action,
                        "status": log.status,
                    },
                })
            
            return {"events": events}
        else:
            logs = await LogEntryRepository.query(db, limit=limit)
            events = []
            for log in logs:
                events.append({
                    "timestamp": log.timestamp.isoformat(),
                    "source": log.log_source,
                    "message": {
                        "source_ip": log.source_ip,
                        "destination_ip": log.destination_ip,
                        "action": log.action,
                        "status": log.status,
                    },
                })
            
            return {"events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

