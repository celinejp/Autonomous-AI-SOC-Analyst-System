"""Tool for querying historical security logs."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import asyncio

from langchain.tools import tool

from app.database.postgres import AsyncSessionLocal
from app.database.repositories import LogEntryRepository
from app.models.log_entry import LogEntry, LogSource


@tool
async def query_logs(
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    user: Optional[str] = None,
    action: Optional[str] = None,
    time_range_hours: int = 24,
    limit: int = 100,
) -> str:
    """Query historical security logs based on filter criteria.
    
    This tool searches through ingested logs stored in PostgreSQL database.
    Use this to investigate related activity, check for similar attacks, or trace user behavior.
    
    Args:
        source_ip: Filter by source IP address
        destination_ip: Filter by destination IP address
        user: Filter by username
        action: Filter by action type (e.g., "login_attempt", "dns_query")
        time_range_hours: How many hours back to search (default: 24)
        limit: Maximum number of results (default: 100)
    
    Returns:
        JSON string with log entries matching the criteria
    """
    # Use async session to query database
    async def _query():
        async with AsyncSessionLocal() as session:
            log_models = await LogEntryRepository.query(
                session=session,
                source_ip=source_ip,
                destination_ip=destination_ip,
                user=user,
                action=action,
                time_range_hours=time_range_hours,
                limit=limit,
            )
            
            # Convert models to dict format
            results = []
            for log_model in log_models:
                results.append({
                    "timestamp": log_model.timestamp.isoformat(),
                    "source_ip": log_model.source_ip,
                    "destination_ip": log_model.destination_ip,
                    "destination_port": log_model.destination_port,
                    "user": log_model.user,
                    "action": log_model.action,
                    "status": log_model.status,
                    "log_source": log_model.log_source,
                    "raw_log": log_model.raw_log[:200] + "..." if len(log_model.raw_log) > 200 else log_model.raw_log,
                })
            
            return {
                "count": len(results),
                "logs": results,
                "filters": {
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "user": user,
                    "action": action,
                    "time_range_hours": time_range_hours,
                },
            }
    
    try:
        # Run async query
        loop = asyncio.get_event_loop()
        result = await loop.run_until_complete(_query())
        return f"Found {result['count']} log entries: {result}"
    except RuntimeError:
        # No event loop, create new one
        result = asyncio.run(_query())
        return f"Found {result['count']} log entries: {result}"
    except Exception as e:
        return f"Error querying logs: {str(e)}"


# Synchronous wrapper for LangChain compatibility
@tool
def query_logs_sync(
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    user: Optional[str] = None,
    action: Optional[str] = None,
    time_range_hours: int = 24,
    limit: int = 100,
) -> str:
    """Query historical security logs (synchronous wrapper).
    
    This tool searches through ingested logs for patterns matching the provided criteria.
    Use this to investigate related activity, check for similar attacks, or trace user behavior.
    """
    # For LangChain tools, return async coroutine info
    return f"Query logs: source_ip={source_ip}, destination_ip={destination_ip}, user={user}, action={action}, last {time_range_hours}h, limit={limit}. (Use async query_logs for actual results)"
