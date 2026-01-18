"""Automated Response Actions API endpoints."""

from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any
from pydantic import BaseModel

from sqlalchemy.ext.asyncio import AsyncSession
from app.database.postgres import get_db
from app.services.response_service import get_response_executor

router = APIRouter()


class BlockIPRequest(BaseModel):
    """Block IP request model."""

    ip_address: str
    duration_hours: int = 24


class DisableAccountRequest(BaseModel):
    """Disable account request model."""

    username: str
    reason: str


class ExecutePlanRequest(BaseModel):
    """Execute response plan request model."""

    incident_id: str
    response_plan: Dict[str, Any]


@router.post("/block-ip")
async def block_ip(request: BlockIPRequest):
    """Block an IP address."""
    try:
        executor = get_response_executor()
        result = await executor.block_ip(request.ip_address, request.duration_hours)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unblock-ip/{ip_address}")
async def unblock_ip(ip_address: str):
    """Unblock an IP address."""
    try:
        executor = get_response_executor()
        result = await executor.unblock_ip(ip_address)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/disable-account")
async def disable_account(request: DisableAccountRequest):
    """Disable a user account."""
    try:
        executor = get_response_executor()
        result = await executor.disable_account(request.username, request.reason)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/enable-account/{username}")
async def enable_account(username: str):
    """Enable a user account."""
    try:
        executor = get_response_executor()
        result = await executor.enable_account(username)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute-plan")
async def execute_response_plan(request: ExecutePlanRequest):
    """Execute a response plan."""
    try:
        executor = get_response_executor()
        result = await executor.execute_response_plan(
            request.response_plan,
            request.incident_id,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/execution-log")
async def get_execution_log():
    """Get response action execution log."""
    try:
        executor = get_response_executor()
        return {"log": executor.get_execution_log()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

