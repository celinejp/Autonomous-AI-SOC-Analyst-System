"""Endpoint action models for EDR integration."""

from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum
from datetime import datetime


class EndpointActionType(str, Enum):
    """Types of endpoint actions."""

    ISOLATE = "isolate"
    UNISOLATE = "unisolate"
    TERMINATE_PROCESS = "terminate_process"
    QUARANTINE_FILE = "quarantine_file"
    COLLECT_ARTIFACTS = "collect_artifacts"
    RUN_SCRIPT = "run_script"
    SCAN = "scan"


class EndpointAction(BaseModel):
    """Endpoint action request model."""

    id: str
    action_type: EndpointActionType
    target_host: str
    target_host_id: Optional[str] = Field(None, description="EDR agent ID")

    # Action-specific parameters
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    script_content: Optional[str] = None

    # Justification
    incident_id: str
    justification: str
    attack_technique: Optional[str] = None

    # Execution tracking
    status: str = "pending"  # pending, approved, executing, completed, failed
    requested_at: datetime
    requested_by: str = "ai_agent"  # user or "ai_agent"
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[str] = None
    error: Optional[str] = None

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class EDRIntegration(BaseModel):
    """Base class for EDR integrations."""

    name: str

    async def isolate_host(self, host_id: str, justification: str) -> EndpointAction:
        """Isolate a host from the network."""
        raise NotImplementedError

    async def terminate_process(self, host_id: str, process_id: int) -> EndpointAction:
        """Terminate a process on a host."""
        raise NotImplementedError

    async def quarantine_file(self, host_id: str, file_hash: str) -> EndpointAction:
        """Quarantine a file on a host."""
        raise NotImplementedError

