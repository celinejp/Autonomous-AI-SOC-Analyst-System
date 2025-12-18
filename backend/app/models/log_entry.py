"""Log entry models."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class LogFormat(str, Enum):
    """Supported log formats."""

    SYSLOG = "syslog"
    JSON = "json"
    CEF = "cef"
    WINDOWS_EVENT = "windows_event"


class LogSource(str, Enum):
    """Log sources."""

    DNS = "dns"
    AUTH = "auth"
    HTTP = "http"
    SYSTEM = "system"


class LogEntry(BaseModel):
    """Normalized log entry model."""

    id: Optional[str] = None
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    user: Optional[str] = None
    action: str
    status: str
    log_source: LogSource
    raw_log: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }

