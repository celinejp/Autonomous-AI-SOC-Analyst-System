"""Log entry models."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

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


class LogSourceType(str, Enum):
    """Extended log source types for SOC analysis."""

    SYSLOG = "syslog"
    WINDOWS_SECURITY = "windows_security"
    WINDOWS_SYSMON = "windows_sysmon"
    FIREWALL = "firewall"
    PROXY = "proxy"
    DNS = "dns"
    EMAIL_GATEWAY = "email_gateway"
    CLOUD_TRAIL = "cloud_trail"
    AZURE_MONITOR = "azure_monitor"
    GCP_LOGGING = "gcp_logging"
    EDR = "edr"
    CUSTOM = "custom"


class LogEntry(BaseModel):
    """Normalized log entry model with enhanced SOC fields."""

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
    
    # Process information
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    return_code: Optional[int] = None
    
    # File information
    file_hash_md5: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_path: Optional[str] = None
    
    # Windows-specific
    registry_key: Optional[str] = None
    event_id: Optional[int] = None
    
    # Authentication
    auth_result: Optional[str] = None  # success/failure/locked/expired
    
    # Network information
    protocol: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    packets: Optional[int] = None
    duration_ms: Optional[int] = None
    
    # DNS information
    dns_query: Optional[str] = None
    dns_response: Optional[str] = None
    
    # HTTP information
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    user_agent: Optional[str] = None
    
    # Email information
    email_subject: Optional[str] = None
    email_sender: Optional[str] = None
    email_recipients: Optional[List[str]] = Field(default_factory=list)
    attachment_names: Optional[List[str]] = Field(default_factory=list)
    
    # Geographic/Network intelligence
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    
    # Cloud-specific
    aws_region: Optional[str] = None
    aws_account: Optional[str] = None
    azure_tenant: Optional[str] = None
    gcp_project: Optional[str] = None
    
    # Extended source type
    log_source_type: Optional[LogSourceType] = None
    
    # Resource tracking
    resource: Optional[str] = None  # Resource ARN, path, etc.

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }

