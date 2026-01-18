"""Network flow models for SOC analysis."""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class NetworkFlow(BaseModel):
    """Network flow telemetry model."""

    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # TCP, UDP, ICMP
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    duration_ms: int
    tcp_flags: Optional[str] = None

    # Derived/enriched fields
    src_geo_country: Optional[str] = None
    dst_geo_country: Optional[str] = None
    src_asn: Optional[str] = None
    dst_asn: Optional[str] = None
    dst_domain: Optional[str] = None  # If resolved

    # TLS metadata (from Zeek/JA3)
    ja3_hash: Optional[str] = None
    ja3s_hash: Optional[str] = None
    server_name: Optional[str] = None  # SNI

    # Classification
    is_internal: bool = False
    is_known_service: bool = False

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class BeaconingAnalysis(BaseModel):
    """Result of beaconing detection analysis."""

    dst_ip: str
    dst_domain: Optional[str] = None
    connection_count: int
    avg_interval_seconds: float
    interval_std_dev: float
    regularity_score: float = Field(ge=0.0, le=1.0)  # 0-1, higher = more regular
    total_bytes: int
    is_suspicious: bool
    confidence: float = Field(ge=0.0, le=1.0)

