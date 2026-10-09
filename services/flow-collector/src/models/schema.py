from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from enum import Enum

class FlowDirection(str, Enum):
    INGRESS = "ingress"
    EGRESS = "egress"
    UNKNOWN = "unknown"

class FlowRecord(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"
    bytes: int = 0
    packets: int = 0
    duration_seconds: float = 0.0
    src_host: Optional[str] = None
    dst_host: Optional[str] = None
    app_name: Optional[str] = None
    direction: FlowDirection = FlowDirection.UNKNOWN
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tenant_id: Optional[str] = None

class FlowStats(BaseModel):
    total_flows_24h: int = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    total_bytes: int = 0
    top_ports: List[dict] = Field(default_factory=list)
    top_protocols: List[dict] = Field(default_factory=list)
