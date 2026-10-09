from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from enum import Enum
import uuid

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class NormalizedLog(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    host: str
    source: str
    log_type: str
    severity: Severity = Severity.INFO
    message: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    incident_id: Optional[str] = None
    original_log: Optional[str] = None  # To keep trace of raw data if needed
    tenant_id: Optional[str] = None

class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class SOARActionStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"

class SOARAction(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    params: Dict[str, Any] = Field(default_factory=dict)
    status: SOARActionStatus = SOARActionStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: int = Field(ge=0, le=100)
    source_logs: List[NormalizedLog]
    status: IncidentStatus = IncidentStatus.OPEN
    description: Optional[str] = None
    artifacts: Dict[str, Any] = Field(default_factory=dict)
    pending_actions: List[SOARAction] = Field(default_factory=list)
    tenant_id: Optional[str] = None
