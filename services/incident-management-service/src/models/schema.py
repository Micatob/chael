from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
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
    original_log: Optional[str] = None

class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

# Valid analyst transitions (state machine enforces SOC workflow)
VALID_TRANSITIONS: Dict[str, List[str]] = {
    "OPEN": ["TRIAGED", "INVESTIGATING", "FALSE_POSITIVE"],
    "TRIAGED": ["INVESTIGATING", "FALSE_POSITIVE", "OPEN"],
    "INVESTIGATING": ["CONTAINED", "RESOLVED", "FALSE_POSITIVE", "OPEN"],
    "CONTAINED": ["RESOLVED", "INVESTIGATING"],
    "RESOLVED": ["CLOSED", "INVESTIGATING"],
    "CLOSED": ["INVESTIGATING"],
    "FALSE_POSITIVE": ["OPEN", "INVESTIGATING"],
}

class SLAPriority(str, Enum):
    P1 = "P1"  # Critical: 1 hour response, 4 hours resolve
    P2 = "P2"  # High: 4 hours response, 24 hours resolve
    P3 = "P3"  # Medium: 8 hours response, 72 hours resolve
    P4 = "P4"  # Low: 24 hours response, 168 hours resolve (7 days)

# SLA targets in hours: (response_hours, resolve_hours)
SLA_TARGETS = {
    "P1": {"response_hours": 1, "resolve_hours": 4},
    "P2": {"response_hours": 4, "resolve_hours": 24},
    "P3": {"response_hours": 8, "resolve_hours": 72},
    "P4": {"response_hours": 24, "resolve_hours": 168},
}

class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: int = Field(ge=0, le=100)
    source_logs: List[Dict[str, Any]]  # Flexible; store log references
    status: IncidentStatus = IncidentStatus.OPEN
    description: Optional[str] = None
    artifacts: Dict[str, Any] = Field(default_factory=dict)
    investigation_results: Optional[Dict[str, Any]] = None
    mitigation_history: List[Dict[str, Any]] = Field(default_factory=list)
    sla_priority: Optional[SLAPriority] = None
    sla_response_deadline: Optional[datetime] = None
    sla_resolve_deadline: Optional[datetime] = None
    sla_responded_at: Optional[datetime] = None
    sla_resolved_at: Optional[datetime] = None
    sla_breached: bool = False
    assigned_to: Optional[str] = None
    # Case workbench (analyst collaboration)
    notes: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    mitre_attack: List[str] = Field(default_factory=list)
    compliance: Dict[str, List[str]] = Field(default_factory=dict)
    # Evidence locker (simple, on-document) + legal hold (blocks purge/close)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    legal_hold: bool = False

class MitigationAction(BaseModel):
    action_type: str  # BLOCK_IP | ISOLATE_HOST | KILL_PROCESS | QUARANTINE_FILE | DELETE_PERSISTENCE | COLLECT_TRIAGE | ...
    target: str       # e.g., "192.168.1.50" or hostname
    reason: str
    params: Dict[str, Any] = Field(default_factory=dict)  # process/pid/path/persistence_* /agent_id
    status: str = "PENDING"
    executed_at: Optional[datetime] = None
    executed_by: str = "SYSTEM"


class CaseNote(BaseModel):
    note_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    author: str = "analyst"
    body: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    visibility: str = "internal"  # internal | external


class EvidenceItem(BaseModel):
    """Seized evidence with hash + custody trail (kept simple: stored on the
    incident document, hash-chained into the incident timeline)."""
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str = "note"  # file | hash | log-slice | image | triage | note
    title: str
    description: str = ""
    sha256: str = ""
    collector: str = "analyst"
    source_host: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    custody: List[Dict[str, Any]] = Field(default_factory=list)  # transfers
    verified: bool = False
    verified_at: Optional[datetime] = None


class TimelineEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = "system"
    action: str  # created | status_change | note_added | investigation | mitigation | assignment | export | ai_analysis
    details: Dict[str, Any] = Field(default_factory=dict)
