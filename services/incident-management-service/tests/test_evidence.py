import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from incidents.service import IncidentService
from models.schema import Incident


class StubRepo:
    """In-memory repo — no OpenSearch needed."""

    def __init__(self):
        self.store = {}

    def create(self, incident: Incident) -> Incident:
        self.store[incident.incident_id] = incident.model_dump()
        return incident

    def get_all(self, status=None):
        incidents = list(self.store.values())
        if status:
            incidents = [i for i in incidents if i.get("status") == status]
        return incidents

    def get_by_id(self, incident_id):
        return self.store.get(incident_id)


def _base_incident():
    return {
        "incident_id": "inc-ev-001",
        "timestamp": "2026-06-01T10:00:00Z",
        "risk_score": 75,
        "source_logs": [],
        "status": "OPEN",
        "description": "SSH brute force from 203.0.113.9",
        "artifacts": {"host": "web-01"},
    }


@pytest.fixture
def service():
    repo = StubRepo()
    repo.store["inc-ev-001"] = dict(_base_incident())
    return IncidentService(repo=repo, engine=None, mitigation_engine=None)


class TestEvidenceLocker:
    def test_seize_creates_sealed_evidence(self, service):
        ev = service.add_evidence("inc-ev-001", {"type": "log-slice", "title": "auth.log 09:55-10:00",
                                                 "sha256": "abc123", "source_host": "web-01"})
        assert ev["evidence_id"]
        assert ev["seal_hash"]
        assert len(ev["custody"]) == 1
        assert ev["custody"][0]["reason"] == "seized"

    def test_seize_requires_title(self, service):
        with pytest.raises(ValueError):
            service.add_evidence("inc-ev-001", {"type": "hash"})

    def test_seize_unknown_incident(self, service):
        with pytest.raises(ValueError):
            service.add_evidence("nope", {"title": "x"})

    def test_transfer_appends_custody_and_resets_verify(self, service):
        ev = service.add_evidence("inc-ev-001", {"title": "memory hash", "sha256": "deadbeef"})
        service.verify_evidence("inc-ev-001", ev["evidence_id"])
        moved = service.transfer_evidence("inc-ev-001", ev["evidence_id"],
                                          {"to": "soc-lead", "reason": "shift handoff"})
        assert moved["custody"][-1]["to"] == "soc-lead"
        assert moved["verified"] is False

    def test_verify_ok(self, service):
        ev = service.add_evidence("inc-ev-001", {"title": "disk image manifest", "sha256": "cafe"})
        result = service.verify_evidence("inc-ev-001", ev["evidence_id"])
        assert result["ok"] is True

    def test_verify_detects_tamper(self, service):
        ev = service.add_evidence("inc-ev-001", {"title": "log slice", "sha256": "orig"})
        stored = service.repo.get_by_id("inc-ev-001")
        stored["evidence"][0]["title"] = "ALTERED TITLE"
        result = service.verify_evidence("inc-ev-001", ev["evidence_id"])
        assert result["ok"] is False

    def test_legal_hold_blocks_close(self, service):
        service.set_legal_hold("inc-ev-001", True)
        with pytest.raises(ValueError, match="legal hold"):
            service.transition_status("inc-ev-001", "INVESTIGATING")
            service.transition_status("inc-ev-001", "CONTAINED")
            service.transition_status("inc-ev-001", "RESOLVED")
        # release → close path works
        service.set_legal_hold("inc-ev-001", False)
        service.transition_status("inc-ev-001", "INVESTIGATING")
        service.transition_status("inc-ev-001", "CONTAINED")
        closed = service.transition_status("inc-ev-001", "RESOLVED")
        assert closed["status"] == "RESOLVED"

    def test_evidence_timeline_entries(self, service):
        service.add_evidence("inc-ev-001", {"title": "ioc list"})
        timeline = service.get_timeline("inc-ev-001")
        actions = [e["action"] for e in timeline]
        assert "evidence_seized" in actions
