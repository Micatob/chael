import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import io
import json
import urllib.request

import pytest
from incidents import dispatcher
from incidents.service import IncidentService
from models.schema import Incident


class StubRepo:
    def __init__(self):
        self.store = {}

    def create(self, incident: Incident) -> Incident:
        self.store[incident.incident_id] = incident.model_dump()
        return incident

    def get_all(self, status=None):
        return list(self.store.values())

    def get_by_id(self, incident_id):
        return self.store.get(incident_id)


class FakeHTTP:
    """Stand-in for urllib.request.urlopen (SOAR task queue endpoint)."""

    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


@pytest.fixture
def fake_soar(monkeypatch):
    calls = {}

    def fake_urlopen(req, timeout=None):
        calls["url"] = req.full_url
        calls["auth"] = req.headers.get("Authorization", "")
        body = json.loads(req.data.decode())
        calls["body"] = body
        return FakeHTTP({"status": "queued", "task": {
            "task_id": "task-123", "status": "PENDING",
            "action": body["action"], "target": body["target"]}})

    monkeypatch.setattr(dispatcher, "_service_jwt", lambda *a: "svc-token")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return calls


class TestDispatch:
    @pytest.mark.parametrize("atype,target,expected", [
        ("BLOCK_IP", "203.0.113.7", "block"),
        ("QUARANTINE_HOST", "web-01", "isolate"),
        ("KILL_PROCESS", "web-01", "kill_process"),
        ("QUARANTINE_FILE", "web-01", "quarantine_file"),
        ("DELETE_PERSISTENCE", "web-01", "delete_persistence"),
        ("COLLECT_TRIAGE", "web-01", "collect_triage"),
    ])
    def test_supported_actions_queue_tasks(self, fake_soar, atype, target, expected):
        out = dispatcher.dispatch_to_soar(
            atype, target, "inc-1", "analyst", {"process": "evil.exe"},
            "http://soar:8083", "http://ident:8004", "admin", "pw")
        assert out["status"] == "QUEUED"
        assert out["task_id"] == "task-123"
        assert fake_soar["body"]["action"] == expected
        assert fake_soar["auth"] == "Bearer svc-token"

    def test_unsupported_action_rejected(self, fake_soar):
        with pytest.raises(ValueError, match="Unsupported"):
            dispatcher.dispatch_to_soar(
                "DISABLE_USER", "jdoe", "inc-1", "analyst", {},
                "http://soar:8083", "http://ident:8004", "admin", "pw")

    def test_soar_down_fails_loudly(self, monkeypatch):
        monkeypatch.setattr(dispatcher, "_service_jwt", lambda *a: "svc-token")

        def boom(req, timeout=None):
            raise ConnectionError("refused")

        monkeypatch.setattr(urllib.request, "urlopen", boom)
        with pytest.raises(RuntimeError, match="NOT executed"):
            dispatcher.dispatch_to_soar(
                "BLOCK_IP", "1.2.3.4", "inc-1", "analyst", {},
                "http://soar:8083", "http://ident:8004", "admin", "pw")


def _seeded_service():
    repo = StubRepo()
    repo.store["inc-x"] = {
        "incident_id": "inc-x", "timestamp": "2026-06-01T10:00:00Z",
        "risk_score": 80, "source_logs": [], "status": "OPEN",
        "description": "malware", "artifacts": {"host": "web-01"},
    }
    return IncidentService(repo=repo, engine=None, mitigation_engine=None)


class TestMitigateService:
    def test_mitigate_queues_real_task(self, fake_soar, monkeypatch):
        import asyncio
        from incidents.mitigation import MitigationEngine
        import incidents.service as svc_mod
        monkeypatch.setattr(svc_mod.IncidentService, "_set_sla_deadlines",
                            lambda self, d: d, raising=False)
        service = _seeded_service()
        service.mitigation_engine = MitigationEngine()
        result = asyncio.run(service.perform_mitigation("inc-x", {
            "action_type": "KILL_PROCESS", "target": "web-01",
            "reason": "kill mimikatz", "params": {"process": "mimikatz.exe"},
            "executed_by": "analyst"}))
        assert result["status"] == "QUEUED"
        assert result["task_id"] == "task-123"
        assert "simulat" not in result.get("details", "").lower()
        stored = service.repo.get_by_id("inc-x")
        assert any("task-123" in str(m) for m in stored.get("mitigation_history", []))

    def test_register_bundle_seals_evidence(self, tmp_path, monkeypatch):
        service = _seeded_service()
        monkeypatch.setattr(IncidentService, "EVIDENCE_DIR", str(tmp_path), raising=False)
        blob = b"fake-triage-zip-bytes"
        ev = service.register_bundle("inc-x", "triage.zip", blob, actor="agent-7")
        assert ev["type"] == "triage"
        import hashlib
        assert ev["sha256"] == hashlib.sha256(blob).hexdigest()
        assert ev["seal_hash"]
        assert (tmp_path / "inc-x" / "triage.zip").read_bytes() == blob

    def test_register_bundle_rejects_oversize(self, tmp_path, monkeypatch):
        service = _seeded_service()
        monkeypatch.setattr(IncidentService, "MAX_BUNDLE_BYTES", 10, raising=False)
        with pytest.raises(ValueError, match="too large"):
            service.register_bundle("inc-x", "big.zip", b"0123456789ABC", actor="a")
