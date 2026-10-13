"""Chunked forensic-image upload: stage chunks, seal with SHA-256, reject tampering."""
import hashlib
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ.setdefault("JWT_SECRET", "test-secret-for-imaging-tests")

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from config import settings
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


def _incident_dict(iid="inc-img-001"):
    return {
        "incident_id": iid,
        "timestamp": "2026-06-01T10:00:00Z",
        "risk_score": 90,
        "source_logs": [],
        "status": "OPEN",
        "description": "Canary imaging target",
        "artifacts": {"host": "canary-01"},
    }


@pytest.fixture
def svc_client(tmp_path):
    from api.main import app
    from api.routers import incidents as inc_router
    repo = StubRepo()
    repo.store["inc-img-001"] = dict(_incident_dict())
    svc = IncidentService(repo=repo, engine=None, mitigation_engine=None)
    svc.EVIDENCE_DIR = str(tmp_path / "evidence")
    app.dependency_overrides[inc_router.get_incident_service] = lambda: svc
    token = jwt.encode({"id": "test-admin", "role": "ADMIN", "tenant_id": "default"},
                       settings.jwt_secret, algorithm=settings.JWT_ALGORITHM)
    headers = {"Authorization": f"Bearer {token}"}
    yield TestClient(app), headers
    app.dependency_overrides.clear()


def _upload(svc_client, blob, kind="memory", filename="mem.bin", incident_id="inc-img-001"):
    client, headers = svc_client
    upload_id = "upltest001"
    chunks = [blob[i:i + 1024] for i in range(0, len(blob), 1024)] or [b""]
    for i, piece in enumerate(chunks):
        r = client.post(f"/api/incidents/{incident_id}/evidence/image-chunk",
                        data={"upload_id": upload_id, "chunk_index": str(i)},
                        files={"chunk": (f"chunk-{i:06d}", piece, "application/octet-stream")},
                        headers=headers)
        assert r.status_code == 200, r.text
    sha = hashlib.sha256(blob).hexdigest()
    r = client.post(f"/api/incidents/{incident_id}/evidence/image-complete",
                    json={"upload_id": upload_id, "filename": filename,
                          "sha256": sha, "kind": kind},
                    headers=headers)
    return r, sha, len(chunks)


class TestImageUpload:
    def test_chunk_round_trip_seals_evidence(self, svc_client):
        blob = b"forensic-bytes-" * 500  # multi-chunk
        r, sha, nchunks = _upload(svc_client, blob)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "sealed"
        assert body["chunks"] == nchunks
        assert body["evidence"]["sha256"] == sha
        assert body["evidence"]["type"] == "memory"

    def test_sha_mismatch_rejected(self, svc_client):
        client, headers = svc_client
        blob = b"real-bytes"
        r = client.post("/api/incidents/inc-img-001/evidence/image-chunk",
                        data={"upload_id": "uplbad001", "chunk_index": "0"},
                        files={"chunk": ("chunk-000000", blob, "application/octet-stream")},
                        headers=headers)
        assert r.status_code == 200
        r = client.post("/api/incidents/inc-img-001/evidence/image-complete",
                        json={"upload_id": "uplbad001", "filename": "x.bin",
                              "sha256": "0" * 64, "kind": "memory"},
                        headers=headers)
        assert r.status_code == 400
        assert "mismatch" in r.json()["detail"].lower()

    def test_unknown_incident_404(self, svc_client):
        client, headers = svc_client
        r = client.post("/api/incidents/nope/eidence/image-chunk".replace("eidence", "evidence"),
                        data={"upload_id": "u1", "chunk_index": "0"},
                        files={"chunk": ("c", b"x", "application/octet-stream")},
                        headers=headers)
        assert r.status_code == 404

    def test_bad_kind_rejected(self, svc_client):
        client, headers = svc_client
        r = client.post("/api/incidents/inc-img-001/evidence/image-complete",
                        json={"upload_id": "u1", "filename": "x",
                              "sha256": "a" * 64, "kind": "tape"},
                        headers=headers)
        assert r.status_code == 400

    def test_analyst_cannot_upload(self, svc_client):
        client, _ = svc_client
        analyst = jwt.encode({"id": "a", "role": "ANALYST", "tenant_id": "default"},
                             settings.jwt_secret, algorithm=settings.JWT_ALGORITHM)
        r = client.post("/api/incidents/inc-img-001/evidence/image-chunk",
                        data={"upload_id": "u2", "chunk_index": "0"},
                        files={"chunk": ("c", b"x", "application/octet-stream")},
                        headers={"Authorization": f"Bearer {analyst}"})
        assert r.status_code == 403
