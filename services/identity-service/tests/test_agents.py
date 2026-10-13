"""Agent registration / mark-online ownership / mTLS proof-of-possession."""
import json
import uuid

from config import settings
from core.identity.jwt import create_access_token


def _admin_headers(client):
    resp = client.post("/api/auth/login", json={
        "username": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_PASSWORD,
    })
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _unique_host(prefix="test-agent"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _register(client, admin_headers, hostname):
    resp = client.post("/api/auth/agent/register", json={"hostname": hostname},
                       headers=admin_headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _hard_delete(client, admin_headers, agent_id):
    client.delete(f"/api/auth/agent/{agent_id}/hard", headers=admin_headers)


class TestManualRegister:
    def test_register_requires_auth(self, client):
        resp = client.post("/api/auth/agent/register", json={"hostname": "nope"})
        assert resp.status_code == 401

    def test_register_returns_credentials(self, client):
        admin = _admin_headers(client)
        host = _unique_host()
        try:
            body = _register(client, admin, host)
            assert body["agent_id"] and body["agent_key"] and body["hostname"] == host
            # Credentials verify immediately (round-trip certainty).
            v = client.post("/api/auth/agent/verify", json={
                "agent_id": body["agent_id"], "agent_key": body["agent_key"]})
            assert v.status_code == 200, v.text
            assert v.json()["access_token"]
        finally:
            _hard_delete(client, admin, body["agent_id"])


class TestMarkOnlineOwnership:
    def test_mark_online_requires_auth(self, client):
        resp = client.post("/api/auth/agent/some-id/mark-online")
        assert resp.status_code == 401

    def test_admin_may_mark_any(self, client):
        admin = _admin_headers(client)
        body = _register(client, admin, _unique_host())
        try:
            resp = client.post(f"/api/auth/agent/{body['agent_id']}/mark-online",
                               headers=admin)
            assert resp.status_code == 200, resp.text
        finally:
            _hard_delete(client, admin, body["agent_id"])

    def test_agent_may_mark_only_itself(self, client):
        admin = _admin_headers(client)
        a = _register(client, admin, _unique_host("mtls-a"))
        b = _register(client, admin, _unique_host("mtls-b"))
        try:
            agent_token = client.post("/api/auth/agent/verify", json={
                "agent_id": a["agent_id"], "agent_key": a["agent_key"]}).json()["access_token"]
            agent_headers = {"Authorization": f"Bearer {agent_token}"}
            own = client.post(f"/api/auth/agent/{a['agent_id']}/mark-online",
                              headers=agent_headers)
            assert own.status_code == 200, own.text
            other = client.post(f"/api/auth/agent/{b['agent_id']}/mark-online",
                                headers=agent_headers)
            assert other.status_code == 403
        finally:
            _hard_delete(client, admin, a["agent_id"])
            _hard_delete(client, admin, b["agent_id"])

    def test_mark_online_unknown_agent_404(self, client):
        admin = _admin_headers(client)
        resp = client.post("/api/auth/agent/does-not-exist/mark-online", headers=admin)
        assert resp.status_code == 404


class TestMTLSSignature:
    def _keypair(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                       backend=default_backend())
        priv = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()).decode()
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return priv, pub

    def _payload(self, machine_id, hostname, public_key):
        return {
            "machine_id": machine_id,
            "hostname": hostname,
            "platform": "Windows",
            "platform_version": "10.0",
            "os_info": "Windows 11",
            "public_key": public_key,
            "agent_version": "1.0.0",
        }

    def _sign(self, payload, private_pem):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agent"))
        from agent_registration import sign_payload, verify_payload_signature
        raw = json.dumps(payload, sort_keys=True).encode()
        sig = sign_payload(raw, private_pem.encode())
        assert verify_payload_signature(raw, sig, payload["public_key"]) is True
        return sig

    def test_valid_signature_registers_mtls(self, client):
        priv, pub = self._keypair()
        machine_id = uuid.uuid4().hex
        payload = self._payload(machine_id, _unique_host("mtls"), pub)
        payload["signature"] = self._sign(payload, priv)
        resp = client.post("/api/agents/register", json=payload)
        assert resp.status_code == 200, resp.text
        assert resp.json()["auth_method"] == "mtls"

    def test_tampered_signature_rejected(self, client):
        priv, pub = self._keypair()
        machine_id = uuid.uuid4().hex
        payload = self._payload(machine_id, _unique_host("mtls"), pub)
        sig = self._sign(payload, priv)
        payload["hostname"] = "evil-renamed-host"  # signed bytes no longer match
        payload["signature"] = sig
        resp = client.post("/api/agents/register", json=payload)
        assert resp.status_code == 401
