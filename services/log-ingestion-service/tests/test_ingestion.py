from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


class TestIngestionEndpoints:
    def test_health_endpoint(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    def test_ingest_normalized_log(self, auth_headers):
        resp = client.post("/api/logs/ingest", json={
            "host": "test-host",
            "source": "test",
            "log_type": "generic",
            "severity": "INFO",
            "message": "test message",
            "metadata": {},
        }, headers=auth_headers)
        assert resp.status_code == 202
        assert resp.json()["status"] == "queued"

    def test_ingest_raw_syslog(self, auth_headers):
        resp = client.post("/api/logs/raw/syslog", json={
            "message": "Failed password for root from 10.0.0.5 port 22 ssh2",
            "host": "web-01",
        }, headers=auth_headers)
        assert resp.status_code == 202
        assert resp.json()["status"] == "queued"

    def test_ingest_raw_unsupported_source(self, auth_headers):
        resp = client.post("/api/logs/raw/unsupported_source", json={"message": "test"}, headers=auth_headers)
        assert resp.status_code == 202


class TestHeartbeatEndpoint:
    def test_heartbeat(self, auth_headers):
        resp = client.post("/api/logs/heartbeat", json={
            "hostname": "test-agent",
            "source_type": "chael-agent",
            "status": "online",
            "metadata": {"version": "1.0.0"},
        }, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"

    def test_heartbeat_defaults(self, auth_headers):
        resp = client.post("/api/logs/heartbeat", json={}, headers=auth_headers)
        assert resp.status_code == 200


class TestQueryEndpoints:
    def test_list_logs(self, auth_headers):
        resp = client.get("/api/logs/", headers=auth_headers)
        assert resp.status_code == 200

    def test_list_logs_with_filters(self, auth_headers):
        resp = client.get("/api/logs/?severity=HIGH&host=test-host&limit=10", headers=auth_headers)
        assert resp.status_code == 200

    def test_export_json(self, auth_headers):
        resp = client.get("/api/logs/export?format=json", headers=auth_headers)
        assert resp.status_code == 200

    def test_export_csv(self, auth_headers):
        resp = client.get("/api/logs/export?format=csv", headers=auth_headers)
        assert resp.status_code == 200

    def test_sources_endpoint(self, auth_headers):
        resp = client.get("/api/logs/sources", headers=auth_headers)
        assert resp.status_code == 200

    def test_stats_endpoint(self, auth_headers):
        resp = client.get("/api/logs/stats", headers=auth_headers)
        assert resp.status_code == 200
