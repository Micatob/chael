from config import settings
from core.identity.jwt import create_access_token
from auth.middleware import require_roles


class TestJWTCreation:
    def test_creates_valid_jwt(self):
        token = create_access_token({"id": "test", "role": "ADMIN"})
        assert isinstance(token, str)
        assert len(token) > 20

    def test_jwt_contains_claims(self):
        token = create_access_token({"id": "usr-001", "username": "admin", "role": "ADMIN"})
        from jose import jwt
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.JWT_ALGORITHM])
        assert payload["role"] == "ADMIN"
        assert payload["id"] == "usr-001"


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_health_returns_service_name(self, client):
        resp = client.get("/health")
        assert "identity-service" in resp.json()["service"]


class TestLoginEndpoint:
    def test_login_success_returns_token(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": settings.ADMIN_USERNAME, "password": settings.ADMIN_PASSWORD},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["role"] == "ADMIN"

    def test_login_failure_returns_401(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrongpassword"},
        )
        assert resp.status_code == 401
        assert "Invalid credentials" in resp.json()["detail"]


class TestRoleSplit:
    def test_approver_login_when_configured(self, client, monkeypatch):
        monkeypatch.setattr(settings, "APPROVER_USERNAME", "approver")
        monkeypatch.setattr(settings, "APPROVER_PASSWORD", "Appr0ver!Pass")
        resp = client.post("/api/auth/login", json={"username": "approver", "password": "Appr0ver!Pass"})
        assert resp.status_code == 200
        assert resp.json()["user"]["role"] == "APPROVER"

    def test_analyst_login_when_configured(self, client, monkeypatch):
        monkeypatch.setattr(settings, "ANALYST_USERNAME", "analyst")
        monkeypatch.setattr(settings, "ANALYST_PASSWORD", "An4lyst!Pass")
        resp = client.post("/api/auth/login", json={"username": "analyst", "password": "An4lyst!Pass"})
        assert resp.status_code == 200
        assert resp.json()["user"]["role"] == "ANALYST"

    def test_approver_disabled_by_default(self, client):
        assert not settings.APPROVER_USERNAME
        resp = client.post("/api/auth/login", json={"username": "approver", "password": "x"})
        assert resp.status_code == 401

    def test_login_missing_fields_returns_422(self, client):
        resp = client.post("/api/auth/login", json={})
        assert resp.status_code == 422


class TestRequireRoles:
    async def test_allows_correct_role(self):
        class MockRequest:
            state = type("State", (), {"user": {"role": "ADMIN"}})()

        checker = require_roles(["ADMIN"])
        result = await checker(MockRequest())
        assert result["role"] == "ADMIN"

    async def test_rejects_insufficient_role(self):
        class MockRequest:
            state = type("State", (), {"user": {"role": "VIEWER"}})()

        checker = require_roles(["ADMIN"])
        import pytest
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            await checker(MockRequest())
        assert exc.value.status_code == 403

    async def test_rejects_unauthenticated(self):
        class MockRequest:
            state = type("State", (), {"user": None})()

        checker = require_roles(["ADMIN"])
        import pytest
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            await checker(MockRequest())
        assert exc.value.status_code == 401


class TestValidateEndpoint:
    def test_validate_with_valid_token(self, client):
        token = create_access_token({"id": "usr-001", "role": "ADMIN"})
        resp = client.get("/api/auth/validate", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["valid"] is True
        assert resp.json()["role"] == "ADMIN"

    def test_validate_without_token_returns_401(self, client):
        resp = client.get("/api/auth/validate")
        assert resp.status_code == 401
