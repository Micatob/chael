import logging
import base64
import json
import hmac
import hashlib
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from config import settings

logger = logging.getLogger(__name__)

PUBLIC_PATHS = {
    "/health",
    "/api/ai/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/metrics",
}


def _decode_jwt(token: str, secret: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    expected_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode()
    if not hmac.compare_digest(sig_b64, expected_b64):
        raise ValueError("Invalid signature")
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    import time
    exp = payload.get("exp")
    if exp and exp < time.time():
        raise ValueError("Token expired")
    return payload


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/")
        if path == "/" or path in PUBLIC_PATHS or any(path.startswith(p) for p in PUBLIC_PATHS if p):
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")

        try:
            token = auth_header.split(" ", 1)[1]
            payload = _decode_jwt(token, settings.jwt_secret)
            request.state.user = payload
            request.state.tenant_id = payload.get("tenant_id", settings.DEFAULT_TENANT_ID)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

        return await call_next(request)


def require_roles(allowed_roles: list[str]):
    async def checker(request: Request):
        user = getattr(request.state, "user", None)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if user.get("role") not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker
