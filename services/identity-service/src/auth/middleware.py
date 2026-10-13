import logging
import re
from fastapi import Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from jose import jwt, JWTError
from config import settings

logger = logging.getLogger(__name__)

PUBLIC_PATHS = {
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/api/auth/health",
    "/api/auth/login",
    "/api/auth/agent/verify",
    "/api/auth/agent/auto-register",
    "/api/auth/validate",
    "/api/auth/agent/version",
    "/metrics",
    "/api/agents/register",
    "/api/agents/verify",
}

PUBLIC_PATH_PATTERNS = [
    re.compile(r"^/api/agents/[^/]+/heartbeat$"),
    re.compile(r"^/api/auth/agent/[^/]+/heartbeat$"),
]

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/")
        if any(path.startswith(p) for p in PUBLIC_PATHS) or path in PUBLIC_PATHS:
            return await call_next(request)
        if any(p.match(path) for p in PUBLIC_PATH_PATTERNS):
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

        try:
            token = auth_header.split(" ", 1)[1]
            payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.JWT_ALGORITHM])
            request.state.user = payload
            request.state.tenant_id = payload.get("tenant_id", settings.DEFAULT_TENANT_ID)
        except JWTError:
            return JSONResponse(status_code=401, content={"detail": "Invalid token"})

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
