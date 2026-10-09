import logging
from fastapi import Request, HTTPException, Depends
from starlette.middleware.base import BaseHTTPMiddleware
from jose import jwt, JWTError
from config import settings

logger = logging.getLogger(__name__)

PUBLIC_PATHS = {
    "/health",
    "/api/incidents/health",
    "/api/analytics/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/metrics",
}

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
            payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.JWT_ALGORITHM])
            request.state.user = payload
            request.state.tenant_id = payload.get("tenant_id", settings.DEFAULT_TENANT_ID)
        except JWTError:
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
