import hmac
import logging
import time
from fastapi import APIRouter, HTTPException, Response, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from jose import jwt, JWTError
from config import settings
from core.identity.jwt import create_access_token, revoke_jti

logger = logging.getLogger(__name__)

router = APIRouter()

# Login brute-force guard (in-memory, per ip+username). Gateway also throttles
# edge (auth_limit 5r/s) — this adds account lockout the gateway can't do.
_FAILED_LOGINS: dict = {}
_MAX_FAILS = 5
_LOCKOUT_SECONDS = 300


def _client_ip(http_request: Request) -> str:
    for h in ("X-Forwarded-For", "X-Real-IP"):
        v = http_request.headers.get(h)
        if v:
            return v.split(",")[0].strip()
    try:
        return http_request.client.host if http_request.client else "unknown"
    except Exception:
        return "unknown"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)

@router.post("/login")
async def login(http_request: Request, request: LoginRequest, response: Response):
    ip = _client_ip(http_request)
    key = (ip, request.username)
    now = time.time()
    # Evict expired lockouts so the table can't grow forever.
    if len(_FAILED_LOGINS) > 1000:
        for k, v in list(_FAILED_LOGINS.items()):
            if v.get("locked_until", 0) <= now:
                _FAILED_LOGINS.pop(k, None)
    state = _FAILED_LOGINS.get(key)
    if state:
        # Lockout expired → fresh start (a single new typo must not re-lock).
        if state.get("locked_until", 0) and state["locked_until"] <= now:
            _FAILED_LOGINS.pop(key, None)
            state = None
    if state and state.get("locked_until", 0) > now:
        retry = int(state["locked_until"] - now)
        return JSONResponse(
            status_code=429,
            content={"detail": f"Too many failed logins. Retry in {retry}s."},
            headers={"Retry-After": str(retry)},
        )
    role = ""
    username = ""
    if hmac.compare_digest(request.username, settings.ADMIN_USERNAME) and \
            hmac.compare_digest(request.password, settings.ADMIN_PASSWORD):
        role, username = "ADMIN", settings.ADMIN_USERNAME
    elif settings.APPROVER_USERNAME and hmac.compare_digest(request.username, settings.APPROVER_USERNAME) and \
            hmac.compare_digest(request.password, settings.APPROVER_PASSWORD):
        role, username = "APPROVER", settings.APPROVER_USERNAME
    elif settings.ANALYST_USERNAME and hmac.compare_digest(request.username, settings.ANALYST_USERNAME) and \
            hmac.compare_digest(request.password, settings.ANALYST_PASSWORD):
        role, username = "ANALYST", settings.ANALYST_USERNAME
    logger.info("Login attempt: username=%s success=%s role=%s", request.username, bool(role), role or "-")
    if not role:
        fails = (_FAILED_LOGINS.get(key, {}).get("count", 0) + 1)
        locked_until = now + _LOCKOUT_SECONDS if fails >= _MAX_FAILS else 0
        _FAILED_LOGINS[key] = {"count": fails, "locked_until": locked_until}
        if locked_until:
            retry = _LOCKOUT_SECONDS
            return JSONResponse(
                status_code=429,
                content={"detail": f"Too many failed logins. Retry in {retry}s."},
                headers={"Retry-After": str(retry)},
            )
        raise HTTPException(status_code=401, detail="Invalid credentials")
    _FAILED_LOGINS.pop(key, None)
    if role:
        tenant_id = settings.DEFAULT_TENANT_ID if settings.TENANT_MODE == "single" else username
        user_data = {
            "id": f"usr-{role.lower()}",
            "username": username,
            "role": role,
            "permissions": ["all"] if role == "ADMIN" else (
                ["soar:approve", "incidents:review"] if role == "APPROVER"
                else ["soar:trigger", "incidents:work"]),
            "tenant_id": tenant_id,
        }
        token = create_access_token(user_data)

        response.set_cookie(
            key="s2_token",
            value=token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

        return {"user": {"username": username, "role": role, "tenant_id": tenant_id}, "access_token": token, "token_type": "bearer"}

    raise HTTPException(status_code=401, detail="Invalid credentials")

@router.get("/validate")
async def validate_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        token = auth_header.split(" ", 1)[1]
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.JWT_ALGORITHM])
        try:
            from core.identity.jwt import is_jti_revoked
            if is_jti_revoked(payload.get("jti", "")):
                raise HTTPException(status_code=401, detail="Session revoked")
        except HTTPException:
            raise
        except Exception:
            pass
        return {"sub": payload.get("sub"), "role": payload.get("role"), "tenant_id": payload.get("tenant_id", settings.DEFAULT_TENANT_ID), "valid": True}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.get("/health")
async def health():
    return {"status": "healthy", "service": "identity-service"}

@router.post("/logout")
async def logout(request: Request, response: Response):
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ", 1)[1]
            payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.JWT_ALGORITHM])
            jti = payload.get("jti", "")
            exp = float(payload.get("exp", 0)) if payload.get("exp") else 0
            revoke_jti(jti, exp)
        except Exception:
            pass
    response.delete_cookie("s2_token")
    return {"message": "Logged out"}
